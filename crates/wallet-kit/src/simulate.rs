//! Independent spend simulation and net-effect summary (spec 11.1 items 1 and 3).
//!
//! Every coin spend is executed locally with the chain's CLVM interpreter. The summary
//! is derived **only** from the resulting conditions and the coins being spent — never
//! from anything the dApp says about the request.

use crate::error::KitError;
use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend};
use chia_puzzle_types::Memos;
use chia_sdk_driver::{CatInfo, Layer, Puzzle, SettlementLayer, StandardLayer};
use chia_sdk_types::{Condition, run_puzzle_with_cost};
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::tree_hash;
use clvmr::{Allocator, NodePtr};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Default CLVM cost limit for one request: the chain's per-block limit.
pub const DEFAULT_MAX_COST: u64 = 11_000_000_000;

/// Puzzle hashes the wallet controls (standard p2 puzzle hashes of its derivations).
#[derive(Debug, Clone, Default)]
pub struct Ownership {
    /// Owned p2 puzzle hashes.
    pub p2_puzzle_hashes: HashSet<Bytes32>,
}

impl Ownership {
    fn owns(&self, ph: &Bytes32) -> bool {
        self.p2_puzzle_hashes.contains(ph)
    }
}

/// An asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "type", content = "asset_id", rename_all = "snake_case")]
pub enum AssetId {
    /// XCH (mojos).
    Xch,
    /// A CAT identified by its TAIL hash.
    Cat(#[serde(serialize_with = "ser_hex32")] Bytes32),
}

fn ser_hex32<S: serde::Serializer>(b: &Bytes32, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(b))
}

fn ser_opt_hex32<S: serde::Serializer>(b: &Option<Bytes32>, s: S) -> Result<S::Ok, S::Error> {
    b.map(hex::encode).serialize(s)
}

/// What happens to one asset for the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssetDelta {
    /// Asset.
    pub asset: AssetId,
    /// Amount leaving the user's coins (smallest units).
    pub sent: u128,
    /// Amount arriving at the user's puzzle hashes from the user's **own** spends. These
    /// outputs are covered by the user's signature (AGG_SIG_ME binds a spend's conditions),
    /// so they cannot be dropped while the user's coins are spent.
    pub received: u128,
    /// Amount arriving from spends the user does **not** own or sign (offer settlement,
    /// counterparty coins). Nothing guarantees these are included on-chain unless the
    /// user's spends assert them (multi-party binding, spec 11.2); a wallet must not treat
    /// them as received without that check.
    pub conditional_received: u128,
    /// `received - sent`: the guaranteed effect.
    pub net: i128,
}

/// Recognised puzzle type of a spent coin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SpendKind {
    /// Standard XCH puzzle.
    Standard,
    /// CAT (`p2_puzzle_hash` is the inner owner).
    Cat {
        /// TAIL hash.
        #[serde(serialize_with = "ser_hex32")]
        asset_id: Bytes32,
        /// Inner p2 puzzle hash.
        #[serde(serialize_with = "ser_hex32")]
        p2_puzzle_hash: Bytes32,
        /// Hidden puzzle hash of a revocable CAT (hex), if any.
        #[serde(serialize_with = "ser_opt_hex32")]
        hidden_puzzle_hash: Option<Bytes32>,
    },
    /// Offer settlement payments puzzle.
    Settlement,
    /// Not recognised: the wallet must show "Unknown contract" and the puzzle hash
    /// (spec 11.1 item 3).
    Unknown,
}

/// Time conditions across the request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TimeLocks {
    /// Not valid before this unix time (`ASSERT_SECONDS_ABSOLUTE`, maximum).
    pub not_before_seconds: Option<u64>,
    /// Not valid before this height (`ASSERT_HEIGHT_ABSOLUTE`, maximum).
    pub not_before_height: Option<u32>,
    /// Expires at this unix time (`ASSERT_BEFORE_SECONDS_ABSOLUTE`, minimum).
    pub expires_seconds: Option<u64>,
    /// Expires at this height (`ASSERT_BEFORE_HEIGHT_ABSOLUTE`, minimum).
    pub expires_height: Option<u32>,
    /// Some spend has relative time conditions (seconds/height since coin creation).
    pub has_relative: bool,
}

/// One signature requirement found in a spend's conditions (exact signing messages are
/// computed by the policy layer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AggSigInfo {
    /// Condition opcode (43–50).
    pub opcode: u8,
    /// G1 public key (hex).
    pub public_key: String,
    /// Raw message from the condition (hex).
    pub message: String,
}

/// Per-spend details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpendInfo {
    /// Coin id (hex).
    pub coin_id: String,
    /// Puzzle hash (hex) — shown for unknown contracts.
    pub puzzle_hash: String,
    /// Amount of the spent coin.
    pub amount: u64,
    /// Recognised puzzle type.
    pub kind: SpendKind,
    /// The coin belongs to the user.
    pub owned: bool,
    /// AGG_SIG conditions.
    pub agg_sigs: Vec<AggSigInfo>,
    /// CLVM cost of running the puzzle.
    pub cost: u64,
}

/// One coin created by a spend the user signs: what the user's signature sends where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutputInfo {
    /// Asset of the created coin.
    pub asset: AssetId,
    /// Amount (smallest units).
    pub amount: u64,
    /// Puzzle hash of the created coin (hex). For a CAT this is the wrapped puzzle hash.
    pub puzzle_hash: String,
    /// The recipient's p2 puzzle hash (hex), the one an address encodes: the puzzle hash
    /// itself for XCH, the hint for a CAT. `None` for a CAT output without a 32-byte hint.
    pub recipient: Option<String>,
    /// Arrives at one of the user's own puzzle hashes (change, or a send to oneself).
    pub to_user: bool,
}

/// Result of [`simulate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Net effect per asset (XCH first), only assets the user touches.
    pub assets: Vec<AssetDelta>,
    /// Fee implied by the request (XCH removed − XCH added) when non-negative. `None`
    /// means outputs exceed inputs, i.e. the request relies on coins not included
    /// (partial or multi-party spend).
    pub implied_fee: Option<u64>,
    /// Sum of `RESERVE_FEE` conditions.
    pub reserve_fee: u64,
    /// Part of [`Self::reserve_fee`] declared by the user's own spends (limit accounting;
    /// fees reserved only by counterparty spends are not the user's loss).
    #[serde(skip)]
    pub owned_reserve_fee: u64,
    /// Time conditions.
    pub time_locks: TimeLocks,
    /// Puzzle hashes of spends with unrecognised puzzles (hex).
    pub unknown_puzzles: Vec<String>,
    /// Total CLVM cost.
    pub cost: u64,
    /// Per-spend details.
    pub spends: Vec<SpendInfo>,
    /// Every coin created by the user's own spends, in order. Lets a wallet say where the
    /// money goes ("0.1 XCH to xch1…", "only to your own addresses") rather than only how
    /// much the user's balance changes.
    pub outputs: Vec<OutputInfo>,
}

impl Summary {
    /// Delta for one asset, if present.
    pub fn asset(&self, a: AssetId) -> Option<&AssetDelta> {
        self.assets.iter().find(|d| d.asset == a)
    }
}

/// Executed spend with its parsed conditions (used by the policy and binding checks).
#[derive(Debug, Clone)]
pub struct ExecutedSpend {
    /// The coin.
    pub coin: Coin,
    /// Recognised kind.
    pub kind: SpendKind,
    /// The coin belongs to the user.
    pub owned: bool,
    /// Parsed conditions.
    pub conditions: Vec<Condition<NodePtr>>,
    /// The first memo of each `CREATE_COIN`, in order, when it is 32 bytes (the hint).
    pub hints: Vec<Option<Bytes32>>,
}

/// Execute all spends; shared by [`simulate`] and the policy layer.
pub fn execute(
    allocator: &mut Allocator,
    coin_spends: &[CoinSpend],
    ownership: &Ownership,
    max_cost: u64,
) -> Result<(Vec<ExecutedSpend>, Vec<u64>), KitError> {
    let mut out = Vec::with_capacity(coin_spends.len());
    let mut costs = Vec::with_capacity(coin_spends.len());
    let mut remaining = max_cost;
    for (i, cs) in coin_spends.iter().enumerate() {
        // Checked before each run: a budget of 0 would mean "unlimited" to the CLVM, while a
        // request whose total cost lands exactly on the budget is still within it.
        if remaining == 0 {
            return Err(KitError::CostExceeded);
        }
        let puzzle = cs
            .puzzle_reveal
            .to_clvm(allocator)
            .map_err(|_| KitError::InvalidRequest("puzzle_reveal"))?;
        let solution = cs
            .solution
            .to_clvm(allocator)
            .map_err(|_| KitError::InvalidRequest("solution"))?;
        if Bytes32::from(tree_hash(allocator, puzzle)) != cs.coin.puzzle_hash {
            return Err(KitError::PuzzleHashMismatch { spend: i });
        }
        let reduction = run_puzzle_with_cost(allocator, puzzle, solution, remaining, true)
            .map_err(|e| match e {
                clvmr::error::EvalErr::CostExceeded => KitError::CostExceeded,
                _ => KitError::Execution { spend: i },
            })?;
        remaining = remaining.saturating_sub(reduction.0);
        let conditions = Vec::<Condition<NodePtr>>::from_clvm(allocator, reduction.1)
            .map_err(|_| KitError::InvalidCondition { spend: i })?;
        let hints = conditions
            .iter()
            .filter_map(|c| match c {
                Condition::CreateCoin(cc) => Some(hint_of(allocator, &cc.memos)),
                _ => None,
            })
            .collect();
        let parsed = Puzzle::parse(allocator, puzzle);
        let kind = if let Some((info, _)) =
            CatInfo::parse(allocator, parsed).map_err(|_| KitError::Execution { spend: i })?
        {
            SpendKind::Cat {
                asset_id: info.asset_id,
                p2_puzzle_hash: info.p2_puzzle_hash,
                hidden_puzzle_hash: info.hidden_puzzle_hash,
            }
        } else if matches!(StandardLayer::parse_puzzle(allocator, parsed), Ok(Some(_))) {
            SpendKind::Standard
        } else if matches!(
            SettlementLayer::parse_puzzle(allocator, parsed),
            Ok(Some(_))
        ) {
            SpendKind::Settlement
        } else {
            SpendKind::Unknown
        };
        let owned = match &kind {
            SpendKind::Cat { p2_puzzle_hash, .. } => ownership.owns(p2_puzzle_hash),
            _ => ownership.owns(&cs.coin.puzzle_hash),
        };
        costs.push(reduction.0);
        out.push(ExecutedSpend {
            coin: cs.coin,
            kind,
            owned,
            conditions,
            hints,
        });
    }
    Ok((out, costs))
}

/// The first memo of a `CREATE_COIN` when it is exactly 32 bytes: the conventional hint.
fn hint_of(allocator: &Allocator, memos: &Memos<NodePtr>) -> Option<Bytes32> {
    let Memos::Some(node) = memos else {
        return None;
    };
    let list = Vec::<Bytes>::from_clvm(allocator, *node).ok()?;
    let first = list.first()?;
    Bytes32::try_from(first.as_ref()).ok()
}

/// Simulate a `signCoinSpends` request and summarise its effect on the user.
pub fn simulate(
    coin_spends: &[CoinSpend],
    ownership: &Ownership,
    max_cost: u64,
) -> Result<Summary, KitError> {
    let mut allocator = Allocator::new();
    let (executed, costs) = execute(&mut allocator, coin_spends, ownership, max_cost)?;
    summarize(&executed, &costs, ownership)
}

/// Asset moved by a spend.
pub(crate) fn asset_of(kind: &SpendKind) -> AssetId {
    match kind {
        SpendKind::Cat { asset_id, .. } => AssetId::Cat(*asset_id),
        _ => AssetId::Xch,
    }
}

/// Earliest of an optional current bound and a new one.
fn earliest<T: Ord + Copy>(current: Option<T>, v: T) -> Option<T> {
    Some(current.map_or(v, |c| c.min(v)))
}

/// [`simulate`] for spends already run by [`execute`].
pub(crate) fn summarize(
    executed: &[ExecutedSpend],
    costs: &[u64],
    ownership: &Ownership,
) -> Result<Summary, KitError> {
    // asset -> (sent, received from own spends, received from other spends)
    let mut deltas: BTreeMap<AssetId, (u128, u128, u128)> = BTreeMap::new();
    // Owned output puzzle hashes per (asset, hidden puzzle hash), computed once.
    let mut wrapped: HashMap<(Bytes32, Option<Bytes32>), HashSet<Bytes32>> = HashMap::new();
    let (mut xch_removed, mut xch_added) = (0u128, 0u128);
    let (mut reserve_fee, mut owned_reserve_fee) = (0u64, 0u64);
    let mut locks = TimeLocks::default();
    let mut spends = Vec::with_capacity(executed.len());
    let mut outputs = Vec::new();

    for (es, cost) in executed.iter().zip(costs) {
        let asset = asset_of(&es.kind);
        if asset == AssetId::Xch {
            xch_removed += u128::from(es.coin.amount);
        }
        if es.owned {
            deltas.entry(asset).or_default().0 += u128::from(es.coin.amount);
        }
        // Owned output puzzle hashes for this spend's asset (CAT outputs are wrapped).
        let owned_set: Option<&HashSet<Bytes32>> = match &es.kind {
            SpendKind::Cat {
                asset_id,
                hidden_puzzle_hash,
                ..
            } => Some(
                wrapped
                    .entry((*asset_id, *hidden_puzzle_hash))
                    .or_insert_with(|| {
                        ownership
                            .p2_puzzle_hashes
                            .iter()
                            .map(|p2| {
                                Bytes32::from(
                                    CatInfo::new(*asset_id, *hidden_puzzle_hash, *p2).puzzle_hash(),
                                )
                            })
                            .collect()
                    }),
            ),
            _ => None,
        };
        let owned_output = |ph: &Bytes32| -> bool {
            owned_set.map_or_else(|| ownership.owns(ph), |set| set.contains(ph))
        };
        let mut agg_sigs = Vec::new();
        let mut hints = es.hints.iter();
        for c in &es.conditions {
            match c {
                Condition::CreateCoin(cc) => {
                    let hint = hints.next().copied().flatten();
                    if asset == AssetId::Xch {
                        xch_added += u128::from(cc.amount);
                    }
                    if es.owned {
                        let recipient = match es.kind {
                            SpendKind::Cat { .. } => hint,
                            _ => Some(cc.puzzle_hash),
                        };
                        outputs.push(OutputInfo {
                            asset,
                            amount: cc.amount,
                            puzzle_hash: hex::encode(cc.puzzle_hash),
                            recipient: recipient.map(hex::encode),
                            to_user: owned_output(&cc.puzzle_hash),
                        });
                    }
                    if owned_output(&cc.puzzle_hash) {
                        let d = deltas.entry(asset).or_default();
                        if es.owned {
                            d.1 += u128::from(cc.amount);
                        } else {
                            d.2 += u128::from(cc.amount);
                        }
                    }
                }
                Condition::ReserveFee(r) => {
                    reserve_fee = reserve_fee
                        .checked_add(r.amount)
                        .ok_or(KitError::Overflow)?;
                    if es.owned {
                        owned_reserve_fee += r.amount;
                    }
                }
                Condition::AssertSecondsAbsolute(t) => {
                    locks.not_before_seconds = locks.not_before_seconds.max(Some(t.seconds))
                }
                Condition::AssertHeightAbsolute(t) => {
                    locks.not_before_height = locks.not_before_height.max(Some(t.height))
                }
                Condition::AssertBeforeSecondsAbsolute(t) => {
                    locks.expires_seconds = earliest(locks.expires_seconds, t.seconds)
                }
                Condition::AssertBeforeHeightAbsolute(t) => {
                    locks.expires_height = earliest(locks.expires_height, t.height)
                }
                Condition::AssertSecondsRelative(_)
                | Condition::AssertHeightRelative(_)
                | Condition::AssertBeforeSecondsRelative(_)
                | Condition::AssertBeforeHeightRelative(_) => {
                    locks.has_relative = true;
                }
                other => {
                    if let Some(sig) = other.clone().into_agg_sig() {
                        agg_sigs.push(AggSigInfo {
                            opcode: sig.kind as u8,
                            public_key: hex::encode(sig.public_key.to_bytes()),
                            message: hex::encode(&sig.message),
                        });
                    }
                }
            }
        }
        spends.push(SpendInfo {
            coin_id: hex::encode(es.coin.coin_id()),
            puzzle_hash: hex::encode(es.coin.puzzle_hash),
            amount: es.coin.amount,
            kind: es.kind.clone(),
            owned: es.owned,
            agg_sigs,
            cost: *cost,
        });
    }

    let assets = deltas
        .into_iter()
        .map(|(asset, (sent, received, conditional_received))| {
            let net = i128::try_from(received).map_err(|_| KitError::Overflow)?
                - i128::try_from(sent).map_err(|_| KitError::Overflow)?;
            Ok(AssetDelta {
                asset,
                sent,
                received,
                conditional_received,
                net,
            })
        })
        .collect::<Result<Vec<_>, KitError>>()?;
    let implied_fee = xch_removed
        .checked_sub(xch_added)
        .and_then(|f| u64::try_from(f).ok());
    let unknown_puzzles = spends
        .iter()
        .filter(|s| s.kind == SpendKind::Unknown)
        .map(|s| s.puzzle_hash.clone())
        .collect();
    Ok(Summary {
        assets,
        implied_fee,
        reserve_fee,
        owned_reserve_fee,
        time_locks: locks,
        unknown_puzzles,
        cost: costs.iter().sum(),
        spends,
        outputs,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::swap_fixture::{anyone_can_spend, owned};
    use chia_protocol::{Bytes, Program};
    use chia_puzzle_types::Memos;
    use chia_sdk_driver::{Cat, CatSpend, SpendContext, SpendWithConditions};
    use chia_sdk_test::{BlsPair, Simulator};
    use chia_sdk_types::Conditions;

    /// Spend a new standard coin of `amount` owned by `from` with `conds`.
    fn standard(
        sim: &mut Simulator,
        from: &BlsPair,
        amount: u64,
        conds: Conditions,
    ) -> Vec<CoinSpend> {
        let coin = sim.new_coin(from.puzzle_hash, amount);
        let mut ctx = SpendContext::new();
        StandardLayer::new(from.pk)
            .spend(&mut ctx, coin, conds)
            .unwrap();
        ctx.take()
    }

    /// Alice sends 700 of 1000 mojos to Bob, keeps 290, pays a 10 mojo fee.
    fn xch_send(sim: &mut Simulator, alice: &BlsPair, bob: &BlsPair) -> Vec<CoinSpend> {
        let conds = Conditions::new()
            .create_coin(bob.puzzle_hash, 700, Memos::None)
            .create_coin(alice.puzzle_hash, 290, Memos::None)
            .reserve_fee(10);
        standard(sim, alice, 1000, conds)
    }

    #[test]
    fn standard_send_from_both_sides() {
        let mut sim = Simulator::new();
        let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
        let spends = xch_send(&mut sim, &alice, &bob);

        let s = simulate(&spends, &owned(alice.puzzle_hash), DEFAULT_MAX_COST).unwrap();
        assert_eq!((s.reserve_fee, s.owned_reserve_fee), (10, 10));
        // Seen by bob, alice's reserved fee is not bob's.
        let b = simulate(&spends, &owned(bob.puzzle_hash), DEFAULT_MAX_COST).unwrap();
        assert_eq!((b.reserve_fee, b.owned_reserve_fee), (10, 0));
        assert_eq!(
            s.asset(AssetId::Xch).unwrap(),
            &AssetDelta {
                asset: AssetId::Xch,
                sent: 1000,
                received: 290,
                conditional_received: 0,
                net: -710
            }
        );
        assert_eq!((s.implied_fee, s.reserve_fee), (Some(10), 10));
        // Where the money goes: 700 to Bob, 290 back to Alice (change).
        let outputs: Vec<_> = s
            .outputs
            .iter()
            .map(|o| (o.amount, o.recipient.clone(), o.to_user))
            .collect();
        assert_eq!(
            outputs,
            vec![
                (700, Some(hex::encode(bob.puzzle_hash)), false),
                (290, Some(hex::encode(alice.puzzle_hash)), true),
            ]
        );
        assert_eq!(s.spends[0].kind, SpendKind::Standard);
        assert!(s.spends[0].owned && s.unknown_puzzles.is_empty());
        assert_eq!(s.spends[0].agg_sigs.len(), 1);
        assert_eq!(
            s.spends[0].agg_sigs[0].opcode, 50,
            "standard puzzle signs with AGG_SIG_ME"
        );

        // Bob does not own or sign Alice's coin: the 700 are conditional, not guaranteed.
        let s = simulate(&spends, &owned(bob.puzzle_hash), DEFAULT_MAX_COST).unwrap();
        let d = s.asset(AssetId::Xch).unwrap();
        assert_eq!((d.received, d.conditional_received, d.net), (0, 700, 0));

        // The simulated request is a real, valid transaction.
        sim.spend_coins(spends, &[alice.sk]).unwrap();
    }

    #[test]
    fn a_send_to_oneself_costs_only_the_fee_and_says_so() {
        // Both outputs go to Alice's own puzzle hash: the net effect is just the fee, and
        // every output is marked as hers, so a wallet can say "to your own address".
        let mut sim = Simulator::new();
        let alice = BlsPair::new(1);
        let conds = Conditions::new()
            .create_coin(alice.puzzle_hash, 100, Memos::None)
            .create_coin(alice.puzzle_hash, 890, Memos::None)
            .reserve_fee(10);
        let spends = standard(&mut sim, &alice, 1000, conds);
        let s = simulate(&spends, &owned(alice.puzzle_hash), DEFAULT_MAX_COST).unwrap();
        assert_eq!(s.asset(AssetId::Xch).unwrap().net, -10);
        assert_eq!(s.outputs.len(), 2);
        assert!(s.outputs.iter().all(|o| o.to_user));
    }

    #[test]
    fn misleading_drain_is_visible() {
        // A request a dApp might describe as "approve 1 mojo" that pays everything to someone else.
        let mut sim = Simulator::new();
        let (alice, attacker) = (BlsPair::new(1), BlsPair::new(9));
        let conds = Conditions::new().create_coin(attacker.puzzle_hash, 5_000_000, Memos::None);
        let spends = standard(&mut sim, &alice, 5_000_000, conds);
        let s = simulate(&spends, &owned(alice.puzzle_hash), DEFAULT_MAX_COST).unwrap();
        let d = s.asset(AssetId::Xch).unwrap();
        assert_eq!((d.sent, d.received, d.net), (5_000_000, 0, -5_000_000));
    }

    #[test]
    fn a_cat_output_names_its_hinted_recipient() {
        let mut sim = Simulator::new();
        let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
        let coin = sim.new_coin(alice.puzzle_hash, 1000);
        let mut ctx = SpendContext::new();
        let (issue, cats) = Cat::single_issuance(
            &mut ctx,
            coin.coin_id(),
            None,
            1000,
            Conditions::new().create_coin(alice.puzzle_hash, 1000, Memos::None),
        )
        .unwrap();
        StandardLayer::new(alice.pk)
            .spend(&mut ctx, coin, issue)
            .unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .unwrap();

        let bob_hint = ctx.hint(bob.puzzle_hash).unwrap();
        let alice_hint = ctx.hint(alice.puzzle_hash).unwrap();
        let inner = StandardLayer::new(alice.pk)
            .spend_with_conditions(
                &mut ctx,
                Conditions::new()
                    .create_coin(bob.puzzle_hash, 400, bob_hint)
                    .create_coin(alice.puzzle_hash, 600, alice_hint),
            )
            .unwrap();
        Cat::spend_all(&mut ctx, &[CatSpend::new(cats[0], inner)]).unwrap();
        let spends = ctx.take();

        let s = simulate(&spends, &owned(alice.puzzle_hash), DEFAULT_MAX_COST).unwrap();
        let outputs: Vec<_> = s
            .outputs
            .iter()
            .map(|o| (o.asset, o.amount, o.recipient.clone(), o.to_user))
            .collect();
        let asset = AssetId::Cat(cats[0].info.asset_id);
        assert_eq!(
            outputs,
            vec![
                (asset, 400, Some(hex::encode(bob.puzzle_hash)), false),
                (asset, 600, Some(hex::encode(alice.puzzle_hash)), true),
            ]
        );
        // The created coin is the wrapped CAT puzzle hash, not the recipient's p2.
        assert_ne!(s.outputs[0].puzzle_hash, hex::encode(bob.puzzle_hash));
    }

    #[test]
    fn cat_transfer() {
        let mut sim = Simulator::new();
        let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
        let coin = sim.new_coin(alice.puzzle_hash, 1000);
        let mut ctx = SpendContext::new();
        // Issue 1000 CAT units to Alice, then send 400 to Bob in a second transaction.
        let (issue, cats) = Cat::single_issuance(
            &mut ctx,
            coin.coin_id(),
            None,
            1000,
            Conditions::new().create_coin(alice.puzzle_hash, 1000, Memos::None),
        )
        .unwrap();
        StandardLayer::new(alice.pk)
            .spend(&mut ctx, coin, issue)
            .unwrap();
        sim.spend_coins(ctx.take(), std::slice::from_ref(&alice.sk))
            .unwrap();

        let cat = cats[0];
        let inner = StandardLayer::new(alice.pk)
            .spend_with_conditions(
                &mut ctx,
                Conditions::new()
                    .create_coin(bob.puzzle_hash, 400, Memos::None)
                    .create_coin(alice.puzzle_hash, 600, Memos::None),
            )
            .unwrap();
        Cat::spend_all(&mut ctx, &[CatSpend::new(cat, inner)]).unwrap();
        let spends = ctx.take();
        let asset = AssetId::Cat(cat.info.asset_id);

        let s = simulate(&spends, &owned(alice.puzzle_hash), DEFAULT_MAX_COST).unwrap();
        assert!(
            matches!(s.spends[0].kind, SpendKind::Cat { p2_puzzle_hash, .. } if p2_puzzle_hash == alice.puzzle_hash)
        );
        assert_eq!(
            s.asset(asset).unwrap(),
            &AssetDelta {
                asset,
                sent: 1000,
                received: 600,
                conditional_received: 0,
                net: -400
            }
        );
        assert!(s.asset(AssetId::Xch).is_none(), "no XCH moves");
        assert_eq!(
            simulate(&spends, &owned(bob.puzzle_hash), DEFAULT_MAX_COST)
                .unwrap()
                .asset(asset)
                .unwrap()
                .conditional_received,
            400
        );
        sim.spend_coins(spends, &[alice.sk]).unwrap();
    }

    #[test]
    fn unknown_puzzle_is_flagged() {
        let bob = BlsPair::new(2);
        let spend = anyone_can_spend(
            0,
            1,
            Conditions::new().create_coin(bob.puzzle_hash, 1, Memos::None),
        );
        let ph = spend.coin.puzzle_hash;
        let s = simulate(&[spend], &Ownership::default(), DEFAULT_MAX_COST).unwrap();
        assert_eq!(s.spends[0].kind, SpendKind::Unknown);
        assert_eq!(s.unknown_puzzles, vec![hex::encode(ph)]);
    }

    #[test]
    fn rejects_mismatched_reveal_failures_and_cost() {
        let mut sim = Simulator::new();
        let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
        let mut spends = xch_send(&mut sim, &alice, &bob);
        let mut wrong = spends[0].clone();
        wrong.coin.puzzle_hash = Bytes32::default();
        assert_eq!(
            simulate(&[wrong], &Ownership::default(), DEFAULT_MAX_COST),
            Err(KitError::PuzzleHashMismatch { spend: 0 })
        );
        assert_eq!(
            simulate(&spends, &Ownership::default(), 1_000),
            Err(KitError::CostExceeded)
        );
        // A request costing exactly the budget is within it; one unit less is not.
        let none = Ownership::default();
        let cost = simulate(&spends, &none, DEFAULT_MAX_COST).unwrap().cost;
        assert_eq!(simulate(&spends, &none, cost).unwrap().cost, cost);
        assert_eq!(
            simulate(&spends, &none, cost - 1),
            Err(KitError::CostExceeded)
        );
        // A solution the puzzle rejects (raises).
        spends[0].solution = Program::from(Bytes::from(vec![0x80]));
        assert_eq!(
            simulate(&spends, &Ownership::default(), DEFAULT_MAX_COST),
            Err(KitError::Execution { spend: 0 })
        );
    }

    #[test]
    fn offer_settlement_payment_is_recognised_and_credited() {
        use chia_puzzle_types::offer::{NotarizedPayment, Payment, SettlementPaymentsSolution};
        // The maker side of an offer: a coin locked in the settlement puzzle pays Bob.
        let bob = BlsPair::new(2);
        let mut ctx = SpendContext::new();
        let puzzle = SettlementLayer.construct_puzzle(&mut ctx).unwrap();
        let ph = Bytes32::from(ctx.tree_hash(puzzle));
        let solution = SettlementLayer
            .construct_solution(
                &mut ctx,
                SettlementPaymentsSolution::new(vec![NotarizedPayment::new(
                    Bytes32::new([7; 32]),
                    vec![Payment::new(bob.puzzle_hash, 250, Memos::None)],
                )]),
            )
            .unwrap();
        let spend = CoinSpend::new(
            Coin::new(Bytes32::new([1; 32]), ph, 250),
            ctx.serialize(&puzzle).unwrap(),
            ctx.serialize(&solution).unwrap(),
        );
        let s = simulate(&[spend], &owned(bob.puzzle_hash), DEFAULT_MAX_COST).unwrap();
        assert_eq!(s.spends[0].kind, SpendKind::Settlement);
        assert_eq!(
            s.asset(AssetId::Xch).unwrap(),
            &AssetDelta {
                asset: AssetId::Xch,
                sent: 0,
                received: 0,
                conditional_received: 250,
                net: 0
            }
        );
    }

    #[test]
    fn unsigned_incoming_spend_does_not_offset_a_real_payment() {
        // Review finding: a fake anyone-can-spend coin "paying" the user must not make a
        // real outgoing payment look neutral, because it can be dropped after signing.
        let mut sim = Simulator::new();
        let (alice, attacker) = (BlsPair::new(1), BlsPair::new(9));
        let conds = Conditions::new().create_coin(attacker.puzzle_hash, 1000, Memos::None);
        let mut spends = standard(&mut sim, &alice, 1000, conds);
        spends.push(anyone_can_spend(
            3,
            1000,
            Conditions::new().create_coin(alice.puzzle_hash, 1000, Memos::None),
        ));
        let s = simulate(&spends, &owned(alice.puzzle_hash), DEFAULT_MAX_COST).unwrap();
        let d = s.asset(AssetId::Xch).unwrap();
        assert_eq!(
            (d.sent, d.received, d.conditional_received, d.net),
            (1000, 0, 1000, -1000)
        );
    }
}
