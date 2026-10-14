//! Independent spend simulation and net-effect summary (spec 11.1 items 1 and 3).
//!
//! Every coin spend is executed locally with the chain's CLVM interpreter. The summary
//! is derived **only** from the resulting conditions and the coins being spent — never
//! from anything the dApp says about the request.

use crate::error::KitError;
use crate::option::{
    self, OptionAction, OptionEffect, OptionLeg, OptionOutput, OptionOutputRole, OptionTerms,
    Revealed, UnderlyingPath,
};
use chia_bls::PublicKey;
use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend};
use chia_puzzle_types::Memos;
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_sdk_driver::{CatInfo, Layer, Puzzle, SettlementLayer, StandardLayer};
use chia_sdk_types::{Condition, run_puzzle_with_cost};
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::{tree_hash, tree_hash_atom, tree_hash_pair};
use clvmr::{Allocator, NodePtr, SExp};
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
    pub(crate) fn owns(&self, ph: &Bytes32) -> bool {
        self.p2_puzzle_hashes.contains(ph)
    }
}

/// An asset. `#[non_exhaustive]`: later versions may add assets, so a `match` needs a
/// wildcard arm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "type", content = "asset_id", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AssetId {
    /// XCH (mojos).
    #[default]
    Xch,
    /// A CAT identified by its TAIL hash.
    Cat(#[serde(serialize_with = "ser_hex32")] Bytes32),
    /// An option contract identified by its launcher id (spec 11.1.1). Amounts are the
    /// mojos of the option singleton (normally 1): one option.
    Option(#[serde(serialize_with = "ser_hex32")] Bytes32),
}

impl AssetId {
    /// XCH and options: coins whose amount is XCH (an option singleton holds mojos).
    pub fn is_mojo_backed(&self) -> bool {
        matches!(self, AssetId::Xch | AssetId::Option(_))
    }
}

pub(crate) fn ser_hex32<S: serde::Serializer>(b: &Bytes32, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(b))
}

pub(crate) fn ser_opt_hex32<S: serde::Serializer>(
    b: &Option<Bytes32>,
    s: S,
) -> Result<S::Ok, S::Error> {
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

/// Recognised puzzle type of a spent coin. `#[non_exhaustive]`: later versions may
/// recognise more puzzles.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
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
    /// The singleton launcher of an option minted in this request (spec 11.1.1). A launcher
    /// that does not launch a verified option stays [`SpendKind::Unknown`].
    SingletonLauncher {
        /// The launcher's coin id: the option's id.
        #[serde(serialize_with = "ser_hex32")]
        launcher_id: Bytes32,
    },
    /// An option contract singleton (spec 11.1.1).
    Option {
        /// Option id.
        #[serde(serialize_with = "ser_hex32")]
        launcher_id: Bytes32,
        /// Owner of the spent option coin (p2 puzzle hash). For a mint, the eve's launch
        /// puzzle; the new owner is in `new_owner`.
        #[serde(serialize_with = "ser_hex32")]
        p2_puzzle_hash: Bytes32,
        /// The collateral coin the option commits to.
        #[serde(serialize_with = "ser_hex32")]
        underlying_coin_id: Bytes32,
        /// Hash of the exercise the option commits to (strike, expiry, creator, amount).
        #[serde(serialize_with = "ser_hex32")]
        underlying_delegated_puzzle_hash: Bytes32,
        /// Mint (eve spend), transfer or exercise (melt).
        action: OptionAction,
        /// The new owner's p2 puzzle hash; `None` when exercised.
        #[serde(serialize_with = "ser_opt_hex32")]
        new_owner: Option<Bytes32>,
        /// The terms, when this request proves them (mint, exercise); a transfer reveals
        /// only their hash.
        terms: Option<OptionTerms>,
    },
    /// The collateral coin of an option (`p2_1_of_n`, bare or inside a CAT).
    OptionUnderlying {
        /// Option id, when this request proves it.
        #[serde(serialize_with = "ser_opt_hex32")]
        launcher_id: Option<Bytes32>,
        /// Creator: receives the strike, takes the collateral back after expiry.
        #[serde(serialize_with = "ser_hex32")]
        creator_puzzle_hash: Bytes32,
        /// Expiry (unix time).
        expiration_seconds: u64,
        /// Exercise or clawback.
        path: UnderlyingPath,
        /// Asset of the collateral.
        asset: AssetId,
        /// Hidden puzzle hash of a revocable CAT collateral, if any.
        #[serde(serialize_with = "ser_opt_hex32")]
        hidden_puzzle_hash: Option<Bytes32>,
    },
    /// Not recognised: the wallet must show "Unknown contract" and the puzzle hash
    /// (spec 11.1 item 3).
    #[default]
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
/// `#[non_exhaustive]`: build one with `OutputInfo::default()` and set its fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
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
    /// The output belongs to an option the request mints (the collateral it locks, or the
    /// launcher), spec 11.1.1. When the user holds that option and its launch is guaranteed
    /// (`option.user_holds_option`) it is not a payment and `recipient` is `None`, except
    /// collateral under another creator: a payment to that creator (`recipient`), who takes
    /// it back after expiry unless the user exercises. Otherwise it is a payment to the
    /// option's owner (`recipient`), or to no one the wallet can name when the launch is
    /// not guaranteed (`recipient` is `None`).
    pub option: Option<OptionOutput>,
    /// The output is an offer settlement coin (the settlement puzzle, bare, inside a CAT or
    /// as an option's owner): whoever spends it chooses where it goes, within the payments
    /// the request asserts (spec 11.2).
    pub settlement: bool,
    /// Created by a spend the user signs but the wallet does not recognise (an unknown
    /// contract around the user's key: an NFT, a vault, a wrapped standard coin). The wallet
    /// cannot say what the spend moves: show it as a danger, never as nothing. Such an output
    /// is never counted as received by the user (spec 11.1 item 3).
    pub unaccounted: bool,
}

/// Result of [`simulate`]. `#[non_exhaustive]`: build one with `Summary::default()` and set
/// its fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
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
    /// Puzzle hashes of spends with unrecognised puzzles (hex), and of spends the user signs
    /// whose puzzle the wallet does not recognise as the user's (see
    /// [`Self::unaccounted_spends`]).
    pub unknown_puzzles: Vec<String>,
    /// Coin ids (hex) of the spends the user signs although the wallet does not recognise
    /// the coin as the user's: an unknown contract that requires one of the wallet's keys
    /// (an NFT, a vault, a wrapped standard coin). They count as the user's for binding,
    /// limits and the amount leaving the user, but what they create is never counted as
    /// received ([`OutputInfo::unaccounted`]). Render them as a danger (spec 11.1 item 3).
    /// Filled when the wallet's keys are known (the request handlers, [`claim_signed`]).
    pub unaccounted_spends: Vec<String>,
    /// Total CLVM cost.
    pub cost: u64,
    /// Per-spend details.
    pub spends: Vec<SpendInfo>,
    /// Every coin created by the user's own spends, in order. Lets a wallet say where the
    /// money goes ("0.1 XCH to xch1…", "only to your own addresses") rather than only how
    /// much the user's balance changes.
    pub outputs: Vec<OutputInfo>,
    /// What the request does with option contracts (spec 11.1.1), every fact computed by
    /// the wallet.
    pub options: Vec<OptionEffect>,
    /// Per user spend, per asset: what the spend removes from the balance, what its own
    /// outputs pay to the user, and the collateral a clawback takes back. The exercise
    /// cover of a request whose signatures are released counts each spend on its own
    /// (spec 11.1.1).
    #[serde(skip)]
    pub(crate) owned_flows: Vec<BTreeMap<AssetId, Flow>>,
}

/// One user spend's effect on one asset (see [`Summary::owned_flows`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Flow {
    /// What the spend removes from the user's balance.
    pub(crate) removed: u128,
    /// What its own outputs pay to the user.
    pub(crate) to_user: u128,
    /// Collateral a clawback takes back (it was locked, not part of the balance).
    pub(crate) clawed: u128,
}

impl Summary {
    /// Delta for one asset, if present.
    pub fn asset(&self, a: AssetId) -> Option<&AssetDelta> {
        self.assets.iter().find(|d| d.asset == a)
    }
}

/// Executed spend with its parsed conditions (used by the policy and binding checks).
/// `#[non_exhaustive]`: produced by [`execute`] only.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    /// The spend's outputs are fixed by the user's own spends: the eve spend of an option
    /// whose launch is guaranteed (spec 11.1.1). Its outputs count as received even when
    /// the spend is not the user's.
    pub outputs_bound: bool,
    /// The `AGG_SIG_ME` messages of this spend that are the tree hash of a quoted program
    /// `(q . conditions)` the spend's solution reveals: the only `AGG_SIG_ME` messages the
    /// policy signs (spec 11.1 item 2).
    pub(crate) quoted_messages: HashSet<Bytes32>,
    /// For the eve spend of a verified mint: the spends whose links decide whether its
    /// launch is guaranteed (spec 11.1.1 item 1).
    pub(crate) mint: Option<option::MintLinks>,
    /// The user's only through the wallet's key: the wallet signs it, but does not recognise
    /// the coin as its own ([`claim_signed`]). `owned` is then also true.
    pub(crate) by_key: bool,
}

impl ExecutedSpend {
    /// The user signs this spend although the wallet does not recognise the coin as the
    /// user's (an unknown contract around the user's key; [`claim_signed`]).
    pub fn signed_unrecognised(&self) -> bool {
        self.by_key
    }
}

/// Every spend for which the wallet would produce a signature (an `AGG_SIG_*` condition
/// naming one of `keys`) is a user spend (spec 11.2): for binding, linking, the sealed
/// rules and the limits. A spend the wallet signs but does not recognise as the user's is
/// marked [`ExecutedSpend::signed_unrecognised`] and counted as owned: its coin leaves the
/// user, and what it creates is never counted as received. Run it after [`execute`] and
/// before [`simulate`]'s summary; the request handlers always do.
pub fn claim_signed(executed: &mut [ExecutedSpend], keys: &HashSet<PublicKey>) {
    for es in executed.iter_mut().filter(|es| !es.owned) {
        let signs = es.conditions.iter().any(|c| {
            c.clone()
                .into_agg_sig()
                .is_some_and(|sig| keys.contains(&sig.public_key))
        });
        if signs {
            es.owned = true;
            es.by_key = true;
        }
    }
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
    let mut revealed = Vec::with_capacity(coin_spends.len());
    let mut coin_ids = HashSet::with_capacity(coin_spends.len());
    for (i, cs) in coin_spends.iter().enumerate() {
        // A coin is spent once: a request that spends it twice can never be valid, and would
        // let the dApp choose between two signed spends of the same coin.
        if !coin_ids.insert(cs.coin.coin_id()) {
            return Err(KitError::InvalidRequest("coinSpends"));
        }
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
        let quoted_messages = quoted_messages(allocator, &conditions, solution);
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
        revealed.push(Revealed {
            puzzle,
            solution,
            cost: reduction.0,
        });
        out.push(ExecutedSpend {
            coin: cs.coin,
            kind,
            owned,
            conditions,
            hints,
            outputs_bound: false,
            quoted_messages,
            mint: None,
            by_key: false,
        });
    }
    option::classify(allocator, &revealed, &mut out, ownership);
    Ok((out, costs))
}

/// The `AGG_SIG_ME` messages among `conditions` that are the tree hash of a quoted program
/// `(q . x)` somewhere in `solution`.
///
/// The standard puzzle signs the tree hash of its delegated puzzle and outputs whatever that
/// puzzle returns for the (unsigned) delegated solution. Only a quoted delegated puzzle
/// returns the same conditions whatever the solution, so only then does the signature cover
/// them. Finding the message's preimage among the quoted programs the solution reveals
/// proves the delegated puzzle is one (tree hashes do not collide), whatever layers wrap
/// the standard puzzle.
fn quoted_messages(
    allocator: &Allocator,
    conditions: &[Condition<NodePtr>],
    solution: NodePtr,
) -> HashSet<Bytes32> {
    let wanted: HashSet<Bytes32> = conditions
        .iter()
        .filter_map(|c| match c {
            Condition::AggSigMe(sig) => Bytes32::try_from(sig.message.as_ref()).ok(),
            _ => None,
        })
        .collect();
    let mut found = HashSet::new();
    if wanted.is_empty() {
        return found;
    }
    // Iterative post-order tree hashing, memoised by node: the solution is a DAG in the
    // allocator, and dApp-chosen depth must not exhaust the stack.
    let mut hashes: HashMap<NodePtr, Bytes32> = HashMap::new();
    let mut stack = vec![(solution, false)];
    while let Some((node, children_done)) = stack.pop() {
        if hashes.contains_key(&node) {
            continue;
        }
        match allocator.sexp(node) {
            SExp::Atom => {
                let h = tree_hash_atom(allocator.atom(node).as_ref());
                hashes.insert(node, Bytes32::from(h));
            }
            SExp::Pair(first, rest) => {
                if !children_done {
                    stack.push((node, true));
                    stack.push((rest, false));
                    stack.push((first, false));
                    continue;
                }
                let (Some(hf), Some(hr)) = (hashes.get(&first), hashes.get(&rest)) else {
                    continue;
                };
                let h = Bytes32::from(tree_hash_pair((*hf).into(), (*hr).into()));
                let is_quote = matches!(allocator.sexp(first), SExp::Atom)
                    && allocator.atom(first).as_ref() == [1u8];
                if is_quote && wanted.contains(&h) {
                    found.insert(h);
                }
                hashes.insert(node, h);
            }
        }
    }
    found
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

/// Asset of the coin a spend removes.
pub(crate) fn asset_of(kind: &SpendKind) -> AssetId {
    match kind {
        SpendKind::Cat { asset_id, .. } => AssetId::Cat(*asset_id),
        SpendKind::Option { launcher_id, .. } | SpendKind::SingletonLauncher { launcher_id } => {
            AssetId::Option(*launcher_id)
        }
        SpendKind::OptionUnderlying { asset, .. } => *asset,
        _ => AssetId::Xch,
    }
}

/// Asset of a coin a spend creates. An option singleton wraps only its odd output; an even
/// output of an option spend is plain XCH. A launcher creates the option's eve singleton.
fn output_asset(kind: &SpendKind, amount: u64) -> AssetId {
    match kind {
        SpendKind::Option { .. } if amount % 2 == 0 => AssetId::Xch,
        other => asset_of(other),
    }
}

/// The CAT layer around a spend's outputs.
fn cat_layer(kind: &SpendKind) -> Option<(Bytes32, Option<Bytes32>)> {
    match kind {
        SpendKind::Cat {
            asset_id,
            hidden_puzzle_hash,
            ..
        } => Some((*asset_id, *hidden_puzzle_hash)),
        SpendKind::OptionUnderlying {
            asset: AssetId::Cat(asset_id),
            hidden_puzzle_hash,
            ..
        } => Some((*asset_id, *hidden_puzzle_hash)),
        _ => None,
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
    // Owned option singleton puzzle hashes per option spend.
    let mut option_owned: HashMap<(Bytes32, Bytes32, Bytes32), HashSet<Bytes32>> = HashMap::new();
    // Coins of a mint (collateral, launcher) -> what they belong to, and who receives them:
    // the mint's owner when its launch is guaranteed and the request does not move the
    // option on; for the collateral of an option the user holds, its creator when that is
    // not the user (it takes the collateral back unless the user exercises in time).
    let mut option_outputs: HashMap<Bytes32, (OptionOutput, Option<Bytes32>)> = HashMap::new();
    // Options the request also moves on (transfers or exercises) after minting them: their
    // mint's owner is not where the option ends up.
    let moved: HashSet<Bytes32> = executed
        .iter()
        .filter_map(|es| match &es.kind {
            SpendKind::Option {
                launcher_id,
                action: OptionAction::Transfer | OptionAction::Exercise,
                ..
            } => Some(*launcher_id),
            _ => None,
        })
        .collect();
    for es in executed {
        if let SpendKind::Option {
            launcher_id,
            underlying_coin_id,
            action: OptionAction::Mint,
            new_owner: Some(owner),
            terms,
            ..
        } = &es.kind
        {
            let named = es.outputs_bound && !moved.contains(launcher_id);
            let user_holds_option = named && ownership.owns(owner);
            let owner = named.then_some(*owner);
            let creator = terms
                .map(|t| t.creator_puzzle_hash)
                .filter(|c| !ownership.owns(c));
            for (coin_id, role) in [
                (*underlying_coin_id, OptionOutputRole::Collateral),
                (*launcher_id, OptionOutputRole::Launcher),
            ] {
                let output = OptionOutput {
                    launcher_id: *launcher_id,
                    role,
                    user_holds_option,
                };
                let recipient = match role {
                    _ if !user_holds_option => owner,
                    OptionOutputRole::Collateral => creator,
                    OptionOutputRole::Launcher => None,
                };
                option_outputs.insert(coin_id, (output, recipient));
            }
        }
    }
    let settlement_ph = Bytes32::from(SETTLEMENT_PAYMENT_HASH);
    let mut funded: HashSet<Bytes32> = HashSet::new();
    let (mut xch_removed, mut xch_added) = (0u128, 0u128);
    let (mut reserve_fee, mut owned_reserve_fee) = (0u64, 0u64);
    let mut locks = TimeLocks::default();
    let mut spends = Vec::with_capacity(executed.len());
    let mut outputs = Vec::new();
    let mut owned_flows = Vec::new();

    for (es, cost) in executed.iter().zip(costs) {
        let mut flows: BTreeMap<AssetId, Flow> = BTreeMap::new();
        let asset = asset_of(&es.kind);
        if asset.is_mojo_backed() {
            xch_removed += u128::from(es.coin.amount);
        }
        // Owned output puzzle hashes for this spend's CAT outputs (wrapped), and the wrapped
        // settlement puzzle hash.
        let layer = cat_layer(&es.kind);
        let owned_cat: Option<&HashSet<Bytes32>> = layer.map(|(asset_id, hidden)| {
            &*wrapped.entry((asset_id, hidden)).or_insert_with(|| {
                ownership
                    .p2_puzzle_hashes
                    .iter()
                    .map(|p2| Bytes32::from(CatInfo::new(asset_id, hidden, *p2).puzzle_hash()))
                    .collect()
            })
        });
        let settlement_out = layer.map_or(settlement_ph, |(asset_id, hidden)| {
            Bytes32::from(CatInfo::new(asset_id, hidden, settlement_ph).puzzle_hash())
        });
        // Owned option singleton puzzle hashes for this spend's odd output.
        let owned_option: Option<&HashSet<Bytes32>> = match &es.kind {
            SpendKind::Option {
                launcher_id,
                underlying_coin_id,
                underlying_delegated_puzzle_hash,
                ..
            } => {
                let key = (
                    *launcher_id,
                    *underlying_coin_id,
                    *underlying_delegated_puzzle_hash,
                );
                Some(&*option_owned.entry(key).or_insert_with(|| {
                    ownership
                        .p2_puzzle_hashes
                        .iter()
                        .map(|p2| option::option_puzzle_hash(key.0, key.1, key.2, *p2))
                        .collect()
                }))
            }
            _ => None,
        };
        // A spend the user signs but the wallet does not recognise: what it creates is not
        // fixed by anything the wallet can check, so it is never received.
        let credited = (es.owned && !es.by_key) || es.outputs_bound;
        let parent_id = es.coin.coin_id();
        // What this spend returns to the user in its own asset, and the XCH an option
        // spend pays out as even (plain XCH) outputs.
        let (mut returned, mut option_even_out) = (0u128, 0u128);
        let mut agg_sigs = Vec::new();
        let mut hints = es.hints.iter();
        for c in &es.conditions {
            match c {
                Condition::CreateCoin(cc) => {
                    let hint = hints.next().copied().flatten();
                    let out_asset = output_asset(&es.kind, cc.amount);
                    let is_option = matches!(out_asset, AssetId::Option(_));
                    let to_user = match (is_option, owned_option, owned_cat) {
                        (true, Some(set), _) => set.contains(&cc.puzzle_hash),
                        // A launcher's child is the eve singleton, never the user's.
                        (true, None, _) => false,
                        (false, _, Some(set)) => set.contains(&cc.puzzle_hash),
                        (false, _, None) => ownership.owns(&cc.puzzle_hash),
                    };
                    if out_asset.is_mojo_backed() {
                        xch_added += u128::from(cc.amount);
                    }
                    if matches!(es.kind, SpendKind::Option { .. }) && !is_option {
                        option_even_out += u128::from(cc.amount);
                    }
                    if to_user && out_asset == asset && !es.by_key {
                        returned += u128::from(cc.amount);
                    }
                    if es.owned && !es.by_key && to_user {
                        flows.entry(out_asset).or_default().to_user += u128::from(cc.amount);
                    }
                    if es.owned {
                        let coin_id = Coin::new(parent_id, cc.puzzle_hash, cc.amount).coin_id();
                        funded.insert(coin_id);
                        let option = option_outputs.get(&coin_id).copied();
                        let new_owner = match &es.kind {
                            SpendKind::Option { new_owner, .. } if is_option => *new_owner,
                            _ => None,
                        };
                        let recipient = match option {
                            // The user holds the option: a lock, not a payment, or (the
                            // collateral under another creator) a payment to the creator;
                            // otherwise a payment to the option's owner, named only if the
                            // launch is guaranteed.
                            Some((_, to)) => to,
                            None if is_option => new_owner,
                            None if owned_cat.is_some() => hint,
                            None => Some(cc.puzzle_hash),
                        };
                        outputs.push(OutputInfo {
                            asset: out_asset,
                            amount: cc.amount,
                            puzzle_hash: hex::encode(cc.puzzle_hash),
                            recipient: recipient.map(hex::encode),
                            to_user,
                            option: option.map(|(o, _)| o),
                            settlement: if is_option {
                                new_owner == Some(settlement_ph)
                            } else {
                                cc.puzzle_hash == settlement_out
                            },
                            unaccounted: es.by_key,
                        });
                    }
                    if to_user {
                        let d = deltas.entry(out_asset).or_default();
                        if credited {
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
        if es.owned {
            let removed = match &es.kind {
                // The eve of a verified mint was created by this request's launcher: nothing
                // the user held leaves (spec 11.1.1).
                SpendKind::Option {
                    action: OptionAction::Mint,
                    ..
                } => 0,
                // Collateral the creator takes back was locked, not part of the balance:
                // only what does not return to the user leaves.
                SpendKind::OptionUnderlying {
                    path: UnderlyingPath::Clawback,
                    ..
                } => u128::from(es.coin.amount).saturating_sub(returned),
                _ => u128::from(es.coin.amount),
            };
            if removed > 0 {
                deltas.entry(asset).or_default().0 += removed;
                flows.entry(asset).or_default().removed += removed;
            }
            // An option singleton is counted as the option; XCH it pays out as even outputs
            // leaves the user's XCH.
            if option_even_out > 0 {
                deltas.entry(AssetId::Xch).or_default().0 += option_even_out;
                flows.entry(AssetId::Xch).or_default().removed += option_even_out;
            }
            if matches!(
                es.kind,
                SpendKind::OptionUnderlying {
                    path: UnderlyingPath::Clawback,
                    ..
                }
            ) {
                flows.entry(asset).or_default().clawed += u128::from(es.coin.amount);
            }
            owned_flows.push(flows);
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
        .zip(executed)
        .filter(|(s, es)| s.kind == SpendKind::Unknown || es.by_key)
        .map(|(s, _)| s.puzzle_hash.clone())
        .collect();
    let unaccounted_spends = spends
        .iter()
        .zip(executed)
        .filter(|(_, es)| es.by_key)
        .map(|(s, _)| s.coin_id.clone())
        .collect();
    Ok(Summary {
        assets,
        implied_fee,
        reserve_fee,
        owned_reserve_fee,
        time_locks: locks,
        unknown_puzzles,
        unaccounted_spends,
        cost: costs.iter().sum(),
        spends,
        outputs,
        options: option_effects(executed, ownership, &funded),
        owned_flows,
    })
}

/// The option effects of a request, one per option spend (and one per clawback).
fn option_effects(
    executed: &[ExecutedSpend],
    ownership: &Ownership,
    funded: &HashSet<Bytes32>,
) -> Vec<OptionEffect> {
    let mut out = Vec::new();
    for es in executed {
        match &es.kind {
            SpendKind::Option {
                launcher_id,
                underlying_coin_id,
                action,
                new_owner,
                terms,
                ..
            } => match (action, new_owner, terms) {
                (OptionAction::Mint, Some(owner), Some(terms)) => out.push(OptionEffect::Mint {
                    launcher_id: *launcher_id,
                    owner: *owner,
                    owner_is_user: ownership.owns(owner),
                    creator_is_user: ownership.owns(&terms.creator_puzzle_hash),
                    funded_by_user: funded.contains(underlying_coin_id),
                    guaranteed: es.outputs_bound,
                    collateral_coin_id: *underlying_coin_id,
                    terms: *terms,
                }),
                (OptionAction::Transfer, Some(to), _) => out.push(OptionEffect::Transfer {
                    launcher_id: *launcher_id,
                    from_user: es.owned,
                    to: *to,
                    to_user: ownership.owns(to),
                    to_settlement: *to == Bytes32::from(SETTLEMENT_PAYMENT_HASH),
                }),
                (OptionAction::Exercise, None, Some(terms)) => out.push(OptionEffect::Exercise {
                    launcher_id: *launcher_id,
                    by_user: es.owned,
                    creator_is_user: ownership.owns(&terms.creator_puzzle_hash),
                    terms: *terms,
                }),
                _ => {}
            },
            SpendKind::OptionUnderlying {
                launcher_id,
                creator_puzzle_hash,
                expiration_seconds,
                path: UnderlyingPath::Clawback,
                asset,
                ..
            } => out.push(OptionEffect::Clawback {
                launcher_id: *launcher_id,
                creator: *creator_puzzle_hash,
                creator_is_user: ownership.owns(creator_puzzle_hash),
                collateral: OptionLeg {
                    asset: *asset,
                    amount: es.coin.amount,
                },
                unlocks_at_seconds: *expiration_seconds,
            }),
            _ => {}
        }
    }
    out
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
    fn a_five_coin_send_shows_the_whole_amount_and_the_chain_accepts_it() {
        // The coins of a real testnet11 wallet whose 2 TXCH send needed five of them. The
        // first spend creates the outputs; the other four only contribute their value.
        let mut sim = Simulator::new();
        let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
        let amounts = [
            1_993_377_483_423u64,
            6_622_523_367,
            6_622_516_577,
            1_000_000_000,
            999_000_000,
        ];
        let total: u64 = amounts.iter().sum();
        let (send, fee) = (2_000_000_000_000u64, 1_000_000u64);
        let mut spends = standard(
            &mut sim,
            &alice,
            amounts[0],
            Conditions::new()
                .create_coin(bob.puzzle_hash, send, Memos::None)
                .create_coin(alice.puzzle_hash, total - send - fee, Memos::None)
                .reserve_fee(fee),
        );
        for amount in &amounts[1..] {
            spends.extend(standard(&mut sim, &alice, *amount, Conditions::new()));
        }

        let s = simulate(&spends, &owned(alice.puzzle_hash), DEFAULT_MAX_COST).unwrap();
        let d = s.asset(AssetId::Xch).unwrap();
        assert_eq!(d.sent, u128::from(total));
        assert_eq!(
            d.net,
            -i128::from(send + fee),
            "the loss is the send plus the fee"
        );
        assert_eq!((s.implied_fee, s.reserve_fee), (Some(fee), fee));
        assert_eq!(s.spends.len(), 5);
        assert!(s.spends.iter().all(|spend| spend.owned));
        let to_others: Vec<_> = s.outputs.iter().filter(|o| !o.to_user).collect();
        assert_eq!(to_others.len(), 1);
        assert_eq!(to_others[0].amount, send);

        // One aggregated signature over all five spends; the chain accepts the bundle.
        sim.spend_coins(spends, &[alice.sk]).unwrap();
        let bob_coins = sim.unspent_coins(bob.puzzle_hash, false);
        assert_eq!(bob_coins.iter().map(|c| c.amount).sum::<u64>(), send);
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
