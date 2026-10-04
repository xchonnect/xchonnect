//! CHIP-0002 `signCoinSpends` requests built for the key the wallet under test exposes.
//!
//! The suite cannot know a third-party wallet's coins, so it asks for its public key
//! (`getPublicKeys`) and constructs spends of standard (`p2_delegated_puzzle_or_hidden`)
//! coins for that key: the puzzle hash is derived from the key, which is what every Chia
//! wallet uses for its receive addresses. A positive control request tells the suite
//! whether this assumption holds before any refusal is read as conformance.
//!
//! Expected effects and signing messages are computed with `xchonnect-wallet-kit`, the
//! same way the spec describes them, so the suite can check *what* a wallet signed and
//! not just that it answered.

use crate::report::Fail;
use chia_bls::{PublicKey, Signature};
use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chia_puzzle_types::Memos;
use chia_puzzle_types::offer::{NotarizedPayment, Payment, SettlementPaymentsSolution};
use chia_puzzle_types::standard::StandardArgs;
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_sdk_driver::{Layer, SettlementLayer, SpendContext, StandardLayer};
use chia_sdk_types::Conditions;
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::tree_hash;
use clvmr::Allocator;
use serde_json::json;
use std::collections::HashSet;
use xchonnect_core::crypto::sha256_parts;
use xchonnect_wallet_kit as kit;
use xchonnect_wallet_kit::simulate::{AssetId, DEFAULT_MAX_COST, Ownership};

fn built(what: &str, e: impl std::fmt::Debug) -> Fail {
    Fail::Fail(format!("the suite could not build the {what} spend: {e:?}"))
}

/// The key a wallet exposed, and the standard puzzle hash derived from it.
#[derive(Debug, Clone)]
pub(crate) struct WalletKey {
    pub(crate) pk: PublicKey,
    pub(crate) puzzle_hash: Bytes32,
    pub(crate) hex: String,
}

impl WalletKey {
    /// Parse a `getPublicKeys` entry (hex, with or without `0x`; spec 9.1 encodings).
    pub(crate) fn parse(hex_key: &str) -> Result<Self, Fail> {
        let bytes = hex::decode(hex_key.trim_start_matches("0x"))
            .ok()
            .and_then(|b| <[u8; 48]>::try_from(b).ok())
            .ok_or_else(|| {
                Fail::Fail(format!(
                    "getPublicKeys returned {hex_key:?}, which is not a 48-byte hex key \
                     (spec 9.1)"
                ))
            })?;
        let pk = PublicKey::from_bytes(&bytes)
            .map_err(|e| Fail::Fail(format!("getPublicKeys returned an invalid key: {e:?}")))?;
        if pk.is_inf() {
            return Err(Fail::Fail(
                "getPublicKeys returned the infinity key, which cannot sign anything".to_owned(),
            ));
        }
        Ok(WalletKey {
            puzzle_hash: Bytes32::from(StandardArgs::curry_tree_hash(pk)),
            pk,
            hex: format!("0x{}", hex::encode(bytes)),
        })
    }

    fn own_coin(&self, parent: u8, amount: u64) -> Coin {
        Coin::new(Bytes32::new([parent; 32]), self.puzzle_hash, amount)
    }

    fn ownership(&self) -> Ownership {
        Ownership {
            p2_puzzle_hashes: [self.puzzle_hash].into_iter().collect(),
        }
    }
}

/// One request the suite can send, with everything needed to judge the answer.
#[derive(Debug, Clone)]
pub(crate) struct Case {
    /// `signCoinSpends` params as JSON text.
    pub(crate) params: String,
    spends: Vec<CoinSpend>,
    partial: bool,
}

impl Case {
    fn new(spends: Vec<CoinSpend>, partial: bool) -> Self {
        let coin_spends: Vec<_> = spends
            .iter()
            .map(|cs| {
                json!({
                    "coin": {
                        "parent_coin_info": format!("0x{}", hex::encode(cs.coin.parent_coin_info)),
                        "puzzle_hash": format!("0x{}", hex::encode(cs.coin.puzzle_hash)),
                        "amount": cs.coin.amount,
                    },
                    "puzzle_reveal": format!("0x{}", hex::encode(cs.puzzle_reveal.as_ref())),
                    "solution": format!("0x{}", hex::encode(cs.solution.as_ref())),
                })
            })
            .collect();
        Case {
            params: json!({ "coinSpends": coin_spends, "partialSign": partial }).to_string(),
            spends,
            partial,
        }
    }

    /// Guaranteed XCH loss the wallet must measure for this request (spec 11.1 item 1).
    pub(crate) fn guaranteed_loss(&self, key: &WalletKey) -> Result<u128, Fail> {
        let summary = kit::simulate(&self.spends, &key.ownership(), DEFAULT_MAX_COST)
            .map_err(|e| built("simulated", e))?;
        Ok(kit::permissions::guaranteed_loss(&summary)
            .get(&AssetId::Xch)
            .copied()
            .unwrap_or(0))
    }

    /// Check that `signature` is exactly the aggregate of the signatures this request
    /// needs from `key`, over the messages the spec prescribes for each AGG_SIG variant.
    pub(crate) fn verify_signature(
        &self,
        key: &WalletKey,
        chain_id: &str,
        signature: &Signature,
    ) -> Result<usize, Fail> {
        let mut a = Allocator::new();
        let (executed, _) =
            kit::simulate::execute(&mut a, &self.spends, &key.ownership(), DEFAULT_MAX_COST)
                .map_err(|e| built("executed", e))?;
        let keys: HashSet<PublicKey> = [key.pk].into_iter().collect();
        let network = network_for(chain_id)?;
        let plan = kit::plan(
            &executed,
            &keys,
            &kit::PolicyOptions {
                network,
                session_chain_id: chain_id.to_owned(),
                allow_agg_sig_unsafe: true,
                partial: self.partial,
            },
        )
        .map_err(|e| built("planned", e))?;
        if plan.ours.is_empty() {
            return Err(Fail::Fail(
                "the suite built a request that needs no signature from the wallet".to_owned(),
            ));
        }
        let pairs = plan
            .ours
            .iter()
            .map(|r| (r.public_key(), r.message_bytes()));
        if !chia_bls::aggregate_verify(signature, pairs) {
            return Err(Fail::Fail(format!(
                "the returned signature is not the aggregate of the {} AGG_SIG message(s) this \
                 request needs for the wallet's own key (spec 11.1 item 2): the wallet signed \
                 something else",
                plan.ours.len()
            )));
        }
        Ok(plan.ours.len())
    }
}

/// `kit::Network` for a CHIP-0002 chain id.
pub(crate) fn network_for(chain_id: &str) -> Result<kit::Network, Fail> {
    match chain_id {
        "mainnet" => Ok(kit::Network::Mainnet),
        "testnet11" => Ok(kit::Network::Testnet11),
        other => Err(Fail::Skip(format!(
            "the wallet reported chainId {other:?}; the suite can only build spends for \
             mainnet and testnet11"
        ))),
    }
}

/// A plain send: the wallet's coin of `amount` pays `amount - change` away and keeps the
/// change, so the guaranteed loss is exactly `amount - change` (spec 11.1 item 1).
pub(crate) fn send(key: &WalletKey, amount: u64, change: u64) -> Result<Case, Fail> {
    let paid = amount
        .checked_sub(change)
        .ok_or_else(|| built("send", "change above the coin amount"))?;
    let coin = key.own_coin(1, amount);
    let mut ctx = SpendContext::new();
    let mut conds = Conditions::new().create_coin(Bytes32::new([9; 32]), paid, Memos::None);
    if change > 0 {
        conds = conds.create_coin(key.puzzle_hash, change, Memos::None);
    }
    StandardLayer::new(key.pk)
        .spend(&mut ctx, coin, conds)
        .map_err(|e| built("send", e))?;
    Ok(Case::new(ctx.take(), false))
}

/// A standard spend whose solution asks for `AGG_SIG_UNSAFE` with the wallet's key: a
/// signature valid in any spend context, which a wallet must refuse by default
/// (spec 11.1 item 2).
pub(crate) fn agg_sig_unsafe(key: &WalletKey) -> Result<Case, Fail> {
    let coin = key.own_coin(2, 1_000);
    let mut ctx = SpendContext::new();
    StandardLayer::new(key.pk)
        .spend(
            &mut ctx,
            coin,
            Conditions::new()
                .create_coin(key.puzzle_hash, 1_000, Memos::None)
                .agg_sig_unsafe(key.pk, b"sign this anywhere".to_vec().into()),
        )
        .map_err(|e| built("AGG_SIG_UNSAFE", e))?;
    Ok(Case::new(ctx.take(), false))
}

/// An unrecognised puzzle that wants the wallet's signature: the wallet cannot tell the
/// user what it does and must not sign blindly (spec 11.1 item 3).
pub(crate) fn unknown_puzzle(key: &WalletKey) -> Result<Case, Fail> {
    let spend = anyone_can_spend(
        3,
        1_000,
        Conditions::new()
            .create_coin(Bytes32::new([9; 32]), 1_000, Memos::None)
            .agg_sig_me(key.pk, b"blind".to_vec().into()),
    )?;
    Ok(Case::new(vec![spend], false))
}

/// A spend of somebody else's coin that needs somebody else's signature: there is
/// nothing here the wallet may sign for (spec 11.1 item 2).
pub(crate) fn foreign_coin() -> Result<Case, Fail> {
    let stranger = other_key()?;
    let puzzle_hash = Bytes32::from(StandardArgs::curry_tree_hash(stranger));
    let coin = Coin::new(Bytes32::new([4; 32]), puzzle_hash, 1_000);
    let mut ctx = SpendContext::new();
    StandardLayer::new(stranger)
        .spend(
            &mut ctx,
            coin,
            Conditions::new().create_coin(Bytes32::new([9; 32]), 1_000, Memos::None),
        )
        .map_err(|e| built("foreign coin", e))?;
    Ok(Case::new(ctx.take(), false))
}

/// A valid BLS key the suite holds no secret for: nothing a wallet may ever sign with.
pub(crate) fn other_key() -> Result<PublicKey, Fail> {
    // The generator point of G1, i.e. the public key of the secret key 1: a well-formed
    // key, deterministic, and not one any wallet can hold.
    const G1_GENERATOR: [u8; 48] = [
        0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac,
        0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b,
        0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb,
        0x22, 0xc6, 0xbb,
    ];
    PublicKey::from_bytes(&G1_GENERATOR)
        .map_err(|e| Fail::Fail(format!("the suite's reference key is invalid: {e:?}")))
}

/// A `partialSign` request in the shape of an offer: the wallet pays `give` mojos into
/// the settlement puzzle and a settlement spend in the same request pays it `take`.
///
/// With `bind` the wallet's spend asserts the puzzle announcement of that payment, so it
/// cannot be included without being paid. Without it the counterparty can take the
/// wallet's coin and drop the payment, and a conforming wallet must refuse to sign
/// (spec 11.2).
pub(crate) fn partial_offer(
    key: &WalletKey,
    give: u64,
    take: u64,
    bind: bool,
) -> Result<Case, Fail> {
    let (payment, announcement) = requested_payment(key.puzzle_hash, take)?;
    let settlement = Bytes32::from(SETTLEMENT_PAYMENT_HASH);
    let coin = key.own_coin(5, give);
    let mut ctx = SpendContext::new();
    let mut conds = Conditions::new().create_coin(settlement, give, Memos::None);
    if bind {
        conds = conds.assert_puzzle_announcement(announcement);
    }
    StandardLayer::new(key.pk)
        .spend(&mut ctx, coin, conds)
        .map_err(|e| built("partial offer", e))?;
    let mut spends = ctx.take();
    spends.push(payment);
    Ok(Case::new(spends, true))
}

/// A settlement-payment spend paying `amount` to `to`, as an offer's requested payment,
/// plus the announcement id a maker has to assert to be bound to it.
fn requested_payment(to: Bytes32, amount: u64) -> Result<(CoinSpend, Bytes32), Fail> {
    let np = NotarizedPayment::new(
        Bytes32::new([7; 32]),
        vec![Payment::new(to, amount, Memos::None)],
    );
    let mut ctx = SpendContext::new();
    let node = ctx.alloc(&np).map_err(|e| built("notarized payment", e))?;
    let message = ctx.tree_hash(node).to_bytes();
    let announcement = Bytes32::from(sha256_parts(&[
        SETTLEMENT_PAYMENT_HASH.as_slice(),
        &message,
    ]));
    let puzzle = SettlementLayer
        .construct_puzzle(&mut ctx)
        .map_err(|e| built("settlement puzzle", e))?;
    let solution = SettlementLayer
        .construct_solution(&mut ctx, SettlementPaymentsSolution::new(vec![np]))
        .map_err(|e| built("settlement solution", e))?;
    let spend = CoinSpend::new(
        Coin::new(
            Bytes32::default(),
            Bytes32::from(SETTLEMENT_PAYMENT_HASH),
            0,
        ),
        ctx.serialize(&puzzle)
            .map_err(|e| built("settlement puzzle", e))?,
        ctx.serialize(&solution)
            .map_err(|e| built("settlement solution", e))?,
    );
    Ok((spend, announcement))
}

/// A coin with the puzzle `1`, whose solution is the condition list: an unrecognised
/// contract from a wallet's point of view.
fn anyone_can_spend(parent: u8, amount: u64, conds: Conditions) -> Result<CoinSpend, Fail> {
    let mut a = Allocator::new();
    let puzzle = Program::from(vec![0x01]);
    let node = puzzle
        .to_clvm(&mut a)
        .map_err(|e| built("anyone-can-spend", e))?;
    let puzzle_hash = Bytes32::from(tree_hash(&a, node));
    let solution = conds
        .to_clvm(&mut a)
        .map_err(|e| built("anyone-can-spend", e))?;
    Ok(CoinSpend::new(
        Coin::new(Bytes32::new([parent; 32]), puzzle_hash, amount),
        puzzle,
        Program::from_clvm(&a, solution).map_err(|e| built("anyone-can-spend", e))?,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;

    /// The suite's own cases must mean what the checks assume they mean, or every
    /// judgement built on them is wrong.
    #[test]
    fn the_cases_have_the_effects_the_checks_rely_on() {
        let pk = chia_bls::SecretKey::from_seed(&[7u8; 32]).public_key();
        let key = WalletKey::parse(&hex::encode(pk.to_bytes())).unwrap();
        assert_eq!(key.pk, pk, "a key without the 0x prefix parses too");
        // A send of 1000 keeping 400 loses exactly 600.
        assert_eq!(
            send(&key, 1_000, 400).unwrap().guaranteed_loss(&key),
            Ok(600)
        );
        // Each case needs exactly one signature from the wallet's key.
        for case in [
            send(&key, 1_000, 0).unwrap(),
            agg_sig_unsafe(&key).unwrap(),
            unknown_puzzle(&key).unwrap(),
            partial_offer(&key, 1_000, 500, true).unwrap(),
            partial_offer(&key, 1_000, 500, false).unwrap(),
        ] {
            let sig = Signature::default();
            let e = case
                .verify_signature(&key, "testnet11", &sig)
                .expect_err("the identity signature must not verify");
            assert!(format!("{e:?}").contains("not the aggregate"), "{e:?}");
        }
        // The partial cases differ only in the binding.
        let bound = partial_offer(&key, 1_000, 500, true).unwrap();
        let unbound = partial_offer(&key, 1_000, 500, false).unwrap();
        assert_ne!(bound.params, unbound.params);
        assert_eq!(bound.guaranteed_loss(&key), Ok(1_000));
        // A spend of somebody else's coin needs nothing from this wallet.
        let foreign = foreign_coin().unwrap();
        assert!(
            foreign
                .verify_signature(&key, "testnet11", &Signature::default())
                .is_err()
        );
        assert_eq!(foreign.guaranteed_loss(&key), Ok(0));
    }
}
