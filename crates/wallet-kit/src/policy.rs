//! Signature scope policy and network check (spec 11.1 items 2 and 6).
//!
//! From the simulated conditions this computes exactly which messages the wallet's keys
//! would sign (with the network's AGG_SIG additional data), refuses `AGG_SIG_UNSAFE`
//! unless the user enabled it for this dApp, and never signs for keys it does not hold.
//!
//! The wallet signs an `AGG_SIG_ME` only over the tree hash of a quoted program the spend
//! reveals, and at most one such message per key and spend. A standard puzzle signs the hash
//! of its delegated puzzle; only a quoted one fixes the conditions the signature
//! authorises, so the conditions the user sees are the only ones the signature allows.
//! `AGG_SIG_UNSAFE` messages that would stand in for a coin-bound or `signMessage`
//! signature are refused even with the override.

use crate::simulate::ExecutedSpend;
use chia_bls::PublicKey;
use chia_protocol::Bytes32;
use chia_sdk_signer::{AggSigConstants, RequiredBlsSignature};
use chia_sdk_types::{MAINNET_CONSTANTS, TESTNET11_CONSTANTS};
use core::fmt;
use serde::Serialize;
use std::collections::HashSet;

/// AGG_SIG_UNSAFE opcode.
pub const AGG_SIG_UNSAFE: u8 = 49;

/// AGG_SIG_ME opcode.
pub const AGG_SIG_ME: u8 = 50;

/// Network the wallet signs for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    /// Chia mainnet.
    Mainnet,
    /// testnet11.
    Testnet11,
    /// Any other network (simulators, private networks).
    Custom {
        /// CHIP-0002 `chainId` string.
        chain_id: String,
        /// Genesis challenge.
        genesis_challenge: Bytes32,
        /// AGG_SIG_ME additional data.
        agg_sig_me: Bytes32,
    },
}

impl Network {
    /// CHIP-0002 `chainId`.
    pub fn chain_id(&self) -> &str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet11 => "testnet11",
            Network::Custom { chain_id, .. } => chain_id,
        }
    }

    /// Genesis challenge.
    pub fn genesis_challenge(&self) -> Bytes32 {
        match self {
            Network::Mainnet => MAINNET_CONSTANTS.genesis_challenge,
            Network::Testnet11 => TESTNET11_CONSTANTS.genesis_challenge,
            Network::Custom {
                genesis_challenge, ..
            } => *genesis_challenge,
        }
    }

    fn agg_sig_constants(&self) -> AggSigConstants {
        AggSigConstants::new(match self {
            Network::Mainnet => MAINNET_CONSTANTS.agg_sig_me_additional_data,
            Network::Testnet11 => TESTNET11_CONSTANTS.agg_sig_me_additional_data,
            Network::Custom { agg_sig_me, .. } => *agg_sig_me,
        })
    }
}

/// The additional data of every coin-bound `AGG_SIG_*` variant on `constants`.
fn suffixes(c: &AggSigConstants) -> [Bytes32; 7] {
    [
        c.me(),
        c.parent(),
        c.puzzle(),
        c.amount(),
        c.puzzle_amount(),
        c.parent_amount(),
        c.parent_puzzle(),
    ]
}

/// An `AGG_SIG_UNSAFE` message whose signature would stand in for another one the wallet
/// only gives after its own checks, so it is refused even where the user allowed
/// `AGG_SIG_UNSAFE`:
///
/// - It ends with the additional data of a coin-bound variant, on this network, mainnet or
///   testnet11 (the same keys sign on every network): its signature is a coin-bound
///   signature for whatever precedes it. The chain refuses such `AGG_SIG_UNSAFE`
///   conditions, so no valid spend needs one signed.
/// - It is 32 bytes long, the length of a CHIP-0002 `signMessage` digest
///   ([`crate::signed_message_hash`]), which cannot be told apart from any other hash.
fn unsafe_message_is_reserved(message: &[u8], network: &AggSigConstants) -> bool {
    if message.len() == 32 {
        return true;
    }
    let known = [
        *network,
        Network::Mainnet.agg_sig_constants(),
        Network::Testnet11.agg_sig_constants(),
    ];
    known
        .iter()
        .flat_map(suffixes)
        .any(|suffix| message.ends_with(suffix.as_ref()))
}

/// Why a request must not be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The session/request is for another network than the wallet's.
    WrongNetwork,
    /// An `AGG_SIG_UNSAFE` for one of the wallet's keys while the dApp has no override.
    AggSigUnsafe,
    /// A required key is not held and `partialSign` is false (CHIP-0002 4005).
    NoSecretKey,
    /// A condition requires a signature from the infinity public key.
    InfinityKey,
    /// Nothing in the request needs the wallet's signature.
    NothingToSign,
    /// An `AGG_SIG_ME` for one of the wallet's keys does not sign a quoted program the spend
    /// reveals, or the spend asks that key for more than one: the signature would not fix
    /// the conditions it authorises.
    UnsignedConditions,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refusal::WrongNetwork => "request is for another network",
            Refusal::AggSigUnsafe => "AGG_SIG_UNSAFE is not allowed for this dApp",
            Refusal::NoSecretKey => "no secret key for a required public key",
            Refusal::InfinityKey => "signature required from the infinity public key",
            Refusal::NothingToSign => "nothing to sign",
            Refusal::UnsignedConditions => "a signature would not cover the spend's conditions",
        })
    }
}

impl std::error::Error for Refusal {}

/// Policy inputs for one request.
#[derive(Debug, Clone)]
pub struct PolicyOptions {
    /// Network the wallet is on.
    pub network: Network,
    /// Network the dApp session was approved for (CHIP-0002 `chainId`).
    pub session_chain_id: String,
    /// The user explicitly allowed `AGG_SIG_UNSAFE` for this dApp (scary confirmation).
    pub allow_agg_sig_unsafe: bool,
    /// CHIP-0002 `partialSign`: skip requirements for keys the wallet does not hold.
    pub partial: bool,
}

/// One signature the wallet would produce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Requirement {
    /// Index of the spend in the request.
    pub spend: usize,
    /// AGG_SIG opcode (43–50).
    pub opcode: u8,
    /// Public key (hex).
    pub public_key: String,
    /// Exact message to sign (hex), including coin/network data for the variant.
    pub message: String,
    /// `AGG_SIG_UNSAFE`: valid in any spend context; the UI must highlight it.
    pub is_unsafe: bool,
    #[serde(skip)]
    pub(crate) key: PublicKey,
    #[serde(skip)]
    pub(crate) message_bytes: Vec<u8>,
}

impl Requirement {
    /// Public key to sign with.
    pub fn public_key(&self) -> &PublicKey {
        &self.key
    }

    /// Message bytes to sign.
    pub fn message_bytes(&self) -> &[u8] {
        &self.message_bytes
    }
}

/// Requirement for a key the wallet does not hold (reported, never signed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Foreign {
    /// Index of the spend.
    pub spend: usize,
    /// AGG_SIG opcode.
    pub opcode: u8,
    /// Public key (hex).
    pub public_key: String,
    #[serde(skip)]
    pub(crate) key: PublicKey,
    #[serde(skip)]
    pub(crate) message_bytes: Vec<u8>,
}

impl SigningPlan {
    /// Every signature the whole request needs, ours and the other parties', as
    /// `(public key, message)`: what an aggregated signature over the bundle must cover.
    pub fn all_requirements(&self) -> Vec<(&PublicKey, &[u8])> {
        self.ours
            .iter()
            .map(|r| (&r.key, r.message_bytes.as_slice()))
            .chain(
                self.foreign
                    .iter()
                    .map(|f| (&f.key, f.message_bytes.as_slice())),
            )
            .collect()
    }
}

/// The signatures a request would need.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SigningPlan {
    /// Signatures the wallet would produce (after approval).
    pub ours: Vec<Requirement>,
    /// Requirements for other keys (other signers in multi-party spends).
    pub foreign: Vec<Foreign>,
    /// Some of `ours` are `AGG_SIG_UNSAFE` (only possible with the override).
    pub has_unsafe: bool,
}

/// Network check (spec 11.1 item 6): refuse sessions approved for another chain.
pub fn check_network(opts: &PolicyOptions) -> Result<(), Refusal> {
    if opts.session_chain_id != opts.network.chain_id() {
        return Err(Refusal::WrongNetwork);
    }
    Ok(())
}

/// Compute the signing plan for executed spends and apply the policy.
pub fn plan(
    spends: &[ExecutedSpend],
    our_keys: &HashSet<PublicKey>,
    opts: &PolicyOptions,
) -> Result<SigningPlan, Refusal> {
    check_network(opts)?;
    let constants = opts.network.agg_sig_constants();
    let mut out = SigningPlan {
        ours: Vec::new(),
        foreign: Vec::new(),
        has_unsafe: false,
    };
    for (i, es) in spends.iter().enumerate() {
        // The one AGG_SIG_ME message each of our keys signs in this spend.
        let mut signed_me: Vec<(PublicKey, Vec<u8>)> = Vec::new();
        for c in &es.conditions {
            let Some(agg) = c.clone().into_agg_sig() else {
                continue;
            };
            if agg.public_key.is_inf() {
                return Err(Refusal::InfinityKey);
            }
            let opcode = agg.kind as u8;
            if !our_keys.contains(&agg.public_key) {
                let req = RequiredBlsSignature::from_condition(&es.coin, agg, &constants);
                out.foreign.push(Foreign {
                    spend: i,
                    opcode,
                    public_key: hex::encode(req.public_key.to_bytes()),
                    message_bytes: req.message(),
                    key: req.public_key,
                });
                continue;
            }
            let is_unsafe = opcode == AGG_SIG_UNSAFE;
            if is_unsafe
                && (!opts.allow_agg_sig_unsafe
                    || unsafe_message_is_reserved(&agg.message, &constants))
            {
                return Err(Refusal::AggSigUnsafe);
            }
            if opcode == AGG_SIG_ME {
                let quoted = Bytes32::try_from(agg.message.as_ref())
                    .is_ok_and(|m| es.quoted_messages.contains(&m));
                if !quoted {
                    return Err(Refusal::UnsignedConditions);
                }
                match signed_me.iter().find(|(k, _)| *k == agg.public_key) {
                    Some((_, m)) if *m != agg.message.as_ref() => {
                        return Err(Refusal::UnsignedConditions);
                    }
                    Some(_) => {}
                    None => signed_me.push((agg.public_key, agg.message.to_vec())),
                }
            }
            let req = RequiredBlsSignature::from_condition(&es.coin, agg, &constants);
            let message_bytes = req.message();
            out.has_unsafe |= is_unsafe;
            out.ours.push(Requirement {
                spend: i,
                opcode,
                public_key: hex::encode(req.public_key.to_bytes()),
                message: hex::encode(&message_bytes),
                is_unsafe,
                key: req.public_key,
                message_bytes,
            });
        }
    }
    if !out.foreign.is_empty() && !opts.partial {
        return Err(Refusal::NoSecretKey);
    }
    if out.ours.is_empty() {
        return Err(Refusal::NothingToSign);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::simulate::{DEFAULT_MAX_COST, Ownership, execute};
    use crate::swap_fixture::{anyone_can_spend, delegated_spend, non_quote_delegations};
    use chia_bls::{Signature, sign};
    use chia_protocol::{Coin, CoinSpend, Program, SpendBundle};
    use chia_puzzle_types::DeriveSynthetic;
    use chia_puzzle_types::Memos;
    use chia_puzzle_types::standard::{StandardArgs, StandardSolution};
    use chia_sdk_driver::{Layer, SpendContext, StandardLayer};
    use chia_sdk_test::{BlsPair, Simulator};
    use chia_sdk_types::Conditions;
    use clvm_traits::{FromClvm, ToClvm};
    use clvmr::{Allocator, NodePtr};
    use proptest::prelude::*;

    fn opts(partial: bool, unsafe_ok: bool) -> PolicyOptions {
        PolicyOptions {
            network: Network::Testnet11,
            session_chain_id: "testnet11".into(),
            allow_agg_sig_unsafe: unsafe_ok,
            partial,
        }
    }

    /// Execute `spends` and plan them for `keys`.
    fn plan_for(
        spends: &[CoinSpend],
        keys: &[PublicKey],
        opts: &PolicyOptions,
    ) -> Result<SigningPlan, Refusal> {
        let mut a = Allocator::new();
        let executed = execute(&mut a, spends, &Ownership::default(), DEFAULT_MAX_COST)
            .unwrap()
            .0;
        plan(&executed, &keys.iter().copied().collect(), opts)
    }

    /// [`plan_for`] of one anyone-can-spend coin whose solution is `conds`.
    fn plan_raw(
        conds: Conditions,
        keys: &[PublicKey],
        opts: &PolicyOptions,
    ) -> Result<SigningPlan, Refusal> {
        plan_for(&[anyone_can_spend(4, 1, conds)], keys, opts)
    }

    fn sign_plan(plan: &SigningPlan, sk: &chia_bls::SecretKey) -> Signature {
        let mut agg = Signature::default();
        for r in &plan.ours {
            agg.aggregate(&sign(sk, r.message_bytes()));
        }
        agg
    }

    /// Alice sends a 100 mojo coin to Bob.
    fn send(sim: &mut Simulator) -> (BlsPair, Vec<CoinSpend>) {
        let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
        let coin = sim.new_coin(alice.puzzle_hash, 100);
        let mut ctx = SpendContext::new();
        let conds = Conditions::new().create_coin(bob.puzzle_hash, 100, Memos::None);
        StandardLayer::new(alice.pk)
            .spend(&mut ctx, coin, conds)
            .unwrap();
        (alice, ctx.take())
    }

    #[test]
    fn computed_messages_produce_a_valid_on_chain_signature() {
        let mut sim = Simulator::new();
        let (alice, spends) = send(&mut sim);
        let plan = plan_for(&spends, &[alice.pk], &opts(false, false)).unwrap();
        assert_eq!(plan.ours.len(), 1);
        assert_eq!(plan.ours[0].opcode, 50);
        assert!(!plan.has_unsafe && plan.foreign.is_empty());
        // Signing exactly the planned messages yields a bundle the chain accepts.
        let sig = sign_plan(&plan, &alice.sk);
        sim.new_transaction(SpendBundle::new(spends, sig)).unwrap();
    }

    #[test]
    fn wrong_network_signature_is_refused_and_would_be_invalid() {
        let mut sim = Simulator::new();
        let (alice, spends) = send(&mut sim);
        let mismatched = PolicyOptions {
            session_chain_id: "mainnet".into(),
            ..opts(false, false)
        };
        assert_eq!(
            plan_for(&spends, &[alice.pk], &mismatched),
            Err(Refusal::WrongNetwork)
        );
        // Messages computed for mainnet do not validate on testnet11.
        let mainnet = PolicyOptions {
            network: Network::Mainnet,
            session_chain_id: "mainnet".into(),
            ..opts(false, false)
        };
        let p = plan_for(&spends, &[alice.pk], &mainnet).unwrap();
        assert!(
            sim.new_transaction(SpendBundle::new(spends, sign_plan(&p, &alice.sk)))
                .is_err()
        );
    }

    #[test]
    fn agg_sig_unsafe_needs_the_per_dapp_override() {
        let alice = BlsPair::new(1);
        let conds = || Conditions::new().agg_sig_unsafe(alice.pk, vec![1, 2, 3].into());
        assert_eq!(
            plan_raw(conds(), &[alice.pk], &opts(false, false)),
            Err(Refusal::AggSigUnsafe)
        );
        let p = plan_raw(conds(), &[alice.pk], &opts(false, true)).unwrap();
        assert!(p.has_unsafe && p.ours[0].is_unsafe);
        assert_eq!(
            p.ours[0].message, "010203",
            "AGG_SIG_UNSAFE signs the raw message"
        );
    }

    #[test]
    fn every_agg_sig_variant_for_own_keys() {
        let alice = BlsPair::new(1);
        let m = || -> chia_protocol::Bytes { vec![9].into() };
        let conds = Conditions::new()
            .agg_sig_parent(alice.pk, m())
            .agg_sig_puzzle(alice.pk, m())
            .agg_sig_amount(alice.pk, m())
            .agg_sig_puzzle_amount(alice.pk, m())
            .agg_sig_parent_amount(alice.pk, m())
            .agg_sig_parent_puzzle(alice.pk, m());
        let p = plan_raw(conds.clone(), &[alice.pk], &opts(false, false)).unwrap();
        assert_eq!(
            p.ours.iter().map(|r| r.opcode).collect::<Vec<_>>(),
            vec![43, 44, 45, 46, 47, 48]
        );
        // Each variant appends different coin data, so all messages differ.
        let unique: HashSet<&str> = p.ours.iter().map(|r| r.message.as_str()).collect();
        assert_eq!(unique.len(), 6);
        // AGG_SIG_ME signs only a quoted program: here the message comes from the solution.
        assert_eq!(
            plan_raw(
                conds.agg_sig_me(alice.pk, m()),
                &[alice.pk],
                &opts(false, false)
            ),
            Err(Refusal::UnsignedConditions)
        );
    }

    #[test]
    fn foreign_keys_are_reported_never_signed() {
        let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
        let both = || {
            Conditions::new()
                .agg_sig_parent(alice.pk, vec![1].into())
                .agg_sig_me(bob.pk, vec![2].into())
        };
        assert_eq!(
            plan_raw(both(), &[alice.pk], &opts(false, false)),
            Err(Refusal::NoSecretKey)
        );
        let p = plan_raw(both(), &[alice.pk], &opts(true, false)).unwrap();
        assert_eq!(p.ours.len(), 1);
        assert_eq!(p.foreign.len(), 1);
        let f = &p.foreign[0];
        assert_eq!(
            (f.spend, f.opcode, f.public_key.clone(), f.key),
            (0, 50, hex::encode(bob.pk.to_bytes()), bob.pk)
        );
        // The other party's message is kept, so a completed bundle can be checked whole.
        assert!(!f.message_bytes.is_empty());
        assert_eq!(p.all_requirements().len(), 2);
        let only_bob = Conditions::new().agg_sig_me(bob.pk, vec![2].into());
        assert_eq!(
            plan_raw(only_bob, &[alice.pk], &opts(true, false)),
            Err(Refusal::NothingToSign)
        );
    }

    #[test]
    fn infinity_public_key_is_refused() {
        let alice = BlsPair::new(1);
        let inf = PublicKey::default();
        assert!(inf.is_inf());
        let conds = Conditions::new()
            .agg_sig_me(inf, vec![1].into())
            .agg_sig_me(alice.pk, vec![2].into());
        assert_eq!(
            plan_raw(conds, &[alice.pk, inf], &opts(true, false)),
            Err(Refusal::InfinityKey)
        );
    }

    /// Plan, for `alice`'s key, a spend of a new coin of hers through the delegated puzzle
    /// and delegated solution `build` makes.
    fn plan_delegated(
        alice: &BlsPair,
        build: impl FnOnce(&mut SpendContext) -> (NodePtr, NodePtr),
        o: &PolicyOptions,
    ) -> Result<SigningPlan, Refusal> {
        let mut ctx = SpendContext::new();
        let (delegated, solution) = build(&mut ctx);
        let coin = Coin::new(Bytes32::new([3; 32]), alice.puzzle_hash, 1000);
        let spend = delegated_spend(&mut ctx, coin, alice.pk, delegated, solution);
        let mut a = Allocator::new();
        match execute(&mut a, &[spend], &Ownership::default(), DEFAULT_MAX_COST) {
            Ok((executed, _)) => plan(&executed, &[alice.pk].into_iter().collect(), o),
            // A program that does not run is never signed either.
            Err(_) => Err(Refusal::NothingToSign),
        }
    }

    #[test]
    fn only_a_quoted_delegated_puzzle_is_signed() {
        let alice = BlsPair::new(1);
        let conds = Conditions::new().create_coin(alice.puzzle_hash, 1000, Memos::None);
        let quoted = plan_delegated(
            &alice,
            |ctx| {
                let q = ctx.alloc(&clvm_traits::clvm_quote!(conds.clone())).unwrap();
                (q, NodePtr::NIL)
            },
            &opts(false, false),
        )
        .unwrap();
        assert_eq!(quoted.ours.len(), 1);
        let mut ctx = SpendContext::new();
        for (name, delegated, solution) in non_quote_delegations(&mut ctx, &conds) {
            let mut moved = Some(ctx.serialize(&delegated).unwrap());
            let sol = ctx.serialize(&solution).unwrap();
            let out = plan_delegated(
                &alice,
                |c| {
                    let d = moved.take().unwrap().to_clvm(c).unwrap();
                    (d, sol.to_clvm(c).unwrap())
                },
                &opts(true, true),
            );
            assert_eq!(out, Err(Refusal::UnsignedConditions), "{name}");
        }
    }

    #[test]
    fn the_hidden_puzzle_path_of_a_wallet_key_never_runs() {
        // Wallet keys carry the default hidden puzzle, which always fails: a spend through
        // the hidden path cannot be simulated, so nothing is signed for it.
        let original = BlsPair::new(5).pk;
        let synthetic = original.derive_synthetic();
        let ph = Bytes32::from(StandardArgs::curry_tree_hash(synthetic));
        let coin = Coin::new(Bytes32::new([3; 32]), ph, 1000);
        let mut ctx = SpendContext::new();
        let layer = StandardLayer::new(synthetic);
        let puzzle = layer.construct_puzzle(&mut ctx).unwrap();
        // The default hidden puzzle `(=)`.
        let hidden = ctx.alloc(&(9u8, ())).unwrap();
        assert_eq!(
            ctx.tree_hash(hidden),
            chia_puzzle_types::standard::DEFAULT_HIDDEN_PUZZLE_HASH.into()
        );
        let solution = layer
            .construct_solution(
                &mut ctx,
                StandardSolution {
                    original_public_key: Some(original),
                    delegated_puzzle: hidden,
                    solution: NodePtr::NIL,
                },
            )
            .unwrap();
        let spend = CoinSpend::new(
            coin,
            ctx.serialize(&puzzle).unwrap(),
            ctx.serialize(&solution).unwrap(),
        );
        let mut a = Allocator::new();
        assert!(matches!(
            execute(&mut a, &[spend], &Ownership::default(), DEFAULT_MAX_COST),
            Err(crate::KitError::Execution { spend: 0 })
        ));
    }

    #[test]
    fn a_coin_spent_twice_in_one_request_is_refused() {
        let mut sim = Simulator::new();
        let (_, spends) = send(&mut sim);
        let twice = [spends[0].clone(), spends[0].clone()];
        let mut a = Allocator::new();
        assert!(matches!(
            execute(&mut a, &twice, &Ownership::default(), DEFAULT_MAX_COST),
            Err(crate::KitError::InvalidRequest("coinSpends"))
        ));
    }

    #[test]
    fn agg_sig_unsafe_over_a_coin_bound_message_is_refused_even_with_the_override() {
        let alice = BlsPair::new(1);
        // The shape of a coin-bound message: a delegated puzzle hash, a coin id, then the
        // variant's additional data.
        let prefix = [[3u8; 32], [7u8; 32]].concat();
        let custom = Network::Custom {
            chain_id: "simulator0".into(),
            genesis_challenge: Bytes32::new([1; 32]),
            agg_sig_me: Bytes32::new([2; 32]),
        };
        for network in [Network::Testnet11, Network::Mainnet, custom.clone()] {
            for suffix in suffixes(&network.agg_sig_constants()) {
                let msg = [prefix.as_slice(), suffix.as_ref()].concat();
                // On the wallet's own network and on another one: the keys are the same.
                for wallet in [Network::Testnet11, custom.clone()] {
                    let o = PolicyOptions {
                        session_chain_id: wallet.chain_id().to_owned(),
                        network: wallet.clone(),
                        ..opts(false, true)
                    };
                    let conds = Conditions::new().agg_sig_unsafe(alice.pk, msg.clone().into());
                    let custom_suffix_elsewhere = network == custom && wallet == Network::Testnet11;
                    let out = plan_raw(conds, &[alice.pk], &o);
                    if custom_suffix_elsewhere {
                        // A private network's data is known only on that network.
                        assert!(out.is_ok());
                    } else {
                        assert_eq!(out, Err(Refusal::AggSigUnsafe));
                    }
                }
            }
        }
        // The additional data anywhere but at the end does not bind a coin.
        let me = Network::Testnet11.agg_sig_constants().me();
        let msg = [me.as_ref(), prefix.as_slice()].concat();
        let conds = Conditions::new().agg_sig_unsafe(alice.pk, msg.into());
        assert!(plan_raw(conds, &[alice.pk], &opts(false, true)).is_ok());
    }

    #[test]
    fn agg_sig_unsafe_over_a_sign_message_digest_is_refused_even_with_the_override() {
        let alice = BlsPair::new(1);
        let digest = crate::signed_message_hash(b"I agree");
        let conds = Conditions::new().agg_sig_unsafe(alice.pk, digest.to_vec().into());
        assert_eq!(
            plan_raw(conds, &[alice.pk], &opts(false, true)),
            Err(Refusal::AggSigUnsafe)
        );
        // Other lengths stay possible with the override.
        for len in [0usize, 31, 33, 64] {
            let conds = Conditions::new().agg_sig_unsafe(alice.pk, vec![5; len].into());
            assert!(
                plan_raw(conds, &[alice.pk], &opts(false, true)).is_ok(),
                "{len}"
            );
        }
    }

    #[test]
    fn one_agg_sig_me_message_per_key_and_spend() {
        let alice = BlsPair::new(1);
        let conds = Conditions::new().create_coin(alice.puzzle_hash, 1000, Memos::None);
        // The same quoted conditions plus a request to sign another quoted program the
        // solution reveals: two messages for one key.
        let out = plan_delegated(
            &alice,
            |ctx| {
                let other = ctx.alloc(&clvm_traits::clvm_quote!(())).unwrap();
                let other_hash = ctx.tree_hash(other);
                let both = conds
                    .clone()
                    .agg_sig_me(alice.pk, Bytes32::from(other_hash).to_vec().into());
                let q = ctx.alloc(&clvm_traits::clvm_quote!(both)).unwrap();
                let sol = ctx.alloc(&(other, ())).unwrap();
                (q, sol)
            },
            &opts(false, false),
        );
        assert_eq!(out, Err(Refusal::UnsignedConditions));
    }

    /// A random CLVM tree: atoms from operators and small values, pairs up to a depth.
    fn tree() -> impl Strategy<Value = Tree> {
        let leaf = prop_oneof![
            (0u8..=12).prop_map(|b| Tree::Atom(vec![b])),
            Just(Tree::Atom(Vec::new())),
            proptest::collection::vec(any::<u8>(), 2..4).prop_map(Tree::Atom),
        ];
        leaf.prop_recursive(5, 48, 3, |inner| {
            (inner.clone(), inner).prop_map(|(a, b)| Tree::Pair(Box::new(a), Box::new(b)))
        })
    }

    fn atom(b: &[u8]) -> Tree {
        Tree::Atom(b.to_vec())
    }

    fn pair(a: Tree, b: Tree) -> Tree {
        Tree::Pair(Box::new(a), Box::new(b))
    }

    /// `(op args…)`.
    fn call(op: u8, args: Vec<Tree>) -> Tree {
        let list = args
            .into_iter()
            .rev()
            .fold(atom(&[]), |rest, a| pair(a, rest));
        pair(atom(&[op]), list)
    }

    /// Programs built from what a dApp would use to make a delegated puzzle output (part
    /// of) its solution: the solution itself, its first element, evaluation of a program
    /// it supplies, a fixed condition consed onto a program, a quoted program run on the
    /// solution, and an `if`.
    fn solution_program() -> impl Strategy<Value = Tree> {
        let leaf = prop_oneof![
            Just(atom(&[1])),
            Just(call(5, vec![atom(&[1])])),
            Just(call(2, vec![atom(&[2]), atom(&[3])])),
        ];
        leaf.prop_recursive(4, 24, 2, |inner| {
            prop_oneof![
                inner
                    .clone()
                    .prop_map(|p| call(4, vec![pair(atom(&[1]), pair(atom(&[1]), atom(&[]))), p])),
                inner
                    .clone()
                    .prop_map(|p| call(2, vec![pair(atom(&[1]), p), atom(&[1])])),
                (inner.clone(), inner)
                    .prop_map(|(a, b)| call(3, vec![pair(atom(&[1]), atom(&[1])), a, b])),
            ]
        })
    }

    #[derive(Debug, Clone)]
    enum Tree {
        Atom(Vec<u8>),
        Pair(Box<Tree>, Box<Tree>),
    }

    fn alloc_tree(a: &mut Allocator, t: &Tree) -> NodePtr {
        match t {
            Tree::Atom(b) => a.new_atom(b).unwrap(),
            Tree::Pair(x, y) => {
                let (x, y) = (alloc_tree(a, x), alloc_tree(a, y));
                a.new_pair(x, y).unwrap()
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Whatever the delegated puzzle, unless it is a quoted program the wallet signs
        /// nothing for the spend, whatever the solution makes it output.
        #[test]
        fn a_non_quote_delegated_puzzle_is_never_signed(
            delegated in prop_oneof![tree(), solution_program()],
            extra in tree(),
            amount in 1u64..1000,
        ) {
            let alice = BlsPair::new(1);
            let mut a = Allocator::new();
            let d = alloc_tree(&mut a, &delegated);
            prop_assume!(!crate::option::is_quote_for_tests(&a, d));
            let conds = Conditions::new().create_coin(alice.puzzle_hash, amount, Memos::None);
            let program = Program::from_clvm(&a, d).unwrap();
            let x = alloc_tree(&mut a, &extra);
            let extra = Program::from_clvm(&a, x).unwrap();
            for which in 0..3 {
                let out = plan_delegated(
                    &alice,
                    |ctx| {
                        let d = program.to_clvm(ctx).unwrap();
                        let list = ctx.alloc(&conds).unwrap();
                        let e = extra.to_clvm(ctx).unwrap();
                        let sol = match which {
                            0 => list,
                            1 => ctx.alloc(&(list, e)).unwrap(),
                            _ => e,
                        };
                        (d, sol)
                    },
                    &opts(true, true),
                );
                prop_assert!(out.is_err(), "signed {:?}", delegated);
            }
        }

        /// Any quoted delegated puzzle is signed, exactly once.
        #[test]
        fn a_quoted_delegated_puzzle_is_signed_once(
            amounts in proptest::collection::vec(1u64..1_000_000, 0..4),
            extra in tree(),
        ) {
            let alice = BlsPair::new(1);
            let mut conds = Conditions::new();
            for a in &amounts {
                conds = conds.create_coin(alice.puzzle_hash, *a, Memos::None);
            }
            let mut a = Allocator::new();
            let x = alloc_tree(&mut a, &extra);
            let extra = Program::from_clvm(&a, x).unwrap();
            let p = plan_delegated(
                &alice,
                |ctx| {
                    let q = ctx.alloc(&clvm_traits::clvm_quote!(conds)).unwrap();
                    (q, extra.to_clvm(ctx).unwrap())
                },
                &opts(false, false),
            )
            .unwrap();
            prop_assert_eq!(p.ours.len(), 1);
        }
    }
}
