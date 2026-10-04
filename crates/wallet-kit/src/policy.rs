//! Signature scope policy and network check (spec 11.1 items 2 and 6).
//!
//! From the simulated conditions this computes exactly which messages the wallet's keys
//! would sign (with the network's AGG_SIG additional data), refuses `AGG_SIG_UNSAFE`
//! unless the user enabled it for this dApp, and never signs for keys it does not hold.

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
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refusal::WrongNetwork => "request is for another network",
            Refusal::AggSigUnsafe => "AGG_SIG_UNSAFE is not allowed for this dApp",
            Refusal::NoSecretKey => "no secret key for a required public key",
            Refusal::InfinityKey => "signature required from the infinity public key",
            Refusal::NothingToSign => "nothing to sign",
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
        for c in &es.conditions {
            let Some(agg) = c.clone().into_agg_sig() else {
                continue;
            };
            if agg.public_key.is_inf() {
                return Err(Refusal::InfinityKey);
            }
            let opcode = agg.kind as u8;
            if !our_keys.contains(&agg.public_key) {
                out.foreign.push(Foreign {
                    spend: i,
                    opcode,
                    public_key: hex::encode(agg.public_key.to_bytes()),
                });
                continue;
            }
            let is_unsafe = opcode == AGG_SIG_UNSAFE;
            if is_unsafe && !opts.allow_agg_sig_unsafe {
                return Err(Refusal::AggSigUnsafe);
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
    use chia_bls::{Signature, sign};
    use chia_protocol::{Coin, CoinSpend, Program, SpendBundle};
    use chia_puzzle_types::Memos;
    use chia_sdk_driver::{SpendContext, StandardLayer};
    use chia_sdk_test::{BlsPair, Simulator};
    use chia_sdk_types::Conditions;
    use clvm_traits::{FromClvm, ToClvm};
    use clvm_utils::tree_hash;
    use clvmr::Allocator;

    fn opts(partial: bool, unsafe_ok: bool) -> PolicyOptions {
        PolicyOptions {
            network: Network::Testnet11,
            session_chain_id: "testnet11".into(),
            allow_agg_sig_unsafe: unsafe_ok,
            partial,
        }
    }

    fn run(spends: &[CoinSpend]) -> Vec<ExecutedSpend> {
        execute(
            &mut Allocator::new(),
            spends,
            &Ownership::default(),
            DEFAULT_MAX_COST,
        )
        .unwrap()
        .0
    }

    fn sign_plan(plan: &SigningPlan, sk: &chia_bls::SecretKey) -> Signature {
        let mut agg = Signature::default();
        for r in &plan.ours {
            agg.aggregate(&sign(sk, r.message_bytes()));
        }
        agg
    }

    #[test]
    fn computed_messages_produce_a_valid_on_chain_signature() {
        let mut sim = Simulator::new();
        let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
        let coin = sim.new_coin(alice.puzzle_hash, 100);
        let mut ctx = SpendContext::new();
        StandardLayer::new(alice.pk)
            .spend(
                &mut ctx,
                coin,
                Conditions::new().create_coin(bob.puzzle_hash, 100, Memos::None),
            )
            .unwrap();
        let spends = ctx.take();
        let plan = plan(
            &run(&spends),
            &[alice.pk].into_iter().collect(),
            &opts(false, false),
        )
        .unwrap();
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
        let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
        let coin = sim.new_coin(alice.puzzle_hash, 100);
        let mut ctx = SpendContext::new();
        StandardLayer::new(alice.pk)
            .spend(
                &mut ctx,
                coin,
                Conditions::new().create_coin(bob.puzzle_hash, 100, Memos::None),
            )
            .unwrap();
        let spends = ctx.take();
        let keys: HashSet<PublicKey> = [alice.pk].into_iter().collect();
        let mismatched = PolicyOptions {
            session_chain_id: "mainnet".into(),
            ..opts(false, false)
        };
        assert_eq!(
            plan(&run(&spends), &keys, &mismatched),
            Err(Refusal::WrongNetwork)
        );
        // Messages computed for mainnet do not validate on testnet11.
        let mainnet = PolicyOptions {
            network: Network::Mainnet,
            session_chain_id: "mainnet".into(),
            ..opts(false, false)
        };
        let p = plan(&run(&spends), &keys, &mainnet).unwrap();
        assert!(
            sim.new_transaction(SpendBundle::new(spends, sign_plan(&p, &alice.sk)))
                .is_err()
        );
    }

    /// Anyone-can-spend coin whose solution is the given conditions.
    fn raw_spend(conds: Conditions) -> CoinSpend {
        let mut a = Allocator::new();
        let puzzle = Program::from(vec![0x01]);
        let node = puzzle.to_clvm(&mut a).unwrap();
        let ph = Bytes32::from(tree_hash(&a, node));
        let sol = conds.to_clvm(&mut a).unwrap();
        CoinSpend::new(
            Coin::new(Bytes32::new([4; 32]), ph, 1),
            puzzle,
            Program::from_clvm(&a, sol).unwrap(),
        )
    }

    #[test]
    fn agg_sig_unsafe_needs_the_per_dapp_override() {
        let alice = BlsPair::new(1);
        let spends = [raw_spend(
            Conditions::new().agg_sig_unsafe(alice.pk, vec![1, 2, 3].into()),
        )];
        let keys: HashSet<PublicKey> = [alice.pk].into_iter().collect();
        assert_eq!(
            plan(&run(&spends), &keys, &opts(false, false)),
            Err(Refusal::AggSigUnsafe)
        );
        let p = plan(&run(&spends), &keys, &opts(false, true)).unwrap();
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
            .agg_sig_parent_puzzle(alice.pk, m())
            .agg_sig_me(alice.pk, m());
        let spends = [raw_spend(conds)];
        let p = plan(
            &run(&spends),
            &[alice.pk].into_iter().collect(),
            &opts(false, false),
        )
        .unwrap();
        assert_eq!(
            p.ours.iter().map(|r| r.opcode).collect::<Vec<_>>(),
            vec![43, 44, 45, 46, 47, 48, 50]
        );
        // Each variant appends different coin data, so all messages differ.
        let unique: HashSet<&str> = p.ours.iter().map(|r| r.message.as_str()).collect();
        assert_eq!(unique.len(), 7);
    }

    #[test]
    fn foreign_keys_are_reported_never_signed() {
        let (alice, bob) = (BlsPair::new(1), BlsPair::new(2));
        let spends = [raw_spend(
            Conditions::new()
                .agg_sig_me(alice.pk, vec![1].into())
                .agg_sig_me(bob.pk, vec![2].into()),
        )];
        let keys: HashSet<PublicKey> = [alice.pk].into_iter().collect();
        assert_eq!(
            plan(&run(&spends), &keys, &opts(false, false)),
            Err(Refusal::NoSecretKey)
        );
        let p = plan(&run(&spends), &keys, &opts(true, false)).unwrap();
        assert_eq!(p.ours.len(), 1);
        assert_eq!(
            p.foreign,
            vec![Foreign {
                spend: 0,
                opcode: 50,
                public_key: hex::encode(bob.pk.to_bytes())
            }]
        );
        let only_bob = [raw_spend(
            Conditions::new().agg_sig_me(bob.pk, vec![2].into()),
        )];
        assert_eq!(
            plan(&run(&only_bob), &keys, &opts(true, false)),
            Err(Refusal::NothingToSign)
        );
    }

    #[test]
    fn infinity_public_key_is_refused() {
        let alice = BlsPair::new(1);
        let inf = PublicKey::default();
        assert!(inf.is_inf());
        let spends = [raw_spend(
            Conditions::new()
                .agg_sig_me(inf, vec![1].into())
                .agg_sig_me(alice.pk, vec![2].into()),
        )];
        assert_eq!(
            plan(
                &run(&spends),
                &[alice.pk, inf].into_iter().collect(),
                &opts(true, false)
            ),
            Err(Refusal::InfinityKey)
        );
    }
}
