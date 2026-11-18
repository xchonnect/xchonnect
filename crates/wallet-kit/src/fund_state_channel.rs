//! `chia_fundStateChannel` (spec 9.1, "State channel funding"): a requester (Nodi) asks the
//! wallet to fund a chia-gaming state channel to an operator, in XCH, in two steps.
//!
//! 1. Without `offer`: the wallet checks the params ([`check_fund_state_channel`]: the shape,
//!    the operator's signed listing, its network, that the reward puzzle hash is its own), asks
//!    the user (operator, amount, fee) and names one of its standard XCH coins holding at least
//!    `amount + fee`, which it keeps for this channel.
//! 2. With `channelId` and `offer` (chia-gaming's funding request, which exists only after the
//!    channel's handshake): the same checks, then [`FundStateChannel::conditions`] checks that
//!    the request continues step 1 on the same pairing and the kept coin ([`KeptChannel`]),
//!    repeats the one offer already signed if any, and ends within [`MAX_FUNDING_BLOCKS`] of
//!    the wallet's height, and gives the conditions of that coin's standard spend, which the
//!    wallet signs and answers unpushed. No second prompt.
//!
//! The coin choice, the prompt, keeping the coin, signing and the answer are the host's.
//! Nothing here uses paychan: `docs/spec/vectors/fund_state_channel.json` (written by Nodi
//! from a channel opened in chia-gaming's simulator) holds it to the spend that opens one.

use crate::handlers::RpcError;
use crate::policy::Network;
use crate::spend::decode_hex;
use chia_bls::{PublicKey, Signature};
use chia_protocol::{Bytes32, Coin};
use clvm_traits::{ToClvm, clvm_list};
use clvm_utils::{tree_hash_atom, tree_hash_pair};
use clvmr::{Allocator, NodePtr};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use xchonnect_core::rpc::codes;

/// The method name.
pub const FUND_STATE_CHANNEL: &str = "chia_fundStateChannel";

/// The listing format this check reads (paychan listing v3: prices in nano-USD).
pub const LISTING_VERSION: u32 = 3;

/// The tag of the operator's listing signature: `sha256tree(("paychan1-listing" listing))`.
pub const TAG_LISTING: &[u8] = b"paychan1-listing";

/// The most conditions an offer may carry: chia-gaming's `RECEIVE_MESSAGE` and paychan's
/// 0-mojo `CREATE_COIN` to the operator's channel key.
pub const MAX_CONDITIONS: usize = 2;
/// The longest condition argument, in bytes.
pub const MAX_ARG: usize = 1024;
/// How far above the wallet's peak height an offer's `maxHeight` may be (spec 9.1): a signed
/// funding spend is valid for at most this many blocks. paychan asks for 32.
pub const MAX_FUNDING_BLOCKS: u64 = 256;
/// Blocks past the highest `maxHeight` signed for a kept coin before the wallet treats the
/// coin as free again (spec 9.1): chia-gaming's own reorg buffer (`CHANNEL_EXPIRY_BUFFER`).
pub const RELEASE_BUFFER_BLOCKS: u64 = 6;

const CREATE_COIN: u32 = 51;
const RECEIVE_MESSAGE: u32 = 67;
const ASSERT_BEFORE_HEIGHT_ABSOLUTE: u32 = 87;
/// `RECEIVE_MESSAGE`'s mode in the initiator's funding request: the sender's puzzle hash and
/// amount, no receiver commitment.
const MODE_PUZZLE_AMOUNT: u8 = 24;

/// The operator's listing (paychan v3). Fields this version does not know are ignored; a
/// missing field makes the listing malformed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    /// `3`.
    pub version: u32,
    /// The key that signed the listing, hex (48 bytes).
    pub operator_pk: String,
    /// The operator's OpenAI-compatible base URL.
    pub endpoint: String,
    /// `mainnet` or `testnet11`.
    pub network: String,
    /// Unix seconds.
    pub issued: u64,
    /// Unix seconds; the listing opens only before it.
    pub expires: u64,
    /// How a channel to this operator is made.
    pub payment: ListedTerms,
    /// Labels, never proofs.
    pub privacy: Privacy,
    /// What the operator sells.
    pub models: Vec<ListedModel>,
}

/// The listing's channel terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListedTerms {
    /// `xch`: the only asset a state channel holds.
    pub asset: String,
    /// The operator's reward puzzle hash, hex (32 bytes): its share at the close.
    pub reward_ph: String,
    /// Blocks an unroll waits before it settles.
    pub unroll_timeout: u64,
    /// Blocks a side has to answer a move once the payment game is on chain.
    pub game_timeout: u64,
    /// The payment game's protocol id, hex.
    pub payment_game: String,
    /// The least a channel may hold, in mojos.
    pub min_amount: u64,
}

/// What the operator says happens to a prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Privacy {
    /// The operator stores prompts or answers.
    pub operator_keeps_prompts: bool,
    /// `deny` or `unknown`.
    pub upstream_data_collection: String,
}

/// One model the operator sells.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListedModel {
    /// The model's name.
    pub id: String,
    /// Tokens.
    pub context_length: Option<u64>,
    /// Nano-USD per token and per request.
    pub price: ListedPrice,
    /// The most one request costs, in nano-USD.
    pub max_cost_nusd: u64,
    /// What backs the token count, a label.
    pub evidence: String,
}

/// Prices in nano-USD (10^-9 dollar).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListedPrice {
    /// Per input token.
    pub input_nusd: u64,
    /// Per output token.
    pub output_nusd: u64,
    /// Per request.
    pub request_nusd: u64,
}

/// One condition of chia-gaming's funding request, as sent: an opcode and its atoms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCondition {
    /// The condition's opcode.
    pub opcode: u32,
    /// Its arguments, atoms.
    pub args: Vec<Vec<u8>>,
}

/// Step 2's `offer`: chia-gaming's funding request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingOffer {
    /// The channel's id: the requester's chia-gaming channel public key.
    pub channel_id: PublicKey,
    /// Mojos to the settlement puzzle: `amount + fee`.
    pub amount: u64,
    /// The opening fee within it.
    pub fee: u64,
    /// Conditions the spend carries verbatim (checked against an allowlist).
    pub conditions: Vec<RawCondition>,
    /// The coin step 1 named.
    pub coin_id: Bytes32,
    /// The spend is valid only below this height. Required.
    pub max_height: u64,
}

/// The pairing a request came in on, as the host names it: unique to one pairing (never
/// shared by two pairings of the same dApp or agent, so not its domain or origin key) and
/// the same across session key rotations (so not a mailbox id). Spec 9.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PairingRef(pub [u8; 32]);

/// What the wallet keeps for a channel between the two steps, and after: the pairing the
/// user approved step 1 on, the coin it named, step 1's request, and the one funding offer it
/// signed. The host stores it durably, keyed by `(pairing, coin_id)`, and stores it again
/// after every [`FundStateChannel::conditions`] **before** the answer leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptChannel {
    /// The pairing step 1 was approved on.
    pub pairing: PairingRef,
    /// The coin step 1 named.
    pub coin_id: Bytes32,
    /// Step 1's checked request (no `offer`).
    pub request: FundStateChannel,
    /// The funding offer signed for this coin, once step 2 was answered.
    pub signed: Option<FundingOffer>,
}

impl KeptChannel {
    /// After the user approved step 1 on `pairing` and the wallet named `coin_id`. `None`
    /// when `step1` carries an offer.
    pub fn new(pairing: PairingRef, step1: FundStateChannel, coin_id: Bytes32) -> Option<Self> {
        step1.offer.is_none().then_some(Self {
            pairing,
            coin_id,
            request: step1,
            signed: None,
        })
    }

    /// The peak height from which the wallet may treat the coin as free again without
    /// spending it itself: the signed `maxHeight` plus [`RELEASE_BUFFER_BLOCKS`]. `None`
    /// before a funding spend was signed (the coin is free once the user releases it).
    pub fn release_height(&self) -> Option<u64> {
        self.signed
            .as_ref()
            .map(|o| o.max_height.saturating_add(RELEASE_BUFFER_BLOCKS))
    }
}

/// A request that passed the checks: what the prompt shows and the wallet keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundStateChannel {
    /// The verified listing.
    pub listing: Listing,
    /// The listing exactly as received (the signed bytes); keep it to show the channel.
    pub listing_text: String,
    /// The listing's signature, hex as received.
    pub listing_signature: String,
    /// The operator key that signed the listing.
    pub operator_pk: PublicKey,
    /// The operator's reward puzzle hash (the listing's `reward_ph`).
    pub operator_reward_puzzle_hash: Bytes32,
    /// Mojos into the channel.
    pub amount: u64,
    /// The opening fee, mojos.
    pub fee: u64,
    /// `amount + fee`: what the coin must hold and what leaves the wallet.
    pub total: u64,
    /// Where the user's rest goes: one of the wallet's own puzzle hashes.
    pub reward_puzzle_hash: Bytes32,
    /// Step 2's funding request; `None` in step 1.
    pub offer: Option<FundingOffer>,
}

/// Runs the checks of spec 9.1 "State channel funding" on a `chia_fundStateChannel` request's
/// params (JSON text), in order, and returns the first refusal: 4000 `invalid_params` (1),
/// 4001 `listing_invalid` (2), `wrong_network` (3), `reward_not_own` (4). `owns` says whether
/// a puzzle hash is one of the wallet's own; `now` is the wallet's clock, unix seconds.
pub fn check_fund_state_channel(
    params_json: &str,
    network: &Network,
    now: u64,
    owns: impl Fn(&Bytes32) -> bool,
) -> Result<FundStateChannel, RpcError> {
    let invalid = invalid_params;
    let refused =
        |reason: &str| RpcError::new(codes::UNAUTHORIZED, "unauthorized").with_reason(reason);

    // 1. The params' shape.
    let params: Value = serde_json::from_str(params_json).map_err(|_| invalid())?;
    let signed = params.get("listing").ok_or_else(invalid)?;
    let listing_text = signed
        .get("listing")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let listing_signature = signed
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let amount = params
        .get("amount")
        .and_then(amount_of)
        .filter(|a| *a > 0)
        .ok_or_else(invalid)?;
    let fee = params.get("fee").and_then(amount_of).ok_or_else(invalid)?;
    let total = amount.checked_add(fee).ok_or_else(invalid)?;
    let reward_puzzle_hash = params
        .get("rewardPuzzleHash")
        .and_then(Value::as_str)
        .and_then(bytes32)
        .ok_or_else(invalid)?;
    let offer = match params.get("offer") {
        None | Some(Value::Null) => None,
        Some(offer) => Some(
            funding_offer(params.get("channelId"), offer)
                .filter(|o| o.amount == total && o.fee == fee)
                .ok_or_else(invalid)?,
        ),
    };

    // 2. The listing opens: its own key signed it, version 3, unexpired, a channel in XCH.
    let (listing, operator_pk) = open_listing(listing_text, listing_signature, now)
        .ok_or_else(|| refused("listing_invalid"))?;
    let operator_reward_puzzle_hash = Some(&listing.payment)
        .filter(|t| t.asset == "xch")
        .and_then(|t| bytes32(&t.reward_ph))
        .ok_or_else(|| refused("listing_invalid"))?;

    // 3. The listing's network is the wallet's.
    if listing.network != network.chain_id() {
        return Err(refused("wrong_network"));
    }

    // 4. The user's rest comes back to the wallet.
    if !owns(&reward_puzzle_hash) {
        return Err(refused("reward_not_own"));
    }

    Ok(FundStateChannel {
        listing_text: listing_text.to_owned(),
        listing_signature: listing_signature.to_owned(),
        listing,
        operator_pk,
        operator_reward_puzzle_hash,
        amount,
        fee,
        total,
        reward_puzzle_hash,
        offer,
    })
}

impl FundStateChannel {
    /// Step 2, received on `pairing`: when this request continues `kept` (the step 1 the user
    /// approved on the same pairing: the same listing, amount, fee and reward puzzle hash, and
    /// the coin it named, which `coin` is) and, if `kept` already signed an offer, repeats
    /// that offer exactly, and `height < maxHeight <= height + MAX_FUNDING_BLOCKS`: the
    /// conditions of `coin`'s standard spend, a CLVM list in `allocator`: `offer.amount` to the
    /// settlement puzzle, the rest of the coin to `change_puzzle_hash` (the wallet's own; no
    /// coin when the rest is 0), the offer's conditions verbatim, then
    /// `ASSERT_BEFORE_HEIGHT_ABSOLUTE maxHeight`. `kept.signed` then holds the offer: the host
    /// stores `kept` before it answers. Anything else is 4000 `invalid_params` and leaves
    /// `kept` as it was.
    ///
    /// `height` is the wallet's own peak height from its own view of the chain, never a value
    /// from the request; a wallet without a recent peak refuses instead. The host signs this
    /// spend (delegated puzzle `(q . conditions)`) and answers it unpushed.
    pub fn conditions(
        &self,
        pairing: &PairingRef,
        kept: &mut KeptChannel,
        coin: &Coin,
        height: u64,
        change_puzzle_hash: Bytes32,
        allocator: &mut Allocator,
    ) -> Result<NodePtr, RpcError> {
        fn clvm<E>(_: E) -> RpcError {
            invalid_params()
        }
        let offer = self.offer.as_ref().ok_or_else(invalid_params)?;
        let step1 = &kept.request;
        let continues = step1.offer.is_none()
            && *pairing == kept.pairing
            && (
                &self.listing_text,
                &self.listing_signature,
                self.amount,
                self.fee,
                self.reward_puzzle_hash,
            ) == (
                &step1.listing_text,
                &step1.listing_signature,
                step1.amount,
                step1.fee,
                step1.reward_puzzle_hash,
            )
            && offer.coin_id == kept.coin_id
            && coin.coin_id() == kept.coin_id
            && kept.signed.as_ref().is_none_or(|signed| signed == offer)
            && height < offer.max_height
            && offer.max_height <= height.saturating_add(MAX_FUNDING_BLOCKS);
        let (true, Some(change)) = (continues, coin.amount.checked_sub(offer.amount)) else {
            return Err(invalid_params());
        };
        let settlement = Bytes32::new(chia_puzzles::SETTLEMENT_PAYMENT_HASH);
        let mut list = vec![
            clvm_list!(CREATE_COIN, settlement, offer.amount)
                .to_clvm(allocator)
                .map_err(clvm)?,
        ];
        if change > 0 {
            list.push(
                clvm_list!(CREATE_COIN, change_puzzle_hash, change)
                    .to_clvm(allocator)
                    .map_err(clvm)?,
            );
        }
        for c in &offer.conditions {
            let mut node = allocator.nil();
            for arg in c.args.iter().rev() {
                let atom = allocator.new_atom(arg).map_err(clvm)?;
                node = allocator.new_pair(atom, node).map_err(clvm)?;
            }
            let opcode = c.opcode.to_clvm(allocator).map_err(clvm)?;
            list.push(allocator.new_pair(opcode, node).map_err(clvm)?);
        }
        list.push(
            clvm_list!(ASSERT_BEFORE_HEIGHT_ABSOLUTE, offer.max_height)
                .to_clvm(allocator)
                .map_err(clvm)?,
        );
        let conditions = list.to_clvm(allocator).map_err(clvm)?;
        kept.signed = Some(offer.clone());
        Ok(conditions)
    }

    /// The listing as the prompt may show it (spec 9.1, "The prompt"): every string is the
    /// operator's text, bounded and without control characters or bidirectional overrides.
    pub fn display(&self) -> ListingDisplay {
        let l = &self.listing;
        let key = hex::encode(self.operator_pk.to_bytes());
        ListingDisplay {
            endpoint: display_text(&l.endpoint, MAX_DISPLAY_URL),
            operator_pk_short: format!(
                "{}…{}",
                key.get(..8).unwrap_or(""),
                key.get(88..).unwrap_or("")
            ),
            operator_pk: key,
            operator_keeps_prompts: l.privacy.operator_keeps_prompts,
            upstream_data_collection: display_text(
                &l.privacy.upstream_data_collection,
                MAX_DISPLAY_LABEL,
            ),
            models: l
                .models
                .iter()
                .take(MAX_DISPLAY_MODELS)
                .map(|m| ModelDisplay {
                    id: display_text(&m.id, MAX_DISPLAY_LABEL),
                    evidence: display_text(&m.evidence, MAX_DISPLAY_LABEL),
                    context_length: m.context_length,
                    price: m.price,
                    max_cost_nusd: m.max_cost_nusd,
                })
                .collect(),
            models_not_shown: l.models.len().saturating_sub(MAX_DISPLAY_MODELS),
        }
    }
}

/// Longest endpoint shown, in characters.
pub const MAX_DISPLAY_URL: usize = 200;
/// Longest label or model id shown, in characters.
pub const MAX_DISPLAY_LABEL: usize = 64;
/// Most models shown.
pub const MAX_DISPLAY_MODELS: usize = 64;

/// What a prompt shows of a verified listing: the operator's statements, made safe to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingDisplay {
    /// The endpoint, as shown.
    pub endpoint: String,
    /// The operator key, hex: the key to look up among the operators the wallet funded.
    pub operator_pk: String,
    /// The operator key's first and last 8 hex digits.
    pub operator_pk_short: String,
    /// Label: the operator keeps prompts or answers.
    pub operator_keeps_prompts: bool,
    /// Label: what the upstream may do with prompts.
    pub upstream_data_collection: String,
    /// The first [`MAX_DISPLAY_MODELS`] models.
    pub models: Vec<ModelDisplay>,
    /// How many models are not in `models`.
    pub models_not_shown: usize,
}

/// One model as a prompt shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelDisplay {
    /// The model's name, as shown.
    pub id: String,
    /// Its evidence label, as shown.
    pub evidence: String,
    /// Tokens.
    pub context_length: Option<u64>,
    /// Nano-USD per token and per request.
    pub price: ListedPrice,
    /// Nano-USD per request at most.
    pub max_cost_nusd: u64,
}

/// `text` without control characters, line breaks and bidirectional controls (as the
/// notification preview's detail line, spec 7.3.3), cut to `max` characters with `…`.
pub fn display_text(text: &str, max: usize) -> String {
    let mut out: String = text
        .chars()
        .filter(|c| {
            !(c.is_control()
                || matches!(c, '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}'))
        })
        .collect();
    if out.chars().count() > max {
        out = out.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
    }
    out
}

/// `sha256tree(("paychan1-listing" listing_json))`: what the operator key signs (BLS
/// augmented scheme, as every Chia signature).
pub fn listing_message(listing_json: &str) -> Bytes32 {
    let nil = tree_hash_atom(&[]);
    tree_hash_pair(
        tree_hash_atom(TAG_LISTING),
        tree_hash_pair(tree_hash_atom(listing_json.as_bytes()), nil),
    )
    .into()
}

fn invalid_params() -> RpcError {
    RpcError::new(codes::INVALID_PARAMS, "invalid params").with_reason("invalid_params")
}

/// The listing and its operator key, when that key signed exactly `text`, the version is 3
/// and it has not expired at `now`.
fn open_listing(text: &str, signature: &str, now: u64) -> Option<(Listing, PublicKey)> {
    let listing: Listing = serde_json::from_str(text).ok()?;
    if listing.version != LISTING_VERSION {
        return None;
    }
    let key = public_key(&listing.operator_pk)?;
    let signature: [u8; 96] = decode_hex(signature)?.try_into().ok()?;
    let signature = Signature::from_bytes(&signature).ok()?;
    if !chia_bls::verify(&signature, &key, listing_message(text)) || listing.expires <= now {
        return None;
    }
    Some((listing, key))
}

/// Step 2's `channelId` and `offer`, when well formed, `maxHeight` is an integer and the
/// conditions are exactly those of chia-gaming's initiator funding request as paychan makes
/// it, in any order: one `RECEIVE_MESSAGE` of mode 24 from a 32-byte puzzle hash for
/// `offer.amount` (its canonical CLVM integer), required, since it ties the settlement coin to
/// the channel's contribution coin; and at most one `CREATE_COIN` of 0 mojos to a 32-byte
/// puzzle hash (the operator's channel-key coin). Nothing else: no `AGG_SIG_*`, no
/// announcement or message the wallet's coin would make.
fn funding_offer(channel_id: Option<&Value>, offer: &Value) -> Option<FundingOffer> {
    let channel_id = public_key(channel_id?.as_str()?).filter(|pk| !pk.is_inf())?;
    let amount = amount_of(offer.get("amount")?)?;
    let amount_atom = clvm_u64(amount);
    let conditions = offer.get("conditions")?.as_array()?;
    if conditions.len() > MAX_CONDITIONS {
        return None;
    }
    let conditions = conditions
        .iter()
        .map(|c| {
            let opcode = u32::try_from(c.get("opcode")?.as_u64()?).ok()?;
            let args = c
                .get("args")?
                .as_array()?
                .iter()
                .map(|a| decode_hex(a.as_str()?).filter(|a| a.len() <= MAX_ARG))
                .collect::<Option<Vec<_>>>()?;
            let allowed = match (opcode, args.as_slice()) {
                (CREATE_COIN, [ph, mojos]) => ph.len() == 32 && mojos.is_empty(),
                (RECEIVE_MESSAGE, [mode, message, sender, sent]) => {
                    mode.as_slice() == [MODE_PUZZLE_AMOUNT]
                        && message.is_empty()
                        && sender.len() == 32
                        && *sent == amount_atom
                }
                _ => false,
            };
            allowed.then_some(RawCondition { opcode, args })
        })
        .collect::<Option<Vec<_>>>()?;
    let count = |op| conditions.iter().filter(|c| c.opcode == op).count();
    if count(RECEIVE_MESSAGE) != 1 || count(CREATE_COIN) > 1 {
        return None;
    }
    Some(FundingOffer {
        channel_id,
        amount,
        fee: amount_of(offer.get("fee")?)?,
        conditions,
        coin_id: bytes32(offer.get("coinId")?.as_str()?)?,
        max_height: offer.get("maxHeight")?.as_u64()?,
    })
}

/// `n` as a canonical CLVM integer atom: big-endian, no redundant leading byte, a leading 0
/// when the top bit is set, empty for 0 (as chia-gaming encodes the message's amount).
fn clvm_u64(n: u64) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let mut atom = bytes.get(start..).unwrap_or_default().to_vec();
    if atom.first().is_some_and(|b| b & 0x80 != 0) {
        atom.insert(0, 0);
    }
    atom
}

fn public_key(text: &str) -> Option<PublicKey> {
    let bytes: [u8; 48] = decode_hex(text)?.try_into().ok()?;
    PublicKey::from_bytes(&bytes).ok()
}

fn bytes32(text: &str) -> Option<Bytes32> {
    let bytes: [u8; 32] = decode_hex(text)?.try_into().ok()?;
    Some(Bytes32::new(bytes))
}

/// An amount as a decimal string or a JSON integer (spec 9.1).
fn amount_of(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s)
            if !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()) =>
        {
            s.parse().ok()
        }
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use chia_bls::{SecretKey, sign};
    use clvm_traits::FromClvm;
    use clvmr::serde::{node_from_bytes, node_to_bytes};
    use proptest::prelude::*;

    const VECTORS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/spec/vectors/fund_state_channel.json"
    ));

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).unwrap()
    }

    fn network(name: &str) -> Network {
        match name {
            "mainnet" => Network::Mainnet,
            _ => Network::Testnet11,
        }
    }

    fn check(case: &Value, p: &Value) -> Result<FundStateChannel, RpcError> {
        let reward = bytes32(case["rewardPuzzleHash"].as_str().unwrap()).unwrap();
        check_fund_state_channel(
            &p.to_string(),
            &network(case["network"].as_str().unwrap()),
            case["now"].as_u64().unwrap(),
            |ph| *ph == reward,
        )
    }

    fn coin(case: &Value) -> Coin {
        let c = &case["coin"];
        Coin::new(
            bytes32(c["parent_coin_info"].as_str().unwrap()).unwrap(),
            bytes32(c["puzzle_hash"].as_str().unwrap()).unwrap(),
            c["amount"].as_u64().unwrap(),
        )
    }

    fn reason(e: &RpcError) -> (i64, String) {
        let data: Value = e
            .data
            .as_deref()
            .map(|d| serde_json::from_str(d).unwrap())
            .unwrap_or(Value::Null);
        (e.code, data["reason"].as_str().unwrap_or("").to_owned())
    }

    fn invalid() -> (i64, String) {
        (4000, "invalid_params".to_owned())
    }

    const PAIRING: PairingRef = PairingRef([1; 32]);

    /// Step 1 of `case`, kept on [`PAIRING`] for the vector's coin.
    fn kept(case: &Value) -> KeptChannel {
        KeptChannel::new(
            PAIRING,
            check(case, &case["step1"]).unwrap(),
            coin(case).coin_id(),
        )
        .unwrap()
    }

    /// `params` (a step 2) for another `amount` and `fee`: the offer's amount and its
    /// `RECEIVE_MESSAGE` amount follow.
    fn with_total(params: &Value, amount: u64, fee: u64) -> Value {
        let total = amount + fee;
        let mut p = params.clone();
        p["amount"] = amount.to_string().into();
        p["fee"] = fee.to_string().into();
        p["offer"]["amount"] = total.to_string().into();
        p["offer"]["fee"] = fee.to_string().into();
        for c in p["offer"]["conditions"].as_array_mut().unwrap() {
            if c["opcode"] == RECEIVE_MESSAGE {
                c["args"][3] = format!("0x{}", hex::encode(clvm_u64(total))).into();
            }
        }
        p
    }

    /// `params` (a step 2) with another `maxHeight`.
    fn with_height(params: &Value, max_height: u64) -> Value {
        let mut p = params.clone();
        p["offer"]["maxHeight"] = max_height.into();
        p
    }

    /// The conditions of a list: each as its opcode and the rest.
    fn split(a: &Allocator, list: NodePtr) -> Vec<(u32, NodePtr)> {
        Vec::<(u32, NodePtr)>::from_clvm(a, list).unwrap()
    }

    /// The `CREATE_COIN`s of a list: puzzle hash and amount.
    fn outputs(a: &Allocator, list: NodePtr) -> Vec<(Bytes32, u64)> {
        split(a, list)
            .into_iter()
            .filter(|(op, _)| *op == CREATE_COIN)
            .map(|(_, rest)| <(Bytes32, (u64, ()))>::from_clvm(a, rest).unwrap())
            .map(|(ph, (amount, ()))| (ph, amount))
            .collect()
    }

    #[test]
    fn the_vectors_spend_is_the_one_that_opened_the_channel() {
        let v = vectors();
        let cases = v["cases"].as_array().unwrap();
        assert!(!cases.is_empty());
        for case in cases {
            let one = check(case, &case["step1"]).unwrap();
            assert_eq!(
                (one.offer.is_none(), one.total),
                (true, one.amount + one.fee)
            );
            assert_eq!(
                coin(case).coin_id(),
                bytes32(case["coinId"].as_str().unwrap()).unwrap()
            );
            let mut kept = kept(case);
            let two = check(case, &case["step2"]).unwrap();
            let offer = two.offer.clone().unwrap();
            assert_eq!(offer.amount, one.total);
            let mut a = Allocator::new();
            let change = bytes32(case["changePuzzleHash"].as_str().unwrap()).unwrap();
            // Any wallet height below maxHeight and within MAX_FUNDING_BLOCKS of it.
            let height = offer.max_height - 1;
            let conds = two
                .conditions(&PAIRING, &mut kept, &coin(case), height, change, &mut a)
                .unwrap();
            assert_eq!(kept.signed, Some(offer));
            // The vector's spend is the standard spend of exactly these conditions: its
            // solution is `(() (q . conditions) ())`.
            let q = a.one();
            let quoted = a.new_pair(q, conds).unwrap();
            let solution = clvm_list!((), quoted, ()).to_clvm(&mut a).unwrap();
            let spend = &case["spendBundle"]["coin_spends"][0];
            assert_eq!(spend["coin"], case["coin"]);
            assert_eq!(
                hex::encode(node_to_bytes(&a, solution).unwrap()),
                spend["solution"].as_str().unwrap().trim_start_matches("0x")
            );
        }
    }

    #[test]
    fn each_check_refuses_with_its_reason_in_order() {
        let v = vectors();
        let case = &v["cases"][0];
        let base = case["step2"].clone();
        let with = |path: &[&str], value: Value| {
            let mut p = base.clone();
            let (last, parents) = path.split_last().unwrap();
            let mut at = &mut p;
            for k in parents {
                at = &mut at[*k];
            }
            at[*last] = value;
            p
        };
        let receive = base["offer"]["conditions"][0].clone();
        assert_eq!(receive["opcode"], 67);
        let operator = base["offer"]["conditions"][1].clone();
        assert_eq!(operator["opcode"], 51);
        let condition =
            |opcode: u32, args: &[&str]| serde_json::json!({ "opcode": opcode, "args": args });
        let conditions = |list: Vec<Value>| with(&["offer", "conditions"], Value::Array(list));
        let receive_with = |at: usize, arg: &str| {
            let mut c = receive.clone();
            c["args"][at] = arg.into();
            c
        };
        let ph = format!("0x{}", "ab".repeat(32));
        let pk = format!(
            "0x{}",
            hex::encode(SecretKey::from_seed(&[2; 32]).public_key().to_bytes())
        );
        let other_signature = hex::encode(sign(&SecretKey::from_seed(&[7; 32]), b"x").to_bytes());
        let invalid = (4000, "invalid_params");
        let mut without_height = base.clone();
        without_height["offer"]
            .as_object_mut()
            .unwrap()
            .remove("maxHeight");
        let cases: Vec<(Value, (i64, &str))> = vec![
            (with(&["amount"], "0".into()), invalid),
            (with(&["amount"], "1.5".into()), invalid),
            (with(&["fee"], Value::Null), invalid),
            (with(&["rewardPuzzleHash"], "0xaa".into()), invalid),
            (with(&["listing"], "{}".into()), invalid),
            (with(&["channelId"], "0x00".into()), invalid),
            (with(&["offer", "amount"], "1".into()), invalid),
            (with(&["offer", "fee"], "1".into()), invalid),
            (with(&["offer", "coinId"], Value::Null), invalid),
            (with(&["offer", "maxHeight"], "1".into()), invalid),
            // maxHeight is required.
            (with(&["offer", "maxHeight"], Value::Null), invalid),
            (without_height, invalid),
            // A third condition, even one that is allowed alone.
            (
                conditions(vec![
                    receive.clone(),
                    operator.clone(),
                    condition(51, &[&ph, "0x"]),
                ]),
                invalid,
            ),
            // No RECEIVE_MESSAGE: the settlement coin would be anyone's.
            (conditions(vec![operator.clone()]), invalid),
            (conditions(vec![]), invalid),
            (conditions(vec![receive.clone(), receive.clone()]), invalid),
            (
                conditions(vec![
                    receive.clone(),
                    condition(51, &[&ph, "0x"]),
                    operator.clone(),
                ]),
                invalid,
            ),
            // A payment to anyone, a signature the wallet would add.
            (
                conditions(vec![receive.clone(), condition(51, &[&ph, "0x01"])]),
                invalid,
            ),
            (
                conditions(vec![receive.clone(), condition(50, &[&pk, "0x01"])]),
                invalid,
            ),
            (
                conditions(vec![receive.clone(), condition(49, &[&pk, "0x01"])]),
                invalid,
            ),
            // What chia-gaming's initiator request never carries.
            (
                conditions(vec![receive.clone(), condition(52, &["0x01"])]),
                invalid,
            ),
            (
                conditions(vec![receive.clone(), condition(60, &["0x01"])]),
                invalid,
            ),
            (
                conditions(vec![receive.clone(), condition(61, &[&ph])]),
                invalid,
            ),
            (
                conditions(vec![receive.clone(), condition(66, &["0x10", "0x"])]),
                invalid,
            ),
            // The receiver's mode, another mode, a message, another sender length, another
            // amount, the same amount not canonical.
            (
                conditions(vec![condition(67, &["0x10", "0x", &ph])]),
                invalid,
            ),
            (conditions(vec![receive_with(0, "0x3f")]), invalid),
            (conditions(vec![receive_with(1, "0x01")]), invalid),
            (conditions(vec![receive_with(2, "0xabab")]), invalid),
            (conditions(vec![receive_with(3, "0x1e8481")]), invalid),
            (conditions(vec![receive_with(3, "0x001e8480")]), invalid),
            (
                with(&["listing", "signature"], other_signature.into()),
                (4001, "listing_invalid"),
            ),
            (
                with(&["rewardPuzzleHash"], ph.clone().into()),
                (4001, "reward_not_own"),
            ),
        ];
        for (p, want) in cases {
            let got = reason(&check(case, &p).unwrap_err());
            assert_eq!((got.0, got.1.as_str()), want, "{p}");
        }
        let reward = bytes32(case["rewardPuzzleHash"].as_str().unwrap()).unwrap();
        let now = case["now"].as_u64().unwrap();
        let at = |net: &Network, now: u64| {
            reason(
                &check_fund_state_channel(&base.to_string(), net, now, |ph| *ph == reward)
                    .unwrap_err(),
            )
            .1
        };
        let net = network(case["network"].as_str().unwrap());
        assert_eq!(at(&net, u64::MAX), "listing_invalid", "expired");
        let other = if matches!(net, Network::Mainnet) {
            Network::Testnet11
        } else {
            Network::Mainnet
        };
        assert_eq!(at(&other, now), "wrong_network");
        // The initiator's request passes in either order, with or without the operator's coin.
        for p in [
            conditions(vec![operator.clone(), receive.clone()]),
            conditions(vec![receive.clone()]),
            conditions(vec![receive.clone(), condition(51, &[&ph, "0x"])]),
        ] {
            assert!(check(case, &p).is_ok(), "{p}");
        }
    }

    #[test]
    fn canonical_clvm_amounts() {
        for (n, atom) in [
            (0u64, ""),
            (1, "01"),
            (0x7f, "7f"),
            (0x80, "0080"),
            (2_000_000, "1e8480"),
            (u64::MAX, "00ffffffffffffffff"),
        ] {
            assert_eq!(hex::encode(clvm_u64(n)), atom, "{n}");
            let mut a = Allocator::new();
            let node = n.to_clvm(&mut a).unwrap();
            assert_eq!(a.atom(node).as_ref(), clvm_u64(n).as_slice(), "{n}");
        }
    }

    #[test]
    fn step_2_must_continue_step_1_on_its_pairing_and_coin() {
        let v = vectors();
        let case = &v["cases"][0];
        let one = check(case, &case["step1"]).unwrap();
        let two = check(case, &case["step2"]).unwrap();
        let max = two.offer.as_ref().unwrap().max_height;
        let height = max - 1;
        let change = Bytes32::new([1; 32]);
        let err = |s: &FundStateChannel, p: &PairingRef, k: &mut KeptChannel, c: &Coin, h: u64| {
            let before = k.clone();
            let e = reason(
                &s.conditions(p, k, c, h, change, &mut Allocator::new())
                    .unwrap_err(),
            );
            assert_eq!(*k, before, "a refusal leaves the kept channel as it was");
            e
        };
        // Step 1 has no offer to sign; a step 2 is not kept as step 1.
        assert_eq!(
            err(&one, &PAIRING, &mut kept(case), &coin(case), height),
            invalid()
        );
        assert!(KeptChannel::new(PAIRING, two.clone(), coin(case).coin_id()).is_none());
        // Another pairing.
        assert_eq!(
            err(
                &two,
                &PairingRef([2; 32]),
                &mut kept(case),
                &coin(case),
                height
            ),
            invalid()
        );
        // Another coin than the offer's; the offer's coin, but not the one kept.
        let mut other = coin(case);
        other.amount += 1;
        assert_eq!(
            err(&two, &PAIRING, &mut kept(case), &other, height),
            invalid()
        );
        let mut kept_other = KeptChannel::new(PAIRING, one.clone(), other.coin_id()).unwrap();
        assert_eq!(
            err(&two, &PAIRING, &mut kept_other, &coin(case), height),
            invalid()
        );
        // Another amount than the approved one, its offer to match.
        let more = with_total(&case["step2"], one.amount + 1, one.fee);
        assert_eq!(
            err(
                &check(case, &more).unwrap(),
                &PAIRING,
                &mut kept(case),
                &coin(case),
                height
            ),
            invalid()
        );
        // maxHeight at or below the wallet's height, or too far above it.
        for h in [max, max + 1] {
            assert_eq!(
                err(&two, &PAIRING, &mut kept(case), &coin(case), h),
                invalid(),
                "{h}"
            );
        }
        let far = with_height(&case["step2"], height + MAX_FUNDING_BLOCKS + 1);
        assert_eq!(
            err(
                &check(case, &far).unwrap(),
                &PAIRING,
                &mut kept(case),
                &coin(case),
                height
            ),
            invalid()
        );
        let edge = with_height(&case["step2"], height + MAX_FUNDING_BLOCKS);
        assert!(
            check(case, &edge)
                .unwrap()
                .conditions(
                    &PAIRING,
                    &mut kept(case),
                    &coin(case),
                    height,
                    change,
                    &mut Allocator::new()
                )
                .is_ok()
        );
        // A coin too small for the offer.
        let small = Coin::new(Bytes32::new([3; 32]), Bytes32::new([4; 32]), one.total - 1);
        let mut p = case["step2"].clone();
        p["offer"]["coinId"] = format!("0x{}", hex::encode(small.coin_id())).into();
        let mut kept_small = KeptChannel::new(PAIRING, one.clone(), small.coin_id()).unwrap();
        assert_eq!(
            err(
                &check(case, &p).unwrap(),
                &PAIRING,
                &mut kept_small,
                &small,
                height
            ),
            invalid()
        );
        // A coin of exactly the total: no change coin; the height assertion comes last.
        let exact = Coin::new(Bytes32::new([3; 32]), Bytes32::new([4; 32]), one.total);
        p["offer"]["coinId"] = format!("0x{}", hex::encode(exact.coin_id())).into();
        let mut kept_exact = KeptChannel::new(PAIRING, one.clone(), exact.coin_id()).unwrap();
        let mut a = Allocator::new();
        let full = two
            .conditions(
                &PAIRING,
                &mut kept(case),
                &coin(case),
                height,
                change,
                &mut a,
            )
            .unwrap();
        let no_change = check(case, &p)
            .unwrap()
            .conditions(&PAIRING, &mut kept_exact, &exact, height, change, &mut a)
            .unwrap();
        let n = |l| split(&a, l).len();
        assert_eq!(n(no_change), n(full) - 1);
        assert_eq!(
            split(&a, no_change).last().unwrap().0,
            ASSERT_BEFORE_HEIGHT_ABSOLUTE
        );
    }

    #[test]
    fn a_repeated_step_2_is_answered_only_when_identical() {
        let v = vectors();
        let case = &v["cases"][0];
        let two = check(case, &case["step2"]).unwrap();
        let offer = two.offer.clone().unwrap();
        let height = offer.max_height - 1;
        let change = Bytes32::new([1; 32]);
        let mut kept = kept(case);
        assert_eq!(kept.release_height(), None);
        let sign = |s: &FundStateChannel, k: &mut KeptChannel| {
            let mut a = Allocator::new();
            s.conditions(&PAIRING, k, &coin(case), height, change, &mut a)
                .map(|l| node_to_bytes(&a, l).unwrap())
        };
        let first = sign(&two, &mut kept).unwrap();
        assert_eq!(
            kept.release_height(),
            Some(offer.max_height + RELEASE_BUFFER_BLOCKS)
        );
        // The same request again: the same spend.
        assert_eq!(sign(&two, &mut kept).unwrap(), first);
        // Another maxHeight, another channel, other conditions: refused, the kept offer stays.
        let later = with_height(&case["step2"], offer.max_height + 1);
        let mut other_channel = case["step2"].clone();
        other_channel["channelId"] = format!(
            "0x{}",
            hex::encode(SecretKey::from_seed(&[3; 32]).public_key().to_bytes())
        )
        .into();
        let mut fewer = case["step2"].clone();
        fewer["offer"]["conditions"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        for p in [later, other_channel, fewer] {
            let s = check(case, &p).unwrap();
            assert_eq!(reason(&sign(&s, &mut kept).unwrap_err()), invalid(), "{p}");
            assert_eq!(kept.signed.as_ref(), Some(&offer));
        }
    }

    fn signed(listing: &Listing, sk: &SecretKey) -> Value {
        let text = serde_json::to_string(listing).unwrap();
        let sig = sign(sk, listing_message(&text));
        serde_json::json!({ "listing": text, "signature": hex::encode(sig.to_bytes()) })
    }

    #[test]
    fn only_a_v3_listing_in_xch_opens_and_its_display_is_safe() {
        let v = vectors();
        let case = &v["cases"][0];
        let mut listing: Listing =
            serde_json::from_str(case["step1"]["listing"]["listing"].as_str().unwrap()).unwrap();
        let sk = SecretKey::from_seed(&[7; 32]);
        listing.operator_pk = hex::encode(sk.public_key().to_bytes());
        listing.endpoint = format!("https://op.example/\u{202e}gpj.exe\n{}", "a".repeat(400));
        listing.models[0].id = "evil\u{2066}\u{0007}model".into();
        listing.models = std::iter::repeat_n(listing.models[0].clone(), 70).collect();
        let mut p = case["step1"].clone();
        p["listing"] = signed(&listing, &sk);
        let d = check(case, &p).unwrap().display();
        assert_eq!(d.endpoint.chars().count(), MAX_DISPLAY_URL);
        assert!(
            d.endpoint.ends_with('…')
                && !d.endpoint.contains('\u{202e}')
                && !d.endpoint.contains('\n')
        );
        assert_eq!(d.models[0].id, "evilmodel");
        assert_eq!(
            (d.models.len(), d.models_not_shown),
            (MAX_DISPLAY_MODELS, 6)
        );
        assert_eq!(d.operator_pk_short.chars().count(), 17);
        for change in [
            |l: &mut Listing| l.version = 2,
            |l: &mut Listing| l.payment.asset = "cat".into(),
            |l: &mut Listing| l.payment.reward_ph = "22".into(),
        ] {
            let mut l = listing.clone();
            change(&mut l);
            p["listing"] = signed(&l, &sk);
            assert_eq!(reason(&check(case, &p).unwrap_err()).1, "listing_invalid");
        }
    }

    /// Writes the `fund_state_channel` fuzz seeds (`XCHONNECT_FUZZ_SEEDS=$PWD/fuzz/corpus`):
    /// the vectors' two requests, which pass every check.
    #[test]
    fn fund_state_channel_fuzz_seeds() {
        let v = vectors();
        for (i, case) in v["cases"].as_array().unwrap().iter().enumerate() {
            for step in ["step1", "step2"] {
                check(case, &case[step]).unwrap();
                if let Some(dir) = std::env::var_os("XCHONNECT_FUZZ_SEEDS") {
                    let dir = std::path::Path::new(&dir).join("fund_state_channel");
                    std::fs::create_dir_all(&dir).unwrap();
                    std::fs::write(dir.join(format!("seed-{i}-{step}")), case[step].to_string())
                        .unwrap();
                }
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn arbitrary_params_never_panic(text in ".{0,400}") {
            let _ = check_fund_state_channel(&text, &Network::Mainnet, 0, |_| true);
        }

        #[test]
        fn a_changed_listing_byte_never_opens(at in 0usize..4000, by in 1u8..=255) {
            let v = vectors();
            let case = &v["cases"][0];
            let mut p = case["step1"].clone();
            let mut text = p["listing"]["listing"].as_str().unwrap().as_bytes().to_vec();
            let at = at % text.len();
            text[at] ^= by;
            prop_assume!(std::str::from_utf8(&text).is_ok());
            p["listing"]["listing"] = String::from_utf8(text).unwrap().into();
            prop_assert_eq!(reason(&check(case, &p).unwrap_err()), (4001, "listing_invalid".to_owned()));
        }

        #[test]
        fn an_accepted_step_2_moves_only_the_total_and_returns_the_rest(
            fee in 0u64..1_000_000,
            extra in 0u64..1_000_000,
            json_number in any::<bool>(),
        ) {
            let v = vectors();
            let case = &v["cases"][0];
            let amount = 1_000u64;
            let total = amount + fee;
            let coin = Coin::new(Bytes32::new([5; 32]), Bytes32::new([6; 32]), total + extra);
            let mut one = case["step1"].clone();
            one["amount"] = if json_number { Value::from(amount) } else { amount.to_string().into() };
            one["fee"] = fee.to_string().into();
            let mut two = with_total(&case["step2"], amount, fee);
            two["amount"] = one["amount"].clone();
            two["offer"]["coinId"] = format!("0x{}", hex::encode(coin.coin_id())).into();
            let mut kept = KeptChannel::new(PAIRING, check(case, &one).unwrap(), coin.coin_id()).unwrap();
            let mut a = Allocator::new();
            let change = Bytes32::new([7; 32]);
            let two = check(case, &two).unwrap();
            let height = two.offer.as_ref().unwrap().max_height - 1;
            let list = two.conditions(&PAIRING, &mut kept, &coin, height, change, &mut a).unwrap();
            let out = outputs(&a, list);
            let settlement = Bytes32::new(chia_puzzles::SETTLEMENT_PAYMENT_HASH);
            prop_assert_eq!(out[0], (settlement, total));
            prop_assert_eq!(out.iter().map(|o| o.1).sum::<u64>(), coin.amount);
            prop_assert_eq!(out.contains(&(change, extra)), extra > 0);
            // The bytes parse back to the same list.
            let bytes = node_to_bytes(&a, list).unwrap();
            let back = node_from_bytes(&mut a, &bytes).unwrap();
            prop_assert_eq!(outputs(&a, back), out);
        }
    }
}
