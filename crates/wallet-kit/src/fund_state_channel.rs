//! `chia_fundStateChannel` (spec 9.1, "State channel funding"): a requester (Nodi) asks the
//! wallet to fund a chia-gaming state channel to an operator, in XCH, in two steps.
//!
//! 1. Without `offer`: the wallet checks the params ([`check_fund_state_channel`]: the shape,
//!    the operator's signed listing, its network, that the reward puzzle hash is its own), asks
//!    the user (operator, amount, fee) and names one of its standard XCH coins holding at least
//!    `amount + fee`, which it keeps for this channel.
//! 2. With `channelId` and `offer` (chia-gaming's funding request, which exists only after the
//!    channel's handshake): the same checks, then [`FundStateChannel::conditions`] checks that
//!    the request continues step 1 on the kept coin and gives the conditions of that coin's
//!    standard spend, which the wallet signs and answers unpushed. No second prompt.
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

/// The most conditions an offer may carry.
pub const MAX_CONDITIONS: usize = 16;
/// The longest condition argument, in bytes.
pub const MAX_ARG: usize = 1024;

const CREATE_COIN: u32 = 51;
const RESERVE_FEE: u32 = 52;
const CREATE_COIN_ANNOUNCEMENT: u32 = 60;
const ASSERT_COIN_ANNOUNCEMENT: u32 = 61;
const SEND_MESSAGE: u32 = 66;
const RECEIVE_MESSAGE: u32 = 67;
const ASSERT_BEFORE_HEIGHT_ABSOLUTE: u32 = 87;

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
    /// The spend is valid only below this height.
    pub max_height: Option<u64>,
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
    /// Step 2: when this request continues `kept` (the step 1 the user approved: the same
    /// listing, amount, fee and reward puzzle hash) on `coin` (the coin step 1 named, holding
    /// at least `total`), the conditions of `coin`'s standard spend, a CLVM list in
    /// `allocator`: `offer.amount` to the settlement puzzle, the rest of the coin to
    /// `change_puzzle_hash` (the wallet's own; no coin when the rest is 0), the offer's
    /// conditions verbatim, then `ASSERT_BEFORE_HEIGHT_ABSOLUTE maxHeight` when set. Anything
    /// else is 4000 `invalid_params`. The host signs this spend (delegated puzzle
    /// `(q . conditions)`) and answers it unpushed.
    pub fn conditions(
        &self,
        kept: &FundStateChannel,
        coin: &Coin,
        change_puzzle_hash: Bytes32,
        allocator: &mut Allocator,
    ) -> Result<NodePtr, RpcError> {
        fn clvm<E>(_: E) -> RpcError {
            invalid_params()
        }
        let offer = self.offer.as_ref().ok_or_else(invalid_params)?;
        let continues = kept.offer.is_none()
            && (
                &self.listing_text,
                &self.listing_signature,
                self.amount,
                self.fee,
                self.reward_puzzle_hash,
            ) == (
                &kept.listing_text,
                &kept.listing_signature,
                kept.amount,
                kept.fee,
                kept.reward_puzzle_hash,
            )
            && offer.coin_id == coin.coin_id();
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
        if let Some(height) = offer.max_height {
            list.push(
                clvm_list!(ASSERT_BEFORE_HEIGHT_ABSOLUTE, height)
                    .to_clvm(allocator)
                    .map_err(clvm)?,
            );
        }
        list.to_clvm(allocator).map_err(clvm)
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

/// Step 2's `channelId` and `offer`, when well formed and every condition is one that
/// chia-gaming's funding request uses, with the arguments it takes; `CREATE_COIN` only of
/// 0 mojos. No `AGG_SIG_*`: the wallet signs nothing but its own coin's spend.
fn funding_offer(channel_id: Option<&Value>, offer: &Value) -> Option<FundingOffer> {
    let channel_id = public_key(channel_id?.as_str()?).filter(|pk| !pk.is_inf())?;
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
            let first = args.first().map(Vec::as_slice);
            let allowed = match (opcode, args.len()) {
                (CREATE_COIN, 2) => first?.len() == 32 && args.get(1)?.is_empty(),
                (ASSERT_COIN_ANNOUNCEMENT, 1) => first?.len() == 32,
                (CREATE_COIN_ANNOUNCEMENT | RESERVE_FEE, 1) | (SEND_MESSAGE, 2) => true,
                (RECEIVE_MESSAGE, n) => matches!((first, n), (Some([16]), 3) | (Some([24]), 4)),
                _ => false,
            };
            allowed.then_some(RawCondition { opcode, args })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(FundingOffer {
        channel_id,
        amount: amount_of(offer.get("amount")?)?,
        fee: amount_of(offer.get("fee")?)?,
        conditions,
        coin_id: bytes32(offer.get("coinId")?.as_str()?)?,
        max_height: match offer.get("maxHeight") {
            None | Some(Value::Null) => None,
            Some(h) => Some(h.as_u64()?),
        },
    })
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
            let kept = check(case, &case["step1"]).unwrap();
            assert_eq!(
                (kept.offer.is_none(), kept.total),
                (true, kept.amount + kept.fee)
            );
            assert_eq!(
                coin(case).coin_id(),
                bytes32(case["coinId"].as_str().unwrap()).unwrap()
            );
            let two = check(case, &case["step2"]).unwrap();
            assert_eq!(two.offer.as_ref().unwrap().amount, kept.total);
            let mut a = Allocator::new();
            let change = bytes32(case["changePuzzleHash"].as_str().unwrap()).unwrap();
            let conds = two.conditions(&kept, &coin(case), change, &mut a).unwrap();
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
        let condition = |opcode: u32, args: &[&str]| {
            let mut p = base.clone();
            p["offer"]["conditions"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({ "opcode": opcode, "args": args }));
            p
        };
        let ph = format!("0x{}", "ab".repeat(32));
        let pk = format!(
            "0x{}",
            hex::encode(SecretKey::from_seed(&[2; 32]).public_key().to_bytes())
        );
        let other_signature = hex::encode(sign(&SecretKey::from_seed(&[7; 32]), b"x").to_bytes());
        let invalid = (4000, "invalid_params");
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
            // A payment to anyone, a signature the wallet would add, a message mode
            // chia-gaming does not use.
            (condition(51, &[&ph, "0x01"]), invalid),
            (condition(50, &[&pk, "0x01"]), invalid),
            (condition(49, &[&pk, "0x01"]), invalid),
            (condition(67, &["0x3f", "0x", &ph]), invalid),
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
        // chia-gaming's conditions pass, a 0-mojo coin to anyone included.
        for p in [
            condition(51, &[&ph, "0x"]),
            condition(61, &[&ph]),
            condition(67, &["0x10", "0x", &ph]),
            condition(66, &["0x10", "0x"]),
        ] {
            assert!(check(case, &p).is_ok(), "{p}");
        }
    }

    #[test]
    fn step_2_must_continue_step_1_on_its_coin() {
        let v = vectors();
        let case = &v["cases"][0];
        let mut a = Allocator::new();
        let kept = check(case, &case["step1"]).unwrap();
        let two = check(case, &case["step2"]).unwrap();
        let change = Bytes32::new([1; 32]);
        let mut err = |s: &FundStateChannel, k: &FundStateChannel, c: &Coin| {
            reason(&s.conditions(k, c, change, &mut a).unwrap_err())
        };
        // Step 1 has no offer to sign; step 2 does not continue another step 2.
        assert_eq!(err(&kept, &kept, &coin(case)), invalid());
        assert_eq!(err(&two, &two, &coin(case)), invalid());
        // Another coin.
        let mut other = coin(case);
        other.amount += 1;
        assert_eq!(err(&two, &kept, &other), invalid());
        // Another amount than the approved one, its offer to match.
        let mut more = case["step2"].clone();
        more["amount"] = (kept.amount + 1).to_string().into();
        more["offer"]["amount"] = (kept.total + 1).to_string().into();
        assert_eq!(
            err(&check(case, &more).unwrap(), &kept, &coin(case)),
            invalid()
        );
        // A coin too small for the offer.
        let small = Coin::new(Bytes32::new([3; 32]), Bytes32::new([4; 32]), kept.total - 1);
        let mut p = case["step2"].clone();
        p["offer"]["coinId"] = format!("0x{}", hex::encode(small.coin_id())).into();
        assert_eq!(err(&check(case, &p).unwrap(), &kept, &small), invalid());
        // A coin of exactly the total: no change coin; without maxHeight, no height assertion.
        let exact = Coin::new(Bytes32::new([3; 32]), Bytes32::new([4; 32]), kept.total);
        p["offer"]["coinId"] = format!("0x{}", hex::encode(exact.coin_id())).into();
        let bounded = check(case, &p).unwrap();
        p["offer"]["maxHeight"] = Value::Null;
        let unbounded = check(case, &p).unwrap();
        let mut a = Allocator::new();
        let full = two.conditions(&kept, &coin(case), change, &mut a).unwrap();
        let no_change = bounded.conditions(&kept, &exact, change, &mut a).unwrap();
        let no_height = unbounded.conditions(&kept, &exact, change, &mut a).unwrap();
        let n = |l| split(&a, l).len();
        assert_eq!(
            (n(full), n(no_change), n(no_height)),
            (n(full), n(full) - 1, n(full) - 2)
        );
        assert_eq!(
            split(&a, no_change).last().unwrap().0,
            ASSERT_BEFORE_HEIGHT_ABSOLUTE
        );
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
            let mut two = case["step2"].clone();
            two["amount"] = one["amount"].clone();
            two["fee"] = one["fee"].clone();
            two["offer"]["amount"] = total.to_string().into();
            two["offer"]["fee"] = fee.to_string().into();
            two["offer"]["coinId"] = format!("0x{}", hex::encode(coin.coin_id())).into();
            let kept = check(case, &one).unwrap();
            let mut a = Allocator::new();
            let change = Bytes32::new([7; 32]);
            let list = check(case, &two).unwrap().conditions(&kept, &coin, change, &mut a).unwrap();
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
