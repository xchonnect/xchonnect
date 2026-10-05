//! A dApp's declared intent, verified against the wallet's own simulation.
//!
//! Spec 11.1 item 1: a wallet MUST ignore dApp-provided labels for amounts and recipients.
//! An intent does not change that. It is a set of **claims** — who receives what, the fee,
//! the net change per asset — that the wallet checks field by field against what it
//! simulated. Every claim that holds is shown as verified; a claim that does not hold, or
//! one the wallet cannot check, refuses the request. So a dApp can explain a custom spend
//! ("this buys an option, 2 XCH to the writer") without the wallet trusting its words: the
//! words are only shown once the simulation has proven them.
//!
//! The one piece of free text is `kind` ("option.buy", "loan.open"): a short machine label
//! the wallet shows as *described by the website*, restricted to `[a-z0-9._-]` so it cannot
//! impersonate interface text.

use crate::simulate::{AssetId, Summary};
use chia_protocol::Bytes32;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// Longest `kind` accepted.
const MAX_KIND: usize = 48;
/// Most claims of one kind (recipients, net changes) accepted.
const MAX_CLAIMS: usize = 64;

/// A payment the dApp says the request makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientClaim {
    /// Asset.
    pub asset: AssetId,
    /// The recipient's p2 puzzle hash (what its address encodes).
    pub puzzle_hash: Bytes32,
    /// Amount (smallest units).
    pub amount: u64,
}

/// A net change per asset the dApp says the user sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetClaim {
    /// Asset.
    pub asset: AssetId,
    /// Signed amount (smallest units); negative is a loss.
    pub amount: i128,
}

/// What a dApp declares about a spend. Every field is optional; whatever is declared must
/// hold exactly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Intent {
    /// Short machine label, shown as described by the website.
    pub kind: Option<String>,
    /// Every payment to someone other than the user. When given, it must list **all** of
    /// them: a payment the dApp did not declare is a mismatch, so an intent cannot hide one.
    pub recipients: Option<Vec<RecipientClaim>>,
    /// The fee (XCH smallest units): the request's implied fee.
    pub fee: Option<u64>,
    /// Net change per listed asset.
    pub net: Option<Vec<NetClaim>>,
}

/// Why an intent was refused. Not shown to the dApp beyond the reason code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentError {
    /// The intent is not well formed.
    Invalid(&'static str),
    /// A claim does not match the simulation.
    Mismatch(&'static str),
}

/// One claim the wallet checked and found true.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VerifiedFact {
    /// A payment to someone else.
    Recipient {
        /// Asset.
        asset: AssetId,
        /// Recipient p2 puzzle hash (hex).
        puzzle_hash: String,
        /// Amount.
        amount: u64,
    },
    /// The fee.
    Fee {
        /// Amount.
        amount: u64,
    },
    /// Net change of one asset.
    Net {
        /// Asset.
        asset: AssetId,
        /// Signed amount, as a decimal string (`i128` does not fit JSON numbers).
        amount: String,
    },
}

/// The verified intent, for the approval prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntentReport {
    /// The dApp's label for the request, if any (described by the website, not verified).
    pub kind: Option<String>,
    /// Every claim, each one checked.
    pub verified: Vec<VerifiedFact>,
    /// The intent declared every payment to others, so no undeclared payment exists.
    pub recipients_complete: bool,
}

fn hex32(value: &Value) -> Option<Bytes32> {
    let text = value.as_str()?;
    let body = text.strip_prefix("0x").unwrap_or(text);
    let bytes = hex::decode(body).ok()?;
    Bytes32::try_from(bytes.as_slice()).ok()
}

/// An amount as a decimal string or a JSON integer.
fn amount_u64(value: &Value) -> Option<u64> {
    match value {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

fn amount_i128(value: &Value) -> Option<i128> {
    match value {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_i64().map(i128::from),
        _ => None,
    }
}

/// `assetId`: absent / null / "xch" for XCH, else a CAT's 32-byte TAIL hash.
fn asset_of(entry: &Value) -> Option<AssetId> {
    match entry.get("assetId") {
        None | Some(Value::Null) => Some(AssetId::Xch),
        Some(Value::String(s)) if s.eq_ignore_ascii_case("xch") => Some(AssetId::Xch),
        Some(other) => hex32(other).map(AssetId::Cat),
    }
}

impl Intent {
    /// Parse the `intent` member of a request's params (camelCase, amounts as strings).
    pub fn from_json(value: &Value) -> Result<Self, IntentError> {
        let obj = value
            .as_object()
            .ok_or(IntentError::Invalid("intent is not an object"))?;
        let kind = match obj.get("kind") {
            None | Some(Value::Null) => None,
            Some(Value::String(k))
                if !k.is_empty()
                    && k.len() <= MAX_KIND
                    && k.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)
                    }) =>
            {
                Some(k.clone())
            }
            Some(_) => return Err(IntentError::Invalid("kind")),
        };
        let list = |key: &str| -> Result<Option<&Vec<Value>>, IntentError> {
            match obj.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::Array(items)) if items.len() <= MAX_CLAIMS => Ok(Some(items)),
                Some(_) => Err(IntentError::Invalid("list")),
            }
        };
        let recipients = list("recipients")?
            .map(|items| {
                items
                    .iter()
                    .map(|entry| {
                        Ok(RecipientClaim {
                            asset: asset_of(entry).ok_or(IntentError::Invalid("assetId"))?,
                            puzzle_hash: entry
                                .get("puzzleHash")
                                .and_then(hex32)
                                .ok_or(IntentError::Invalid("puzzleHash"))?,
                            amount: entry
                                .get("amount")
                                .and_then(amount_u64)
                                .ok_or(IntentError::Invalid("amount"))?,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let net = list("netChange")?
            .map(|items| {
                items
                    .iter()
                    .map(|entry| {
                        Ok(NetClaim {
                            asset: asset_of(entry).ok_or(IntentError::Invalid("assetId"))?,
                            amount: entry
                                .get("amount")
                                .and_then(amount_i128)
                                .ok_or(IntentError::Invalid("amount"))?,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let fee = match obj.get("fee") {
            None | Some(Value::Null) => None,
            Some(v) => Some(amount_u64(v).ok_or(IntentError::Invalid("fee"))?),
        };
        Ok(Intent {
            kind,
            recipients,
            fee,
            net,
        })
    }

    /// Check every claim against the simulation. All must hold.
    pub fn verify(&self, summary: &Summary) -> Result<IntentReport, IntentError> {
        let mut verified = Vec::new();

        if let Some(claims) = &self.recipients {
            // What the user's own spends pay to others, summed per (asset, recipient).
            let mut actual: BTreeMap<(AssetId, String), u128> = BTreeMap::new();
            for output in summary.outputs.iter().filter(|o| !o.to_user) {
                // A payment whose recipient the wallet cannot name (a CAT output without a
                // hint) cannot be checked, so a complete declaration cannot be confirmed.
                let recipient = output
                    .recipient
                    .clone()
                    .ok_or(IntentError::Mismatch("unnamed_recipient"))?;
                *actual.entry((output.asset, recipient)).or_default() += u128::from(output.amount);
            }
            let mut declared: BTreeMap<(AssetId, String), u128> = BTreeMap::new();
            for claim in claims {
                *declared
                    .entry((claim.asset, hex::encode(claim.puzzle_hash)))
                    .or_default() += u128::from(claim.amount);
            }
            if actual != declared {
                return Err(IntentError::Mismatch("recipients"));
            }
            for ((asset, puzzle_hash), amount) in declared {
                verified.push(VerifiedFact::Recipient {
                    asset,
                    puzzle_hash,
                    amount: u64::try_from(amount).map_err(|_| IntentError::Mismatch("amount"))?,
                });
            }
        }

        if let Some(fee) = self.fee {
            if summary.implied_fee != Some(fee) {
                return Err(IntentError::Mismatch("fee"));
            }
            verified.push(VerifiedFact::Fee { amount: fee });
        }

        if let Some(claims) = &self.net {
            for claim in claims {
                let actual = summary.asset(claim.asset).map_or(0, |d| d.net);
                if actual != claim.amount {
                    return Err(IntentError::Mismatch("net_change"));
                }
                verified.push(VerifiedFact::Net {
                    asset: claim.asset,
                    amount: claim.amount.to_string(),
                });
            }
        }

        Ok(IntentReport {
            kind: self.kind.clone(),
            verified,
            recipients_complete: self.recipients.is_some(),
        })
    }
}
