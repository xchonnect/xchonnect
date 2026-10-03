//! Method layer helpers (spec 9.1): error codes and request/response correlation.
//!
//! `params` and `result` are CHIP-0002 JSON texts passed through unchanged; the core
//! only checks that they are syntactically valid JSON and never interprets Chia data.

use crate::cbor::{self, Value};
use crate::error::{Error, Result};
use crate::message::{Message, RpcError, RpcOutcome};

/// CHIP-0002 and Xchonnect error codes (spec 9.1).
pub mod codes {
    /// Malformed params.
    pub const INVALID_PARAMS: i64 = 4000;
    /// Not permitted or refused by policy.
    pub const UNAUTHORIZED: i64 = 4001;
    /// The user declined.
    pub const USER_REJECTED: i64 = 4002;
    /// Spendable balance exceeded.
    pub const SPENDABLE_BALANCE_EXCEEDED: i64 = 4003;
    /// Unknown or unsupported method.
    pub const METHOD_NOT_FOUND: i64 = 4004;
    /// Required key not held and `partialSign` false.
    pub const NO_SECRET_KEY: i64 = 4005;
    /// Prompt rate limit or spending limit.
    pub const LIMIT_EXCEEDED: i64 = 4029;
    /// Request expired before the user decided.
    pub const REQUEST_EXPIRED: i64 = 4100;
    /// Spend could not be decoded and unknown contracts are disabled.
    pub const UNSUPPORTED_CONTENT: i64 = 4101;
}

/// Build an `rpc.request`. Fails if `params` is not valid JSON.
pub fn request(method: &str, params_json: &str) -> Result<Message> {
    if method.is_empty() || method.len() > 128 {
        return Err(Error::Malformed("method"));
    }
    check_json(params_json)?;
    Ok(Message::RpcRequest {
        method: method.to_owned(),
        params: params_json.to_owned(),
    })
}

/// Build a successful `rpc.response`.
pub fn result(request_id: [u8; 16], result_json: &str) -> Result<Message> {
    check_json(result_json)?;
    Ok(Message::RpcResponse {
        request_id,
        outcome: RpcOutcome::Result(result_json.to_owned()),
    })
}

/// Build an error `rpc.response`.
pub fn error(
    request_id: [u8; 16],
    code: i64,
    message: &str,
    data_json: Option<&str>,
) -> Result<Message> {
    if let Some(d) = data_json {
        check_json(d)?;
    }
    Ok(Message::RpcResponse {
        request_id,
        outcome: RpcOutcome::Error(RpcError {
            code,
            message: message.chars().take(512).collect(),
            data: data_json.map(str::to_owned),
        }),
    })
}

/// Strip a `chip0002_` alias prefix (spec 9.1: wallets accept both forms).
pub fn canonical_method(method: &str) -> &str {
    method.strip_prefix("chip0002_").unwrap_or(method)
}

fn check_json(s: &str) -> Result<()> {
    serde_json::from_str::<serde::de::IgnoredAny>(s)
        .map(|_| ())
        .map_err(|_| Error::Malformed("not valid JSON"))
}

/// A request awaiting its response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Request id.
    pub id: [u8; 16],
    /// Method name.
    pub method: String,
    /// Request expiry.
    pub exp: u64,
    /// The wallet confirmed receipt (`rpc.received`).
    pub delivered: bool,
}

/// What a response or receipt resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// `rpc.received` for a pending request.
    Delivered(Pending),
    /// Final response.
    Completed(Pending, RpcOutcome),
}

/// dApp-side tracker correlating responses with requests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PendingRequests {
    items: Vec<Pending>,
}

impl PendingRequests {
    /// Maximum tracked requests.
    pub const MAX: usize = 256;

    /// Record a sent request.
    pub fn insert(&mut self, id: [u8; 16], method: &str, exp: u64) -> Result<()> {
        if self.items.iter().any(|p| p.id == id) {
            return Err(Error::State("duplicate request id"));
        }
        if self.items.len() >= Self::MAX {
            return Err(Error::State("too many pending requests"));
        }
        self.items.push(Pending {
            id,
            method: method.to_owned(),
            exp,
            delivered: false,
        });
        Ok(())
    }

    /// Resolve an incoming `rpc.response` / `rpc.received`.
    pub fn resolve(&mut self, message: &Message) -> Result<Resolution> {
        match message {
            Message::RpcReceived { request_id } => {
                let p = self
                    .items
                    .iter_mut()
                    .find(|p| p.id == *request_id)
                    .ok_or(Error::State("unknown request id"))?;
                p.delivered = true;
                Ok(Resolution::Delivered(p.clone()))
            }
            Message::RpcResponse {
                request_id,
                outcome,
            } => {
                let idx = self
                    .items
                    .iter()
                    .position(|p| p.id == *request_id)
                    .ok_or(Error::State("unknown or already answered request id"))?;
                let p = self.items.remove(idx);
                Ok(Resolution::Completed(p, outcome.clone()))
            }
            _ => Err(Error::State("not an rpc response")),
        }
    }

    /// Remove and return requests whose expiry has passed.
    pub fn expire(&mut self, now: u64) -> Vec<Pending> {
        let (expired, keep): (Vec<_>, Vec<_>) = self.items.drain(..).partition(|p| p.exp < now);
        self.items = keep;
        expired
    }

    /// Currently pending requests.
    pub fn items(&self) -> &[Pending] {
        &self.items
    }

    /// Serialise for storage alongside the session.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        cbor::encode(&Value::Array(
            self.items
                .iter()
                .map(|p| {
                    Value::text_map(vec![
                        ("id", Value::bytes(&p.id)),
                        ("m", Value::text(&p.method)),
                        ("exp", Value::Uint(p.exp)),
                        ("d", Value::Bool(p.delivered)),
                    ])
                })
                .collect(),
        ))
    }

    /// Restore from [`PendingRequests::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = cbor::decode(bytes)?;
        let arr = v.as_array().ok_or(Error::Malformed("pending"))?;
        let mut items = Vec::with_capacity(arr.len());
        for e in arr {
            items.push(Pending {
                id: e
                    .get("id")
                    .and_then(Value::as_bytes)
                    .and_then(|b| b.try_into().ok())
                    .ok_or(Error::Malformed("id"))?,
                method: e
                    .get("m")
                    .and_then(Value::as_text)
                    .ok_or(Error::Malformed("m"))?
                    .to_owned(),
                exp: e
                    .get("exp")
                    .and_then(Value::as_u64)
                    .ok_or(Error::Malformed("exp"))?,
                delivered: e
                    .get("d")
                    .and_then(Value::as_bool)
                    .ok_or(Error::Malformed("d"))?,
            });
        }
        Ok(PendingRequests { items })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn builders_validate_json_only() {
        assert!(request("signCoinSpends", r#"{"coinSpends":[],"partialSign":true}"#).is_ok());
        assert!(request("signCoinSpends", "{not json").is_err());
        assert!(request("", "{}").is_err());
        assert!(
            result([0; 16], "12345678901234567890123").is_ok(),
            "big numbers pass through untouched"
        );
        assert!(error([0; 16], codes::USER_REJECTED, "user rejected request", None).is_ok());
        assert_eq!(
            canonical_method("chip0002_signCoinSpends"),
            "signCoinSpends"
        );
        assert_eq!(canonical_method("chia_takeOffer"), "chia_takeOffer");
    }

    #[test]
    fn correlation() {
        let mut p = PendingRequests::default();
        p.insert([1; 16], "chainId", 100).unwrap();
        p.insert([2; 16], "signMessage", 50).unwrap();
        assert!(p.insert([1; 16], "x", 1).is_err());
        assert!(
            matches!(p.resolve(&Message::RpcReceived { request_id: [1; 16] }).unwrap(), Resolution::Delivered(d) if d.delivered)
        );
        let resp = result([1; 16], "\"mainnet\"").unwrap();
        assert!(
            matches!(p.resolve(&resp).unwrap(), Resolution::Completed(d, _) if d.method == "chainId")
        );
        assert!(p.resolve(&resp).is_err(), "duplicate response");
        assert!(
            p.resolve(&result([9; 16], "1").unwrap()).is_err(),
            "unknown id"
        );
        let restored = PendingRequests::from_bytes(&p.to_bytes().unwrap()).unwrap();
        assert_eq!(restored, p);
        assert_eq!(p.expire(60).len(), 1);
        assert!(p.items().is_empty());
    }
}
