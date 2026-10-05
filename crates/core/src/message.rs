//! Inner plaintext and typed message bodies (`docs/spec/wire/envelope.cddl`).
//!
//! Unknown keys inside inner maps are ignored for forward compatibility (spec 17);
//! required keys with the wrong type or size are errors.

use crate::cbor::Value;
use crate::crypto::{MailboxId, Token};
use crate::error::{Error, Result};

/// Largest permitted `seq` (2^53 - 1, safe in JavaScript).
pub const MAX_SEQ: u64 = (1 << 53) - 1;

/// Decoded inner plaintext of a session envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inner {
    /// Strictly increasing per direction, starting at 1.
    pub seq: u64,
    /// Issued-at, unix seconds.
    pub iat: u64,
    /// Expiry, unix seconds.
    pub exp: u64,
    /// Random message id; the `request_id` of responses to this message.
    pub id: [u8; 16],
    /// Typed message.
    pub message: Message,
}

/// Optional wallet metadata shared during pairing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalletMeta {
    /// Display name.
    pub name: Option<String>,
    /// Icon URL (https).
    pub icon: Option<String>,
    /// Universal-link base for same-device requests.
    pub link: Option<String>,
}

/// Error object of an `rpc.response` (CHIP-0002 codes, spec 9.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// Numeric code.
    pub code: i64,
    /// Human-readable message.
    pub message: String,
    /// Optional JSON text.
    pub data: Option<String>,
}

/// Result or error of an RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcOutcome {
    /// JSON text result.
    Result(String),
    /// Error.
    Error(RpcError),
}

/// `session.rotate` phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotatePhase {
    /// Initiator's offer.
    Offer,
    /// Responder's answer.
    Accept,
}

/// `session.rotate` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotate {
    /// Offer or accept.
    pub phase: RotatePhase,
    /// The new epoch number.
    pub epoch: u64,
    /// Fresh X25519 public key.
    pub epk: [u8; 32],
    /// The sender's new mailbox.
    pub mailbox: MailboxId,
    /// Write token for the sender's new mailbox.
    pub write_token: Token,
}

/// Spending limits in `session.permissions` (decimal mojo strings).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Limits {
    /// Per request.
    pub per_request_mojos: Option<String>,
    /// Per day.
    pub per_day_mojos: Option<String>,
}

/// `session.permissions` body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Permissions {
    /// Allowed CHIP-0002 methods.
    pub methods: Vec<String>,
    /// Exposed public keys (lowercase hex).
    pub keys: Vec<String>,
    /// Optional limits.
    pub limits: Option<Limits>,
}

/// The states an `rpc.status` may report, in the order a request passes through them:
/// shown to the user, approved, broadcast by the wallet.
pub const RPC_STATUS_STATES: [&str; 3] = ["shown", "approved", "broadcast"];

/// Typed message carried in an inner plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// `rpc.request`.
    RpcRequest {
        /// CHIP-0002 method name.
        method: String,
        /// JSON text params.
        params: String,
    },
    /// `rpc.response`.
    RpcResponse {
        /// `id` of the request.
        request_id: [u8; 16],
        /// Result or error.
        outcome: RpcOutcome,
    },
    /// `rpc.received` delivery receipt.
    RpcReceived {
        /// `id` of the request.
        request_id: [u8; 16],
    },
    /// `rpc.cancel` (dApp to wallet): withdraw a request the user has not decided yet. The
    /// wallet answers it with `rpc.response` error 4102; a request already signed is not
    /// affected (spec 9.1).
    RpcCancel {
        /// `id` of the request.
        request_id: [u8; 16],
    },
    /// `rpc.status` (wallet to dApp): progress of a request, repeatable and never terminal
    /// (`rpc.response` is). See [`RPC_STATUS_STATES`].
    RpcStatus {
        /// `id` of the request.
        request_id: [u8; 16],
        /// One of [`RPC_STATUS_STATES`].
        state: String,
        /// The transaction id once the wallet has broadcast it.
        tx_id: Option<[u8; 32]>,
    },
    /// `session.confirm` (dApp to wallet, pairing step 6).
    SessionConfirm {
        /// dApp session mailbox D.
        mailbox: MailboxId,
        /// Write token for D.
        write_token: Token,
    },
    /// `session.ready` (wallet to dApp after SAS confirmation).
    SessionReady {
        /// Optional wallet metadata.
        meta: Option<WalletMeta>,
    },
    /// `session.rotate`.
    SessionRotate(Rotate),
    /// `session.permissions`.
    SessionPermissions(Permissions),
    /// `session.end`.
    SessionEnd {
        /// Optional reason.
        reason: Option<String>,
    },
    /// `session.ping`.
    SessionPing,
    /// `session.pong`.
    SessionPong,
    /// A type this implementation does not know; hosts ignore it.
    Unknown {
        /// The type string.
        type_name: String,
    },
}

impl Message {
    /// Wire type string.
    pub fn type_name(&self) -> &str {
        match self {
            Message::RpcRequest { .. } => "rpc.request",
            Message::RpcResponse { .. } => "rpc.response",
            Message::RpcReceived { .. } => "rpc.received",
            Message::RpcCancel { .. } => "rpc.cancel",
            Message::RpcStatus { .. } => "rpc.status",
            Message::SessionConfirm { .. } => "session.confirm",
            Message::SessionReady { .. } => "session.ready",
            Message::SessionRotate(_) => "session.rotate",
            Message::SessionPermissions(_) => "session.permissions",
            Message::SessionEnd { .. } => "session.end",
            Message::SessionPing => "session.ping",
            Message::SessionPong => "session.pong",
            Message::Unknown { type_name } => type_name,
        }
    }

    fn body(&self) -> Result<Value> {
        Ok(match self {
            Message::RpcRequest { method, params } => Value::text_map(vec![
                ("method", Value::text(method)),
                ("params", Value::text(params)),
            ]),
            Message::RpcResponse {
                request_id,
                outcome,
            } => {
                let mut e = vec![("request_id", Value::bytes(request_id))];
                match outcome {
                    RpcOutcome::Result(r) => e.push(("result", Value::text(r))),
                    RpcOutcome::Error(err) => {
                        let mut f = vec![
                            ("code", Value::int(err.code)),
                            ("message", Value::text(&err.message)),
                        ];
                        if let Some(d) = &err.data {
                            f.push(("data", Value::text(d)));
                        }
                        e.push(("error", Value::text_map(f)));
                    }
                }
                Value::text_map(e)
            }
            Message::RpcReceived { request_id } | Message::RpcCancel { request_id } => {
                Value::text_map(vec![("request_id", Value::bytes(request_id))])
            }
            Message::RpcStatus {
                request_id,
                state,
                tx_id,
            } => {
                let mut e = vec![
                    ("request_id", Value::bytes(request_id)),
                    ("state", Value::text(state)),
                ];
                if let Some(id) = tx_id {
                    e.push(("tx_id", Value::bytes(id)));
                }
                Value::text_map(e)
            }
            Message::SessionConfirm {
                mailbox,
                write_token,
            } => Value::text_map(vec![
                ("mbx", Value::bytes(&mailbox.0)),
                ("w", Value::bytes(write_token.expose())),
            ]),
            Message::SessionReady { meta } => {
                Value::text_map(meta.iter().map(|m| ("meta", meta_to_value(m))).collect())
            }
            Message::SessionRotate(r) => Value::text_map(vec![
                (
                    "phase",
                    Value::text(if r.phase == RotatePhase::Offer {
                        "offer"
                    } else {
                        "accept"
                    }),
                ),
                ("epoch", Value::Uint(r.epoch)),
                ("epk", Value::bytes(&r.epk)),
                ("mbx", Value::bytes(&r.mailbox.0)),
                ("w", Value::bytes(r.write_token.expose())),
            ]),
            Message::SessionPermissions(p) => {
                let mut e = vec![
                    (
                        "methods",
                        Value::Array(p.methods.iter().map(|m| Value::text(m)).collect()),
                    ),
                    (
                        "keys",
                        Value::Array(p.keys.iter().map(|k| Value::text(k)).collect()),
                    ),
                ];
                if let Some(l) = &p.limits {
                    let mut f = Vec::new();
                    if let Some(v) = &l.per_request_mojos {
                        f.push(("per_request_mojos", Value::text(v)));
                    }
                    if let Some(v) = &l.per_day_mojos {
                        f.push(("per_day_mojos", Value::text(v)));
                    }
                    e.push(("limits", Value::text_map(f)));
                }
                Value::text_map(e)
            }
            Message::SessionEnd { reason } => {
                Value::text_map(reason.iter().map(|r| ("reason", Value::text(r))).collect())
            }
            Message::SessionPing | Message::SessionPong => Value::Map(vec![]),
            Message::Unknown { .. } => {
                return Err(Error::State("cannot send unknown message type"));
            }
        })
    }

    fn from_parts(type_name: &str, body: &Value) -> Result<Message> {
        if !body.is_map() {
            return Err(Error::Malformed("body must be a map"));
        }
        Ok(match type_name {
            "rpc.request" => Message::RpcRequest {
                method: req_text(body, "method", 1, 128)?,
                params: req_text(body, "params", 0, usize::MAX)?,
            },
            "rpc.response" => {
                let request_id = req_array::<16>(body, "request_id")?;
                let outcome = match (body.get("result"), body.get("error")) {
                    (Some(r), None) => RpcOutcome::Result(
                        r.as_text().ok_or(Error::Malformed("result"))?.to_owned(),
                    ),
                    (None, Some(e)) => RpcOutcome::Error(RpcError {
                        code: req(e, "code")?
                            .as_i64()
                            .ok_or(Error::Malformed("error.code"))?,
                        message: req_text(e, "message", 0, 512)?,
                        data: opt_text(e, "data", usize::MAX)?,
                    }),
                    _ => {
                        return Err(Error::Malformed(
                            "rpc.response needs exactly one of result/error",
                        ));
                    }
                };
                Message::RpcResponse {
                    request_id,
                    outcome,
                }
            }
            "rpc.received" => Message::RpcReceived {
                request_id: req_array::<16>(body, "request_id")?,
            },
            "rpc.cancel" => Message::RpcCancel {
                request_id: req_array::<16>(body, "request_id")?,
            },
            "rpc.status" => {
                let state = req_text(body, "state", 1, 16)?;
                if !RPC_STATUS_STATES.contains(&state.as_str()) {
                    return Err(Error::Malformed("rpc.status state"));
                }
                Message::RpcStatus {
                    request_id: req_array::<16>(body, "request_id")?,
                    state,
                    tx_id: match body.get("tx_id") {
                        None => None,
                        Some(_) => Some(req_array::<32>(body, "tx_id")?),
                    },
                }
            }
            "session.confirm" => Message::SessionConfirm {
                mailbox: MailboxId(req_array::<16>(body, "mbx")?),
                write_token: Token::from_bytes(req_array::<32>(body, "w")?),
            },
            "session.ready" => Message::SessionReady {
                meta: body.get("meta").map(meta_from_value).transpose()?,
            },
            "session.rotate" => Message::SessionRotate(Rotate {
                phase: match req_text(body, "phase", 1, 16)?.as_str() {
                    "offer" => RotatePhase::Offer,
                    "accept" => RotatePhase::Accept,
                    _ => return Err(Error::Malformed("rotate phase")),
                },
                epoch: req(body, "epoch")?
                    .as_u64()
                    .ok_or(Error::Malformed("epoch"))?,
                epk: req_array::<32>(body, "epk")?,
                mailbox: MailboxId(req_array::<16>(body, "mbx")?),
                write_token: Token::from_bytes(req_array::<32>(body, "w")?),
            }),
            "session.permissions" => {
                let limits = match body.get("limits") {
                    Some(l) if l.is_map() => Some(Limits {
                        per_request_mojos: opt_text(l, "per_request_mojos", 40)?,
                        per_day_mojos: opt_text(l, "per_day_mojos", 40)?,
                    }),
                    Some(_) => return Err(Error::Malformed("limits")),
                    None => None,
                };
                Message::SessionPermissions(Permissions {
                    methods: text_list(req(body, "methods")?)?,
                    keys: text_list(req(body, "keys")?)?,
                    limits,
                })
            }
            "session.end" => Message::SessionEnd {
                reason: opt_text(body, "reason", 128)?,
            },
            "session.ping" => Message::SessionPing,
            "session.pong" => Message::SessionPong,
            other => Message::Unknown {
                type_name: other.to_owned(),
            },
        })
    }
}

impl Inner {
    /// Encode to canonical CBOR (without padding).
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.seq == 0 || self.seq > MAX_SEQ {
            return Err(Error::Malformed("seq out of range"));
        }
        let v = Value::text_map(vec![
            ("seq", Value::Uint(self.seq)),
            ("iat", Value::Uint(self.iat)),
            ("exp", Value::Uint(self.exp)),
            ("id", Value::bytes(&self.id)),
            ("type", Value::text(self.message.type_name())),
            ("body", self.message.body()?),
        ]);
        crate::cbor::encode(&v)
    }

    /// Decode from a CBOR value (already unpadded and canonical-checked).
    pub fn from_value(v: &Value) -> Result<Inner> {
        if !v.is_map() {
            return Err(Error::Malformed("inner must be a map"));
        }
        let seq = req(v, "seq")?.as_u64().ok_or(Error::Malformed("seq"))?;
        if seq == 0 || seq > MAX_SEQ {
            return Err(Error::Malformed("seq out of range"));
        }
        let type_name = req_text(v, "type", 1, 64)?;
        Ok(Inner {
            seq,
            iat: req(v, "iat")?.as_u64().ok_or(Error::Malformed("iat"))?,
            exp: req(v, "exp")?.as_u64().ok_or(Error::Malformed("exp"))?,
            id: req_array::<16>(v, "id")?,
            message: Message::from_parts(&type_name, req(v, "body")?)?,
        })
    }
}

/// Pairing reply plaintext (spec 6.3 step 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingReply {
    /// Wallet mailbox W.
    pub mailbox: MailboxId,
    /// Write token for W.
    pub write_token: Token,
    /// Optional metadata.
    pub meta: Option<WalletMeta>,
}

impl PairingReply {
    /// Encode to canonical CBOR.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = vec![
            ("mbx", Value::bytes(&self.mailbox.0)),
            ("w", Value::bytes(self.write_token.expose())),
        ];
        if let Some(m) = &self.meta {
            e.push(("meta", meta_to_value(m)));
        }
        crate::cbor::encode(&Value::text_map(e))
    }

    /// Decode from a CBOR value.
    pub fn from_value(v: &Value) -> Result<Self> {
        if !v.is_map() {
            return Err(Error::Malformed("pairing reply must be a map"));
        }
        Ok(PairingReply {
            mailbox: MailboxId(req_array::<16>(v, "mbx")?),
            write_token: Token::from_bytes(req_array::<32>(v, "w")?),
            meta: v.get("meta").map(meta_from_value).transpose()?,
        })
    }
}

fn meta_to_value(m: &WalletMeta) -> Value {
    let mut e = Vec::new();
    if let Some(n) = &m.name {
        e.push(("name", Value::text(n)));
    }
    if let Some(i) = &m.icon {
        e.push(("icon", Value::text(i)));
    }
    if let Some(l) = &m.link {
        e.push(("link", Value::text(l)));
    }
    Value::text_map(e)
}

fn meta_from_value(v: &Value) -> Result<WalletMeta> {
    if !v.is_map() {
        return Err(Error::Malformed("meta"));
    }
    Ok(WalletMeta {
        name: opt_text(v, "name", 64)?,
        icon: opt_text(v, "icon", 256)?,
        link: opt_text(v, "link", 256)?,
    })
}

fn req<'a>(v: &'a Value, key: &'static str) -> Result<&'a Value> {
    v.get(key).ok_or(Error::Malformed(key))
}

fn req_text(v: &Value, key: &'static str, min: usize, max: usize) -> Result<String> {
    let t = req(v, key)?.as_text().ok_or(Error::Malformed(key))?;
    if t.len() < min || t.len() > max {
        return Err(Error::Malformed(key));
    }
    Ok(t.to_owned())
}

fn opt_text(v: &Value, key: &'static str, max: usize) -> Result<Option<String>> {
    match v.get(key) {
        None => Ok(None),
        Some(x) => {
            let t = x.as_text().ok_or(Error::Malformed(key))?;
            if t.len() > max {
                return Err(Error::Malformed(key));
            }
            Ok(Some(t.to_owned()))
        }
    }
}

fn req_array<const N: usize>(v: &Value, key: &'static str) -> Result<[u8; N]> {
    req(v, key)?
        .as_bytes()
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Malformed(key))
}

fn text_list(v: &Value) -> Result<Vec<String>> {
    v.as_array()
        .ok_or(Error::Malformed("list"))?
        .iter()
        .map(|x| {
            x.as_text()
                .map(str::to_owned)
                .ok_or(Error::Malformed("list item"))
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cbor;

    fn roundtrip(m: Message) {
        let inner = Inner {
            seq: 7,
            iat: 100,
            exp: 200,
            id: [3; 16],
            message: m,
        };
        let bytes = inner.encode().unwrap();
        let back = Inner::from_value(&cbor::decode(&bytes).unwrap()).unwrap();
        assert_eq!(back, inner);
    }

    #[test]
    fn a_status_outside_the_known_states_is_refused() {
        let inner = Inner {
            seq: 1,
            iat: 100,
            exp: 200,
            id: [3; 16],
            message: Message::RpcStatus {
                request_id: [3; 16],
                state: "approved".into(),
                tx_id: None,
            },
        };
        let mut bytes = inner.encode().unwrap();
        // Same length, an unknown state: "approved" -> "approves".
        let at = bytes.windows(8).position(|w| w == b"approved").unwrap();
        if let Some(last) = bytes.get_mut(at + 7) {
            *last = b's';
        }
        assert!(Inner::from_value(&cbor::decode(&bytes).unwrap()).is_err());
    }

    #[test]
    fn all_messages_roundtrip() {
        roundtrip(Message::RpcRequest {
            method: "signCoinSpends".into(),
            params: "{\"coinSpends\":[]}".into(),
        });
        roundtrip(Message::RpcResponse {
            request_id: [1; 16],
            outcome: RpcOutcome::Result("\"0xab\"".into()),
        });
        roundtrip(Message::RpcResponse {
            request_id: [1; 16],
            outcome: RpcOutcome::Error(RpcError {
                code: 4002,
                message: "user rejected request".into(),
                data: None,
            }),
        });
        roundtrip(Message::RpcReceived {
            request_id: [2; 16],
        });
        roundtrip(Message::RpcCancel {
            request_id: [3; 16],
        });
        roundtrip(Message::RpcStatus {
            request_id: [3; 16],
            state: "approved".into(),
            tx_id: None,
        });
        roundtrip(Message::RpcStatus {
            request_id: [3; 16],
            state: "broadcast".into(),
            tx_id: Some([9; 32]),
        });
        roundtrip(Message::SessionConfirm {
            mailbox: MailboxId([4; 16]),
            write_token: Token::from_bytes([5; 32]),
        });
        roundtrip(Message::SessionReady {
            meta: Some(WalletMeta {
                name: Some("Klimper".into()),
                ..Default::default()
            }),
        });
        roundtrip(Message::SessionReady { meta: None });
        roundtrip(Message::SessionRotate(Rotate {
            phase: RotatePhase::Offer,
            epoch: 1,
            epk: [6; 32],
            mailbox: MailboxId([7; 16]),
            write_token: Token::from_bytes([8; 32]),
        }));
        roundtrip(Message::SessionPermissions(Permissions {
            methods: vec!["signCoinSpends".into()],
            keys: vec!["0xab".into()],
            limits: Some(Limits {
                per_request_mojos: Some("1000".into()),
                per_day_mojos: None,
            }),
        }));
        roundtrip(Message::SessionEnd {
            reason: Some("logout".into()),
        });
        roundtrip(Message::SessionPing);
        roundtrip(Message::SessionPong);
    }

    #[test]
    fn unknown_fields_ignored_unknown_type_surfaced() {
        let v = Value::text_map(vec![
            ("seq", Value::Uint(1)),
            ("iat", Value::Uint(1)),
            ("exp", Value::Uint(2)),
            ("id", Value::bytes(&[0; 16])),
            ("type", Value::text("future.thing")),
            ("body", Value::text_map(vec![("x", Value::Null)])),
            ("ext", Value::Uint(9)),
        ]);
        let inner = Inner::from_value(&v).unwrap();
        assert_eq!(
            inner.message,
            Message::Unknown {
                type_name: "future.thing".into()
            }
        );
    }

    #[test]
    fn rejects_bad_fields() {
        let base = |seq: u64, id: Value| {
            Value::text_map(vec![
                ("seq", Value::Uint(seq)),
                ("iat", Value::Uint(1)),
                ("exp", Value::Uint(2)),
                ("id", id),
                ("type", Value::text("session.ping")),
                ("body", Value::Map(vec![])),
            ])
        };
        assert!(Inner::from_value(&base(0, Value::bytes(&[0; 16]))).is_err());
        assert!(Inner::from_value(&base(MAX_SEQ + 1, Value::bytes(&[0; 16]))).is_err());
        assert!(Inner::from_value(&base(1, Value::bytes(&[0; 15]))).is_err());
        assert!(Inner::from_value(&base(1, Value::bytes(&[0; 16]))).is_ok());
    }
}
