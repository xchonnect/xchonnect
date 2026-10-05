//! The full session the privacy checks observe: pairing, signing and a push wake-up.
//!
//! The flow is transport-agnostic ([`Transport`]), so the same script runs in process
//! against the relay's router and over HTTP against real relay and gateway processes
//! with a Postgres database behind them.
//!
//! Every value the project promises not to expose is *planted* here — a client IP in the
//! forwarding headers, a wallet `User-Agent`, a device token, a Chia address, a BLS
//! public key, an amount and a unique plaintext marker inside the encrypted request.
//! A run that stops planting one of them fails [`crate::inventory::verify`] rather than
//! passing vacuously.

use crate::scan::{Class, Secrets};
use async_trait::async_trait;
use serde_json::{Value, json};
use xchonnect_core::b64;
use xchonnect_core::crypto::{Ed25519Seed, MailboxId, OsEntropy, Token};
use xchonnect_core::message::{Limits, Message, Permissions, RpcOutcome, WalletMeta};
use xchonnect_core::origin::OriginDocument;
use xchonnect_core::pairing::{DappPairing, DappPairingParams, VerifiedUri, WalletPairing};
use xchonnect_core::push::{Platform, PushToken};
use xchonnect_core::session::Outgoing;
use xchonnect_core::uri::{LocalSigner, PairingUri, ParseOptions};

/// Client address planted in `X-Forwarded-For`, `X-Real-IP` and `Forwarded`
/// (RFC 5737 documentation range, so it can never be a real client).
pub const CLIENT_IP: &str = "203.0.113.77";
/// Client `User-Agent`.
pub const USER_AGENT: &str = "KlimperProbe/1.4.2 (iPhone; iOS 18.3; CFNetwork/1498.700.2)";
/// Platform device push token (APNs shape: 64 hex characters).
pub const DEVICE_TOKEN: &str = "7f3a9c1d2e4b5a6978f0c1d2e3b4a5968d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a";
/// Chia address inside the encrypted signing request.
pub const CHIA_ADDRESS: &str = "xch1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz8ht6y5";
/// BLS public key inside the encrypted permissions and request (96 hex characters).
pub const BLS_PUBKEY: &str = "a7f2a7f2a7f2a7f2a7f2a7f2a7f2a7f2a7f2a7f2a7f2a7f2a7f2a7f2a7f2a7f2\
                              a7f2a7f2a7f2a7f2a7f2a7f2a7f2a7f2";
/// Marker carried in the encrypted message plaintext.
pub const PLAINTEXT_MARKER: &str = "XCHONNECT-PRIVACY-PROBE-PLAINTEXT-8f2a7c41d9";
/// Amount in mojos inside the encrypted request.
pub const AMOUNT_MOJOS: &str = "133742000000001";
/// Business API key used for one mailbox creation.
pub const API_KEY: &str = "privacy-probe-api-key-0123456789";
/// Business customer the API key maps to.
pub const CUSTOMER: &str = "privacy-probe-customer";
/// dApp domain in the pairing URI.
pub const DAPP_DOMAIN: &str = "dapp.example";
/// Origin key id.
pub const ORIGIN_KID: &str = "privacy-probe-k1";

/// One relay request.
#[derive(Debug)]
pub struct Call<'a> {
    /// HTTP method.
    pub method: &'a str,
    /// Path with query.
    pub path: &'a str,
    /// Capability token for the `Authorization` header.
    pub token: Option<&'a Token>,
    /// Business API key header.
    pub api_key: Option<&'a str>,
    /// JSON body.
    pub body: Option<Value>,
}

impl<'a> Call<'a> {
    /// A call with no token, key or body.
    pub fn new(method: &'a str, path: &'a str) -> Self {
        Call {
            method,
            path,
            token: None,
            api_key: None,
            body: None,
        }
    }

    /// Add a bearer capability token.
    pub fn token(mut self, token: &'a Token) -> Self {
        self.token = Some(token);
        self
    }

    /// Add a business API key.
    pub fn api_key(mut self, key: &'a str) -> Self {
        self.api_key = Some(key);
        self
    }

    /// Add a JSON body.
    pub fn body(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }
}

/// How the flow talks to the relay. Implementations must send [`CLIENT_IP`] in the
/// forwarding headers and [`USER_AGENT`] as the user agent on every request.
#[async_trait]
pub trait Transport: Send + Sync + std::fmt::Debug {
    /// Perform one call, returning the status and the parsed JSON body (`Value::Null`
    /// when the body is empty or not JSON).
    async fn call(&self, call: Call<'_>) -> Result<(u16, Value), String>;
}

/// Where the gateway lives.
#[derive(Debug, Clone)]
pub struct Params {
    /// Wake-up URL registered with the relay.
    pub gateway_url: String,
    /// Gateway public key the device token is sealed to.
    pub gateway_pk: [u8; 32],
    /// Relay URL written into the pairing URI (must be `https` and a public host, so it
    /// is independent of where the test relay actually listens).
    pub uri_relay: String,
}

/// What the flow planted and observed.
#[derive(Debug)]
pub struct Outcome {
    /// Every value the surfaces are scanned for.
    pub secrets: Secrets,
    /// Human-readable trace of what the flow did.
    pub notes: Vec<String>,
    /// Mailboxes created, base64url.
    pub mailboxes: Vec<String>,
    /// Sealed push tokens registered, in order.
    pub sealed_tokens: Vec<Vec<u8>>,
    /// Wake-ups the relay should have dispatched (at least).
    pub expected_wakes: u64,
}

type Res<T> = Result<T, String>;

fn err(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}

async fn expect(t: &dyn Transport, call: Call<'_>, want: u16) -> Res<Value> {
    let what = format!("{} {}", call.method, call.path);
    let (status, body) = t.call(call).await?;
    if status != want {
        return Err(format!("{what}: expected {want}, got {status}: {body}"));
    }
    Ok(body)
}

fn string_field(v: &Value, key: &str) -> Res<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("response has no string `{key}`: {v}"))
}

/// Create a mailbox; returns its id.
async fn create_mailbox(
    t: &dyn Transport,
    read: &Token,
    write: &Token,
    push: Option<Value>,
    api_key: Option<&str>,
) -> Res<MailboxId> {
    let mut body = json!({
        "read_token_hash": b64::encode(&read.hash()),
        "write_token_hash": b64::encode(&write.hash()),
    });
    if let (Some(push), Some(o)) = (push, body.as_object_mut()) {
        o.insert("push_reg".into(), push);
    }
    let mut call = Call::new("POST", "/v1/mailboxes").body(body);
    if let Some(key) = api_key {
        call = call.api_key(key);
    }
    let v = expect(t, call, 201).await?;
    MailboxId::from_b64(&string_field(&v, "mailbox_id")?).map_err(err)
}

/// Post an envelope to its destination mailbox; returns the relay's message id.
async fn post(t: &dyn Transport, out: &Outgoing, ttl_s: u64) -> Res<String> {
    let path = format!("/v1/mailboxes/{}/messages", out.mailbox.to_b64());
    let body = json!({ "env": b64::encode(&out.envelope), "ttl_s": ttl_s });
    let call = Call::new("POST", &path).token(&out.write_token).body(body);
    string_field(&expect(t, call, 202).await?, "msg_id")
}

/// Fetch one envelope and acknowledge it; returns `(msg_id, envelope bytes)`.
async fn fetch_one(t: &dyn Transport, mailbox: &MailboxId, read: &Token) -> Res<(String, Vec<u8>)> {
    let path = format!("/v1/mailboxes/{}/messages?limit=4", mailbox.to_b64());
    let v = expect(t, Call::new("GET", &path).token(read), 200).await?;
    let first = v
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .ok_or_else(|| format!("no message in mailbox {}: {v}", mailbox.to_b64()))?;
    let msg_id = string_field(first, "msg_id")?;
    let env = b64::decode(&string_field(first, "env")?).map_err(err)?;
    let path = format!("/v1/mailboxes/{}/ack", mailbox.to_b64());
    let body = json!({ "msg_ids": [msg_id.clone()] });
    expect(t, Call::new("POST", &path).token(read).body(body), 204).await?;
    Ok((msg_id, env))
}

fn push_reg(gateway_url: &str, sealed: &[u8]) -> Value {
    json!({ "gateway_url": gateway_url, "sealed_token": b64::encode(sealed) })
}

fn seal_device_token(gateway_pk: &[u8; 32], now: u64, hint: u8) -> Res<Vec<u8>> {
    PushToken {
        platform: Platform::Test,
        device_token: DEVICE_TOKEN.to_owned(),
        hint_key: [hint; 32],
        exp: now + 30 * 24 * 3600,
    }
    .seal(&mut OsEntropy, gateway_pk, now)
    .map_err(err)
}

fn signing_params() -> String {
    json!({
        "walletId": 1,
        "address": CHIA_ADDRESS,
        "publicKey": BLS_PUBKEY,
        "amount": AMOUNT_MOJOS,
        "memo": PLAINTEXT_MARKER,
    })
    .to_string()
}

fn origin(signer: &LocalSigner) -> Res<OriginDocument> {
    let json = format!(
        r#"{{"v":1,"name":"Privacy Probe dApp","origin_keys":[{{"kid":"{ORIGIN_KID}","pk":"{}","not_after":"2035-01-01"}}]}}"#,
        b64::encode(&signer.public_key())
    );
    OriginDocument::parse(json.as_bytes()).map_err(err)
}

/// Run the whole flow against `t`.
///
/// # Errors
/// Any unexpected relay answer or crypto failure; the checks treat that as a failed run
/// rather than a passed one.
pub async fn run(t: &dyn Transport, p: &Params, now: u64) -> Res<Outcome> {
    let mut rng = OsEntropy;
    let mut notes: Vec<String> = Vec::new();
    let mut secrets = Secrets::new();
    let mut msg_ids: Vec<String> = Vec::new();
    let mut envelopes: Vec<Vec<u8>> = Vec::new();

    secrets
        .text(
            Class::ClientIp,
            "client IP in forwarding headers",
            CLIENT_IP,
        )
        .text(Class::UserAgent, "wallet user agent", USER_AGENT)
        .text(Class::DeviceToken, "device push token", DEVICE_TOKEN)
        .text(Class::ChiaAddress, "payment address", CHIA_ADDRESS)
        .text(Class::PublicKey, "wallet BLS public key", BLS_PUBKEY)
        .text(
            Class::MessagePlaintext,
            "plaintext marker",
            PLAINTEXT_MARKER,
        )
        .text(Class::MessagePlaintext, "amount in mojos", AMOUNT_MOJOS)
        .text(Class::GatewayUrl, "vendor gateway URL", &p.gateway_url)
        .text(Class::CustomerId, "business customer", CUSTOMER)
        .text(Class::ApiKey, "business API key", API_KEY);

    // --- mailboxes ---------------------------------------------------------
    let token = || Token::random(&mut OsEntropy);
    let (p_read, p_write) = (token(), token());
    let (w_read, w_write) = (token(), token());
    let (d_read, d_write) = (token(), token());
    let sealed = seal_device_token(&p.gateway_pk, now, 0x5a)?;

    let pairing_mbx = create_mailbox(t, &p_read, &p_write, None, None).await?;
    let wallet_mbx = create_mailbox(
        t,
        &w_read,
        &w_write,
        Some(push_reg(&p.gateway_url, &sealed)),
        None,
    )
    .await?;
    // The dApp mailbox is created with the business API key, so the relay records a
    // customer for it (metered, spec 13.5).
    let dapp_mbx = create_mailbox(t, &d_read, &d_write, None, Some(API_KEY)).await?;
    notes.push("created pairing, wallet and dApp mailboxes".to_owned());

    for (label, id) in [
        ("pairing mailbox P", &pairing_mbx),
        ("wallet mailbox W", &wallet_mbx),
        ("dApp mailbox D", &dapp_mbx),
    ] {
        secrets.bytes(Class::MailboxId, label, &id.0);
    }
    for (label, token) in [
        ("pairing read token", &p_read),
        ("pairing write token", &p_write),
        ("wallet read token", &w_read),
        ("wallet write token", &w_write),
        ("dApp read token", &d_read),
        ("dApp write token", &d_write),
    ] {
        secrets.bytes(Class::PlaintextToken, label, token.expose());
        secrets.bytes(Class::TokenHash, &format!("{label} hash"), &token.hash());
    }
    secrets.opaque_bytes(Class::SealedPushToken, "sealed device token", &sealed);

    // --- pairing (spec 6.3) -----------------------------------------------
    let signer = LocalSigner::new(Ed25519Seed::from_bytes([0x11; 32]), ORIGIN_KID).map_err(err)?;
    let doc = origin(&signer)?;
    let mut dapp = DappPairing::new(
        &mut rng,
        now,
        &signer,
        DappPairingParams {
            relay: &p.uri_relay,
            domain: DAPP_DOMAIN,
            pairing_mailbox: pairing_mbx,
            pairing_write: p_write.clone(),
            lifetime_s: 300,
            ticket: None,
            options: ParseOptions::default(),
        },
    )
    .map_err(err)?;

    let parsed = PairingUri::parse(&dapp.uri().to_uri(), ParseOptions::default()).map_err(err)?;
    let verified = VerifiedUri::new(parsed, &doc, now).map_err(err)?;
    let meta = WalletMeta {
        name: Some("Klimper Privacy Probe".to_owned()),
        icon: None,
        link: None,
    };
    let (wallet, reply) = WalletPairing::reply(
        &mut rng,
        now,
        &verified,
        wallet_mbx,
        w_read.clone(),
        w_write.clone(),
        Some(meta),
    )
    .map_err(err)?;
    envelopes.push(reply.envelope.clone());
    msg_ids.push(post(t, &reply, 300).await?);

    let (id, env) = fetch_one(t, &pairing_mbx, &p_read).await?;
    msg_ids.push(id);
    let accepted = dapp.on_reply(now, &env).map_err(err)?;
    let path = format!("/v1/mailboxes/{}", pairing_mbx.to_b64());
    expect(t, Call::new("DELETE", &path).token(&p_read), 204).await?;
    notes.push("pairing reply accepted, pairing mailbox deleted".to_owned());

    if accepted.sas() != wallet.sas() {
        return Err("SAS mismatch between dApp and wallet".to_owned());
    }
    let (mut dapp_session, confirm) = accepted
        .confirm(&mut rng, now, dapp_mbx, d_read.clone(), d_write.clone())
        .map_err(err)?;
    envelopes.push(confirm.envelope.clone());
    // This post lands in the wallet mailbox, which has a push registration: the relay
    // dispatches a content-free wake-up to the gateway (spec 7.3).
    msg_ids.push(post(t, &confirm, 300).await?);

    let (id, env) = fetch_one(t, &wallet_mbx, &w_read).await?;
    msg_ids.push(id);
    let mut wallet_session = wallet.on_confirm(now, &env).map_err(err)?;
    let ready = wallet_session
        .confirm_sas(&mut rng, now, None)
        .map_err(err)?
        .ok_or("wallet produced no session.ready")?;
    envelopes.push(ready.envelope.clone());
    msg_ids.push(post(t, &ready, 300).await?);

    let (id, env) = fetch_one(t, &dapp_mbx, &d_read).await?;
    msg_ids.push(id);
    dapp_session.open(now, &dapp_mbx, &env).map_err(err)?;
    dapp_session.confirm_sas(&mut rng, now, None).map_err(err)?;
    if !dapp_session.is_active() || !wallet_session.is_active() {
        return Err("session did not become active".to_owned());
    }
    notes.push("session active on both sides".to_owned());

    // --- permissions, carrying the wallet public key ----------------------
    let permissions = Permissions {
        methods: vec!["signCoinSpends".to_owned(), "getPublicKeys".to_owned()],
        keys: vec![BLS_PUBKEY.to_owned()],
        limits: Some(Limits {
            per_request_mojos: Some(AMOUNT_MOJOS.to_owned()),
            per_day_mojos: Some(AMOUNT_MOJOS.to_owned()),
        }),
    };
    let out = wallet_session
        .seal(&mut rng, now, Message::SessionPermissions(permissions), 600)
        .map_err(err)?;
    envelopes.push(out.envelope.clone());
    msg_ids.push(post(t, &out, 600).await?);
    let (id, env) = fetch_one(t, &dapp_mbx, &d_read).await?;
    msg_ids.push(id);
    dapp_session.open(now, &dapp_mbx, &env).map_err(err)?;

    // --- signing request and response -------------------------------------
    let request = Message::RpcRequest {
        method: "signCoinSpends".to_owned(),
        params: signing_params(),
    };
    let out = dapp_session
        .seal(&mut rng, now, request, 600)
        .map_err(err)?;
    let request_id = out.id;
    envelopes.push(out.envelope.clone());
    msg_ids.push(post(t, &out, 600).await?);

    let (id, env) = fetch_one(t, &wallet_mbx, &w_read).await?;
    msg_ids.push(id);
    let inner = wallet_session.open(now, &wallet_mbx, &env).map_err(err)?;
    match &inner.message {
        Message::RpcRequest { params, .. } if params.contains(PLAINTEXT_MARKER) => {}
        other => {
            return Err(format!(
                "wallet did not receive the planted request: {other:?}"
            ));
        }
    }
    let result = json!({
        "signature": BLS_PUBKEY,
        "signedBy": [BLS_PUBKEY],
        "address": CHIA_ADDRESS,
        "memo": PLAINTEXT_MARKER,
    })
    .to_string();
    let response = Message::RpcResponse {
        request_id,
        outcome: RpcOutcome::Result(result),
    };
    let out = wallet_session
        .seal(&mut rng, now, response, 600)
        .map_err(err)?;
    envelopes.push(out.envelope.clone());
    msg_ids.push(post(t, &out, 600).await?);
    let (id, env) = fetch_one(t, &dapp_mbx, &d_read).await?;
    msg_ids.push(id);
    let inner = dapp_session.open(now, &dapp_mbx, &env).map_err(err)?;
    match &inner.message {
        Message::RpcResponse {
            outcome: RpcOutcome::Result(r),
            ..
        } if r.contains(PLAINTEXT_MARKER) => {}
        other => return Err(format!("dApp did not receive the signature: {other:?}")),
    }
    notes.push("signCoinSpends request and response delivered end to end".to_owned());

    // One message is deliberately left queued and unacknowledged, so that a database
    // dump taken after the run still contains a stored envelope and its message id.
    let out = dapp_session
        .seal(&mut rng, now, Message::SessionPing, 3600)
        .map_err(err)?;
    envelopes.push(out.envelope.clone());
    msg_ids.push(post(t, &out, 3600).await?);
    notes.push("left one envelope queued for the database dump".to_owned());

    // --- push re-registration ---------------------------------------------
    let resealed = seal_device_token(&p.gateway_pk, now, 0x7b)?;
    let path = format!("/v1/mailboxes/{}/push", wallet_mbx.to_b64());
    let body = json!({ "push_reg": push_reg(&p.gateway_url, &resealed) });
    expect(t, Call::new("PUT", &path).token(&w_read).body(body), 204).await?;
    secrets.opaque_bytes(
        Class::SealedPushToken,
        "re-registered device token",
        &resealed,
    );

    // --- error paths: they log and count, so they are scanned too ----------
    let msgs = format!("/v1/mailboxes/{}/messages", wallet_mbx.to_b64());
    let unknown = format!("/v1/mailboxes/{}/messages", "A".repeat(22));
    let truncated = envelopes
        .last()
        .and_then(|e| e.get(..20))
        .map(b64::encode)
        .unwrap_or_default();
    let cases: Vec<(Call<'_>, u16)> = vec![
        (Call::new("GET", &msgs).token(&p_read), 404),
        (Call::new("GET", &unknown).token(&w_read), 404),
        (
            Call::new("GET", "/v1/mailboxes/not-an-id/messages").token(&w_read),
            404,
        ),
        (
            Call::new("POST", &msgs)
                .token(&w_write)
                .body(json!({ "env": "!!" })),
            400,
        ),
        (
            Call::new("POST", &msgs)
                .token(&w_write)
                .body(json!({ "env": truncated })),
            400,
        ),
        (
            Call::new("POST", "/v1/mailboxes")
                .api_key("not-the-real-key-0123456789")
                .body(json!({
                    "read_token_hash": b64::encode(&p_read.hash()),
                    "write_token_hash": b64::encode(&p_write.hash()),
                })),
            403,
        ),
        (
            Call::new("POST", "/v1/mailboxes")
                .body(json!({ "read_token_hash": "AA", "write_token_hash": "BB" })),
            400,
        ),
    ];
    for (call, want) in cases {
        expect(t, call, want).await?;
    }
    notes.push("error paths exercised".to_owned());

    // Health and aggregate endpoints, which an operator scrapes.
    expect(t, Call::new("GET", "/healthz"), 200).await?;
    expect(t, Call::new("GET", "/readyz"), 200).await?;
    expect(t, Call::new("GET", "/v1/info"), 200).await?;

    for (i, env) in envelopes.iter().enumerate() {
        secrets.opaque_bytes(Class::Ciphertext, &format!("envelope {i}"), env);
    }
    for (i, id) in msg_ids.iter().enumerate() {
        if let Ok(raw) = b64::decode(id) {
            secrets.bytes(Class::MsgId, &format!("message id {i}"), &raw);
        }
    }

    Ok(Outcome {
        secrets,
        notes,
        mailboxes: [pairing_mbx, wallet_mbx, dapp_mbx]
            .iter()
            .map(MailboxId::to_b64)
            .collect(),
        sealed_tokens: vec![sealed, resealed],
        expected_wakes: 1,
    })
}

/// Field names of a relay-to-gateway wake-up body, sorted.
///
/// The body must be exactly `{"sealed_token": "<base64url>"}` (spec 7.3): anything else
/// is something extra travelling from the relay to a vendor gateway.
pub fn wake_body_fields(body: &str) -> Res<Vec<String>> {
    let parsed: Value = serde_json::from_str(body).map_err(|e| format!("wake body: {e}"))?;
    let object = parsed
        .as_object()
        .ok_or_else(|| "wake body is not a JSON object".to_owned())?;
    let mut keys: Vec<String> = object.keys().cloned().collect();
    keys.sort();
    Ok(keys)
}

/// Open a sealed push token with the gateway key and return its CBOR map keys.
///
/// The sealed token is the only thing the relay forwards to a vendor gateway, so its
/// shape is a privacy interface: a new field would be new data about the user leaving
/// the relay. The check pins the key set rather than a struct definition.
pub fn sealed_token_fields(
    gateway_sk: &xchonnect_core::crypto::X25519Secret,
    sealed: &[u8],
) -> Res<Vec<String>> {
    use xchonnect_core::cbor::{self, Value as Cbor};
    use xchonnect_core::crypto::HpkeReceiver;
    let (enc, ct) = sealed
        .split_at_checked(32)
        .ok_or("sealed token too short")?;
    let enc: [u8; 32] = enc.try_into().map_err(err)?;
    let mut ctx =
        HpkeReceiver::setup(gateway_sk, &enc, xchonnect_core::push::INFO, None).map_err(err)?;
    let plaintext = ctx.open(b"", ct).map_err(err)?;
    let Cbor::Map(entries) = cbor::decode(&plaintext).map_err(err)? else {
        return Err("sealed token plaintext is not a CBOR map".to_owned());
    };
    let mut keys: Vec<String> = entries
        .iter()
        .map(|(k, _)| match k {
            Cbor::Text(t) => t.clone(),
            other => format!("{other:?}"),
        })
        .collect();
    keys.sort();
    Ok(keys)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn planted_values_have_the_shapes_the_detectors_look_for() {
        assert_eq!(DEVICE_TOKEN.len(), 64);
        assert_eq!(BLS_PUBKEY.len(), 96);
        assert!(BLS_PUBKEY.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(DEVICE_TOKEN.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(CHIA_ADDRESS.starts_with("xch1") && CHIA_ADDRESS.len() > 24);
        assert!(API_KEY.len() >= 16, "the relay rejects shorter keys");
        let mut s = crate::scan::Surface::new("probe");
        s.line(format!(
            "{CLIENT_IP} {CHIA_ADDRESS} {BLS_PUBKEY} {USER_AGENT}"
        ));
        let hits = crate::scan::scan_patterns(&s, &[]);
        let found: Vec<&str> = hits.iter().map(|h| h.pattern.id()).collect();
        for want in [
            "ipv4_literal",
            "chia_address_shape",
            "hex_key_shape",
            "user_agent_shape",
        ] {
            assert!(found.contains(&want), "{want} not in {found:?}");
        }
    }
}
