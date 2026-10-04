//! The checks. Each one creates its own mailboxes so checks are independent and can be
//! run individually with `--only`.

use super::client::{Req, Resp};
use super::ctx::{
    CheckRes, Ctx, Fail, Mailbox, Method, accepted_id, created_id, ensure, error_code,
    expect_error, parse_messages, random_b64, skip, tokens,
};
use super::envelope::{self, Item};
use super::{CheckInfo, Tier};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use xchonnect_core::b64;
use xchonnect_core::envelope::{BUCKETS, Kind};

pub(crate) struct Check {
    pub(crate) info: CheckInfo,
    pub(crate) run: fn(&Ctx) -> CheckRes,
}

const fn check(
    id: &'static str,
    title: &'static str,
    spec: &'static str,
    tier: Tier,
    run: fn(&Ctx) -> CheckRes,
) -> Check {
    Check {
        info: CheckInfo {
            id,
            title,
            spec,
            tier,
        },
        run,
    }
}

use Tier::{Aggressive, Default as D, Slow};

pub(crate) const CHECKS: &[Check] = &[
    check(
        "R-INFO-01",
        "GET /v1/info returns protocol 1 with well-formed limits",
        "relay-api.md §GET /v1/info",
        D,
        info_shape,
    ),
    check(
        "R-INFO-02",
        "/v1/info publishes gateway allowlist and pow difficulty when applicable",
        "relay-api.md §GET /v1/info; spec 7.3.1 rule 6",
        D,
        info_conditional,
    ),
    check(
        "R-CREATE-01",
        "mailbox creation with an advertised method returns 201 and a 16-byte mailbox_id",
        "relay-api.md §POST /v1/mailboxes",
        D,
        create_basic,
    ),
    check(
        "R-CREATE-02",
        "unknown request fields are ignored",
        "relay-api.md §Conventions",
        D,
        create_unknown_fields,
    ),
    check(
        "R-CREATE-03",
        "malformed creation requests are rejected with 400 bad_request",
        "relay-api.md §Errors",
        D,
        create_malformed,
    ),
    check(
        "R-CREATE-04",
        "creation without proof is rejected with 403 auth_required unless open",
        "relay-api.md §Errors; spec 7.4",
        D,
        create_auth_required,
    ),
    check(
        "R-POW-01",
        "proof-of-work challenge is well-formed and a solution creates a mailbox",
        "spec 7.4; relay-api.md §POST /v1/challenge",
        D,
        pow_flow,
    ),
    check(
        "R-POW-02",
        "spent, wrong or tampered proofs are rejected with 403 pow_invalid",
        "spec 7.4",
        D,
        pow_invalid,
    ),
    check(
        "R-TICKET-01",
        "sponsorship tickets are issued with an API key and are single-use",
        "spec 7.5; relay-api.md §POST /v1/tickets",
        D,
        ticket_flow,
    ),
    check(
        "R-TICKET-02",
        "ticket issuance without a valid API key is refused with 403",
        "spec 7.5; relay-api.md §Errors",
        D,
        ticket_needs_key,
    ),
    check(
        "R-APIKEY-01",
        "unknown API keys are rejected with 403 api_key_invalid",
        "relay-api.md §Errors",
        D,
        api_key_invalid,
    ),
    check(
        "R-AUTH-01",
        "read and write tokens are not interchangeable",
        "relay-api.md §Identifiers",
        D,
        auth_not_interchangeable,
    ),
    check(
        "R-AUTH-02",
        "the relay hashes presented tokens (token accepted, its hash is not)",
        "relay-api.md §Identifiers and hashes",
        D,
        auth_hashes,
    ),
    check(
        "R-AUTH-03",
        "creation with equal read and write hashes is rejected with 400",
        "relay-api.md §Identifiers and hashes",
        D,
        auth_equal_hashes,
    ),
    check(
        "R-NF-01",
        "not_found is byte-identical for unknown mailbox, wrong token, malformed id, missing auth and deleted mailbox",
        "relay-api.md §Errors; spec 7.2",
        D,
        not_found_identical,
    ),
    check(
        "R-MSG-01",
        "posted envelopes are returned byte-identical and stay until acknowledged",
        "relay-api.md §POST/GET messages",
        D,
        msg_roundtrip,
    ),
    check(
        "R-MSG-02",
        "messages are returned in acceptance order",
        "relay-api.md §GET messages",
        D,
        msg_order,
    ),
    check(
        "R-MSG-03",
        "fetch returns at most 32 messages and honours limit",
        "relay-api.md §GET messages",
        D,
        msg_fetch_limit,
    ),
    check(
        "R-MSG-04",
        "ack deletes messages, ignores unknown ids and caps at 256 ids",
        "relay-api.md §POST ack; spec 7.1",
        D,
        msg_ack,
    ),
    check(
        "R-MSG-05",
        "ttl_s is clamped to [60, max_ttl_s] rather than rejected",
        "relay-api.md §POST messages",
        D,
        msg_ttl_clamp,
    ),
    check(
        "R-MSG-06",
        "messages expire after ttl_s",
        "spec 7.1; relay-api.md §Retention",
        Slow,
        msg_ttl_expiry,
    ),
    check(
        "R-ENV-01",
        "envelopes that are not valid CBOR are rejected with 400",
        "relay-api.md §POST messages",
        D,
        env_bad_cbor,
    ),
    check(
        "R-ENV-02",
        "non-canonical CBOR envelopes are rejected with 400",
        "relay-api.md §POST messages; spec 5.4",
        D,
        env_non_canonical,
    ),
    check(
        "R-ENV-03",
        "wrong nonce or ciphertext lengths are rejected with 400",
        "relay-api.md §POST messages",
        D,
        env_lengths,
    ),
    check(
        "R-ENV-04",
        "envelopes with extra or missing keys are rejected with 400",
        "relay-api.md §POST messages; envelope.cddl",
        D,
        env_keys,
    ),
    check(
        "R-ENV-05",
        "wrong version or kind is rejected with 400",
        "relay-api.md §POST messages",
        D,
        env_version_kind,
    ),
    check(
        "R-ENV-06",
        "every bucket size and pairing envelopes are accepted",
        "relay-api.md §POST messages; spec 5.3",
        D,
        env_valid_sizes,
    ),
    check(
        "R-ENV-07",
        "envelopes above max_envelope_bytes are rejected",
        "relay-api.md §POST messages",
        D,
        env_too_big,
    ),
    check(
        "R-ENV-08",
        "env that is not base64url, or a missing env, is rejected with 400",
        "relay-api.md §Conventions",
        D,
        env_encoding,
    ),
    check(
        "R-SIZE-01",
        "request bodies above 400 KiB get 413 too_large",
        "relay-api.md §Conventions",
        D,
        size_limit,
    ),
    check(
        "R-QUOTA-01",
        "a full mailbox answers 409 mailbox_full until messages are acknowledged",
        "relay-api.md §Errors",
        D,
        quota_full,
    ),
    check(
        "R-POLL-01",
        "a long-poll returns early when a message arrives",
        "relay-api.md §GET messages",
        D,
        poll_early,
    ),
    check(
        "R-POLL-02",
        "a long-poll on an empty mailbox returns an empty list after the wait",
        "relay-api.md §GET messages",
        D,
        poll_timeout,
    ),
    check(
        "R-POLL-03",
        "wait is clamped to max_wait_s",
        "relay-api.md §GET messages",
        Slow,
        poll_clamp,
    ),
    check(
        "R-RATE-01",
        "rate limiting answers 429 rate_limited with Retry-After",
        "relay-api.md §Errors; spec 7.1",
        Aggressive,
        rate_limit,
    ),
    check(
        "R-PUSH-01",
        "push registration requires https, port 443, no userinfo, at most 512 bytes",
        "spec 7.3.1 rules 1 and 7",
        D,
        push_url_rules,
    ),
    check(
        "R-PUSH-02",
        "allowlist mode rejects private, loopback, metadata and unlisted gateways at registration",
        "spec 7.3.1 rules 6 and 7",
        D,
        push_allowlist,
    ),
    check(
        "R-PUSH-03",
        "an accepted gateway can be registered, replaced and removed",
        "relay-api.md §PUT push; spec 7.3",
        D,
        push_set_remove,
    ),
    check(
        "R-DEL-01",
        "DELETE removes the mailbox and its messages and needs the read token",
        "relay-api.md §DELETE; spec 7.1",
        D,
        delete_semantics,
    ),
    check(
        "R-ERR-01",
        "error bodies are exactly {\"error\": code} with application/json",
        "relay-api.md §Errors",
        D,
        error_shape,
    ),
    check(
        "R-CORS-01",
        "CORS preflight allows Authorization and Content-Type without credentials",
        "browser interop, cf. spec 10.2; not yet normative for relays",
        D,
        cors_preflight,
    ),
    check(
        "R-CORS-02",
        "responses carry Access-Control-Allow-Origin without credentials",
        "browser interop, cf. spec 10.2; not yet normative for relays",
        D,
        cors_response,
    ),
    check(
        "R-HTTP-01",
        "responses carry Cache-Control: no-store",
        "hardening, cf. spec 13.5; not yet normative",
        D,
        cache_control,
    ),
    check(
        "R-HTTP-02",
        "the relay never sets cookies",
        "relay-api.md §Conventions",
        D,
        no_cookies,
    ),
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn get_info(ctx: &Ctx) -> Result<Resp, Fail> {
    ctx.call(&Req::new("GET", "/v1/info"))
}

fn ids_of(msgs: &[(String, String)]) -> Vec<String> {
    msgs.iter().map(|(i, _)| i.clone()).collect()
}

fn post_body(env: &[u8]) -> Value {
    json!({ "env": b64::encode(env) })
}

fn post_raw_env(ctx: &Ctx, mb: &Mailbox, env: &[u8]) -> Result<Resp, Fail> {
    ctx.post(mb, env, None)
}

/// Every envelope in `cases` must be rejected with `400 bad_request`; nothing may be stored.
fn expect_rejected_envs(ctx: &Ctx, cases: &[(&str, Vec<u8>)]) -> CheckRes {
    let mb = ctx.mailbox()?;
    for (what, env) in cases {
        let r = post_raw_env(ctx, &mb, env)?;
        expect_error(&r, 400, "bad_request", what)?;
    }
    let left = ctx.fetch(&mb, "")?;
    ensure!(
        left.is_empty(),
        "{} rejected envelope(s) were stored",
        left.len()
    );
    Ok(None)
}

fn sealed_token() -> String {
    random_b64::<64>()
}

fn push_body(url: &str) -> Value {
    json!({ "push_reg": { "gateway_url": url, "sealed_token": sealed_token() } })
}

fn put_push(ctx: &Ctx, mb: &Mailbox, body: &Value) -> Result<Resp, Fail> {
    ctx.call(
        &Req::new("PUT", mb.path("/push"))
            .bearer(mb.read.expose())
            .json(body),
    )
}

/// A URL the relay accepts at registration, if one can be derived from `/v1/info`.
fn accepted_gateway(ctx: &Ctx) -> Option<String> {
    match ctx.gateway_allowlist() {
        None => Some("https://push.example.com/v1/wake".to_owned()),
        Some(list) => list.first().map(|p| {
            if p.ends_with('/') {
                format!("{p}v1/wake")
            } else {
                p.clone()
            }
        }),
    }
}

/// Both registration paths (PUT push and creation) must reject `url` with
/// `403 gateway_not_allowed`.
fn expect_gateway_rejected(ctx: &Ctx, mb: &Mailbox, url: &str) -> Result<(), Fail> {
    let r = put_push(ctx, mb, &push_body(url))?;
    expect_error(&r, 403, "gateway_not_allowed", &format!("PUT push {url}"))?;
    let (r, _, _) = ctx.create_raw(&push_body(url), ctx.default_method()?)?;
    expect_error(
        &r,
        403,
        "gateway_not_allowed",
        &format!("creation with push_reg {url}"),
    )
}

// ---------------------------------------------------------------------------
// /v1/info
// ---------------------------------------------------------------------------

fn info_shape(ctx: &Ctx) -> CheckRes {
    let r = get_info(ctx)?;
    ensure!(
        r.status == 200,
        "GET /v1/info: expected 200, got {}",
        r.describe()
    );
    ensure!(
        r.header("content-type")
            .is_some_and(|c| c.starts_with("application/json")),
        "content-type is {:?}, expected application/json",
        r.header("content-type")
    );
    let v = r.json();
    ensure!(
        v.is_object(),
        "body is not a JSON object: {}",
        r.body_text()
    );
    ensure!(
        v.get("protocol").and_then(Value::as_u64) == Some(1),
        "protocol must be 1, got {:?}",
        v.get("protocol")
    );
    let num = |k: &str| v.get(k).and_then(Value::as_u64);
    for k in [
        "max_wait_s",
        "max_wait_ohttp_s",
        "default_ttl_s",
        "max_ttl_s",
        "max_envelope_bytes",
        "max_messages_per_mailbox",
    ] {
        ensure!(
            num(k).is_some(),
            "{k} missing or not a non-negative integer"
        );
    }
    let (def, max) = (
        num("default_ttl_s").unwrap_or(0),
        num("max_ttl_s").unwrap_or(0),
    );
    ensure!(
        (60..=604_800).contains(&max),
        "max_ttl_s {max} outside [60, 604800] (spec 7.1: max 7 days)"
    );
    ensure!(
        (60..=max).contains(&def),
        "default_ttl_s {def} outside [60, max_ttl_s]"
    );
    ensure!(
        num("max_wait_ohttp_s") <= num("max_wait_s"),
        "max_wait_ohttp_s exceeds max_wait_s"
    );
    ensure!(
        num("max_messages_per_mailbox").unwrap_or(0) > 0,
        "max_messages_per_mailbox is 0"
    );
    let methods = v.get("mailbox_creation").and_then(Value::as_array);
    ensure!(
        methods.is_some_and(|m| !m.is_empty()),
        "mailbox_creation must be a non-empty array"
    );
    for m in methods.into_iter().flatten() {
        ensure!(
            matches!(m.as_str(), Some("api_key" | "ticket" | "pow" | "open")),
            "unknown mailbox_creation method {m}"
        );
    }
    ensure!(
        matches!(
            v.get("gateway_policy").and_then(Value::as_str),
            Some("allowlist" | "open")
        ),
        "gateway_policy must be \"allowlist\" or \"open\", got {:?}",
        v.get("gateway_policy")
    );
    ensure!(
        v.get("ohttp").is_some_and(Value::is_boolean),
        "ohttp must be a boolean"
    );
    Ok(None)
}

fn info_conditional(ctx: &Ctx) -> CheckRes {
    let v = &ctx.info;
    if v.get("gateway_policy").and_then(Value::as_str) == Some("allowlist") {
        let list = v.get("gateway_allowlist").and_then(Value::as_array);
        ensure!(
            list.is_some(),
            "gateway_policy is allowlist but gateway_allowlist is missing"
        );
        for p in list.into_iter().flatten() {
            ensure!(p.is_string(), "gateway_allowlist entry {p} is not a string");
        }
    }
    if ctx.offers("pow") {
        ensure!(
            ctx.info_u64("pow_difficulty").is_some_and(|d| d <= 255),
            "pow is offered but pow_difficulty is missing or invalid"
        );
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Mailbox creation
// ---------------------------------------------------------------------------

fn create_basic(ctx: &Ctx) -> CheckRes {
    let method = ctx.default_method()?;
    let a = ctx.mailbox()?;
    let b = ctx.mailbox()?;
    ensure!(a.id != b.id, "two creations returned the same mailbox_id");
    let msgs = ctx.fetch(&a, "")?;
    ensure!(msgs.is_empty(), "a new mailbox is not empty");
    Ok(Some(format!("created via {method:?}")))
}

fn create_unknown_fields(ctx: &Ctx) -> CheckRes {
    let extra = json!({ "x_conformance_unknown": 1, "another_field": { "nested": [true] } });
    ctx.mailbox_with(&extra, ctx.default_method()?)?;
    Ok(None)
}

fn create_malformed(ctx: &Ctx) -> CheckRes {
    let method = ctx.default_method()?;
    let r = ctx.send(&Req::new("POST", "/v1/mailboxes").raw_json(b"{not json".to_vec()))?;
    expect_error(&r, 400, "bad_request", "malformed JSON")?;
    let (read, write) = tokens();
    let cases: Vec<(&str, Value)> = vec![
        (
            "31-byte read_token_hash",
            json!({ "read_token_hash": random_b64::<31>(), "write_token_hash": b64::encode(&write.hash()) }),
        ),
        (
            "33-byte write_token_hash",
            json!({ "read_token_hash": b64::encode(&read.hash()), "write_token_hash": random_b64::<33>() }),
        ),
        (
            "non-base64url hash",
            json!({ "read_token_hash": "!!not base64!!", "write_token_hash": b64::encode(&write.hash()) }),
        ),
        (
            "missing write_token_hash",
            json!({ "read_token_hash": b64::encode(&read.hash()) }),
        ),
        (
            "numeric hash",
            json!({ "read_token_hash": 5, "write_token_hash": b64::encode(&write.hash()) }),
        ),
    ];
    for (what, body) in cases {
        let map = body.as_object().cloned().unwrap_or_default();
        let r = ctx.create_raw_with(&|| ctx.creation_req(map.clone(), method))?;
        expect_error(&r, 400, "bad_request", what)?;
    }
    Ok(None)
}

fn create_auth_required(ctx: &Ctx) -> CheckRes {
    if ctx.offers("open") {
        skip!("relay offers open creation");
    }
    let (r, _, _) = ctx.create_raw(&Value::Null, Method::Open)?;
    expect_error(&r, 403, "auth_required", "creation without proof")?;
    Ok(None)
}

// ---------------------------------------------------------------------------
// Proof-of-work, tickets, API keys
// ---------------------------------------------------------------------------

fn pow_flow(ctx: &Ctx) -> CheckRes {
    if !ctx.offers("pow") {
        skip!("relay does not offer pow");
    }
    if !ctx.pow_usable() {
        skip!("pow_difficulty above 26: clients refuse to solve it (spec 7.4)");
    }
    let r = ctx.call(&Req::new("POST", "/v1/challenge").raw_json(b"{}".to_vec()))?;
    ensure!(
        r.status == 200,
        "POST /v1/challenge: expected 200, got {}",
        r.describe()
    );
    let v = r.json();
    let ch = v
        .get("challenge")
        .and_then(Value::as_str)
        .and_then(|c| b64::decode(c).ok())
        .ok_or_else(|| Fail::Fail("challenge missing or not base64url".into()))?;
    ensure!(
        ch.len() == 42,
        "challenge is {} bytes, expected 42",
        ch.len()
    );
    let parsed = xchonnect_core::pow::parse(&ch)
        .map_err(|e| Fail::Fail(format!("challenge does not parse: {e:?}")))?;
    let difficulty = v.get("difficulty").and_then(Value::as_u64);
    ensure!(
        difficulty == Some(u64::from(parsed.difficulty)),
        "difficulty field {difficulty:?} != embedded {}",
        parsed.difficulty
    );
    ensure!(
        difficulty == ctx.info_u64("pow_difficulty"),
        "challenge difficulty {difficulty:?} != /v1/info pow_difficulty {:?}",
        ctx.info_u64("pow_difficulty")
    );
    let expires = v.get("expires_at").and_then(Value::as_u64);
    ensure!(
        expires == Some(parsed.expires_at),
        "expires_at field {expires:?} != embedded {}",
        parsed.expires_at
    );
    // 120 s validity; tolerate 60 s of clock difference between suite and relay.
    ensure!(
        parsed.expires_at <= now() + 180,
        "expires_at is {} s ahead (max 120)",
        parsed.expires_at.saturating_sub(now())
    );
    ctx.mailbox_with(&Value::Null, Method::Pow)?;
    Ok(None)
}

fn pow_invalid(ctx: &Ctx) -> CheckRes {
    if !ctx.pow_usable() {
        skip!("relay does not offer pow with difficulty <= 26");
    }
    // Spent challenge.
    let proof = ctx.solve_pow()?;
    let (read, write) = tokens();
    let body = Ctx::hashes_body(&read, &write, &json!({ "pow": proof }));
    let req = Req::new("POST", "/v1/mailboxes").json(&Value::Object(body.clone()));
    created_id(&ctx.send(&req)?)?;
    let (read2, write2) = tokens();
    let reuse = Ctx::hashes_body(&read2, &write2, &json!({ "pow": proof }));
    let r = ctx.send(&Req::new("POST", "/v1/mailboxes").json(&Value::Object(reuse)))?;
    expect_error(&r, 403, "pow_invalid", "reused challenge")?;

    // Wrong nonce: the first nonce whose hash misses the target.
    let r = ctx.call(&Req::new("POST", "/v1/challenge").raw_json(b"{}".to_vec()))?;
    let ch = r
        .json()
        .get("challenge")
        .and_then(Value::as_str)
        .and_then(|c| b64::decode(c).ok())
        .ok_or_else(|| Fail::Fail(format!("POST /v1/challenge: {}", r.describe())))?;
    let difficulty = xchonnect_core::pow::parse(&ch)
        .map(|i| i.difficulty)
        .unwrap_or(0);
    if difficulty > 0 {
        let bad = (0u64..)
            .map(u64::to_be_bytes)
            .find(|n| {
                let h = xchonnect_core::crypto::sha256_parts(&[b"xchonnect v1 pow", &ch, n]);
                leading_zero_bits(&h) < u32::from(difficulty)
            })
            .unwrap_or([0; 8]);
        let body = Ctx::hashes_body(
            &read2,
            &write2,
            &json!({ "pow": { "challenge": b64::encode(&ch), "nonce": b64::encode(&bad) } }),
        );
        let r = ctx.send(&Req::new("POST", "/v1/mailboxes").json(&Value::Object(body)))?;
        expect_error(&r, 403, "pow_invalid", "nonce that misses the difficulty")?;
    }

    // Tampered MAC with a valid solution for the tampered bytes.
    let mut ch2 = b64::decode(
        ctx.solve_pow()?
            .get("challenge")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
    .unwrap_or_default();
    if let Some(last) = ch2.last_mut() {
        *last ^= 0x01;
    }
    let nonce =
        xchonnect_core::pow::solve(&ch2).map_err(|e| Fail::Fail(format!("solve: {e:?}")))?;
    let body = Ctx::hashes_body(
        &read2,
        &write2,
        &json!({ "pow": { "challenge": b64::encode(&ch2), "nonce": b64::encode(&nonce) } }),
    );
    let r = ctx.send(&Req::new("POST", "/v1/mailboxes").json(&Value::Object(body)))?;
    expect_error(&r, 403, "pow_invalid", "challenge with tampered MAC")?;
    Ok(None)
}

fn leading_zero_bits(h: &[u8]) -> u32 {
    let mut n = 0;
    for b in h {
        if *b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

fn ticket_flow(ctx: &Ctx) -> CheckRes {
    if !ctx.offers("ticket") {
        skip!("relay does not offer tickets");
    }
    let Some(key) = ctx.api_key.as_deref() else {
        skip!("needs --api-key");
    };
    let r = ctx.call(
        &Req::new("POST", "/v1/tickets")
            .header("xchonnect-api-key", key)
            .raw_json(b"{}".to_vec()),
    )?;
    ensure!(
        r.status == 200,
        "POST /v1/tickets: expected 200, got {}",
        r.describe()
    );
    let v = r.json();
    let ticket = v
        .get("ticket")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    ensure!(
        b64::decode(&ticket).is_ok_and(|t| t.len() == 32),
        "ticket is not base64url of 32 bytes"
    );
    let exp = v.get("expires_at").and_then(Value::as_u64).unwrap_or(0);
    ensure!(
        exp <= now() + 660,
        "ticket valid for {} s (max 600)",
        exp.saturating_sub(now())
    );
    let with_ticket = json!({ "ticket": ticket });
    ctx.mailbox_with(&with_ticket, Method::Open)?;
    let (r, _, _) = ctx.create_raw(&with_ticket, Method::Open)?;
    expect_error(&r, 403, "ticket_invalid", "reused ticket")?;
    let (r, _, _) = ctx.create_raw(&json!({ "ticket": random_b64::<32>() }), Method::Open)?;
    expect_error(&r, 403, "ticket_invalid", "unknown ticket")?;
    Ok(None)
}

fn ticket_needs_key(ctx: &Ctx) -> CheckRes {
    if !ctx.offers("ticket") {
        skip!("relay does not offer tickets");
    }
    let r = ctx.call(&Req::new("POST", "/v1/tickets").raw_json(b"{}".to_vec()))?;
    ensure!(
        r.status == 403
            && matches!(
                error_code(&r).as_deref(),
                Some("api_key_invalid" | "auth_required")
            ),
        "POST /v1/tickets without key: expected 403 api_key_invalid or auth_required, got {}",
        r.describe()
    );
    let r = ctx.call(
        &Req::new("POST", "/v1/tickets")
            .header("xchonnect-api-key", "xchonnect-conformance-bogus-key")
            .raw_json(b"{}".to_vec()),
    )?;
    expect_error(
        &r,
        403,
        "api_key_invalid",
        "POST /v1/tickets with unknown key",
    )?;
    Ok(None)
}

fn api_key_invalid(ctx: &Ctx) -> CheckRes {
    if !ctx.offers("api_key") {
        skip!("relay does not offer api_key creation");
    }
    let (read, write) = tokens();
    let r = ctx.call(
        &Req::new("POST", "/v1/mailboxes")
            .header("xchonnect-api-key", "xchonnect-conformance-bogus-key")
            .json(&Value::Object(Ctx::hashes_body(
                &read,
                &write,
                &Value::Null,
            ))),
    )?;
    expect_error(&r, 403, "api_key_invalid", "creation with unknown API key")?;
    if ctx.api_key.is_some() {
        ctx.mailbox_with(&Value::Null, Method::ApiKey)?;
        Ok(None)
    } else {
        Ok(Some("valid-key creation not tested (no --api-key)".into()))
    }
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

fn auth_not_interchangeable(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let env = envelope::session_nth(1);
    let r = ctx.call(
        &Req::new("POST", mb.path("/messages"))
            .bearer(mb.read.expose())
            .json(&post_body(&env)),
    )?;
    expect_error(&r, 404, "not_found", "posting with the read token")?;
    let r = ctx.call(&Req::new("GET", mb.path("/messages")).bearer(mb.write.expose()))?;
    expect_error(&r, 404, "not_found", "fetching with the write token")?;
    let r = ctx.call(
        &Req::new("POST", mb.path("/ack"))
            .bearer(mb.write.expose())
            .json(&json!({ "msg_ids": [] })),
    )?;
    expect_error(&r, 404, "not_found", "ack with the write token")?;
    let r = ctx.call(
        &Req::new("PUT", mb.path("/push"))
            .bearer(mb.write.expose())
            .json(&json!({ "push_reg": null })),
    )?;
    expect_error(&r, 404, "not_found", "PUT push with the write token")?;
    ctx.post_ok(&mb, &env)?;
    ensure!(
        ctx.fetch(&mb, "")?.len() == 1,
        "the message posted with the write token is missing"
    );
    Ok(None)
}

fn auth_hashes(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let r = ctx.call(&Req::new("GET", mb.path("/messages")).bearer(&mb.read.hash()))?;
    expect_error(
        &r,
        404,
        "not_found",
        "presenting the read token hash as bearer",
    )?;
    let r = ctx.call(
        &Req::new("POST", mb.path("/messages"))
            .bearer(&mb.write.hash())
            .json(&post_body(&envelope::session_nth(1))),
    )?;
    expect_error(
        &r,
        404,
        "not_found",
        "presenting the write token hash as bearer",
    )?;
    ctx.fetch(&mb, "")?;
    Ok(None)
}

fn auth_equal_hashes(ctx: &Ctx) -> CheckRes {
    let method = ctx.default_method()?;
    let (read, _) = tokens();
    let r = ctx.create_raw_with(&|| {
        ctx.creation_req(Ctx::hashes_body(&read, &read, &Value::Null), method)
    })?;
    expect_error(&r, 400, "bad_request", "equal read and write hashes")?;
    Ok(None)
}

// ---------------------------------------------------------------------------
// Byte-identical not_found
// ---------------------------------------------------------------------------

fn not_found_identical(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let gone = ctx.mailbox()?;
    let r = ctx.call(&Req::new("DELETE", gone.path("")).bearer(gone.read.expose()))?;
    ensure!(
        r.status == 204,
        "DELETE: expected 204, got {}",
        r.describe()
    );

    let random_token = || format!("Bearer {}", random_b64::<32>());
    let read_auth = |m: &Mailbox| format!("Bearer {}", b64::encode(m.read.expose()));
    let write_auth = |m: &Mailbox| format!("Bearer {}", b64::encode(m.write.expose()));

    let post_env = post_body(&envelope::session_nth(7));
    // (method, suffix, uses write token, body)
    let endpoints: [(&'static str, &str, bool, Option<Value>); 5] = [
        ("GET", "/messages", false, None),
        ("POST", "/messages", true, Some(post_env)),
        ("POST", "/ack", false, Some(json!({ "msg_ids": [] }))),
        ("PUT", "/push", false, Some(json!({ "push_reg": null }))),
        ("DELETE", "", false, None),
    ];
    let mut compared = 0;
    for (method, suffix, write, body) in &endpoints {
        let other = if *write {
            read_auth(&mb)
        } else {
            write_auth(&mb)
        };
        let own_gone = if *write {
            write_auth(&gone)
        } else {
            read_auth(&gone)
        };
        let variants: Vec<(&str, String, Option<String>)> = vec![
            (
                "unknown mailbox",
                format!("/v1/mailboxes/{}{suffix}", random_b64::<16>()),
                Some(random_token()),
            ),
            ("wrong token", mb.path(suffix), Some(random_token())),
            ("other capability's token", mb.path(suffix), Some(other)),
            (
                "malformed mailbox id",
                format!("/v1/mailboxes/not-a-mailbox-id{suffix}"),
                Some(random_token()),
            ),
            ("missing Authorization", mb.path(suffix), None),
            (
                "malformed Authorization",
                mb.path(suffix),
                Some("Bearer not*base64url".to_owned()),
            ),
            ("deleted mailbox", gone.path(suffix), Some(own_gone)),
        ];
        let mut first: Option<(&str, Resp)> = None;
        for (what, path, auth) in variants {
            let mut req = Req::new(method, path);
            if let Some(a) = auth {
                req = req.header("authorization", a);
            }
            if let Some(b) = body {
                req = req.json(b);
            }
            let r = ctx.call(&req)?;
            expect_error(&r, 404, "not_found", &format!("{method} {suffix} ({what})"))?;
            match &first {
                None => first = Some((what, r)),
                Some((w0, r0)) => {
                    ensure!(
                        r.body == r0.body,
                        "{method} {suffix}: body differs between {w0} and {what}"
                    );
                    ensure!(
                        r.comparable_headers() == r0.comparable_headers(),
                        "{method} {suffix}: headers differ between {w0} ({:?}) and {what} ({:?})",
                        r0.comparable_headers(),
                        r.comparable_headers()
                    );
                    compared += 1;
                }
            }
        }
    }
    // The real mailbox must be unaffected by all of the above.
    ctx.fetch(&mb, "")?;
    Ok(Some(format!("{compared} response pairs compared")))
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

fn msg_roundtrip(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let env = envelope::session_nth(42);
    let id = ctx.post_ok(&mb, &env)?;
    for round in ["first", "second"] {
        let msgs = ctx.fetch(&mb, "")?;
        ensure!(
            msgs.len() == 1,
            "{round} fetch returned {} messages, expected 1",
            msgs.len()
        );
        let (mid, menv) = msgs.first().cloned().unwrap_or_default();
        ensure!(
            mid == id,
            "{round} fetch: msg_id differs from the one returned by POST"
        );
        ensure!(
            b64::decode(&menv).is_ok_and(|e| e == env),
            "{round} fetch: envelope is not byte-identical"
        );
    }
    Ok(None)
}

fn msg_order(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let mut ids = Vec::new();
    for i in 0..6 {
        ids.push(ctx.post_nth(&mb, i)?);
    }
    let msgs = ctx.fetch(&mb, "")?;
    ensure!(
        ids_of(&msgs) == ids,
        "fetch order differs from acceptance order"
    );
    for (i, (_, env)) in msgs.iter().enumerate() {
        ensure!(
            b64::decode(env).is_ok_and(|e| e == envelope::session_nth(i)),
            "message {i}: envelope does not match"
        );
    }
    // Order is kept after acknowledging from the middle.
    ctx.ack_ok(&mb, ids.get(2..4).unwrap_or_default())?;
    let rest = ctx.fetch(&mb, "")?;
    let expected: Vec<String> = ids
        .iter()
        .enumerate()
        .filter(|(i, _)| !(2..4).contains(i))
        .map(|(_, id)| id.clone())
        .collect();
    ensure!(
        ids_of(&rest) == expected,
        "order changed after acknowledging messages 2 and 3"
    );
    Ok(None)
}

fn msg_fetch_limit(ctx: &Ctx) -> CheckRes {
    let quota = ctx.info_u64("max_messages_per_mailbox").unwrap_or(0);
    let mb = ctx.mailbox()?;
    let n = usize::try_from(quota.min(33)).unwrap_or(33);
    let mut ids = Vec::new();
    for i in 0..n {
        ids.push(ctx.post_nth(&mb, i)?);
    }
    let two = ctx.fetch(&mb, "limit=2")?;
    ensure!(
        ids_of(&two) == ids.iter().take(2).cloned().collect::<Vec<_>>(),
        "limit=2 returned {} messages (or not the oldest two)",
        two.len()
    );
    let note = if n >= 33 {
        let all = ctx.fetch(&mb, "")?;
        ensure!(
            all.len() == 32,
            "fetch without limit returned {} of 33 messages, expected 32",
            all.len()
        );
        ensure!(
            ids_of(&all) == ids.iter().take(32).cloned().collect::<Vec<_>>(),
            "fetch without limit did not return the oldest 32"
        );
        let big = ctx.fetch(&mb, "limit=1000")?;
        ensure!(
            big.len() == 32,
            "limit=1000 returned {} messages, expected 32",
            big.len()
        );
        None
    } else {
        Some(format!(
            "max_messages_per_mailbox is {quota}: the 32-message cap was not exercised"
        ))
    };
    ctx.ack_ok(&mb, &ids)?;
    ensure!(
        ctx.fetch(&mb, "")?.is_empty(),
        "mailbox not empty after acknowledging everything"
    );
    Ok(note)
}

fn msg_ack(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let ids: Vec<String> = (0..3)
        .map(|i| ctx.post_nth(&mb, i))
        .collect::<Result<_, _>>()?;
    let (a, b, c) = match ids.as_slice() {
        [a, b, c] => (a.clone(), b.clone(), c.clone()),
        _ => return Err(Fail::Fail("posting failed".into())),
    };
    let r = ctx.ack(&mb, &[a.clone(), c.clone(), random_b64::<16>()])?;
    ensure!(
        r.status == 204,
        "ack with an unknown id: expected 204, got {}",
        r.describe()
    );
    ensure!(
        ids_of(&ctx.fetch(&mb, "")?) == vec![b.clone()],
        "after acking 1st and 3rd, only the 2nd should remain"
    );
    let r = ctx.ack(&mb, &[a, c])?;
    ensure!(
        r.status == 204,
        "repeated ack: expected 204, got {}",
        r.describe()
    );
    let many: Vec<String> = (0..256).map(|_| random_b64::<16>()).collect();
    let r = ctx.ack(&mb, &many)?;
    ensure!(
        r.status == 204,
        "ack with 256 ids: expected 204, got {}",
        r.describe()
    );
    let too_many: Vec<String> = (0..257).map(|_| random_b64::<16>()).collect();
    let r = ctx.ack(&mb, &too_many)?;
    expect_error(&r, 400, "bad_request", "ack with 257 ids")?;
    let r = ctx.call(
        &Req::new("POST", mb.path("/ack"))
            .bearer(mb.read.expose())
            .raw_json(b"{\"msg_ids\": 5}".to_vec()),
    )?;
    expect_error(&r, 400, "bad_request", "ack with msg_ids not an array")?;
    ensure!(
        ids_of(&ctx.fetch(&mb, "")?) == vec![b],
        "the unacknowledged message disappeared"
    );
    Ok(None)
}

fn msg_ttl_clamp(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let max = ctx.info_u64("max_ttl_s").unwrap_or(604_800);
    let ttls = [0, 1, 59, max + 1, 1_000_000_000_000];
    for (i, ttl) in ttls.iter().enumerate() {
        accepted_id(&ctx.post(&mb, &envelope::session_nth(i), Some(*ttl))?).map_err(
            |e| match e {
                Fail::Fail(m) => Fail::Fail(format!("ttl_s={ttl}: {m}")),
                s @ Fail::Skip(_) => s,
            },
        )?;
    }
    // An unclamped ttl_s of 0 or 1 would have expired by now.
    std::thread::sleep(Duration::from_millis(2_500));
    let msgs = ctx.fetch(&mb, "")?;
    ensure!(
        msgs.len() == ttls.len(),
        "{} of {} messages left after 2.5 s: short ttl_s values were not clamped to 60",
        msgs.len(),
        ttls.len()
    );
    Ok(None)
}

fn msg_ttl_expiry(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let short = accepted_id(&ctx.post(&mb, &envelope::session_nth(1), Some(60))?)?;
    let long = accepted_id(&ctx.post(&mb, &envelope::session_nth(2), Some(600))?)?;
    std::thread::sleep(Duration::from_secs(63));
    let ids = ids_of(&ctx.fetch(&mb, "")?);
    ensure!(
        !ids.contains(&short),
        "message with ttl_s=60 still delivered after 63 s"
    );
    ensure!(ids.contains(&long), "message with ttl_s=600 disappeared");
    Ok(None)
}

// ---------------------------------------------------------------------------
// Envelope validation
// ---------------------------------------------------------------------------

fn env_bad_cbor(ctx: &Ctx) -> CheckRes {
    let valid = envelope::valid(Kind::Session, 1024);
    let mut trailing = valid.clone();
    trailing.push(0x00);
    let truncated = valid.get(..valid.len() - 10).unwrap_or_default().to_vec();
    expect_rejected_envs(
        ctx,
        &[
            ("empty envelope", Vec::new()),
            ("break byte", vec![0xff]),
            ("random bytes", vec![0x1c, 0x5f, 0xff, 0x00, 0x01]),
            ("truncated envelope", truncated),
            ("trailing byte", trailing),
            ("CBOR array instead of map", {
                let mut v = envelope::head(4, 4);
                v.extend([0x01, 0x01, 0x40, 0x40]);
                v
            }),
        ],
    )
}

fn env_non_canonical(ctx: &Ctx) -> CheckRes {
    let mut unsorted = envelope::parts(1, 1, 24, 1024);
    unsorted.swap(0, 1);
    // Version encoded as 0x18 0x01 (non-minimal integer).
    let mut long_int = envelope::head(5, 4);
    long_int.extend([0x01, 0x18, 0x01, 0x02, 0x01, 0x03]);
    long_int.extend(envelope::head(2, 24));
    long_int.extend([0x11; 24]);
    long_int.extend([0x04]);
    long_int.extend(envelope::head(2, 1024));
    long_int.extend(vec![0x22; 1024]);
    // Indefinite-length map.
    let mut indefinite = vec![0xbf];
    indefinite.extend(
        envelope::map(&envelope::parts(1, 1, 24, 1024))
            .get(1..)
            .unwrap_or_default(),
    );
    indefinite.push(0xff);
    // Duplicate key.
    let mut dup = envelope::parts(1, 1, 24, 1024);
    dup.insert(1, (1, Item::Uint(1)));
    expect_rejected_envs(
        ctx,
        &[
            ("map keys out of canonical order", envelope::map(&unsorted)),
            ("non-minimal integer encoding", long_int),
            ("indefinite-length map", indefinite),
            ("duplicate map key", envelope::map(&dup)),
        ],
    )
}

fn env_lengths(ctx: &Ctx) -> CheckRes {
    let e = |kind, n, ct| envelope::map(&envelope::parts(1, kind, n, ct));
    expect_rejected_envs(
        ctx,
        &[
            ("session nonce of 12 bytes", e(1, 12, 1024)),
            ("session nonce of 32 bytes", e(1, 32, 1024)),
            ("session ct of 1000 bytes", e(1, 24, 1000)),
            ("session ct of 2048 bytes", e(1, 24, 2048)),
            ("session ct of 1025 bytes", e(1, 24, 1025)),
            ("session ct of 0 bytes", e(1, 24, 0)),
            ("pairing enc of 24 bytes", e(2, 24, 1024)),
            ("pairing ct of 4096 bytes", e(2, 32, 4096)),
        ],
    )
}

fn env_keys(ctx: &Ctx) -> CheckRes {
    let mut extra = envelope::parts(1, 1, 24, 1024);
    extra.push((5, Item::Uint(0)));
    let mut missing = envelope::parts(1, 1, 24, 1024);
    missing.pop();
    let mut no_version = envelope::parts(1, 1, 24, 1024);
    no_version.remove(0);
    let mut text_key = envelope::map(&envelope::parts(1, 1, 24, 1024));
    // Replace the map head (4 entries) by 5 and append "x": 0 (text keys sort after uints).
    if let Some(h) = text_key.first_mut() {
        *h = 0xa5;
    }
    text_key.extend([0x61, b'x', 0x00]);
    expect_rejected_envs(
        ctx,
        &[
            ("extra key 5", envelope::map(&extra)),
            ("extra text key", text_key),
            ("missing ct (key 4)", envelope::map(&missing)),
            ("missing version (key 1)", envelope::map(&no_version)),
            (
                "n as unsigned int",
                envelope::map(&[
                    (1, Item::Uint(1)),
                    (2, Item::Uint(1)),
                    (3, Item::Uint(7)),
                    (4, Item::Bytes(vec![0; 1024])),
                ]),
            ),
        ],
    )
}

fn env_version_kind(ctx: &Ctx) -> CheckRes {
    let e = |v, kind, n| envelope::map(&envelope::parts(v, kind, n, 1024));
    expect_rejected_envs(
        ctx,
        &[
            ("version 0", e(0, 1, 24)),
            ("version 2", e(2, 1, 24)),
            ("kind 0", e(1, 0, 24)),
            ("kind 3", e(1, 3, 24)),
        ],
    )
}

fn env_valid_sizes(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let max = ctx.max_envelope_bytes();
    let mut posted = Vec::new();
    let mut skipped = Vec::new();
    let mut envs = vec![(
        "pairing envelope".to_owned(),
        envelope::valid(Kind::Pairing, 1024),
    )];
    for b in BUCKETS {
        envs.push((
            format!("session ct of {b} bytes"),
            envelope::valid(Kind::Session, b),
        ));
    }
    for (what, env) in envs {
        if env.len() > max {
            skipped.push(what);
            continue;
        }
        let r = ctx.post(&mb, &env, None)?;
        let id = accepted_id(&r).map_err(|e| match e {
            Fail::Fail(m) => Fail::Fail(format!("{what}: {m}")),
            s @ Fail::Skip(_) => s,
        })?;
        posted.push((id, env));
    }
    let msgs = ctx.fetch(&mb, "")?;
    ensure!(
        msgs.len() == posted.len(),
        "fetched {} of {} messages",
        msgs.len(),
        posted.len()
    );
    for ((id, env), (mid, menv)) in posted.iter().zip(&msgs) {
        ensure!(id == mid, "messages out of order");
        ensure!(
            b64::decode(menv).is_ok_and(|e| &e == env),
            "envelope of {} bytes not returned byte-identical",
            env.len()
        );
    }
    Ok((!skipped.is_empty()).then(|| {
        format!(
            "above max_envelope_bytes, not tested: {}",
            skipped.join(", ")
        )
    }))
}

fn env_too_big(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let max = ctx.max_envelope_bytes();
    // A largest-bucket envelope padded past the limit (still below the 400 KiB body cap).
    let ct = (max + 64).max(262_144 + 64);
    let env = envelope::map(&envelope::parts(1, 1, 24, ct));
    if b64::encode(&env).len() + 16 > 400 * 1024 {
        skip!("max_envelope_bytes too large to exceed within the 400 KiB body limit");
    }
    let r = post_raw_env(ctx, &mb, &env)?;
    let code = error_code(&r);
    ensure!(
        (r.status == 400 && code.as_deref() == Some("bad_request"))
            || (r.status == 413 && code.as_deref() == Some("too_large")),
        "envelope of {} bytes: expected 400 bad_request or 413 too_large, got {}",
        env.len(),
        r.describe()
    );
    ensure!(
        ctx.fetch(&mb, "")?.is_empty(),
        "oversized envelope was stored"
    );
    Ok(Some(format!(
        "answered {} {}",
        r.status,
        code.unwrap_or_default()
    )))
}

fn env_encoding(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let auth = |body: &[u8]| {
        Req::new("POST", mb.path("/messages"))
            .bearer(mb.write.expose())
            .raw_json(body.to_vec())
    };
    let std_b64 = {
        // Standard alphabet with padding: '+', '/' and '=' are not base64url.
        let env = envelope::valid(Kind::Session, 1024);
        let mut s = b64::encode(&env).replace('-', "+").replace('_', "/");
        s.push_str("+/==");
        s
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "env with non-base64url characters",
            br#"{"env":"!!!not base64!!!"}"#.to_vec(),
        ),
        (
            "env in the standard base64 alphabet",
            json!({ "env": std_b64 }).to_string().into_bytes(),
        ),
        ("missing env", br#"{"ttl_s":3600}"#.to_vec()),
        ("env as a number", br#"{"env":12345}"#.to_vec()),
        ("malformed JSON", b"{\"env\":".to_vec()),
        (
            "ttl_s as a string",
            json!({ "env": b64::encode(&envelope::valid(Kind::Session, 1024)), "ttl_s": "60" })
                .to_string()
                .into_bytes(),
        ),
    ];
    for (what, body) in cases {
        let r = ctx.call(&auth(&body))?;
        expect_error(&r, 400, "bad_request", what)?;
    }
    ensure!(
        ctx.fetch(&mb, "")?.is_empty(),
        "a rejected message was stored"
    );
    Ok(None)
}

fn size_limit(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let mut body = b"{\"env\":\"".to_vec();
    body.resize(401 * 1024, b'A');
    body.extend(b"\"}");
    let r = ctx.call(
        &Req::new("POST", mb.path("/messages"))
            .bearer(mb.write.expose())
            .raw_json(body),
    )?;
    expect_error(&r, 413, "too_large", "POST messages with a 401 KiB body")?;
    let mut body = b"{\"read_token_hash\":\"".to_vec();
    body.resize(401 * 1024, b'A');
    body.extend(b"\"}");
    let r = ctx.call(&Req::new("POST", "/v1/mailboxes").raw_json(body))?;
    expect_error(
        &r,
        413,
        "too_large",
        "POST /v1/mailboxes with a 401 KiB body",
    )?;
    ensure!(
        ctx.fetch(&mb, "")?.is_empty(),
        "an oversized message was stored"
    );
    Ok(None)
}

fn quota_full(ctx: &Ctx) -> CheckRes {
    let quota = ctx.info_u64("max_messages_per_mailbox").unwrap_or(0);
    if quota > 64 {
        skip!(
            "max_messages_per_mailbox is {quota}; filling more than 64 messages is too slow (configure a smaller quota on a test relay)"
        );
    }
    let mb = ctx.mailbox()?;
    let mut ids = Vec::new();
    for i in 0..usize::try_from(quota).unwrap_or(0) {
        ids.push(ctx.post_nth(&mb, i)?);
    }
    let r = ctx.post(&mb, &envelope::session_nth(999), None)?;
    expect_error(
        &r,
        409,
        "mailbox_full",
        &format!("message {} into a mailbox with quota {quota}", quota + 1),
    )?;
    ctx.ack_ok(&mb, ids.get(..1).unwrap_or_default())?;
    ctx.post_nth(&mb, 1000)?;
    Ok(None)
}

// ---------------------------------------------------------------------------
// Long-polling
// ---------------------------------------------------------------------------

fn poll_early(ctx: &Ctx) -> CheckRes {
    let max = ctx.max_wait_s();
    if max < 4 {
        skip!("max_wait_s is {max}; need at least 4 s to observe an early return");
    }
    let wait = max.min(15);
    let mb = ctx.mailbox()?;
    let (res, elapsed) = std::thread::scope(|s| {
        let poller = s.spawn(|| {
            let started = Instant::now();
            let r = ctx.fetch_raw(&mb, &format!("wait={wait}"));
            (r, started.elapsed())
        });
        std::thread::sleep(Duration::from_secs(1));
        let posted = ctx.post_ok(&mb, &envelope::session_nth(5));
        let (r, el) = poller.join().unwrap_or((
            Err(Fail::Fail("poller thread panicked".into())),
            Duration::ZERO,
        ));
        (posted.and_then(|id| r.map(|r| (id, r))), el)
    });
    let (id, r) = res?;
    ensure!(
        r.status == 200,
        "long-poll: expected 200, got {}",
        r.describe()
    );
    let msgs = parse_messages(&r)?;
    ensure!(
        ids_of(&msgs) == vec![id],
        "long-poll did not return the message that arrived"
    );
    ensure!(
        elapsed < Duration::from_secs(wait.saturating_sub(1)),
        "long-poll with wait={wait} returned after {:.1} s; expected right after the message arrived (~1 s)",
        elapsed.as_secs_f64()
    );
    Ok(Some(format!(
        "returned after {:.1} s of wait={wait}",
        elapsed.as_secs_f64()
    )))
}

fn poll_timeout(ctx: &Ctx) -> CheckRes {
    let wait = ctx.max_wait_s().min(2);
    let mb = ctx.mailbox()?;
    let started = Instant::now();
    let r = ctx.fetch_raw(&mb, &format!("wait={wait}"))?;
    let elapsed = started.elapsed();
    ensure!(
        r.status == 200,
        "long-poll: expected 200, got {}",
        r.describe()
    );
    ensure!(
        parse_messages(&r)?.is_empty(),
        "long-poll on an empty mailbox returned messages"
    );
    ensure!(
        elapsed + Duration::from_millis(250) >= Duration::from_secs(wait),
        "wait={wait} returned after {:.2} s",
        elapsed.as_secs_f64()
    );
    ensure!(
        elapsed < Duration::from_secs(wait + 5),
        "wait={wait} took {:.1} s",
        elapsed.as_secs_f64()
    );
    // wait=0 (the default) returns immediately.
    let started = Instant::now();
    ctx.fetch(&mb, "")?;
    ensure!(
        started.elapsed() < Duration::from_secs(2),
        "fetch without wait blocked for {:.1} s",
        started.elapsed().as_secs_f64()
    );
    Ok(None)
}

fn poll_clamp(ctx: &Ctx) -> CheckRes {
    let max = ctx.max_wait_s();
    let mb = ctx.mailbox()?;
    let started = Instant::now();
    let r = ctx.fetch_raw(&mb, "wait=3600")?;
    let elapsed = started.elapsed();
    ensure!(
        r.status == 200,
        "wait=3600: expected 200, got {}",
        r.describe()
    );
    ensure!(
        elapsed < Duration::from_secs(max + 5),
        "wait=3600 took {:.1} s with max_wait_s={max}",
        elapsed.as_secs_f64()
    );
    Ok(Some(format!(
        "returned after {:.1} s (max_wait_s={max})",
        elapsed.as_secs_f64()
    )))
}

// ---------------------------------------------------------------------------
// Rate limits
// ---------------------------------------------------------------------------

fn rate_limit(ctx: &Ctx) -> CheckRes {
    const MAX_WRITES: usize = 2_000;
    let mb = ctx.mailbox()?;
    let quota = usize::try_from(ctx.info_u64("max_messages_per_mailbox").unwrap_or(1)).unwrap_or(1);
    let mut pending = Vec::new();
    for i in 0..MAX_WRITES {
        let r = ctx.send(&Ctx::post_req(&mb, &envelope::session_nth(i), None))?;
        match r.status {
            202 => {
                pending.push(accepted_id(&r)?);
                if pending.len() * 2 >= quota {
                    ctx.ack_ok(&mb, &pending)?;
                    pending.clear();
                }
            }
            429 => {
                expect_error(&r, 429, "rate_limited", "rate-limited write")?;
                let retry = r
                    .header("retry-after")
                    .and_then(|v| v.trim().parse::<u64>().ok());
                let Some(retry) = retry else {
                    return Err(Fail::Fail(format!(
                        "429 without a valid integer Retry-After (got {:?})",
                        r.header("retry-after")
                    )));
                };
                ensure!(retry >= 1, "Retry-After is 0");
                if retry <= 15 {
                    std::thread::sleep(Duration::from_secs(retry));
                    ctx.post_ok(&mb, &envelope::session_nth(i))?;
                }
                return Ok(Some(format!("429 after {i} writes, Retry-After: {retry}")));
            }
            _ => {
                return Err(Fail::Fail(format!(
                    "write {i}: unexpected {}",
                    r.describe()
                )));
            }
        }
    }
    skip!("no 429 within {MAX_WRITES} writes to one mailbox; the relay may not limit writes")
}

// ---------------------------------------------------------------------------
// Push registration
// ---------------------------------------------------------------------------

fn push_url_rules(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let allow = ctx.gateway_allowlist().unwrap_or_default();
    let base = accepted_gateway(ctx).unwrap_or_else(|| "https://push.example.com/v1/wake".into());
    let host_part = base.strip_prefix("https://").unwrap_or(&base).to_owned();
    let host = host_part.split('/').next().unwrap_or_default().to_owned();
    let path = host_part.get(host.len()..).unwrap_or_default().to_owned();
    // Scheme and port: the operator may allowlist another port (rule 1), so variants
    // matching an allowlist entry are not tested.
    let mut urls = vec![
        format!("http://{host_part}"),
        format!("https://{host}:8443{path}"),
        format!("ftp://{host_part}"),
    ];
    urls.retain(|u| !allow.iter().any(|p| u.starts_with(p.as_str())));
    // Userinfo, length and missing scheme are rejected regardless of the allowlist.
    urls.extend([
        format!("https://user:pass@{host_part}"),
        format!("https://{host}@evil.example{path}"),
        format!("{base}/{}", "a".repeat(520)),
        "push.example.com/v1/wake".to_owned(),
    ]);
    for url in &urls {
        expect_gateway_rejected(ctx, &mb, url)?;
    }
    Ok(Some(format!("{} URLs rejected", urls.len())))
}

fn push_allowlist(ctx: &Ctx) -> CheckRes {
    let Some(allow) = ctx.gateway_allowlist() else {
        skip!(
            "relay is in open gateway mode: destination checks happen at dispatch (spec 7.3.1 rule 7) and are not observable at registration"
        );
    };
    let mb = ctx.mailbox()?;
    let mut urls: Vec<String> = [
        "https://127.0.0.1/v1/wake",
        "https://localhost/v1/wake",
        "https://10.0.0.1/v1/wake",
        "https://192.168.1.1/v1/wake",
        "https://100.64.0.1/v1/wake",
        "https://169.254.169.254/latest/meta-data/",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://[::1]/v1/wake",
        "https://[fd00::1]/v1/wake",
        "https://xchonnect-conformance-unlisted.example/v1/wake",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    // Look-alike hosts of each allowlisted prefix.
    for p in &allow {
        if let Some(rest) = p.strip_prefix("https://") {
            let host = rest.split('/').next().unwrap_or_default();
            urls.push(format!("https://{host}.evil.example/v1/wake"));
        }
    }
    urls.retain(|u| !allow.iter().any(|p| u.starts_with(p.as_str())));
    for url in &urls {
        expect_gateway_rejected(ctx, &mb, url)?;
    }
    Ok(Some(format!("{} URLs rejected", urls.len())))
}

fn push_set_remove(ctx: &Ctx) -> CheckRes {
    let Some(url) = accepted_gateway(ctx) else {
        skip!("gateway allowlist is empty: no URL can be registered");
    };
    let mb = ctx.mailbox_with(&push_body(&url), ctx.default_method()?)?;
    for (what, body) in [
        ("replace", push_body(&url)),
        ("remove", json!({ "push_reg": null })),
        ("set again", push_body(&url)),
    ] {
        let r = put_push(ctx, &mb, &body)?;
        ensure!(
            r.status == 204,
            "PUT push ({what}) with {url}: expected 204, got {}",
            r.describe()
        );
    }
    let r = put_push(
        ctx,
        &mb,
        &json!({ "push_reg": { "gateway_url": url, "sealed_token": "!!not base64!!" } }),
    )?;
    expect_error(&r, 400, "bad_request", "sealed_token not base64url")?;
    // Registration must not affect message acceptance.
    ctx.post_nth(&mb, 1)?;
    Ok(Some(format!("used {url}")))
}

// ---------------------------------------------------------------------------
// DELETE
// ---------------------------------------------------------------------------

fn delete_semantics(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    ctx.post_nth(&mb, 1)?;
    let r = ctx.call(&Req::new("DELETE", mb.path("")).bearer(mb.write.expose()))?;
    expect_error(&r, 404, "not_found", "DELETE with the write token")?;
    ensure!(
        ctx.fetch(&mb, "")?.len() == 1,
        "DELETE with the write token affected the mailbox"
    );
    let r = ctx.call(&Req::new("DELETE", mb.path("")).bearer(mb.read.expose()))?;
    ensure!(
        r.status == 204,
        "DELETE with the read token: expected 204, got {}",
        r.describe()
    );
    ensure!(r.body.is_empty(), "204 with a body");
    let r = ctx.fetch_raw(&mb, "")?;
    expect_error(&r, 404, "not_found", "fetch after DELETE")?;
    let r = ctx.post(&mb, &envelope::session_nth(2), None)?;
    expect_error(&r, 404, "not_found", "post after DELETE")?;
    let r = ctx.call(&Req::new("DELETE", mb.path("")).bearer(mb.read.expose()))?;
    expect_error(&r, 404, "not_found", "second DELETE")?;
    Ok(None)
}

// ---------------------------------------------------------------------------
// Error model and HTTP behaviour
// ---------------------------------------------------------------------------

/// A representative set of responses: success and error codes across endpoints.
fn sample_responses(ctx: &Ctx) -> Result<Vec<(String, Resp)>, Fail> {
    let mut out = Vec::new();
    out.push(("GET /v1/info".to_owned(), get_info(ctx)?));
    let (r, read, write) = ctx.create_raw(&Value::Null, ctx.default_method()?)?;
    let id = created_id(&r)?;
    out.push(("POST /v1/mailboxes (201)".to_owned(), r));
    let mb = Mailbox { id, read, write };
    let r = ctx.post(&mb, &envelope::session_nth(1), None)?;
    let msg = accepted_id(&r)?;
    out.push(("POST messages (202)".to_owned(), r));
    out.push(("GET messages (200)".to_owned(), ctx.fetch_raw(&mb, "")?));
    out.push(("POST ack (204)".to_owned(), ctx.ack(&mb, &[msg])?));
    out.push((
        "GET unknown mailbox (404)".to_owned(),
        ctx.call(
            &Req::new(
                "GET",
                format!("/v1/mailboxes/{}/messages", random_b64::<16>()),
            )
            .bearer(&[0; 32]),
        )?,
    ));
    out.push((
        "POST /v1/mailboxes malformed (400)".to_owned(),
        ctx.send(&Req::new("POST", "/v1/mailboxes").raw_json(b"[]".to_vec()))?,
    ));
    out.push((
        "POST messages bad envelope (400)".to_owned(),
        ctx.post(&mb, &[0xff], None)?,
    ));
    Ok(out)
}

fn error_shape(ctx: &Ctx) -> CheckRes {
    let mut checked = 0;
    for (what, r) in sample_responses(ctx)? {
        if r.status < 400 {
            continue;
        }
        ensure!(
            error_code(&r).is_some(),
            "{what}: body is not exactly {{\"error\": code}}: {}",
            r.body_text()
        );
        ensure!(
            r.header("content-type")
                .is_some_and(|c| c.starts_with("application/json")),
            "{what}: content-type {:?}",
            r.header("content-type")
        );
        checked += 1;
    }
    if ctx.offers("api_key") {
        let r = ctx.send(
            &Req::new("POST", "/v1/mailboxes")
                .header("xchonnect-api-key", "xchonnect-conformance-bogus-key")
                .json(&json!({})),
        )?;
        ensure!(
            r.status >= 400 && error_code(&r).is_some(),
            "403/400 error body malformed: {}",
            r.describe()
        );
        checked += 1;
    }
    Ok(Some(format!("{checked} error responses checked")))
}

const ORIGIN: &str = "https://dapp.example";

fn header_list_contains(list: Option<&str>, item: &str) -> bool {
    list.is_some_and(|l| l.split(',').any(|h| h.trim().eq_ignore_ascii_case(item)))
}

fn cors_preflight(ctx: &Ctx) -> CheckRes {
    let path = format!("/v1/mailboxes/{}/messages", random_b64::<16>());
    for (method, p) in [
        ("POST", path.as_str()),
        ("GET", path.as_str()),
        ("PUT", "/v1/mailboxes/AAAAAAAAAAAAAAAAAAAAAA/push"),
        ("DELETE", "/v1/mailboxes/AAAAAAAAAAAAAAAAAAAAAA"),
        ("POST", "/v1/mailboxes"),
    ] {
        let r = ctx.send(
            &Req::new("OPTIONS", p)
                .header("origin", ORIGIN)
                .header("access-control-request-method", method)
                .header(
                    "access-control-request-headers",
                    "authorization,content-type",
                ),
        )?;
        let what = format!("preflight {method} {p}");
        ensure!(
            (200..300).contains(&r.status),
            "{what}: expected 2xx, got {}",
            r.describe()
        );
        let acao = r.header("access-control-allow-origin");
        ensure!(
            acao == Some("*") || acao == Some(ORIGIN),
            "{what}: Access-Control-Allow-Origin is {acao:?}"
        );
        let acah = r.header("access-control-allow-headers");
        // `*` does not cover Authorization (Fetch standard), so it must be listed.
        ensure!(
            header_list_contains(acah, "authorization"),
            "{what}: Access-Control-Allow-Headers {acah:?} lacks authorization"
        );
        ensure!(
            header_list_contains(acah, "content-type") || header_list_contains(acah, "*"),
            "{what}: Access-Control-Allow-Headers {acah:?} lacks content-type"
        );
        let acam = r.header("access-control-allow-methods");
        ensure!(
            header_list_contains(acam, method) || header_list_contains(acam, "*"),
            "{what}: Access-Control-Allow-Methods {acam:?} lacks {method}"
        );
        ensure!(
            r.header("access-control-allow-credentials") != Some("true"),
            "{what}: Access-Control-Allow-Credentials: true (no credentials are ever involved)"
        );
    }
    Ok(None)
}

fn cors_response(ctx: &Ctx) -> CheckRes {
    for (what, req) in [
        ("GET /v1/info", Req::new("GET", "/v1/info")),
        (
            "404 not_found",
            Req::new(
                "GET",
                format!("/v1/mailboxes/{}/messages", random_b64::<16>()),
            )
            .bearer(&[1; 32]),
        ),
    ] {
        let r = ctx.call(&req.header("origin", ORIGIN))?;
        let acao = r.header("access-control-allow-origin");
        ensure!(
            acao == Some("*") || acao == Some(ORIGIN),
            "{what}: Access-Control-Allow-Origin is {acao:?}"
        );
        ensure!(
            r.header("access-control-allow-credentials") != Some("true"),
            "{what}: allows credentials"
        );
    }
    Ok(None)
}

fn cache_control(ctx: &Ctx) -> CheckRes {
    for (what, r) in sample_responses(ctx)? {
        let cc = r.header("cache-control");
        ensure!(
            header_list_contains(cc, "no-store"),
            "{what}: Cache-Control is {cc:?}, expected no-store"
        );
    }
    Ok(None)
}

fn no_cookies(ctx: &Ctx) -> CheckRes {
    for (what, r) in sample_responses(ctx)? {
        ensure!(
            r.header("set-cookie").is_none(),
            "{what}: response sets a cookie"
        );
    }
    let seen = ctx
        .client
        .cookies_seen
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    ensure!(seen.is_empty(), "Set-Cookie seen on: {}", seen.join(", "));
    Ok(None)
}
