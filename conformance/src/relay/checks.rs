//! The checks. Each one creates its own mailboxes so checks are independent and can be
//! run individually with `--only`.

use super::client::{Req, Resp};
use super::ctx::{
    API_KEY_INVALID, AUTH_REQUIRED, BAD_REQUEST, CheckRes, Ctx, Fail, GATEWAY_NOT_ALLOWED,
    MAILBOX_FULL, Mailbox, Method, NOT_FOUND, POW_INVALID, RATE_LIMITED, TICKET_INVALID, TOO_LARGE,
    accepted_id, created_id, ensure, error_code, expect_error, expect_status, field,
    parse_messages, post_empty, random_b64, skip, tokens,
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

/// Builds [`CHECKS`] from `id tier function "spec" "title";` entries.
macro_rules! checks {
    ($($id:literal $tier:ident $run:ident $spec:literal $title:literal;)*) => {
        pub(crate) const CHECKS: &[Check] = &[$(Check {
            info: CheckInfo { id: $id, title: $title, spec: $spec, tier: $tier },
            run: $run,
        }),*];
    };
}

use Tier::{Aggressive, Default as D, Slow};

checks! {
    "R-INFO-01" D info_shape "relay-api.md §GET /v1/info"
        "GET /v1/info returns protocol 1 with well-formed limits";
    "R-INFO-02" D info_conditional "relay-api.md §GET /v1/info; spec 7.3.1 rule 6"
        "/v1/info publishes gateway allowlist and pow difficulty when applicable";
    "R-CREATE-01" D create_basic "relay-api.md §POST /v1/mailboxes"
        "mailbox creation with an advertised method returns 201 and a 16-byte mailbox_id";
    "R-CREATE-02" D create_unknown_fields "relay-api.md §Conventions"
        "unknown request fields are ignored";
    "R-CREATE-03" D create_malformed "relay-api.md §Errors"
        "malformed creation requests are rejected with 400 bad_request";
    "R-CREATE-04" D create_auth_required "relay-api.md §Errors; spec 7.4"
        "creation without proof is rejected with 403 auth_required unless open";
    "R-POW-01" D pow_flow "spec 7.4; relay-api.md §POST /v1/challenge"
        "proof-of-work challenge is well-formed and a solution creates a mailbox";
    "R-POW-02" D pow_invalid "spec 7.4"
        "spent, wrong or tampered proofs are rejected with 403 pow_invalid";
    "R-TICKET-01" D ticket_flow "spec 7.5; relay-api.md §POST /v1/tickets"
        "sponsorship tickets are issued with an API key and are single-use";
    "R-TICKET-02" D ticket_needs_key "spec 7.5; relay-api.md §Errors"
        "ticket issuance without a valid API key is refused with 403";
    "R-APIKEY-01" D api_key_invalid "relay-api.md §Errors"
        "unknown API keys are rejected with 403 api_key_invalid";
    "R-AUTH-01" D auth_not_interchangeable "relay-api.md §Identifiers"
        "read and write tokens are not interchangeable";
    "R-AUTH-02" D auth_hashes "relay-api.md §Identifiers and hashes"
        "the relay hashes presented tokens (token accepted, its hash is not)";
    "R-AUTH-03" D auth_equal_hashes "relay-api.md §Identifiers and hashes"
        "creation with equal read and write hashes is rejected with 400";
    "R-NF-01" D not_found_identical "relay-api.md §Errors; spec 7.2"
        "not_found is byte-identical for unknown mailbox, wrong token, malformed id, missing auth and deleted mailbox";
    "R-MSG-01" D msg_roundtrip "relay-api.md §POST/GET messages"
        "posted envelopes are returned byte-identical and stay until acknowledged";
    "R-MSG-02" D msg_order "relay-api.md §GET messages"
        "messages are returned in acceptance order";
    "R-MSG-03" D msg_fetch_limit "relay-api.md §GET messages"
        "fetch returns at most 32 messages and honours limit";
    "R-MSG-04" D msg_ack "relay-api.md §POST ack; spec 7.1"
        "ack deletes messages, ignores unknown ids and caps at 256 ids";
    "R-MSG-05" D msg_ttl_clamp "relay-api.md §POST messages"
        "ttl_s is clamped to [60, max_ttl_s] rather than rejected";
    "R-MSG-06" Slow msg_ttl_expiry "spec 7.1; relay-api.md §Retention"
        "messages expire after ttl_s";
    "R-ENV-01" D env_bad_cbor "relay-api.md §POST messages"
        "envelopes that are not valid CBOR are rejected with 400";
    "R-ENV-02" D env_non_canonical "relay-api.md §POST messages; spec 5.4"
        "non-canonical CBOR envelopes are rejected with 400";
    "R-ENV-03" D env_lengths "relay-api.md §POST messages"
        "wrong nonce or ciphertext lengths are rejected with 400";
    "R-ENV-04" D env_keys "relay-api.md §POST messages; envelope.cddl"
        "envelopes with extra or missing keys are rejected with 400";
    "R-ENV-05" D env_version_kind "relay-api.md §POST messages"
        "wrong version or kind is rejected with 400";
    "R-ENV-06" D env_valid_sizes "relay-api.md §POST messages; spec 5.3"
        "every bucket size and pairing envelopes are accepted";
    "R-ENV-07" D env_too_big "relay-api.md §POST messages"
        "envelopes above max_envelope_bytes are rejected";
    "R-ENV-08" D env_encoding "relay-api.md §Conventions"
        "env that is not base64url, or a missing env, is rejected with 400";
    "R-SIZE-01" D size_limit "relay-api.md §Conventions"
        "request bodies above 400 KiB get 413 too_large";
    "R-QUOTA-01" D quota_full "relay-api.md §Errors"
        "a full mailbox answers 409 mailbox_full until messages are acknowledged";
    "R-POLL-01" D poll_early "relay-api.md §GET messages"
        "a long-poll returns early when a message arrives";
    "R-POLL-02" D poll_timeout "relay-api.md §GET messages"
        "a long-poll on an empty mailbox returns an empty list after the wait";
    "R-POLL-03" Slow poll_clamp "relay-api.md §GET messages"
        "wait is clamped to max_wait_s";
    "R-RATE-01" Aggressive rate_limit "relay-api.md §Errors; spec 7.1"
        "rate limiting answers 429 rate_limited with Retry-After";
    "R-PUSH-01" D push_url_rules "spec 7.3.1 rules 1 and 7"
        "push registration requires https, port 443, no userinfo, at most 512 bytes";
    "R-PUSH-02" D push_allowlist "spec 7.3.1 rules 6 and 7"
        "allowlist mode rejects private, loopback, metadata and unlisted gateways at registration";
    "R-PUSH-03" D push_set_remove "relay-api.md §PUT push; spec 7.3"
        "an accepted gateway can be registered, replaced and removed";
    "R-DEL-01" D delete_semantics "relay-api.md §DELETE; spec 7.1"
        "DELETE removes the mailbox and its messages and needs the read token";
    "R-ERR-01" D error_shape "relay-api.md §Errors"
        "error bodies are exactly {\"error\": code} with application/json";
    "R-CORS-01" D cors_preflight "browser interop, cf. spec 10.2; not yet normative for relays"
        "CORS preflight allows Authorization and Content-Type without credentials";
    "R-CORS-02" D cors_response "browser interop, cf. spec 10.2; not yet normative for relays"
        "responses carry Access-Control-Allow-Origin without credentials";
    "R-HTTP-01" D cache_control "hardening, cf. spec 13.5; not yet normative"
        "responses carry Cache-Control: no-store";
    "R-HTTP-02" D no_cookies "relay-api.md §Conventions"
        "the relay never sets cookies";
}

// ---- Helpers -------------------------------------------------------------------------------

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

/// `method` on the mailbox endpoint `suffix`, authorized with `token`.
fn mb_req(mb: &Mailbox, method: &'static str, suffix: &str, token: &[u8]) -> Req {
    Req::new(method, mb.path(suffix)).bearer(token)
}

/// `POST /v1/mailboxes` with `body` and no proof added.
fn creation(body: serde_json::Map<String, Value>) -> Req {
    Req::new("POST", "/v1/mailboxes").json(&Value::Object(body))
}

/// Every envelope in `cases` must be rejected with `400 bad_request`; nothing may be stored.
fn expect_rejected_envs(ctx: &Ctx, cases: &[(&str, Vec<u8>)]) -> CheckRes {
    let mb = ctx.mailbox()?;
    for (what, env) in cases {
        expect_error(&ctx.post(&mb, env, None)?, BAD_REQUEST, what)?;
    }
    let left = ctx.fetch(&mb, "")?;
    ensure!(
        left.is_empty(),
        "{} rejected envelope(s) were stored",
        left.len()
    );
    Ok(None)
}

fn push_body(url: &str) -> Value {
    json!({ "push_reg": { "gateway_url": url, "sealed_token": random_b64::<64>() } })
}

fn put_push(ctx: &Ctx, mb: &Mailbox, body: &Value) -> Result<Resp, Fail> {
    ctx.call(&mb_req(mb, "PUT", "/push", mb.read.expose()).json(body))
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

/// Both registration paths (PUT push and creation) must reject every URL in `urls` with
/// `403 gateway_not_allowed`.
fn expect_gateways_rejected(ctx: &Ctx, urls: &[String]) -> CheckRes {
    let mb = ctx.mailbox()?;
    for url in urls {
        let r = put_push(ctx, &mb, &push_body(url))?;
        expect_error(&r, GATEWAY_NOT_ALLOWED, &format!("PUT push {url}"))?;
        let (r, _, _) = ctx.create_raw(&push_body(url), ctx.default_method()?)?;
        let what = format!("creation with push_reg {url}");
        expect_error(&r, GATEWAY_NOT_ALLOWED, &what)?;
    }
    Ok(Some(format!("{} URLs rejected", urls.len())))
}

// ---- /v1/info ------------------------------------------------------------------------------

fn info_shape(ctx: &Ctx) -> CheckRes {
    let r = get_info(ctx)?;
    expect_status(&r, 200, "GET /v1/info")?;
    let ct = r.header("content-type");
    ensure!(
        ct.is_some_and(|c| c.starts_with("application/json")),
        "content-type is {ct:?}, expected application/json"
    );
    let v = r.json();
    ensure!(
        v.is_object(),
        "body is not a JSON object: {}",
        r.body_text()
    );
    ensure!(
        field(&v, "protocol").as_u64() == Some(1),
        "protocol must be 1, got {:?}",
        v.get("protocol")
    );
    let num = |k: &str| field(&v, k).as_u64();
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
    let methods = field(&v, "mailbox_creation").as_array();
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
            field(&v, "gateway_policy").as_str(),
            Some("allowlist" | "open")
        ),
        "gateway_policy must be \"allowlist\" or \"open\", got {:?}",
        v.get("gateway_policy")
    );
    ensure!(field(&v, "ohttp").is_boolean(), "ohttp must be a boolean");
    Ok(None)
}

fn info_conditional(ctx: &Ctx) -> CheckRes {
    let v = &ctx.info;
    if field(v, "gateway_policy").as_str() == Some("allowlist") {
        let list = field(v, "gateway_allowlist").as_array();
        ensure!(
            list.is_some(),
            "gateway_policy is allowlist but gateway_allowlist is missing"
        );
        for p in list.into_iter().flatten() {
            ensure!(p.is_string(), "gateway_allowlist entry {p} is not a string");
        }
    }
    ensure!(
        !ctx.offers("pow") || ctx.info_u64("pow_difficulty").is_some_and(|d| d <= 255),
        "pow is offered but pow_difficulty is missing or invalid"
    );
    Ok(None)
}

// ---- Mailbox creation ----------------------------------------------------------------------

fn create_basic(ctx: &Ctx) -> CheckRes {
    let method = ctx.default_method()?;
    let (a, b) = (ctx.mailbox()?, ctx.mailbox()?);
    ensure!(a.id != b.id, "two creations returned the same mailbox_id");
    ensure!(ctx.fetch(&a, "")?.is_empty(), "a new mailbox is not empty");
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
    expect_error(&r, BAD_REQUEST, "malformed JSON")?;
    let (read, write) = tokens();
    let (read, write) = (b64::encode(&read.hash()), b64::encode(&write.hash()));
    let cases = [
        (
            "31-byte read_token_hash",
            json!({ "read_token_hash": random_b64::<31>(), "write_token_hash": write }),
        ),
        (
            "33-byte write_token_hash",
            json!({ "read_token_hash": read, "write_token_hash": random_b64::<33>() }),
        ),
        (
            "non-base64url hash",
            json!({ "read_token_hash": "!!not base64!!", "write_token_hash": write }),
        ),
        (
            "missing write_token_hash",
            json!({ "read_token_hash": read }),
        ),
        (
            "numeric hash",
            json!({ "read_token_hash": 5, "write_token_hash": write }),
        ),
    ];
    for (what, body) in cases {
        let map = body.as_object().cloned().unwrap_or_default();
        let r = ctx.create_raw_with(&|| ctx.creation_req(map.clone(), method))?;
        expect_error(&r, BAD_REQUEST, what)?;
    }
    Ok(None)
}

fn create_auth_required(ctx: &Ctx) -> CheckRes {
    if ctx.offers("open") {
        skip!("relay offers open creation");
    }
    let (r, _, _) = ctx.create_raw(&Value::Null, Method::Open)?;
    expect_error(&r, AUTH_REQUIRED, "creation without proof")?;
    Ok(None)
}

// ---- Proof-of-work, tickets, API keys ------------------------------------------------------

fn pow_flow(ctx: &Ctx) -> CheckRes {
    if !ctx.offers("pow") {
        skip!("relay does not offer pow");
    }
    if !ctx.pow_usable() {
        skip!("pow_difficulty above 26: clients refuse to solve it (spec 7.4)");
    }
    let r = ctx.call(&post_empty("/v1/challenge"))?;
    expect_status(&r, 200, "POST /v1/challenge")?;
    let v = r.json();
    let ch = field(&v, "challenge")
        .as_str()
        .and_then(|c| b64::decode(c).ok())
        .ok_or_else(|| "challenge missing or not base64url".to_owned())?;
    ensure!(
        ch.len() == 42,
        "challenge is {} bytes, expected 42",
        ch.len()
    );
    let parsed =
        xchonnect_core::pow::parse(&ch).map_err(|e| format!("challenge does not parse: {e:?}"))?;
    let difficulty = field(&v, "difficulty").as_u64();
    ensure!(
        difficulty == Some(u64::from(parsed.difficulty)),
        "difficulty field {difficulty:?} != embedded {}",
        parsed.difficulty
    );
    let advertised = ctx.info_u64("pow_difficulty");
    ensure!(
        difficulty == advertised,
        "challenge difficulty {difficulty:?} != /v1/info pow_difficulty {advertised:?}"
    );
    let expires = field(&v, "expires_at").as_u64();
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
    let with_pow = |pow: &Value| {
        let (read, write) = tokens();
        creation(Ctx::hashes_body(&read, &write, &json!({ "pow": pow })))
    };
    let pow_of = |ch: &[u8], nonce: &[u8]| json!({ "challenge": b64::encode(ch), "nonce": b64::encode(nonce) });

    // Spent challenge.
    let proof = ctx.solve_pow()?;
    created_id(&ctx.send(&with_pow(&proof))?)?;
    let r = ctx.send(&with_pow(&proof))?;
    expect_error(&r, POW_INVALID, "reused challenge")?;

    // Wrong nonce: the first nonce whose hash misses the target.
    let r = ctx.call(&post_empty("/v1/challenge"))?;
    let ch = field(&r.json(), "challenge")
        .as_str()
        .and_then(|c| b64::decode(c).ok())
        .ok_or_else(|| format!("POST /v1/challenge: {}", r.describe()))?;
    let difficulty = xchonnect_core::pow::parse(&ch).map_or(0, |i| i.difficulty);
    if difficulty > 0 {
        let bad = (0u64..)
            .map(u64::to_be_bytes)
            .find(|n| {
                let h = xchonnect_core::crypto::sha256_parts(&[b"xchonnect v1 pow", &ch, n]);
                leading_zero_bits(&h) < u32::from(difficulty)
            })
            .unwrap_or([0; 8]);
        let r = ctx.send(&with_pow(&pow_of(&ch, &bad)))?;
        expect_error(&r, POW_INVALID, "nonce that misses the difficulty")?;
    }

    // Tampered MAC with a valid solution for the tampered bytes.
    let solved = ctx.solve_pow()?;
    let mut ch2 =
        b64::decode(field(&solved, "challenge").as_str().unwrap_or_default()).unwrap_or_default();
    if let Some(last) = ch2.last_mut() {
        *last ^= 0x01;
    }
    let nonce = xchonnect_core::pow::solve(&ch2).map_err(|e| format!("solve: {e:?}"))?;
    let r = ctx.send(&with_pow(&pow_of(&ch2, &nonce)))?;
    expect_error(&r, POW_INVALID, "challenge with tampered MAC")?;
    Ok(None)
}

fn leading_zero_bits(h: &[u8]) -> u32 {
    let mut n = 0;
    for b in h {
        if *b != 0 {
            return n + b.leading_zeros();
        }
        n += 8;
    }
    n
}

fn ticket_flow(ctx: &Ctx) -> CheckRes {
    if !ctx.offers("ticket") {
        skip!("relay does not offer tickets");
    }
    let key = ctx.api_key()?;
    let r = ctx.call(&post_empty("/v1/tickets").header("xchonnect-api-key", key))?;
    expect_status(&r, 200, "POST /v1/tickets")?;
    let v = r.json();
    let ticket = field(&v, "ticket").as_str().unwrap_or_default();
    ensure!(
        b64::decode(ticket).is_ok_and(|t| t.len() == 32),
        "ticket is not base64url of 32 bytes"
    );
    let exp = field(&v, "expires_at").as_u64().unwrap_or(0);
    ensure!(
        exp <= now() + 660,
        "ticket valid for {} s (max 600)",
        exp.saturating_sub(now())
    );
    let with_ticket = json!({ "ticket": ticket });
    ctx.mailbox_with(&with_ticket, Method::Open)?;
    let (r, _, _) = ctx.create_raw(&with_ticket, Method::Open)?;
    expect_error(&r, TICKET_INVALID, "reused ticket")?;
    let (r, _, _) = ctx.create_raw(&json!({ "ticket": random_b64::<32>() }), Method::Open)?;
    expect_error(&r, TICKET_INVALID, "unknown ticket")?;
    Ok(None)
}

fn ticket_needs_key(ctx: &Ctx) -> CheckRes {
    if !ctx.offers("ticket") {
        skip!("relay does not offer tickets");
    }
    let r = ctx.call(&post_empty("/v1/tickets"))?;
    ensure!(
        r.status == 403
            && matches!(
                error_code(&r).as_deref(),
                Some("api_key_invalid" | "auth_required")
            ),
        "POST /v1/tickets without key: expected 403 api_key_invalid or auth_required, got {}",
        r.describe()
    );
    let bogus = post_empty("/v1/tickets").header("xchonnect-api-key", BOGUS_KEY);
    let r = ctx.call(&bogus)?;
    expect_error(&r, API_KEY_INVALID, "POST /v1/tickets with unknown key")?;
    Ok(None)
}

const BOGUS_KEY: &str = "xchonnect-conformance-bogus-key";

fn api_key_invalid(ctx: &Ctx) -> CheckRes {
    if !ctx.offers("api_key") {
        skip!("relay does not offer api_key creation");
    }
    let (read, write) = tokens();
    let req = creation(Ctx::hashes_body(&read, &write, &Value::Null));
    let r = ctx.call(&req.header("xchonnect-api-key", BOGUS_KEY))?;
    expect_error(&r, API_KEY_INVALID, "creation with unknown API key")?;
    if ctx.api_key.is_none() {
        return Ok(Some("valid-key creation not tested (no --api-key)".into()));
    }
    ctx.mailbox_with(&Value::Null, Method::ApiKey)?;
    Ok(None)
}

// ---- Tokens --------------------------------------------------------------------------------

fn auth_not_interchangeable(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let env = envelope::session_nth(1);
    let (read, write) = (mb.read.expose(), mb.write.expose());
    for (what, req) in [
        (
            "posting with the read token",
            mb_req(&mb, "POST", "/messages", read).json(&post_body(&env)),
        ),
        (
            "fetching with the write token",
            mb_req(&mb, "GET", "/messages", write),
        ),
        (
            "ack with the write token",
            mb_req(&mb, "POST", "/ack", write).json(&json!({ "msg_ids": [] })),
        ),
        (
            "PUT push with the write token",
            mb_req(&mb, "PUT", "/push", write).json(&json!({ "push_reg": null })),
        ),
    ] {
        expect_error(&ctx.call(&req)?, NOT_FOUND, what)?;
    }
    ctx.post_ok(&mb, &env)?;
    ensure!(
        ctx.fetch(&mb, "")?.len() == 1,
        "the message posted with the write token is missing"
    );
    Ok(None)
}

fn auth_hashes(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let r = ctx.call(&mb_req(&mb, "GET", "/messages", &mb.read.hash()))?;
    expect_error(&r, NOT_FOUND, "presenting the read token hash as bearer")?;
    let post = mb_req(&mb, "POST", "/messages", &mb.write.hash());
    let r = ctx.call(&post.json(&post_body(&envelope::session_nth(1))))?;
    expect_error(&r, NOT_FOUND, "presenting the write token hash as bearer")?;
    ctx.fetch(&mb, "")?;
    Ok(None)
}

fn auth_equal_hashes(ctx: &Ctx) -> CheckRes {
    let method = ctx.default_method()?;
    let (read, _) = tokens();
    let r = ctx.create_raw_with(&|| {
        ctx.creation_req(Ctx::hashes_body(&read, &read, &Value::Null), method)
    })?;
    expect_error(&r, BAD_REQUEST, "equal read and write hashes")?;
    Ok(None)
}

// ---- Byte-identical not_found --------------------------------------------------------------

fn not_found_identical(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let gone = ctx.mailbox()?;
    let r = ctx.call(&mb_req(&gone, "DELETE", "", gone.read.expose()))?;
    expect_status(&r, 204, "DELETE")?;

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
        let (other, own_gone) = if *write {
            (read_auth(&mb), write_auth(&gone))
        } else {
            (write_auth(&mb), read_auth(&gone))
        };
        let variants = [
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
            expect_error(&r, NOT_FOUND, &format!("{method} {suffix} ({what})"))?;
            let Some((w0, r0)) = &first else {
                first = Some((what, r));
                continue;
            };
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
    // The real mailbox must be unaffected by all of the above.
    ctx.fetch(&mb, "")?;
    Ok(Some(format!("{compared} response pairs compared")))
}

// ---- Messages ------------------------------------------------------------------------------

fn msg_roundtrip(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let env = envelope::session_nth(42);
    let id = ctx.post_ok(&mb, &env)?;
    for round in ["first", "second"] {
        let msgs = ctx.fetch(&mb, "")?;
        let n = msgs.len();
        ensure!(n == 1, "{round} fetch returned {n} messages, expected 1");
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
    let ids = ctx.post_n(&mb, 6)?;
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
    let mut expected = ids;
    expected.drain(2..4);
    ensure!(
        ids_of(&ctx.fetch(&mb, "")?) == expected,
        "order changed after acknowledging messages 2 and 3"
    );
    Ok(None)
}

fn msg_fetch_limit(ctx: &Ctx) -> CheckRes {
    let quota = ctx.info_u64("max_messages_per_mailbox").unwrap_or(0);
    let mb = ctx.mailbox()?;
    let n = usize::try_from(quota.min(33)).unwrap_or(33);
    let ids = ctx.post_n(&mb, n)?;
    let oldest = |k: usize| ids.iter().take(k).cloned().collect::<Vec<_>>();
    let two = ctx.fetch(&mb, "limit=2")?;
    ensure!(
        ids_of(&two) == oldest(2),
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
            ids_of(&all) == oldest(32),
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
    let [a, b, c]: [String; 3] = ctx
        .post_n(&mb, 3)?
        .try_into()
        .map_err(|_| Fail::Fail("posting failed".into()))?;
    let random_ids = |n: usize| (0..n).map(|_| random_b64::<16>()).collect::<Vec<_>>();
    let r = ctx.ack(&mb, &[a.clone(), c.clone(), random_b64::<16>()])?;
    expect_status(&r, 204, "ack with an unknown id")?;
    ensure!(
        ids_of(&ctx.fetch(&mb, "")?) == [b.clone()],
        "after acking 1st and 3rd, only the 2nd should remain"
    );
    expect_status(&ctx.ack(&mb, &[a, c])?, 204, "repeated ack")?;
    expect_status(&ctx.ack(&mb, &random_ids(256))?, 204, "ack with 256 ids")?;
    let r = ctx.ack(&mb, &random_ids(257))?;
    expect_error(&r, BAD_REQUEST, "ack with 257 ids")?;
    let not_array = mb_req(&mb, "POST", "/ack", mb.read.expose());
    let r = ctx.call(&not_array.raw_json(b"{\"msg_ids\": 5}".to_vec()))?;
    expect_error(&r, BAD_REQUEST, "ack with msg_ids not an array")?;
    ensure!(
        ids_of(&ctx.fetch(&mb, "")?) == [b],
        "the unacknowledged message disappeared"
    );
    Ok(None)
}

fn msg_ttl_clamp(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let max = ctx.info_u64("max_ttl_s").unwrap_or(604_800);
    let ttls = [0, 1, 59, max + 1, 1_000_000_000_000];
    for (i, ttl) in ttls.iter().enumerate() {
        accepted_id(&ctx.post(&mb, &envelope::session_nth(i), Some(*ttl))?)
            .map_err(|e| e.context(format!("ttl_s={ttl}")))?;
    }
    // An unclamped ttl_s of 0 or 1 would have expired by now.
    std::thread::sleep(Duration::from_millis(2_500));
    let left = ctx.fetch(&mb, "")?.len();
    ensure!(
        left == ttls.len(),
        "{left} of {} messages left after 2.5 s: short ttl_s values were not clamped to 60",
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

// ---- Envelope validation -------------------------------------------------------------------

fn env_bad_cbor(ctx: &Ctx) -> CheckRes {
    let valid = envelope::valid(Kind::Session, 1024);
    let mut trailing = valid.clone();
    trailing.push(0x00);
    let truncated = valid.get(..valid.len() - 10).unwrap_or_default().to_vec();
    let mut array = envelope::head(4, 4);
    array.extend([0x01, 0x01, 0x40, 0x40]);
    expect_rejected_envs(
        ctx,
        &[
            ("empty envelope", Vec::new()),
            ("break byte", vec![0xff]),
            ("random bytes", vec![0x1c, 0x5f, 0xff, 0x00, 0x01]),
            ("truncated envelope", truncated),
            ("trailing byte", trailing),
            ("CBOR array instead of map", array),
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
    let valid = envelope::map(&envelope::parts(1, 1, 24, 1024));
    indefinite.extend(valid.get(1..).unwrap_or_default());
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
    let base = || envelope::parts(1, 1, 24, 1024);
    let mut extra = base();
    extra.push((5, Item::Uint(0)));
    let mut missing = base();
    missing.pop();
    let mut no_version = base();
    no_version.remove(0);
    let mut text_key = envelope::map(&base());
    // Replace the map head (4 entries) by 5 and append "x": 0 (text keys sort after uints).
    if let Some(h) = text_key.first_mut() {
        *h = 0xa5;
    }
    text_key.extend([0x61, b'x', 0x00]);
    let n_uint = [
        (1, Item::Uint(1)),
        (2, Item::Uint(1)),
        (3, Item::Uint(7)),
        (4, Item::Bytes(vec![0; 1024])),
    ];
    expect_rejected_envs(
        ctx,
        &[
            ("extra key 5", envelope::map(&extra)),
            ("extra text key", text_key),
            ("missing ct (key 4)", envelope::map(&missing)),
            ("missing version (key 1)", envelope::map(&no_version)),
            ("n as unsigned int", envelope::map(&n_uint)),
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
    let (mut posted, mut skipped) = (Vec::new(), Vec::new());
    let pairing = (
        "pairing envelope".to_owned(),
        envelope::valid(Kind::Pairing, 1024),
    );
    let sessions = BUCKETS.iter().map(|&b| {
        (
            format!("session ct of {b} bytes"),
            envelope::valid(Kind::Session, b),
        )
    });
    for (what, env) in std::iter::once(pairing).chain(sessions) {
        if env.len() > max {
            skipped.push(what);
            continue;
        }
        let id = accepted_id(&ctx.post(&mb, &env, None)?).map_err(|e| e.context(&what))?;
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
    let r = ctx.post(&mb, &env, None)?;
    let code = error_code(&r);
    ensure!(
        matches!(
            (r.status, code.as_deref()),
            (400, Some("bad_request")) | (413, Some("too_large"))
        ),
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
    let valid = b64::encode(&envelope::valid(Kind::Session, 1024));
    // Standard alphabet with padding: '+', '/' and '=' are not base64url.
    let std_b64 = valid.replace('-', "+").replace('_', "/") + "+/==";
    let cases: [(&str, Vec<u8>); 6] = [
        (
            "env with non-base64url characters",
            br#"{"env":"!!!not base64!!!"}"#.to_vec(),
        ),
        (
            "env in the standard base64 alphabet",
            json!({ "env": std_b64 }).to_string().into(),
        ),
        ("missing env", br#"{"ttl_s":3600}"#.to_vec()),
        ("env as a number", br#"{"env":12345}"#.to_vec()),
        ("malformed JSON", b"{\"env\":".to_vec()),
        (
            "ttl_s as a string",
            json!({ "env": valid, "ttl_s": "60" }).to_string().into(),
        ),
    ];
    for (what, body) in cases {
        let r = ctx.call(&mb_req(&mb, "POST", "/messages", mb.write.expose()).raw_json(body))?;
        expect_error(&r, BAD_REQUEST, what)?;
    }
    ensure!(
        ctx.fetch(&mb, "")?.is_empty(),
        "a rejected message was stored"
    );
    Ok(None)
}

fn size_limit(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let oversized = |field: &str| {
        let mut body = format!("{{\"{field}\":\"").into_bytes();
        body.resize(401 * 1024, b'A');
        body.extend(b"\"}");
        body
    };
    let post = mb_req(&mb, "POST", "/messages", mb.write.expose());
    let r = ctx.call(&post.raw_json(oversized("env")))?;
    expect_error(&r, TOO_LARGE, "POST messages with a 401 KiB body")?;
    let create = Req::new("POST", "/v1/mailboxes");
    let r = ctx.call(&create.raw_json(oversized("read_token_hash")))?;
    expect_error(&r, TOO_LARGE, "POST /v1/mailboxes with a 401 KiB body")?;
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
    let ids = ctx.post_n(&mb, usize::try_from(quota).unwrap_or(0))?;
    let r = ctx.post(&mb, &envelope::session_nth(999), None)?;
    let what = format!("message {} into a mailbox with quota {quota}", quota + 1);
    expect_error(&r, MAILBOX_FULL, &what)?;
    ctx.ack_ok(&mb, ids.get(..1).unwrap_or_default())?;
    ctx.post_nth(&mb, 1000)?;
    Ok(None)
}

// ---- Long-polling --------------------------------------------------------------------------

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
    expect_status(&r, 200, "long-poll")?;
    ensure!(
        ids_of(&parse_messages(&r)?) == [id],
        "long-poll did not return the message that arrived"
    );
    let secs = elapsed.as_secs_f64();
    ensure!(
        elapsed < Duration::from_secs(wait.saturating_sub(1)),
        "long-poll with wait={wait} returned after {secs:.1} s; expected right after the message arrived (~1 s)"
    );
    Ok(Some(format!("returned after {secs:.1} s of wait={wait}")))
}

fn poll_timeout(ctx: &Ctx) -> CheckRes {
    let wait = ctx.max_wait_s().min(2);
    let mb = ctx.mailbox()?;
    let started = Instant::now();
    let r = ctx.fetch_raw(&mb, &format!("wait={wait}"))?;
    let elapsed = started.elapsed();
    expect_status(&r, 200, "long-poll")?;
    ensure!(
        parse_messages(&r)?.is_empty(),
        "long-poll on an empty mailbox returned messages"
    );
    let secs = elapsed.as_secs_f64();
    ensure!(
        elapsed + Duration::from_millis(250) >= Duration::from_secs(wait),
        "wait={wait} returned after {secs:.2} s"
    );
    ensure!(
        elapsed < Duration::from_secs(wait + 5),
        "wait={wait} took {secs:.1} s"
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
    let secs = elapsed.as_secs_f64();
    expect_status(&r, 200, "wait=3600")?;
    ensure!(
        elapsed < Duration::from_secs(max + 5),
        "wait=3600 took {secs:.1} s with max_wait_s={max}"
    );
    Ok(Some(format!(
        "returned after {secs:.1} s (max_wait_s={max})"
    )))
}

// ---- Rate limits ---------------------------------------------------------------------------

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
                expect_error(&r, RATE_LIMITED, "rate-limited write")?;
                let header = r.header("retry-after");
                let retry = header
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .ok_or_else(|| {
                        format!("429 without a valid integer Retry-After (got {header:?})")
                    })?;
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

// ---- Push registration ---------------------------------------------------------------------

fn push_url_rules(ctx: &Ctx) -> CheckRes {
    let allow = ctx.gateway_allowlist().unwrap_or_default();
    let base = accepted_gateway(ctx).unwrap_or_else(|| "https://push.example.com/v1/wake".into());
    let host_part = base.strip_prefix("https://").unwrap_or(&base);
    let (host, path) = host_part.split_at(host_part.find('/').unwrap_or(host_part.len()));
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
    expect_gateways_rejected(ctx, &urls)
}

fn push_allowlist(ctx: &Ctx) -> CheckRes {
    let Some(allow) = ctx.gateway_allowlist() else {
        skip!(
            "relay is in open gateway mode: destination checks happen at dispatch (spec 7.3.1 rule 7) and are not observable at registration"
        );
    };
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
    .map(str::to_owned)
    .into();
    // Look-alike hosts of each allowlisted prefix.
    for rest in allow.iter().filter_map(|p| p.strip_prefix("https://")) {
        let host = rest.split('/').next().unwrap_or_default();
        urls.push(format!("https://{host}.evil.example/v1/wake"));
    }
    urls.retain(|u| !allow.iter().any(|p| u.starts_with(p.as_str())));
    expect_gateways_rejected(ctx, &urls)
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
        expect_status(&r, 204, &format!("PUT push ({what}) with {url}"))?;
    }
    let bad = json!({ "push_reg": { "gateway_url": url, "sealed_token": "!!not base64!!" } });
    let r = put_push(ctx, &mb, &bad)?;
    expect_error(&r, BAD_REQUEST, "sealed_token not base64url")?;
    // Registration must not affect message acceptance.
    ctx.post_nth(&mb, 1)?;
    Ok(Some(format!("used {url}")))
}

// ---- DELETE --------------------------------------------------------------------------------

fn delete_semantics(ctx: &Ctx) -> CheckRes {
    let mb = ctx.mailbox()?;
    let delete = |token: &[u8]| ctx.call(&mb_req(&mb, "DELETE", "", token));
    ctx.post_nth(&mb, 1)?;
    expect_error(
        &delete(mb.write.expose())?,
        NOT_FOUND,
        "DELETE with the write token",
    )?;
    ensure!(
        ctx.fetch(&mb, "")?.len() == 1,
        "DELETE with the write token affected the mailbox"
    );
    let r = delete(mb.read.expose())?;
    expect_status(&r, 204, "DELETE with the read token")?;
    ensure!(r.body.is_empty(), "204 with a body");
    expect_error(&ctx.fetch_raw(&mb, "")?, NOT_FOUND, "fetch after DELETE")?;
    let r = ctx.post(&mb, &envelope::session_nth(2), None)?;
    expect_error(&r, NOT_FOUND, "post after DELETE")?;
    expect_error(&delete(mb.read.expose())?, NOT_FOUND, "second DELETE")?;
    Ok(None)
}

// ---- Error model and HTTP behaviour --------------------------------------------------------

/// A representative set of responses: success and error codes across endpoints.
fn sample_responses(ctx: &Ctx) -> Result<Vec<(&'static str, Resp)>, Fail> {
    let mut out = vec![("GET /v1/info", get_info(ctx)?)];
    let (r, read, write) = ctx.create_raw(&Value::Null, ctx.default_method()?)?;
    let mb = Mailbox {
        id: created_id(&r)?,
        read,
        write,
    };
    out.push(("POST /v1/mailboxes (201)", r));
    let r = ctx.post(&mb, &envelope::session_nth(1), None)?;
    let msg = accepted_id(&r)?;
    out.push(("POST messages (202)", r));
    out.push(("GET messages (200)", ctx.fetch_raw(&mb, "")?));
    out.push(("POST ack (204)", ctx.ack(&mb, &[msg])?));
    let unknown = format!("/v1/mailboxes/{}/messages", random_b64::<16>());
    let r = ctx.call(&Req::new("GET", unknown).bearer(&[0; 32]))?;
    out.push(("GET unknown mailbox (404)", r));
    let r = ctx.send(&Req::new("POST", "/v1/mailboxes").raw_json(b"[]".to_vec()))?;
    out.push(("POST /v1/mailboxes malformed (400)", r));
    out.push((
        "POST messages bad envelope (400)",
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
        let ct = r.header("content-type");
        ensure!(
            ct.is_some_and(|c| c.starts_with("application/json")),
            "{what}: content-type {ct:?}"
        );
        checked += 1;
    }
    if ctx.offers("api_key") {
        let req = Req::new("POST", "/v1/mailboxes").header("xchonnect-api-key", BOGUS_KEY);
        let r = ctx.send(&req.json(&json!({})))?;
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

/// `Access-Control-Allow-Origin` must be `*` or [`ORIGIN`].
fn expect_acao(r: &Resp, what: &str) -> Result<(), Fail> {
    let acao = r.header("access-control-allow-origin");
    ensure!(
        acao == Some("*") || acao == Some(ORIGIN),
        "{what}: Access-Control-Allow-Origin is {acao:?}"
    );
    Ok(())
}

fn allows_credentials(r: &Resp) -> bool {
    r.header("access-control-allow-credentials") == Some("true")
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
        expect_acao(&r, &what)?;
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
            !allows_credentials(&r),
            "{what}: Access-Control-Allow-Credentials: true (no credentials are ever involved)"
        );
    }
    Ok(None)
}

fn cors_response(ctx: &Ctx) -> CheckRes {
    let unknown = format!("/v1/mailboxes/{}/messages", random_b64::<16>());
    for (what, req) in [
        ("GET /v1/info", Req::new("GET", "/v1/info")),
        ("404 not_found", Req::new("GET", unknown).bearer(&[1; 32])),
    ] {
        let r = ctx.call(&req.header("origin", ORIGIN))?;
        expect_acao(&r, what)?;
        ensure!(!allows_credentials(&r), "{what}: allows credentials");
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
