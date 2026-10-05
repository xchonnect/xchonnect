//! The checks. Each one pairs its own session, so every check is independent and can be
//! run alone with `--only`.
//!
//! The rule the suite follows: a wallet is judged by what it puts on the relay. "Refused"
//! means an `rpc.response` carrying an error, or nothing at all; it never means a result
//! the dApp could use. Returning *something* that looks like a signature where the spec
//! requires a refusal is always a failure, whatever the wallet called it.

use super::driver::{self, Variant};
use super::spends::{self, WalletKey};
use super::{Ctx, DEFAULT, Profile, SLOW, UriSpecTweak, now, tail};
use crate::report::{CheckInfo, CheckRes, Fail, ensure, skip};
use chia_bls::Signature;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use xchonnect_core::message::{Message, RpcError, RpcOutcome};
use xchonnect_core::rpc::codes;

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

use DEFAULT as D;
use SLOW as S;

checks! {
    "W-PAIR-01" D pair_happy_path "spec 6.3 steps 2-9"
        "the wallet verifies the origin document, replies and completes the handshake";
    "W-ORIGIN-01" D origin_forged_signature "spec 6.3 step 2; 13.4 property 3"
        "a URI signed by a key the domain does not publish is refused";
    "W-ORIGIN-02" D origin_unknown_kid "spec 6.1; 6.3 step 2"
        "a document without the key id the URI names is refused";
    "W-ORIGIN-03" D origin_expired_key "spec 6.1"
        "an origin key that is no longer valid is refused";
    "W-ORIGIN-04" D origin_missing "spec 6.1; 6.3 step 2"
        "a domain that publishes no origin document is refused";
    "W-ORIGIN-05" D origin_malformed "spec 6.1; xchonnect.schema.json"
        "a document that does not match the schema is refused";
    "W-URI-01" D uri_expired "spec 6.2; 6.3 step 2"
        "an expired pairing URI is refused even with a valid origin document";
    "W-URI-02" D uri_tampered "spec 6.2; 6.3 step 2"
        "a URI whose contents the origin signature does not cover is refused";
    "W-SAS-01" D sas_displayed "spec 5.2; 6.3 step 8"
        "the wallet shows the same six-digit code the dApp derives";
    "W-SAS-02" D sas_mismatch_ends "spec 6.3 step 8"
        "a wallet whose user reports different codes ends the session and answers nothing";
    "W-PAIR-02" S pair_confirm_timeout "spec 6.3 step 7"
        "a wallet that gets no session.confirm gives up within five minutes";
    "W-SESSION-01" D session_ping "spec 9.2"
        "session.ping is answered with session.pong";
    "W-END-01" D session_end "spec 9.2; 6.3 step 8"
        "after session.end the wallet sends nothing further";
    "W-MSG-01" D msg_tampered_and_replayed "spec 5.3"
        "a tampered or replayed envelope is ignored and the session survives it";
    "W-MSG-02" D msg_out_of_order "spec 5.3"
        "an envelope whose seq is not above the last accepted one is rejected";
    "W-MSG-03" D msg_expired "spec 5.3"
        "an expired inner message is not acted on";
    "W-RPC-01" D rpc_required_methods "spec 9.1"
        "chainId, connect and getPublicKeys answer as CHIP-0002 requires, with aliases";
    "W-RPC-02" D rpc_unknown_method "spec 9.1"
        "an unknown method is answered with error 4004";
    "W-RPC-03" D rpc_invalid_params "spec 9.1"
        "malformed params are answered with an error, never a signature";
    "W-SIGN-01" D sign_control "spec 11.1 items 1 and 2"
        "a spend of the wallet's own coin is signed with exactly the signatures the spec prescribes";
    "W-SIGN-02" D sign_unexposed_key "spec 9.3; 11.1 item 2"
        "signMessage for a key the wallet never exposed produces no signature";
    "W-SIGN-03" D sign_foreign_coin "spec 11.1 item 2"
        "a request that needs only somebody else's signature produces no signature";
    "W-SIGN-04" D sign_agg_sig_unsafe "spec 11.1 item 2; 9.1"
        "AGG_SIG_UNSAFE is refused by default";
    "W-SIGN-05" D sign_unknown_puzzle "spec 11.1 item 3"
        "a spend of an unrecognised puzzle is not signed blindly";
    "W-LIMIT-01" D limit_per_request "spec 9.3; 11.1 item 5"
        "a spend above the configured per-request limit is refused";
    "W-PARTIAL-01" D partial_unbound "spec 11.2; 13.4 property 4"
        "no partial signature is produced for an unbound multi-party spend";
    "W-PARTIAL-02" D partial_bound "spec 11.2"
        "a bound partial spend is signed and the binding is the only difference";
    "W-REJECT-01" D reject_user "spec 9.1"
        "a request the user declines is answered with 4002 and no signature";
    "W-ROT-01" D rotation "spec 9.2.1"
        "the wallet accepts a key rotation and the session continues in the new epoch";
}

// --- helpers -------------------------------------------------------------------------

/// The error of an `rpc.response`, or `None` when the wallet returned a result.
fn error_of(outcome: &RpcOutcome) -> Option<&RpcError> {
    match outcome {
        RpcOutcome::Error(e) => Some(e),
        RpcOutcome::Result(_) => None,
    }
}

/// The result JSON of an `rpc.response`.
fn result_of(outcome: &RpcOutcome) -> Option<&str> {
    match outcome {
        RpcOutcome::Result(r) => Some(r.as_str()),
        RpcOutcome::Error(_) => None,
    }
}

/// A BLS signature in a `signCoinSpends` / `signMessage` result, if that is what it is.
fn signature_in(result: &str) -> Option<Signature> {
    let hex: String = serde_json::from_str(result).ok()?;
    let bytes = hex::decode(hex.trim_start_matches("0x")).ok()?;
    Signature::from_bytes(&<[u8; 96]>::try_from(bytes).ok()?).ok()
}

/// Require that `outcome` is a refusal. `expected` is the code the spec prescribes; a
/// refusal with another code passes with a note, because refusing is the security
/// requirement and the code is an interoperability one (spec Appendix A records wallets
/// that answer every error as 4001).
fn expect_refusal(
    outcome: &RpcOutcome,
    expected: i64,
    reason: Option<&str>,
    what: &str,
) -> Result<Option<String>, Fail> {
    let Some(e) = error_of(outcome) else {
        let result = result_of(outcome).unwrap_or_default();
        let signed = signature_in(result).is_some();
        return Err(Fail::Fail(format!(
            "{what}, but the wallet answered with a result{}: {}",
            if signed {
                " that is a BLS signature"
            } else {
                ""
            },
            cut(result)
        )));
    };
    let got_reason = e
        .data
        .as_deref()
        .and_then(|d| serde_json::from_str::<Value>(d).ok())
        .and_then(|v| v.get("reason").and_then(Value::as_str).map(str::to_owned));
    let mut notes = Vec::new();
    if e.code != expected {
        notes.push(format!(
            "refused with {} instead of the prescribed {expected}",
            e.code
        ));
    }
    match (reason, got_reason.as_deref()) {
        (Some(want), Some(got)) if got != want => {
            notes.push(format!("error.data reason {got:?}, expected {want:?}"));
        }
        (Some(want), None) => notes.push(format!("no error.data reason {want:?}")),
        _ => {}
    }
    Ok((!notes.is_empty()).then(|| notes.join("; ")))
}

/// Number of `rpc.*` messages received so far. Session messages the wallet sends on its
/// own (`session.permissions`, pongs) must not count when a check asks whether the wallet
/// acted on a particular request.
fn rpc_messages(live: &super::Live) -> usize {
    live.seen
        .iter()
        .filter(|i| {
            matches!(
                i.message,
                Message::RpcResponse { .. } | Message::RpcReceived { .. }
            )
        })
        .count()
}

fn cut(s: &str) -> String {
    let shown: String = s.chars().take(160).collect();
    if s.chars().count() > 160 {
        format!("{shown}…")
    } else {
        shown
    }
}

/// Show the wallet a pairing URI it must refuse, and require that it posts nothing at all
/// to the pairing mailbox.
fn expect_no_reply(
    ctx: &Ctx,
    served: super::Served,
    tweak: UriSpecTweak,
    because: &str,
) -> CheckRes {
    let (mut pairing, mut wallet) = ctx.offer(
        Variant::Normal,
        served,
        &tweak,
        &format!("refuse: {because}"),
    )?;
    let fetches_before = ctx.origin.fetches();
    let started = Instant::now();
    let mut gone = || wallet.exited().is_some();
    let outcome =
        pairing.wait_for_reply_while(&ctx.relay, now, ctx.refusal_timeout(), Some(&mut gone));
    let waited = started.elapsed();
    let output = tail(&wallet.output());
    match outcome {
        Ok(None) => {}
        Ok(Some(_)) => {
            return Err(Fail::Fail(format!(
                "the wallet paired although {because}: it must abort, and must not offer to \
                 continue anyway (spec 6.3 step 2). Wallet output: {output}"
            )));
        }
        Err(Fail::Fail(e)) => {
            return Err(Fail::Fail(format!(
                "the wallet posted to the pairing mailbox although {because}: {e}"
            )));
        }
        Err(skipped) => return Err(skipped),
    }
    if ctx.opts.manual && !driver::confirm("did the wallet refuse and show an error?") {
        return Err(Fail::Fail(format!(
            "the operator reported that the wallet did not refuse although {because}"
        )));
    }
    let fetched = ctx.origin.fetches() > fetches_before;
    let exited = wallet.wait(Duration::from_millis(200));
    Ok(Some(format!(
        "no pairing reply in {:.1?}{}{}",
        waited,
        if fetched {
            "; the wallet did fetch the origin document"
        } else {
            ""
        },
        match exited {
            Some(false) => "; the wallet exited with an error",
            Some(true) => "; the wallet exited",
            None => "",
        }
    )))
}

/// `x=<expiry>` is covered by the origin signature; moving it invalidates the signature
/// without changing anything a syntax check would notice.
fn bump_expiry(uri: &str) -> String {
    let Some((head, rest)) = uri.split_once("&x=") else {
        return uri.to_owned();
    };
    let (value, tail) = rest.split_once('&').unwrap_or((rest, ""));
    let bumped = value
        .parse::<u64>()
        .map_or_else(|_| value.to_owned(), |v| v.saturating_add(1).to_string());
    if tail.is_empty() {
        format!("{head}&x={bumped}")
    } else {
        format!("{head}&x={bumped}&{tail}")
    }
}

/// Learn the wallet's chain, key and whether it signs, in one session (see [`Profile`]).
pub(crate) fn discover(ctx: &Ctx) -> Result<Profile, Fail> {
    let (mut live, _wallet) = ctx.session(Variant::Normal)?;
    let t = ctx.timeout();
    let chain = live.request(&ctx.relay, &now, "chainId", "{}", t)?;
    let chain_id: String = result_of(&chain)
        .and_then(|r| serde_json::from_str(r).ok())
        .ok_or_else(|| {
            Fail::Skip(format!(
                "the wallet did not answer chainId with a JSON string (spec 9.1): {:?}; the \
                 signing checks need to know the chain",
                chain
            ))
        })?;
    let keys = live.request(&ctx.relay, &now, "getPublicKeys", r#"{"limit":1}"#, t)?;
    let first = result_of(&keys)
        .and_then(|r| serde_json::from_str::<Vec<String>>(r).ok())
        .and_then(|v| v.first().cloned())
        .ok_or_else(|| {
            Fail::Skip(format!(
                "the wallet exposed no public key (spec 9.1 getPublicKeys): {keys:?}; the \
                 signing checks cannot build spends for it"
            ))
        })?;
    let key = WalletKey::parse(&first)?;
    // A spend of the wallet's own coin, well below any sane limit: the control that tells
    // the signing checks apart from a wallet that simply refuses everything.
    let case = spends::send(&key, 1_000, 400)?;
    let outcome = live.request(&ctx.relay, &now, "signCoinSpends", &case.params, t)?;
    let control = match (&outcome, result_of(&outcome).and_then(signature_in)) {
        (_, Some(sig)) => case
            .verify_signature(&key, &chain_id, &sig)
            .map(|n| format!("signed {n} AGG_SIG message(s) correctly")),
        (RpcOutcome::Error(e), _) => Err(Fail::Skip(format!(
            "the wallet refused the control spend with {} {}: the suite cannot tell a \
             conforming refusal below from a wallet that refuses every request",
            e.code,
            cut(&e.message)
        ))),
        (RpcOutcome::Result(r), None) => Err(Fail::Fail(format!(
            "signCoinSpends returned {} instead of a BLS signature (spec 9.1)",
            cut(r)
        ))),
    };
    live.finish(&ctx.relay, now(), "conformance profiling done");
    Ok(Profile {
        chain_id,
        key,
        signs: control.is_ok(),
        control: control.clone().unwrap_or_else(|e| match e {
            Fail::Fail(m) | Fail::Skip(m) => m,
        }),
    })
}

/// Run `body` against a session, with the wallet's own key, after profiling.
/// Run `body` against a session in which the wallet's own key is needed, which means the
/// suite has to profile the wallet first (see [`discover`]).
fn with_signing_session(
    ctx: &Ctx,
    body: &dyn Fn(&Ctx, &Profile, &mut super::Live) -> CheckRes,
) -> CheckRes {
    let profile = ctx.profile()?;
    let out = with_session(ctx, &|ctx, live| body(ctx, profile, live));
    // Whether the wallet signs at all decides how much a refusal below is worth.
    match (out, profile.signs) {
        (Ok(note), true) => Ok(note),
        (Ok(note), false) => Ok(join(
            note,
            Some(format!("W-SIGN-01 did not pass: {}", profile.control)),
        )),
        (Err(e), _) => Err(e),
    }
}

/// Run `body` against a session. Used by the checks that need nothing from the wallet
/// but a session, so that they also judge a wallet the suite cannot profile.
fn with_session(ctx: &Ctx, body: &dyn Fn(&Ctx, &mut super::Live) -> CheckRes) -> CheckRes {
    let (mut live, wallet) = ctx.session(Variant::Normal)?;
    let out = body(ctx, &mut live);
    live.finish(&ctx.relay, now(), "conformance check done");
    drop(wallet);
    out
}

fn join(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => Some(format!("{a}; {b}")),
        (a, b) => a.or(b),
    }
}

// --- pairing -------------------------------------------------------------------------

fn pair_happy_path(ctx: &Ctx) -> CheckRes {
    let (mut live, wallet) = ctx.session(Variant::Normal)?;
    let fetched = ctx.origin.fetches();
    let name = live.wallet_name.clone();
    let sas = live.sas.clone();
    live.finish(&ctx.relay, now(), "conformance check done");
    drop(wallet);
    ensure!(
        fetched > 0,
        "the wallet paired without ever fetching {}: it cannot have verified the origin \
         signature (spec 6.1 requires a fresh fetch on every pairing)",
        super::origin::WELL_KNOWN
    );
    Ok(Some(format!(
        "paired as {:?}, SAS {sas}",
        name.unwrap_or_else(|| "<no name given>".to_owned())
    )))
}

fn origin_forged_signature(ctx: &Ctx) -> CheckRes {
    expect_no_reply(
        ctx,
        ctx.dapp.forged_key(),
        UriSpecTweak::default(),
        "the domain publishes a different key, so the URI signature is a forgery",
    )
}

fn origin_unknown_kid(ctx: &Ctx) -> CheckRes {
    expect_no_reply(
        ctx,
        ctx.dapp.unknown_kid(),
        UriSpecTweak::default(),
        "the document does not contain the key id the URI names",
    )
}

fn origin_expired_key(ctx: &Ctx) -> CheckRes {
    expect_no_reply(
        ctx,
        ctx.dapp.expired_key(),
        UriSpecTweak::default(),
        "the origin key's not_after has passed",
    )
}

fn origin_missing(ctx: &Ctx) -> CheckRes {
    expect_no_reply(
        ctx,
        super::Served::NotFound,
        UriSpecTweak::default(),
        "the domain publishes no origin document at all",
    )
}

fn origin_malformed(ctx: &Ctx) -> CheckRes {
    expect_no_reply(
        ctx,
        ctx.dapp.malformed(),
        UriSpecTweak::default(),
        "the document announces an unsupported version",
    )
}

fn uri_expired(ctx: &Ctx) -> CheckRes {
    expect_no_reply(
        ctx,
        ctx.dapp.good(),
        UriSpecTweak {
            // Issued ten minutes ago with the maximum lifetime: expired by five minutes,
            // well beyond the tolerated clock skew.
            issued_secs_ago: 600,
            lifetime_s: 300,
            ..UriSpecTweak::default()
        },
        "the pairing URI expired five minutes ago",
    )
}

fn uri_tampered(ctx: &Ctx) -> CheckRes {
    expect_no_reply(
        ctx,
        ctx.dapp.good(),
        UriSpecTweak {
            tamper: Some(bump_expiry),
            ..UriSpecTweak::default()
        },
        "the URI's expiry was changed after signing, so the signature no longer covers it",
    )
}

fn sas_displayed(ctx: &Ctx) -> CheckRes {
    let (mut live, wallet) = ctx.session(Variant::Normal)?;
    let sas = live.sas.clone();
    let output = wallet.output();
    live.finish(&ctx.relay, now(), "conformance check done");
    if ctx.opts.manual {
        return if driver::confirm(&format!("does the wallet show the code {sas}?")) {
            Ok(Some(format!("the operator confirmed the code {sas}")))
        } else {
            Err(Fail::Fail(format!(
                "the operator reported that the wallet does not show {sas}: the two sides \
                 derived different root keys, or the wallet shows the code wrongly (spec 5.2)"
            )))
        };
    }
    let grouped = match (sas.get(..3), sas.get(3..)) {
        (Some(a), Some(b)) => format!("{a} {b}"),
        _ => sas.clone(),
    };
    if output.contains(&sas) || output.contains(&grouped) {
        return Ok(Some(format!("the wallet printed the code {sas}")));
    }
    skip!(
        "the code {sas} is not in the wallet's output, so the suite cannot see what the \
         wallet displayed; compare it by hand or run with --manual. Output: {}",
        tail(&output)
    )
}

fn sas_mismatch_ends(ctx: &Ctx) -> CheckRes {
    let (mut pairing, wallet) = ctx.offer(
        Variant::SasMismatch,
        ctx.dapp.good(),
        &UriSpecTweak::default(),
        "pair, then report that the codes do not match",
    )?;
    let accepted = pairing
        .wait_for_reply(&ctx.relay, now, ctx.timeout())?
        .ok_or_else(|| {
            Fail::Fail(format!(
                "the wallet did not reply to the pairing URI; wallet output: {}",
                tail(&wallet.output())
            ))
        })?;
    // Up to session.confirm the flow is normal; the wallet's user then says the codes
    // differ, so the wallet must send session.end instead of session.ready.
    let mut live = super::dapp::confirm(&ctx.relay, pairing, accepted, now)?;
    let ready = |l: &super::Live| l.session.peer_ready();
    live.pump(&ctx.relay, &now, ctx.refusal_timeout(), &ready)?;
    let became_ready = ready(&live);
    let ended = live.ended_by_wallet();
    let types = live.types().join(", ");
    live.finish(&ctx.relay, now(), "conformance check done");
    drop(wallet);
    ensure!(
        !became_ready,
        "the wallet sent session.ready although its user reported that the codes do not \
         match: it must end the session and delete it (spec 6.3 step 8). Messages received: \
         [{types}]"
    );
    Ok(Some(if ended {
        "the wallet answered a code mismatch with session.end".to_owned()
    } else {
        format!(
            "the wallet never became active after a code mismatch, but sent no session.end \
             either (spec 6.3 step 8 asks for one); messages received: [{types}]"
        )
    }))
}

fn pair_confirm_timeout(ctx: &Ctx) -> CheckRes {
    let (mut pairing, mut wallet) = ctx.offer(
        Variant::Normal,
        ctx.dapp.good(),
        &UriSpecTweak::default(),
        "pair, then wait in vain for the dApp to confirm",
    )?;
    pairing
        .wait_for_reply(&ctx.relay, now, ctx.timeout())?
        .ok_or_else(|| Fail::Fail("the wallet did not reply to the pairing URI".to_owned()))?;
    // Never send session.confirm. Spec 6.3 step 7: the wallet gives up after five
    // minutes and tells the user the code may already have been used.
    let limit = Duration::from_secs(xchonnect_core::pairing::CONFIRM_TIMEOUT_S + 60);
    match wallet.wait(limit) {
        Some(_) => Ok(Some(format!("the wallet gave up within {limit:?}"))),
        None if ctx.opts.manual => {
            if driver::confirm("did the wallet give up and warn about a used code?") {
                Ok(Some("the operator confirmed the timeout".to_owned()))
            } else {
                Err(Fail::Fail(
                    "the wallet did not give up five minutes after replying (spec 6.3 step 7)"
                        .to_owned(),
                ))
            }
        }
        None => Err(Fail::Fail(format!(
            "the wallet was still running {limit:?} after it replied, with no session.confirm: \
             it must abort and tell the user the pairing code may already have been used \
             (spec 6.3 step 7)"
        ))),
    }
}

// --- session hygiene -----------------------------------------------------------------

fn session_ping(ctx: &Ctx) -> CheckRes {
    let (mut live, _wallet) = ctx.session(Variant::Normal)?;
    let out = live
        .session
        .seal(
            &mut xchonnect_core::crypto::OsEntropy,
            now(),
            Message::SessionPing,
            300,
        )
        .map_err(|e| Fail::Fail(format!("the suite could not seal a ping: {e}")))?;
    ctx.relay.post(&out)?;
    let pong = |l: &super::Live| l.types().iter().any(|t| t == "session.pong");
    live.pump(&ctx.relay, &now, ctx.timeout(), &pong)?;
    let answered = pong(&live);
    let types = live.types().join(", ");
    live.finish(&ctx.relay, now(), "conformance check done");
    ensure!(
        answered,
        "session.ping was not answered with session.pong within {:?} (spec 9.2); messages \
         received: [{types}]",
        ctx.timeout()
    );
    Ok(None)
}

fn session_end(ctx: &Ctx) -> CheckRes {
    let (mut live, mut wallet) = ctx.session(Variant::Normal)?;
    // Nothing of the wallet's is outstanding before the end.
    live.pump(&ctx.relay, &now, Duration::from_secs(1), &|_| false)?;
    live.end(&ctx.relay, now(), "conformance check done");
    // Everything the wallet still posts after session.end is a message for a session it
    // was told is over. A wallet that exits has posted all it ever will, so the wait ends
    // there rather than running out the timeout.
    let started = Instant::now();
    let exited = wallet.wait(ctx.refusal_timeout());
    let waited = started.elapsed();
    let after = live.raw_backlog(&ctx.relay);
    live.cleanup(&ctx.relay);
    ensure!(
        after == 0,
        "the wallet posted {after} more message(s) after session.end (spec 9.2: the session \
         is over and its keys are deleted)"
    );
    Ok(Some(format!(
        "nothing posted in the {:.1?} after session.end{}",
        waited,
        match exited {
            Some(_) => "; the wallet exited",
            None => "",
        }
    )))
}

fn msg_tampered_and_replayed(ctx: &Ctx) -> CheckRes {
    let (mut live, _wallet) = ctx.session(Variant::Normal)?;
    let rng = &mut xchonnect_core::crypto::OsEntropy;
    let request = xchonnect_core::rpc::request("chainId", "{}")
        .map_err(|e| Fail::Fail(format!("the suite built an invalid request: {e}")))?;
    let out = live
        .session
        .seal(rng, now(), request, 300)
        .map_err(|e| Fail::Fail(format!("the suite could not seal the request: {e}")))?;
    // One byte of the ciphertext flipped: the AEAD tag cannot verify any more.
    let mut tampered = out.envelope.clone();
    let last = tampered.len().saturating_sub(1);
    if let Some(b) = tampered.get_mut(last) {
        *b ^= 0x01;
    }
    let baseline = rpc_messages(&live);
    ctx.relay
        .post_raw(&out.mailbox, &out.write_token, &tampered)?;
    std::thread::sleep(ctx.refusal_timeout());
    live.pump(&ctx.relay, &now, Duration::from_secs(1), &|_| false)?;
    ensure!(
        rpc_messages(&live) == baseline,
        "the wallet acted on an envelope whose ciphertext was altered (spec 5.3: decryption \
         failure must be rejected); messages received: [{}]",
        live.types().join(", ")
    );
    // The intact envelope is answered, which shows the session was not torn down.
    ctx.relay.post(&out)?;
    let answered = |l: &super::Live| l.response(&out.id).is_some();
    live.pump(&ctx.relay, &now, ctx.timeout(), &answered)?;
    ensure!(
        answered(&live),
        "after ignoring a tampered envelope the wallet stopped answering: a rejected message \
         must not end the session (spec 5.3)"
    );
    // The same bytes again: already-used seq, so no second answer.
    let before = rpc_messages(&live);
    ctx.relay.post(&out)?;
    std::thread::sleep(ctx.refusal_timeout());
    live.pump(&ctx.relay, &now, Duration::from_secs(1), &|_| false)?;
    let extra = rpc_messages(&live).saturating_sub(before);
    live.finish(&ctx.relay, now(), "conformance check done");
    ensure!(
        extra == 0,
        "the wallet answered a replayed envelope {extra} more time(s) (spec 5.3: seq must be \
         strictly above the last accepted one)"
    );
    Ok(Some(
        "tampered envelope ignored, session survived, replay not answered".to_owned(),
    ))
}

fn msg_out_of_order(ctx: &Ctx) -> CheckRes {
    let (mut live, _wallet) = ctx.session(Variant::Normal)?;
    let rng = &mut xchonnect_core::crypto::OsEntropy;
    let mut seal = |method: &str| {
        xchonnect_core::rpc::request(method, "{}")
            .and_then(|m| live.session.seal(rng, now(), m, 300))
            .map_err(|e| Fail::Fail(format!("the suite could not seal a request: {e}")))
    };
    let first = seal("chainId")?;
    let second = seal("connect")?;
    // Posted in reverse: the wallet accepts seq n+1 and must then reject seq n.
    ctx.relay.post(&second)?;
    let got_second = |l: &super::Live| l.response(&second.id).is_some();
    live.pump(&ctx.relay, &now, ctx.timeout(), &got_second)?;
    ensure!(
        got_second(&live),
        "the wallet did not answer the newer of two requests within {:?}",
        ctx.timeout()
    );
    ctx.relay.post(&first)?;
    std::thread::sleep(ctx.refusal_timeout());
    live.pump(&ctx.relay, &now, Duration::from_secs(1), &|_| false)?;
    let answered_old = live.response(&first.id).is_some();
    live.finish(&ctx.relay, now(), "conformance check done");
    ensure!(
        !answered_old,
        "the wallet answered a message whose seq was below one it had already accepted \
         (spec 5.3): replay protection is not enforced"
    );
    Ok(None)
}

fn msg_expired(ctx: &Ctx) -> CheckRes {
    let (mut live, _wallet) = ctx.session(Variant::Normal)?;
    let rng = &mut xchonnect_core::crypto::OsEntropy;
    let request = xchonnect_core::rpc::request("chainId", "{}")
        .map_err(|e| Fail::Fail(format!("the suite built an invalid request: {e}")))?;
    // Issued ten minutes ago with a one-second lifetime: `exp` is long past.
    let out = live
        .session
        .seal(rng, now().saturating_sub(600), request, 1)
        .map_err(|e| Fail::Fail(format!("the suite could not seal the request: {e}")))?;
    ctx.relay.post(&out)?;
    std::thread::sleep(ctx.refusal_timeout());
    live.pump(&ctx.relay, &now, Duration::from_secs(1), &|_| false)?;
    let outcome = live.response(&out.id);
    live.finish(&ctx.relay, now(), "conformance check done");
    match outcome {
        None => Ok(Some("the expired request was ignored".to_owned())),
        Some(o) => {
            let note = expect_refusal(
                &o,
                codes::REQUEST_EXPIRED,
                None,
                "the request's exp was ten minutes in the past, so it must be rejected \
                 (spec 5.3)",
            )?;
            Ok(join(
                Some("answered with an error instead of ignoring it".to_owned()),
                note,
            ))
        }
    }
}

// --- the RPC layer -------------------------------------------------------------------

fn rpc_required_methods(ctx: &Ctx) -> CheckRes {
    let (mut live, _wallet) = ctx.session(Variant::Normal)?;
    let t = ctx.timeout();
    let mut problems = Vec::new();
    let chain = live.request(&ctx.relay, &now, "chainId", "{}", t)?;
    let chain_id: Option<String> = result_of(&chain).and_then(|r| serde_json::from_str(r).ok());
    if chain_id.as_deref().is_none_or(str::is_empty) {
        problems.push(format!(
            "chainId answered {chain:?}, expected a JSON string"
        ));
    }
    let connect = live.request(&ctx.relay, &now, "connect", r#"{"eager":false}"#, t)?;
    if result_of(&connect).and_then(|r| serde_json::from_str::<bool>(r).ok()) != Some(true) {
        problems.push(format!("connect answered {connect:?}, expected true"));
    }
    // The `chip0002_` alias must be accepted for every method (spec 9.1).
    let aliased = live.request(
        &ctx.relay,
        &now,
        "chip0002_getPublicKeys",
        r#"{"limit":2}"#,
        t,
    )?;
    let keys: Option<Vec<String>> = result_of(&aliased).and_then(|r| serde_json::from_str(r).ok());
    match &keys {
        Some(k) if k.iter().all(|s| WalletKey::parse(s).is_ok()) => {}
        _ => problems.push(format!(
            "chip0002_getPublicKeys answered {aliased:?}, expected an array of hex keys"
        )),
    }
    let receipts = live
        .seen
        .iter()
        .filter(|i| matches!(i.message, Message::RpcReceived { .. }))
        .count();
    live.finish(&ctx.relay, now(), "conformance check done");
    ensure!(problems.is_empty(), "{}", problems.join("; "));
    Ok(Some(format!(
        "chainId {}, {} key(s) exposed, {receipts} rpc.received receipt(s)",
        chain_id.unwrap_or_default(),
        keys.as_ref().map_or(0, Vec::len)
    )))
}

fn rpc_unknown_method(ctx: &Ctx) -> CheckRes {
    let (mut live, _wallet) = ctx.session(Variant::Normal)?;
    let outcome = live.request(
        &ctx.relay,
        &now,
        "chia_conformanceNoSuchMethod",
        "{}",
        ctx.timeout(),
    )?;
    live.finish(&ctx.relay, now(), "conformance check done");
    let Some(e) = error_of(&outcome) else {
        return Err(Fail::Fail(format!(
            "an unknown method was answered with a result: {}",
            cut(result_of(&outcome).unwrap_or_default())
        )));
    };
    ensure!(
        e.code == codes::METHOD_NOT_FOUND,
        "an unknown method was answered with code {} instead of {} (spec 9.1)",
        e.code,
        codes::METHOD_NOT_FOUND
    );
    Ok(None)
}

fn rpc_invalid_params(ctx: &Ctx) -> CheckRes {
    let (mut live, _wallet) = ctx.session(Variant::Normal)?;
    let t = ctx.timeout();
    // No `message`, no `publicKey`, and a coinSpends list that is not a list.
    let a = live.request(&ctx.relay, &now, "signMessage", r#"{"nonsense":true}"#, t)?;
    let b = live.request(
        &ctx.relay,
        &now,
        "signCoinSpends",
        r#"{"coinSpends":"not an array"}"#,
        t,
    )?;
    live.finish(&ctx.relay, now(), "conformance check done");
    let notes = [
        expect_refusal(
            &a,
            codes::INVALID_PARAMS,
            None,
            "signMessage had no message",
        )?,
        expect_refusal(
            &b,
            codes::INVALID_PARAMS,
            None,
            "coinSpends was a string instead of an array",
        )?,
    ];
    Ok(notes
        .into_iter()
        .flatten()
        .reduce(|a, b| format!("{a}; {b}")))
}

// --- signing safety ------------------------------------------------------------------

fn sign_control(ctx: &Ctx) -> CheckRes {
    let p = ctx.profile()?;
    if p.signs {
        Ok(Some(format!("{} on {}", p.control, p.chain_id)))
    } else {
        skip!("{}", p.control)
    }
}

fn sign_unexposed_key(ctx: &Ctx) -> CheckRes {
    // Deliberately independent of the wallet's own key: a wallet that hands out
    // signatures for any key it is asked about must fail here even if the suite could
    // not profile it.
    with_session(ctx, &|ctx, live| {
        let stranger = spends::other_key()?;
        let params = json!({
            "message": "0x48656c6c6f",
            "publicKey": format!("0x{}", hex::encode(stranger.to_bytes())),
        })
        .to_string();
        let outcome = live.request(&ctx.relay, &now, "signMessage", &params, ctx.timeout())?;
        expect_refusal(
            &outcome,
            codes::UNAUTHORIZED,
            None,
            "signMessage named a key the wallet never exposed to this dApp (spec 9.3)",
        )
    })
}

fn sign_foreign_coin(ctx: &Ctx) -> CheckRes {
    with_session(ctx, &|ctx, live| {
        let case = spends::foreign_coin()?;
        let outcome = live.request(
            &ctx.relay,
            &now,
            "signCoinSpends",
            &case.params,
            ctx.timeout(),
        )?;
        if let Some(sig) = result_of(&outcome).and_then(signature_in) {
            ensure!(
                sig == Signature::default(),
                "the wallet returned a signature for a request that only needs another \
                 party's key (spec 11.1 item 2)"
            );
            return Ok(Some(
                "answered with the identity signature, which signs nothing".to_owned(),
            ));
        }
        expect_refusal(
            &outcome,
            codes::NO_SECRET_KEY,
            None,
            "the request spends a coin the wallet does not own and needs a key it does not \
             hold, with partialSign false",
        )
    })
}

fn sign_agg_sig_unsafe(ctx: &Ctx) -> CheckRes {
    with_signing_session(ctx, &|ctx, p, live| {
        let case = spends::agg_sig_unsafe(&p.key)?;
        let outcome = live.request(
            &ctx.relay,
            &now,
            "signCoinSpends",
            &case.params,
            ctx.timeout(),
        )?;
        expect_refusal(
            &outcome,
            codes::UNAUTHORIZED,
            Some("agg_sig_unsafe"),
            "the spend asks for an AGG_SIG_UNSAFE signature, which is valid in any context \
             and must be refused unless the user explicitly allowed it (spec 11.1 item 2)",
        )
    })
}

fn sign_unknown_puzzle(ctx: &Ctx) -> CheckRes {
    with_signing_session(ctx, &|ctx, p, live| {
        let case = spends::unknown_puzzle(&p.key)?;
        let outcome = live.request(
            &ctx.relay,
            &now,
            "signCoinSpends",
            &case.params,
            ctx.timeout(),
        )?;
        expect_refusal(
            &outcome,
            codes::UNSUPPORTED_CONTENT,
            None,
            "the request spends a puzzle the wallet cannot decode, so it cannot show the user \
             what it does (spec 11.1 item 3)",
        )
    })
}

fn limit_per_request(ctx: &Ctx) -> CheckRes {
    with_signing_session(ctx, &|ctx, p, live| {
        // session.permissions follows session.ready, so give it a moment to arrive.
        let announced = |l: &super::Live| l.permissions.is_some();
        live.pump(&ctx.relay, &now, Duration::from_secs(3), &announced)?;
        let announced = live
            .permissions
            .as_ref()
            .and_then(|x| x.limits.as_ref())
            .and_then(|l| l.per_request_mojos.as_deref())
            .and_then(|v| v.parse::<u128>().ok());
        let Some(limit) = announced.or(ctx.opts.xch_per_request_limit) else {
            skip!(
                "the wallet announced no per-request XCH limit in session.permissions; \
                 configure one in the wallet and pass --xch-per-request-limit <mojos> so the \
                 suite can check that it is enforced (spec 9.3)"
            );
        };
        let amount = u64::try_from(limit.saturating_add(1_000)).map_err(|_| {
            Fail::Skip("the configured limit is larger than a coin can hold".to_owned())
        })?;
        let case = spends::send(&p.key, amount, 0)?;
        let loss = case.guaranteed_loss(&p.key)?;
        ensure!(
            loss > limit,
            "the suite built a spend losing {loss} mojos, which is not above the limit {limit}"
        );
        let outcome = live.request(
            &ctx.relay,
            &now,
            "signCoinSpends",
            &case.params,
            ctx.timeout(),
        )?;
        let note = expect_refusal(
            &outcome,
            codes::LIMIT_EXCEEDED,
            Some("per_request"),
            &format!(
                "the request loses {loss} mojos for sure, above the per-request limit of \
                 {limit} (spec 9.3, 11.1 item 5)"
            ),
        )?;
        Ok(join(Some(format!("limit {limit}, request {loss}")), note))
    })
}

fn partial_unbound(ctx: &Ctx) -> CheckRes {
    with_signing_session(ctx, &|ctx, p, live| {
        let case = spends::partial_offer(&p.key, 1_000, 500, false)?;
        let outcome = live.request(
            &ctx.relay,
            &now,
            "signCoinSpends",
            &case.params,
            ctx.timeout(),
        )?;
        if let Some(sig) = result_of(&outcome).and_then(signature_in) {
            // A partial signature here is the exact failure invariant 4 forbids.
            let valid = case.verify_signature(&p.key, &p.chain_id, &sig).is_ok();
            return Err(Fail::Fail(format!(
                "the wallet produced a partial signature for a spend that is not bound to the \
                 counterparty's payment (spec 11.2, invariant 13.4.4): the counterparty can \
                 take the 1000 mojos and drop the 500 it owes. The signature {} the request's \
                 AGG_SIG messages",
                if valid { "matches" } else { "does not match" }
            )));
        }
        expect_refusal(
            &outcome,
            codes::UNAUTHORIZED,
            Some("unbound_partial"),
            "the user's spend does not assert the counterparty's settlement payment",
        )
    })
}

fn partial_bound(ctx: &Ctx) -> CheckRes {
    with_signing_session(ctx, &|ctx, p, live| {
        let case = spends::partial_offer(&p.key, 1_000, 500, true)?;
        let outcome = live.request(
            &ctx.relay,
            &now,
            "signCoinSpends",
            &case.params,
            ctx.timeout(),
        )?;
        match (&outcome, result_of(&outcome).and_then(signature_in)) {
            (_, Some(sig)) => {
                let n = case.verify_signature(&p.key, &p.chain_id, &sig)?;
                Ok(Some(format!("signed {n} AGG_SIG message(s) correctly")))
            }
            (RpcOutcome::Error(e), _) if e.code == codes::METHOD_NOT_FOUND => skip!(
                "the wallet does not support partialSign ({} {}); W-PARTIAL-01 still applies",
                e.code,
                cut(&e.message)
            ),
            (RpcOutcome::Error(e), _) => skip!(
                "the wallet refused a correctly bound partial spend with {} {}{}: it is safe \
                 but stricter than spec 11.2, and W-PARTIAL-01 cannot distinguish it from a \
                 wallet that refuses every partial request",
                e.code,
                cut(&e.message),
                e.data
                    .as_deref()
                    .map_or(String::new(), |d| format!(" {}", cut(d)))
            ),
            (RpcOutcome::Result(r), None) => Err(Fail::Fail(format!(
                "signCoinSpends returned {} instead of a BLS signature (spec 9.1)",
                cut(r)
            ))),
        }
    })
}

fn reject_user(ctx: &Ctx) -> CheckRes {
    let profile = ctx.profile()?;
    let (mut live, wallet) = ctx.session(Variant::Reject)?;
    let params = json!({
        "message": "0x48656c6c6f",
        "publicKey": profile.key.hex,
    })
    .to_string();
    let outcome = live.request(&ctx.relay, &now, "signMessage", &params, ctx.timeout());
    live.finish(&ctx.relay, now(), "conformance check done");
    drop(wallet);
    let note = expect_refusal(
        &outcome?,
        codes::USER_REJECTED,
        None,
        "the wallet's user declined the request",
    )?;
    Ok(note)
}

// --- rotation ------------------------------------------------------------------------

fn rotation(ctx: &Ctx) -> CheckRes {
    let (mut live, _wallet) = ctx.session(Variant::Normal)?;
    let rng = &mut xchonnect_core::crypto::OsEntropy;
    let fresh = ctx.relay.create_mailbox()?;
    live.track(&fresh);
    let before = live.session.epoch();
    let offer = live
        .session
        .begin_rotation(
            rng,
            now(),
            fresh.id,
            fresh.read.clone(),
            fresh.write.clone(),
        )
        .map_err(|e| Fail::Fail(format!("the suite could not offer a rotation: {e}")))?;
    ctx.relay.post(&offer)?;
    let rotated = |l: &super::Live| l.session.epoch() > before;
    live.pump(&ctx.relay, &now, ctx.timeout(), &rotated)?;
    ensure!(
        rotated(&live),
        "the wallet did not accept the rotation offer within {:?} (spec 9.2.1); messages \
         received: [{}]",
        ctx.timeout(),
        live.types().join(", ")
    );
    // The session has to keep working under the new epoch keys.
    let outcome = live.request(&ctx.relay, &now, "chainId", "{}", ctx.timeout());
    let epoch = live.session.epoch();
    live.finish(&ctx.relay, now(), "conformance check done");
    let outcome = outcome?;
    ensure!(
        result_of(&outcome).is_some(),
        "after the rotation chainId was answered with {outcome:?} instead of a result \
         (spec 9.2.1: seq continues and the session carries on)"
    );
    Ok(Some(format!("epoch {before} -> {epoch}")))
}
