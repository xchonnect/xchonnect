//! Minimal command-line Xchonnect wallet for development and interop testing.
//!
//! **It holds no keys and never signs anything real.** Signing requests are answered
//! with the BLS identity signature (`0xc000…`) so dApp flows can be exercised end to end.
//!
//! ```text
//! xchonnect-wallet-cli pair '<xchonnect:v1?... URI>' [--dev] [--auto-approve] [--name NAME]
//! ```

// `serde_json::Value` indexing returns `Null` for missing keys and every written value
// is an object literal, so indexing cannot panic here.
#![allow(clippy::indexing_slicing)]

use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use xchonnect_core::crypto::{MailboxId, OsEntropy, Token};
use xchonnect_core::domain::display_domain;
use xchonnect_core::message::{Message, RotatePhase, WalletMeta};
use xchonnect_core::origin::{MAX_DOCUMENT_BYTES, OriginDocument};
use xchonnect_core::pairing::{VerifiedUri, WalletPairing};
use xchonnect_core::rpc::{self, codes};
use xchonnect_core::session::{Outgoing, Session};
use xchonnect_core::uri::{PairingUri, ParseOptions};
use xchonnect_core::{b64, pow};

type Res<T> = Result<T, String>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct Opts {
    uri: String,
    dev: bool,
    auto: bool,
    name: String,
}

fn parse_args() -> Res<Opts> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("pair") {
        return Err(USAGE.into());
    }
    let mut o = Opts {
        uri: String::new(),
        dev: false,
        auto: false,
        name: "CLI Test Wallet".into(),
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "--dev" => o.dev = true,
            "--auto-approve" => o.auto = true,
            "--name" => o.name = args.next().ok_or("--name needs a value")?,
            s if o.uri.is_empty() && !s.starts_with("--") => o.uri = s.to_owned(),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    if o.uri.is_empty() {
        return Err(USAGE.into());
    }
    Ok(o)
}

const USAGE: &str =
    "usage: xchonnect-wallet-cli pair '<pairing URI>' [--dev] [--auto-approve] [--name NAME]";

// ---------------------------------------------------------------------------
// Relay client
// ---------------------------------------------------------------------------

struct Relay {
    base: String,
    agent: ureq::Agent,
}

impl Relay {
    fn new(base: &str) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(40)))
            .build()
            .into();
        Relay {
            base: base.to_owned(),
            agent,
        }
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&Token>,
        body: Option<Value>,
    ) -> Res<(u16, Value)> {
        let url = format!("{}{path}", self.base);
        let auth = token.map(|t| format!("Bearer {}", b64::encode(t.expose())));
        let resp = match (method, body) {
            ("GET", _) => {
                let mut r = self.agent.get(&url);
                if let Some(a) = &auth {
                    r = r.header("authorization", a);
                }
                r.call()
            }
            ("DELETE", _) => {
                let mut r = self.agent.delete(&url);
                if let Some(a) = &auth {
                    r = r.header("authorization", a);
                }
                r.call()
            }
            (_, body) => {
                let mut r = self
                    .agent
                    .post(&url)
                    .header("content-type", "application/json");
                if let Some(a) = &auth {
                    r = r.header("authorization", a);
                }
                r.send(body.unwrap_or(Value::Null).to_string())
            }
        }
        .map_err(|e| format!("relay request failed: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp
            .into_body()
            .read_to_string()
            .map_err(|e| e.to_string())?;
        let v = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        };
        Ok((status, v))
    }

    fn ok(
        &self,
        method: &str,
        path: &str,
        token: Option<&Token>,
        body: Option<Value>,
    ) -> Res<Value> {
        let (st, v) = self.call(method, path, token, body)?;
        if (200..300).contains(&st) {
            Ok(v)
        } else {
            Err(format!(
                "relay error {st} {}",
                v["error"].as_str().unwrap_or("?")
            ))
        }
    }

    fn create_mailbox(
        &self,
        read: &Token,
        write: &Token,
        ticket: Option<&[u8; 32]>,
    ) -> Res<MailboxId> {
        let info = self.ok("GET", "/v1/info", None, None)?;
        let methods: Vec<&str> = info["mailbox_creation"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let mut body = json!({ "read_token_hash": b64::encode(&read.hash()), "write_token_hash": b64::encode(&write.hash()) });
        if let (Some(t), true) = (ticket, methods.contains(&"ticket")) {
            body["ticket"] = json!(b64::encode(t));
        } else if methods.contains(&"pow") {
            let c = self.ok("POST", "/v1/challenge", None, None)?;
            let ch = c["challenge"].as_str().ok_or("bad challenge")?;
            let nonce = pow::solve(&b64::decode(ch).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            body["pow"] = json!({ "challenge": ch, "nonce": b64::encode(&nonce) });
        }
        let v = self.ok("POST", "/v1/mailboxes", None, Some(body))?;
        MailboxId::from_b64(v["mailbox_id"].as_str().ok_or("no mailbox id")?)
            .map_err(|e| e.to_string())
    }

    fn post(&self, out: &Outgoing) -> Res<()> {
        self.ok(
            "POST",
            &format!("/v1/mailboxes/{}/messages", out.mailbox.to_b64()),
            Some(&out.write_token),
            Some(json!({ "env": b64::encode(&out.envelope) })),
        )?;
        Ok(())
    }

    fn fetch(&self, mbx: &MailboxId, read: &Token, wait: u64) -> Res<Vec<(String, Vec<u8>)>> {
        let v = self.ok(
            "GET",
            &format!("/v1/mailboxes/{}/messages?wait={wait}", mbx.to_b64()),
            Some(read),
            None,
        )?;
        let mut out = Vec::new();
        for m in v["messages"].as_array().cloned().unwrap_or_default() {
            let id = m["msg_id"].as_str().unwrap_or_default().to_owned();
            let env =
                b64::decode(m["env"].as_str().unwrap_or_default()).map_err(|e| e.to_string())?;
            out.push((id, env));
        }
        Ok(out)
    }

    fn ack(&self, mbx: &MailboxId, read: &Token, ids: &[String]) -> Res<()> {
        if !ids.is_empty() {
            self.ok(
                "POST",
                &format!("/v1/mailboxes/{}/ack", mbx.to_b64()),
                Some(read),
                Some(json!({ "msg_ids": ids })),
            )?;
        }
        Ok(())
    }

    fn delete(&self, mbx: &MailboxId, read: &Token) {
        let _ = self.call(
            "DELETE",
            &format!("/v1/mailboxes/{}", mbx.to_b64()),
            Some(read),
            None,
        );
    }
}

fn fetch_origin(domain: &str, dev: bool) -> Res<OriginDocument> {
    let scheme = if dev && domain.starts_with("localhost") {
        "http"
    } else {
        "https"
    };
    let url = format!("{scheme}://{domain}/.well-known/xchonnect.json");
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let resp = agent
        .get(&url)
        .call()
        .map_err(|e| format!("cannot fetch {url}: {e}"))?;
    let body = resp
        .into_body()
        .with_config()
        .limit(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_vec()
        .map_err(|e| format!("origin document: {e}"))?;
    OriginDocument::parse(&body).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Wallet
// ---------------------------------------------------------------------------

fn ask(prompt: &str, auto: bool) -> bool {
    if auto {
        println!("{prompt} [auto-approved]");
        return true;
    }
    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    matches!(line.trim(), "y" | "Y" | "yes")
}

/// Test answers as JSON text, or `(code, message)` errors. The CLI holds no keys:
/// signatures are the BLS identity element.
fn answer(method: &str, params: &str, auto: bool) -> Result<String, (i64, &'static str)> {
    match rpc::canonical_method(method) {
        "chainId" => Ok(json!("testnet11").to_string()),
        "connect" => Ok("true".into()),
        "getPublicKeys" => Ok(json!([format!("0x{}", "ab".repeat(48))]).to_string()),
        "signMessage" | "signCoinSpends" => {
            let shown: String = params.chars().take(400).collect();
            println!("  params: {shown}");
            if ask(
                &format!("  Approve {method}? (test wallet: returns the identity signature)"),
                auto,
            ) {
                Ok(json!(format!("0xc0{}", "00".repeat(95))).to_string())
            } else {
                Err((codes::USER_REJECTED, "user rejected request"))
            }
        }
        _ => Err((codes::METHOD_NOT_FOUND, "method not found")),
    }
}

fn run(o: Opts) -> Res<()> {
    let opts = ParseOptions {
        developer_mode: o.dev,
    };
    let uri = PairingUri::parse(&o.uri, opts).map_err(|e| e.to_string())?;
    let doc = fetch_origin(&uri.domain, o.dev)?;
    let shown = display_domain(&uri.domain);
    let verified = VerifiedUri::new(uri, &doc, now())
        .map_err(|e| format!("verification failed, aborting: {e}"))?;
    println!(
        "Verified dApp: {} ({})",
        verified.dapp_name(),
        shown.unicode
    );
    if shown.unicode != shown.ascii {
        println!("  ASCII form: {}", shown.ascii);
    }
    for w in &shown.warnings {
        println!("  WARNING: {w:?} — check the address carefully");
    }
    if !ask("Pair with this dApp?", o.auto) {
        return Err("pairing declined".into());
    }
    let relay = Relay::new(&verified.uri().relay);
    let (read, write) = (Token::random(&mut OsEntropy), Token::random(&mut OsEntropy));
    let mbx = relay.create_mailbox(&read, &write, verified.uri().ticket.as_ref())?;
    let meta = WalletMeta {
        name: Some(o.name.clone()),
        ..Default::default()
    };
    let (pairing, reply) = WalletPairing::reply(
        &mut OsEntropy,
        now(),
        &verified,
        mbx,
        read.clone(),
        write,
        Some(meta),
    )
    .map_err(|e| e.to_string())?;
    relay.post(&reply).map_err(|e| {
        if e.contains("not_found") {
            "this pairing code was already used or expired; another device may have paired with it"
                .to_owned()
        } else {
            e
        }
    })?;
    println!("SAS: {}", pairing.sas());
    let _ = std::io::stdout().flush();

    // Wait for session.confirm (spec 6.3 step 7).
    let mut session: Option<Session> = None;
    while session.is_none() {
        if pairing.timed_out(now()) {
            return Err(
                "the dApp did not confirm in time; the code may have been used by another device"
                    .into(),
            );
        }
        let msgs = relay.fetch(&mbx, &read, 5)?;
        let mut ids = Vec::new();
        for (id, env) in msgs {
            ids.push(id);
            if session.is_none() {
                session = pairing.on_confirm(now(), &env).ok();
            }
        }
        relay.ack(&mbx, &read, &ids)?;
    }
    let mut s = session.ok_or("no session")?;
    if !ask(&format!("Does the dApp show {}?", pairing.sas()), o.auto) {
        let end = s
            .reject_sas(&mut OsEntropy, now())
            .map_err(|e| e.to_string())?;
        relay.post(&end)?;
        return Err("codes did not match; session ended".into());
    }
    if let Some(ready) = s
        .confirm_sas(
            &mut OsEntropy,
            now(),
            Some(WalletMeta {
                name: Some(o.name.clone()),
                ..Default::default()
            }),
        )
        .map_err(|e| e.to_string())?
    {
        relay.post(&ready)?;
    }
    println!("Paired. Waiting for requests (Ctrl-C to quit)...");
    serve(&relay, &mut s, o.auto)
}

fn serve(relay: &Relay, s: &mut Session, auto: bool) -> Res<()> {
    loop {
        let mut boxes = Vec::new();
        if let Some((m, t)) = s.draining_mailbox() {
            boxes.push((m, t.clone(), true));
        }
        boxes.push((s.own_mailbox(), s.own_read_token().clone(), false));
        for (mbx, read, draining) in boxes {
            let msgs = relay.fetch(&mbx, &read, if draining { 0 } else { 20 })?;
            if draining && msgs.is_empty() {
                if let Some(r) = s.finish_drain() {
                    relay.delete(&r.mailbox, &r.read_token);
                }
                continue;
            }
            let mut ids = Vec::new();
            for (id, env) in msgs {
                let inner = match s.open(now(), &mbx, &env) {
                    Ok(i) => i,
                    Err(e) => {
                        eprintln!("ignored message: {e}");
                        ids.push(id);
                        continue;
                    }
                };
                ids.push(id);
                match inner.message {
                    Message::RpcRequest { method, params } => {
                        println!("Request {method}");
                        let receipt = s
                            .seal(
                                &mut OsEntropy,
                                now(),
                                Message::RpcReceived {
                                    request_id: inner.id,
                                },
                                3600,
                            )
                            .map_err(|e| e.to_string())?;
                        relay.post(&receipt)?;
                        let msg = match answer(&method, &params, auto) {
                            Ok(result) => rpc::result(inner.id, &result),
                            Err((code, text)) => rpc::error(inner.id, code, text, None),
                        }
                        .map_err(|e| e.to_string())?;
                        let out = s
                            .seal(&mut OsEntropy, now(), msg, 3600)
                            .map_err(|e| e.to_string())?;
                        relay.post(&out)?;
                        println!("  answered");
                    }
                    Message::SessionRotate(r) if r.phase == RotatePhase::Offer => {
                        let (nr, nw) =
                            (Token::random(&mut OsEntropy), Token::random(&mut OsEntropy));
                        let nm = relay.create_mailbox(&nr, &nw, None)?;
                        let (accept, abandoned) = s
                            .accept_rotation(&mut OsEntropy, now(), &r, nm, nr, nw)
                            .map_err(|e| e.to_string())?;
                        if let Some(a) = abandoned {
                            relay.delete(&a.mailbox, &a.read_token);
                        }
                        relay.post(&accept)?;
                        println!("Rotated to epoch {}", s.epoch());
                    }
                    Message::SessionPing => {
                        let pong = s
                            .seal(&mut OsEntropy, now(), Message::SessionPong, 300)
                            .map_err(|e| e.to_string())?;
                        relay.post(&pong)?;
                    }
                    Message::SessionEnd { reason } => {
                        relay.ack(&mbx, &read, &ids)?;
                        relay.delete(&s.own_mailbox(), s.own_read_token());
                        println!("Session ended by dApp ({})", reason.unwrap_or_default());
                        return Ok(());
                    }
                    other => println!("Message {}", other.type_name()),
                }
            }
            relay.ack(&mbx, &read, &ids)?;
        }
    }
}

fn main() {
    let result = parse_args().and_then(run);
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
