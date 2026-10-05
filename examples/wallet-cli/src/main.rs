//! Minimal command-line Xchonnect wallet for development and interop testing.
//!
//! By default **it holds no keys and never signs anything real**: signing requests are
//! answered with the BLS identity signature (`0xc000…`) so dApp flows can be exercised.
//! With `--dev-key <seed>` it derives a development key and answers through
//! `xchonnect-wallet-kit` (simulation, policy, limits, approval, real BLS signatures).
//! Development keys from a command-line argument are for testnet only.
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
use xchonnect_wallet_kit::{self as kit, DailySpend, PermissionError};

type Res<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

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
    dev_key: Option<String>,
    network: String,
    /// Per-request XCH limit for this dApp, in mojos (spec 9.3).
    limit_per_request: Option<u128>,
    /// Per-day XCH limit for this dApp, in mojos.
    limit_per_day: Option<u128>,
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
        dev_key: None,
        network: "testnet11".into(),
        limit_per_request: None,
        limit_per_day: None,
    };
    let mojos = |v: Option<String>, flag: &str| -> Res<u128> {
        v.ok_or_else(|| format!("{flag} needs a number of mojos"))?
            .parse()
            .map_err(|_| format!("{flag} needs a whole number of mojos"))
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "--dev" => o.dev = true,
            "--auto-approve" => o.auto = true,
            "--name" => o.name = args.next().ok_or("--name needs a value")?,
            "--dev-key" => o.dev_key = Some(args.next().ok_or("--dev-key needs a seed")?),
            "--network" => o.network = args.next().ok_or("--network needs a value")?,
            "--limit-xch-per-request" => {
                o.limit_per_request = Some(mojos(args.next(), "--limit-xch-per-request")?);
            }
            "--limit-xch-per-day" => {
                o.limit_per_day = Some(mojos(args.next(), "--limit-xch-per-day")?);
            }
            s if o.uri.is_empty() && !s.starts_with("--") => o.uri = s.to_owned(),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    if o.uri.is_empty() {
        return Err(USAGE.into());
    }
    Ok(o)
}

const USAGE: &str = "usage: xchonnect-wallet-cli pair '<pairing URI>' [--dev] [--auto-approve] [--name NAME] [--dev-key SEED (testnet11 only)] [--network testnet11|mainnet] [--limit-xch-per-request MOJOS] [--limit-xch-per-day MOJOS]";

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
        let resp = match method {
            "GET" | "DELETE" => {
                let mut r = if method == "GET" {
                    self.agent.get(&url)
                } else {
                    self.agent.delete(&url)
                };
                if let Some(a) = &auth {
                    r = r.header("authorization", a);
                }
                r.call()
            }
            _ => {
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
        let text = resp.into_body().read_to_string().map_err(err)?;
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
            let nonce = pow::solve(&b64::decode(ch).map_err(err)?).map_err(err)?;
            body["pow"] = json!({ "challenge": ch, "nonce": b64::encode(&nonce) });
        }
        let v = self.ok("POST", "/v1/mailboxes", None, Some(body))?;
        MailboxId::from_b64(v["mailbox_id"].as_str().ok_or("no mailbox id")?).map_err(err)
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
            let env = b64::decode(m["env"].as_str().unwrap_or_default()).map_err(err)?;
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
    let url = xchonnect_core::uri::origin_document_url(
        domain,
        xchonnect_core::uri::ParseOptions {
            developer_mode: dev,
        },
    );
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
    OriginDocument::parse(&body).map_err(err)
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

/// Development wallet backed by `xchonnect-wallet-kit` (`--dev-key`).
struct DevWallet {
    sk: chia_bls::SecretKey,
    pk: chia_bls::PublicKey,
    puzzle_hash: chia_protocol::Bytes32,
    network: kit::Network,
    permissions: kit::DappPermissions,
    limits: MemLimits,
    auto: bool,
}

#[derive(Default)]
struct MemLimits(std::cell::RefCell<DailySpend>);

impl kit::LimitStore for MemLimits {
    fn load(&self) -> Result<DailySpend, PermissionError> {
        Ok(self.0.borrow().clone())
    }
    fn save(&self, r: &DailySpend) -> Result<(), PermissionError> {
        *self.0.borrow_mut() = r.clone();
        Ok(())
    }
}

impl kit::Signer for DevWallet {
    fn sign(
        &self,
        pk: &chia_bls::PublicKey,
        msg: &[u8],
    ) -> Result<chia_bls::Signature, kit::SignerError> {
        if *pk != self.pk {
            return Err(kit::SignerError::KeyUnavailable);
        }
        Ok(chia_bls::sign(&self.sk, msg))
    }
}

impl kit::Approver for DevWallet {
    fn approve(&self, prompt: &kit::Prompt<'_>) -> bool {
        let shown = serde_json::to_string_pretty(prompt).unwrap_or_default();
        println!(
            "  Simulated request (this is what will happen, not what the dApp claims):\n{shown}"
        );
        ask("  Approve and sign?", self.auto)
    }
}

impl DevWallet {
    fn new(seed: &str, o: &Opts) -> Res<Self> {
        use chia_puzzle_types::DeriveSynthetic;
        let (network, auto) = (o.network.as_str(), o.auto);
        // A key derived from a command-line seed must never sign real funds.
        let network = match network {
            "testnet11" => kit::Network::Testnet11,
            "mainnet" => return Err("--dev-key is for testnet11 only, never mainnet".into()),
            other => return Err(format!("unknown network {other}")),
        };
        if seed.len() < 16 {
            return Err("--dev-key seed must have at least 16 characters".into());
        }
        let master = chia_bls::SecretKey::from_seed(&xchonnect_core::crypto::sha256_parts(&[
            b"xchonnect dev wallet",
            seed.as_bytes(),
        ]));
        let sk = chia_bls::master_to_wallet_unhardened(&master, 0).derive_synthetic();
        let pk = sk.public_key();
        let puzzle_hash = chia_protocol::Bytes32::from(
            chia_puzzle_types::standard::StandardArgs::curry_tree_hash(pk),
        );
        let mut permissions = kit::DappPermissions::new_default(pk);
        // Per-dApp spending limits (spec 9.3): a real wallet asks the user for these
        // during pairing; here they come from the command line.
        if o.limit_per_request.is_some() || o.limit_per_day.is_some() {
            permissions.limits.insert(
                kit::AssetId::Xch,
                kit::AssetLimit {
                    per_request: o.limit_per_request,
                    per_day: o.limit_per_day,
                },
            );
        }
        Ok(DevWallet {
            permissions,
            sk,
            pk,
            puzzle_hash,
            network,
            limits: MemLimits::default(),
            auto,
        })
    }

    fn handle(
        &self,
        dapp: &str,
        method: &str,
        params: &str,
    ) -> Result<String, (i64, String, Option<String>)> {
        let ownership = kit::Ownership {
            p2_puzzle_hashes: [self.puzzle_hash].into_iter().collect(),
        };
        let keys = [self.pk].into_iter().collect();
        let ctx = kit::RequestContext {
            dapp,
            network: self.network.clone(),
            session_chain_id: self.network.chain_id(),
            permissions: &self.permissions,
            allow_agg_sig_unsafe: false,
            allow_unknown_contracts: false,
            ownership: &ownership,
            keys: &keys,
            limits: &self.limits,
            now: now(),
        };
        kit::handle(method, params, &ctx, self, self).map_err(|e| (e.code, e.message, e.data))
    }
}

fn run(o: Opts) -> Res<()> {
    let dev_wallet = o
        .dev_key
        .as_deref()
        .map(|seed| DevWallet::new(seed, &o))
        .transpose()?;
    if let Some(w) = &dev_wallet {
        println!(
            "Development key (testnet only): public key 0x{}",
            hex::encode(w.pk.to_bytes())
        );
        println!(
            "  receive puzzle hash 0x{} on {}",
            hex::encode(w.puzzle_hash),
            w.network.chain_id()
        );
    }
    let opts = ParseOptions {
        developer_mode: o.dev,
    };
    let uri = PairingUri::parse(&o.uri, opts).map_err(err)?;
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
    let meta = || WalletMeta {
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
        Some(meta()),
    )
    .map_err(err)?;
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
        let end = s.reject_sas(&mut OsEntropy, now()).map_err(err)?;
        relay.post(&end)?;
        return Err("codes did not match; session ended".into());
    }
    if let Some(ready) = s
        .confirm_sas(&mut OsEntropy, now(), Some(meta()))
        .map_err(err)?
    {
        relay.post(&ready)?;
    }
    // Tell the dApp what it is allowed to ask for, including the spending limits, so it
    // does not have to discover them by being refused (spec 9.3).
    if let Some(w) = &dev_wallet {
        send(
            &relay,
            &mut s,
            Message::SessionPermissions(w.permissions.to_message()),
            3600,
        )?;
    }
    println!("Paired. Waiting for requests (Ctrl-C to quit)...");
    let dapp = verified.uri().domain.clone();
    serve(&relay, &mut s, o.auto, dev_wallet.as_ref(), &dapp)
}

/// Seal `msg` for the dApp and post it.
fn send(relay: &Relay, s: &mut Session, msg: Message, ttl: u64) -> Res<()> {
    let out = s.seal(&mut OsEntropy, now(), msg, ttl).map_err(err)?;
    relay.post(&out)
}

fn serve(
    relay: &Relay,
    s: &mut Session,
    auto: bool,
    dev: Option<&DevWallet>,
    dapp: &str,
) -> Res<()> {
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
                ids.push(id);
                let inner = match s.open(now(), &mbx, &env) {
                    Ok(i) => i,
                    Err(e) => {
                        eprintln!("ignored message: {e}");
                        continue;
                    }
                };
                match inner.message {
                    Message::RpcRequest { method, params } => {
                        println!("Request {method}");
                        let receipt = Message::RpcReceived {
                            request_id: inner.id,
                        };
                        send(relay, s, receipt, 3600)?;
                        let outcome = match dev {
                            Some(w) => w.handle(dapp, &method, &params),
                            None => answer(&method, &params, auto)
                                .map_err(|(c, t)| (c, t.to_owned(), None)),
                        };
                        let msg = match outcome {
                            Ok(result) => rpc::result(inner.id, &result),
                            Err((code, text, data)) => {
                                rpc::error(inner.id, code, &text, data.as_deref())
                            }
                        }
                        .map_err(err)?;
                        send(relay, s, msg, 3600)?;
                        println!("  answered");
                    }
                    Message::SessionRotate(r) if r.phase == RotatePhase::Offer => {
                        let (nr, nw) =
                            (Token::random(&mut OsEntropy), Token::random(&mut OsEntropy));
                        let nm = relay.create_mailbox(&nr, &nw, None)?;
                        let (accept, abandoned) = s
                            .accept_rotation(&mut OsEntropy, now(), &r, nm, nr, nw)
                            .map_err(err)?;
                        if let Some(a) = abandoned {
                            relay.delete(&a.mailbox, &a.read_token);
                        }
                        relay.post(&accept)?;
                        println!("Rotated to epoch {}", s.epoch());
                    }
                    Message::SessionPing => send(relay, s, Message::SessionPong, 300)?,
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use chia_protocol::SpendBundle;
    use chia_puzzle_types::Memos;
    use chia_sdk_driver::{SpendContext, StandardLayer};
    use chia_sdk_test::Simulator;
    use chia_sdk_types::Conditions;

    /// The CLI's dev-key path signs a real spend of its own coin that the chain accepts.
    #[test]
    fn dev_wallet_signs_a_valid_testnet_spend() {
        let opts = |network: &str| Opts {
            uri: String::new(),
            dev: true,
            auto: true,
            name: "test".into(),
            dev_key: None,
            network: network.to_owned(),
            limit_per_request: None,
            limit_per_day: None,
        };
        let seed = "interop development seed";
        let w = DevWallet::new(seed, &opts("testnet11")).unwrap();
        assert!(DevWallet::new(seed, &opts("mainnet")).is_err());
        // A configured limit reaches both the policy and the session.permissions message.
        let mut limited = opts("testnet11");
        limited.limit_per_request = Some(500);
        let l = DevWallet::new(seed, &limited).unwrap();
        assert_eq!(
            l.permissions
                .to_message()
                .limits
                .and_then(|x| x.per_request_mojos),
            Some("500".to_owned())
        );
        let mut sim = Simulator::new();
        let coin = sim.new_coin(w.puzzle_hash, 1_000);
        let mut ctx = SpendContext::new();
        StandardLayer::new(w.pk)
            .spend(
                &mut ctx,
                coin,
                Conditions::new()
                    .create_coin(chia_protocol::Bytes32::new([9; 32]), 990, Memos::None)
                    .reserve_fee(10),
            )
            .unwrap();
        let spends = ctx.take();
        let params = json!({ "coinSpends": spends.iter().map(|cs| json!({
            "coin": { "parent_coin_info": hex::encode(cs.coin.parent_coin_info), "puzzle_hash": hex::encode(cs.coin.puzzle_hash), "amount": cs.coin.amount },
            "puzzle_reveal": hex::encode(cs.puzzle_reveal.as_ref()), "solution": hex::encode(cs.solution.as_ref()),
        })).collect::<Vec<_>>() }).to_string();
        let result = w
            .handle("localhost:5173", "signCoinSpends", &params)
            .unwrap();
        let sig_hex: String = serde_json::from_str(&result).unwrap();
        let sig = chia_bls::Signature::from_bytes(
            &hex::decode(sig_hex.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        sim.new_transaction(SpendBundle::new(spends, sig)).unwrap();
        // The example dApp's sample request uses a fake coin: refused, not signed.
        let fake = json!({ "coinSpends": [{ "coin": { "parent_coin_info": "11".repeat(32), "puzzle_hash": "22".repeat(32), "amount": "1000" }, "puzzle_reveal": "0x80", "solution": "0x80" }] }).to_string();
        assert_eq!(
            w.handle("localhost:5173", "signCoinSpends", &fake)
                .unwrap_err()
                .0,
            4000
        );
    }
}
