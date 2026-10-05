//! Push probe: exercise a push gateway the way a relay does, with a device token you
//! paste in, so APNs delivery can be checked on a real phone (TASK-46).
//!
//! ```text
//! xchonnect-push-probe keys <gateway>
//! xchonnect-push-probe seal --key <b64url> --token <device token> [--sandbox] [--days N]
//! xchonnect-push-probe wake <gateway> --token <device token> [--sandbox] [--days N] [--key <b64url>]
//! ```
//!
//! `wake` fetches the gateway key from `/v1/keys` unless `--key` is given, seals the token
//! (spec 7.3.2), posts it to `/v1/wake` and prints the delivery counters from `/metrics`
//! before and after, since the wake response itself is uniform by design.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use xchonnect_core::b64;
use xchonnect_core::crypto::{Entropy, OsEntropy};
use xchonnect_core::push::{Platform, PushToken};

type Res<T> = Result<T, String>;

#[derive(Debug, Default)]
struct Opts {
    gateway: Option<String>,
    key: Option<String>,
    token: Option<String>,
    sandbox: bool,
    days: u64,
}

fn parse(mut args: impl Iterator<Item = String>) -> Res<Opts> {
    let mut o = Opts {
        days: 30,
        ..Opts::default()
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "--key" => o.key = Some(args.next().ok_or("--key needs a value")?),
            "--token" => o.token = Some(args.next().ok_or("--token needs a value")?),
            "--sandbox" => o.sandbox = true,
            "--days" => {
                let d = args.next().ok_or("--days needs a value")?;
                o.days = d
                    .parse()
                    .map_err(|_| format!("--days: not a number: {d}"))?;
            }
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            s if o.gateway.is_none() => o.gateway = Some(s.trim_end_matches('/').to_owned()),
            s => return Err(format!("unexpected argument {s}")),
        }
    }
    Ok(o)
}

fn now() -> Res<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| e.to_string())
}

/// Seal `token` to the gateway key: what a wallet hands the relay at registration.
fn seal(key_b64: &str, token: &str, sandbox: bool, days: u64) -> Res<String> {
    let key: [u8; 32] = b64::decode_array(key_b64).map_err(|e| format!("gateway key: {e}"))?;
    let mut hint_key = [0u8; 32];
    OsEntropy.fill(&mut hint_key);
    let now = now()?;
    let token = PushToken {
        platform: if sandbox {
            Platform::ApnsSandbox
        } else {
            Platform::Apns
        },
        device_token: token.trim().to_owned(),
        hint_key,
        exp: now + days * 24 * 3600,
    };
    let sealed = token
        .seal(&mut OsEntropy, &key, now)
        .map_err(|e| format!("seal: {e}"))?;
    Ok(b64::encode(&sealed))
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .build()
        .into()
}

fn get(url: &str) -> Res<String> {
    agent()
        .get(url)
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("GET {url}: {e}"))
}

fn first_key(gateway: &str) -> Res<String> {
    let body = get(&format!("{gateway}/v1/keys"))?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("/v1/keys: {e}"))?;
    v.get("keys")
        .and_then(|k| k.get(0))
        .and_then(|k| k.as_str())
        .map(str::to_owned)
        .ok_or_else(|| "/v1/keys lists no key".to_owned())
}

/// The gateway's delivery counters, for a before/after comparison.
fn counters(gateway: &str) -> String {
    match get(&format!("{gateway}/metrics")) {
        Ok(m) => m
            .lines()
            .filter(|l| l.starts_with("xchonnect_gateway_") && !l.starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n"),
        Err(e) => format!("(no /metrics: {e})"),
    }
}

fn run(cmd: &str, o: Opts) -> Res<()> {
    match cmd {
        "keys" => {
            let g = o.gateway.ok_or("keys needs the gateway URL")?;
            println!("{}", get(&format!("{g}/v1/keys"))?);
        }
        "seal" => {
            let key = o.key.ok_or("seal needs --key")?;
            let token = o.token.ok_or("seal needs --token")?;
            println!("{}", seal(&key, &token, o.sandbox, o.days)?);
        }
        "wake" => {
            let g = o.gateway.ok_or("wake needs the gateway URL")?;
            let token = o.token.ok_or("wake needs --token")?;
            let key = match o.key {
                Some(k) => k,
                None => first_key(&g)?,
            };
            let sealed = seal(&key, &token, o.sandbox, o.days)?;
            println!("before:\n{}", counters(&g));
            let body = serde_json::json!({ "sealed_token": sealed }).to_string();
            let status = agent()
                .post(&format!("{g}/v1/wake"))
                .header("content-type", "application/json")
                .send(body)
                .map_err(|e| format!("POST /v1/wake: {e}"))?
                .status();
            println!("POST /v1/wake -> {status}");
            // Delivery runs after the 202, so give it a moment before reading the counters.
            std::thread::sleep(Duration::from_secs(3));
            println!("after:\n{}", counters(&g));
        }
        _ => return Err(format!("unknown command {cmd}; use keys, seal or wake")),
    }
    Ok(())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let result = match args.next() {
        Some(cmd) => parse(args).and_then(|o| run(&cmd, o)),
        None => Err("usage: xchonnect-push-probe keys|seal|wake …".to_owned()),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use xchonnect_core::crypto::X25519Secret;

    #[test]
    fn a_sealed_token_opens_at_the_gateway_with_the_platform_and_device_token() {
        let sk = X25519Secret::random(&mut OsEntropy);
        let pk = b64::encode(&sk.public_key());
        let sealed = seal(&pk, " abcd1234 ", true, 30).unwrap();
        let opened = PushToken::open(&sk, &b64::decode(&sealed).unwrap(), now().unwrap()).unwrap();
        assert_eq!(opened.platform, Platform::ApnsSandbox);
        assert_eq!(opened.device_token, "abcd1234");
    }

    #[test]
    fn options_parse_and_reject_unknown_flags() {
        let o = parse(
            [
                "http://g/".into(),
                "--token".into(),
                "t".into(),
                "--sandbox".into(),
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(o.gateway.as_deref(), Some("http://g"));
        assert!(o.sandbox);
        assert_eq!(o.days, 30);
        assert!(parse(["--nope".into()].into_iter()).is_err());
    }
}
