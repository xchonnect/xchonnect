//! Command line for the Xchonnect conformance suites.
//!
//! ```text
//! xchonnect-conformance relay  <base-url> [options]
//! xchonnect-conformance wallet --relay <url> --wallet '<command with {uri}>' [options]
//! xchonnect-conformance list [relay|wallet]
//! ```
//!
//! Exit codes: 0 all selected checks passed or were skipped, 1 at least one failed,
//! 2 usage error.

use std::process::ExitCode;
use xchonnect_conformance::report::{CheckInfo, Report};
use xchonnect_conformance::{relay, wallet};

const USAGE: &str = "usage:
  xchonnect-conformance relay <base-url> [options]
  xchonnect-conformance wallet --relay <url> --wallet '<command with {uri}>' [options]
  xchonnect-conformance list [relay|wallet]

common options:
  --only <id>[,<id>...]  run only these checks (repeatable; runs opt-in checks too)
  --json                 print a JSON report instead of text

relay options:
  --api-key <key>        business API key for ticket / api_key checks
                         (or XCHONNECT_CONFORMANCE_API_KEY)
  --aggressive           also run checks that exhaust rate limits
  --slow                 also run checks that take over a minute

wallet options:
  --relay <url>              relay both sides meet on (required)
  --wallet <command>         pairs the wallet; {uri} is replaced by the pairing URI
  --wallet-sas-mismatch <c>  same, for a wallet whose user reports different codes
  --wallet-reject <command>  same, for a wallet whose user declines requests
  --manual                   pair by hand instead (phone wallets)
  --domain <domain>          domain the suite claims (default localhost:<port>)
  --listen <addr>            address of the origin-document server (default 127.0.0.1:0)
  --xch-per-request-limit <mojos>
                             the per-request XCH limit configured in the wallet
  --timeout <s>              wait for a reply or a response (default 30)
  --refusal-timeout <s>      wait before concluding the wallet will not answer (default 8)
  --slow                     also run checks that wait for multi-minute timeouts";

fn main() -> ExitCode {
    match parse(std::env::args().skip(1).collect()) {
        Ok(Cmd::List(which)) => {
            for c in which {
                println!("{:<14} {}{} ({})", c.id, c.title, c.tier_suffix(), c.spec);
            }
            ExitCode::SUCCESS
        }
        Ok(Cmd::Run(report, json)) => {
            if json {
                let out = serde_json::to_string_pretty(&report.to_json()).unwrap_or_default();
                println!("{out}");
            } else {
                print!("{}", report.to_text());
            }
            ExitCode::from(u8::from(!report.is_success()))
        }
        Err(e) => {
            eprintln!("{e}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

enum Cmd {
    List(Vec<CheckInfo>),
    Run(Box<Report>, bool),
}

fn parse(args: Vec<String>) -> Result<Cmd, String> {
    let mut it = args.into_iter();
    match it.next().as_deref() {
        Some("list") => {
            let mut all = match it.next().as_deref() {
                None => [relay::checks(), wallet::checks()].concat(),
                Some("relay") => relay::checks(),
                Some("wallet") => wallet::checks(),
                Some(other) => return Err(format!("unknown suite {other}")),
            };
            if let Some(extra) = it.next() {
                return Err(format!("unexpected argument {extra}"));
            }
            all.dedup_by_key(|c| c.id);
            Ok(Cmd::List(all))
        }
        Some("relay") => parse_relay(it),
        Some("wallet") => parse_wallet(it),
        Some("-h" | "--help") | None => Err("xchonnect-conformance".into()),
        Some(other) => Err(format!("unknown command {other}")),
    }
}

/// Collect `--only a,b --only c` into check ids, rejecting unknown ones.
fn add_only(only: &mut Vec<String>, value: &str) {
    let ids = value.split(',').map(str::trim).filter(|s| !s.is_empty());
    only.extend(ids.map(str::to_owned));
}

fn check_ids(only: &[String], known: &[CheckInfo], suite: &str) -> Result<(), String> {
    for id in only {
        if !known.iter().any(|c| c.id.eq_ignore_ascii_case(id)) {
            return Err(format!(
                "unknown check id {id} (see `xchonnect-conformance list {suite}`)"
            ));
        }
    }
    Ok(())
}

fn number(value: Option<String>, flag: &str) -> Result<u64, String> {
    value
        .ok_or_else(|| format!("{flag} needs a value"))?
        .parse()
        .map_err(|_| format!("{flag} needs a whole number"))
}

fn parse_relay(mut it: impl Iterator<Item = String>) -> Result<Cmd, String> {
    let mut opts = relay::Options {
        api_key: std::env::var("XCHONNECT_CONFORMANCE_API_KEY")
            .ok()
            .filter(|k| !k.is_empty()),
        ..relay::Options::default()
    };
    let mut json = false;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => json = true,
            "--aggressive" => opts.aggressive = true,
            "--slow" => opts.slow = true,
            "--api-key" => opts.api_key = Some(it.next().ok_or("--api-key needs a value")?),
            "--only" => add_only(&mut opts.only, &it.next().ok_or("--only needs a check id")?),
            s if opts.base_url.is_empty() && !s.starts_with("--") => {
                opts.base_url = s.trim_end_matches('/').to_owned();
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    check_url(&opts.base_url, "<base-url>")?;
    check_ids(&opts.only, &relay::checks(), "relay")?;
    Ok(Cmd::Run(Box::new(relay::run(&opts)), json))
}

fn parse_wallet(mut it: impl Iterator<Item = String>) -> Result<Cmd, String> {
    let mut opts = wallet::Options::default();
    let mut json = false;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => json = true,
            "--manual" => opts.manual = true,
            "--slow" => opts.slow = true,
            "--relay" => opts.relay = it.next().ok_or("--relay needs a URL")?,
            "--wallet" => opts.wallet = it.next().ok_or("--wallet needs a command")?,
            "--wallet-sas-mismatch" => {
                opts.wallet_sas_mismatch =
                    Some(it.next().ok_or("--wallet-sas-mismatch needs a command")?);
            }
            "--wallet-reject" => {
                opts.wallet_reject = Some(it.next().ok_or("--wallet-reject needs a command")?);
            }
            "--domain" => opts.domain = Some(it.next().ok_or("--domain needs a domain")?),
            "--listen" => opts.listen = it.next().ok_or("--listen needs an address")?,
            "--xch-per-request-limit" => {
                opts.xch_per_request_limit = Some(
                    it.next()
                        .ok_or("--xch-per-request-limit needs a value")?
                        .parse()
                        .map_err(|_| "--xch-per-request-limit needs a whole number of mojos")?,
                );
            }
            "--timeout" => opts.timeout_s = number(it.next(), "--timeout")?,
            "--refusal-timeout" => {
                opts.refusal_timeout_s = number(it.next(), "--refusal-timeout")?;
            }
            "--only" => add_only(&mut opts.only, &it.next().ok_or("--only needs a check id")?),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    check_url(&opts.relay, "--relay")?;
    if opts.manual {
        if !opts.wallet.is_empty() {
            return Err("--manual and --wallet are mutually exclusive".into());
        }
    } else if opts.wallet.is_empty() {
        return Err("missing --wallet '<command with {uri}>' (or --manual)".into());
    }
    if opts.timeout_s == 0 || opts.refusal_timeout_s == 0 {
        return Err("timeouts must be at least one second".into());
    }
    check_ids(&opts.only, &wallet::checks(), "wallet")?;
    Ok(Cmd::Run(Box::new(wallet::run(&opts)), json))
}

fn check_url(url: &str, flag: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err(format!("missing {flag}"));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!("{flag} must start with http:// or https://"));
    }
    Ok(())
}
