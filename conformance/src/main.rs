//! `xchonnect-conformance relay <base-url> [--only <id>] [--json] [--api-key <key>]
//! [--aggressive] [--slow]`
//!
//! Exit codes: 0 all selected checks passed or were skipped, 1 at least one failed,
//! 2 usage error.

use std::process::ExitCode;
use xchonnect_conformance::relay::{self, Options, Tier};

const USAGE: &str = "usage:
  xchonnect-conformance relay <base-url> [options]
  xchonnect-conformance list

options:
  --only <id>[,<id>...]  run only these checks (repeatable; runs opt-in checks too)
  --json                 print a JSON report instead of text
  --api-key <key>        business API key for ticket / api_key checks
                         (or XCHONNECT_CONFORMANCE_API_KEY)
  --aggressive           also run checks that exhaust rate limits
  --slow                 also run checks that take over a minute";

fn main() -> ExitCode {
    match parse(std::env::args().skip(1).collect()) {
        Ok(Cmd::List) => {
            for c in relay::checks() {
                let tier = match c.tier {
                    Tier::Default => "",
                    Tier::Aggressive => " [--aggressive]",
                    Tier::Slow => " [--slow]",
                };
                println!("{:<12} {}{tier} ({})", c.id, c.title, c.spec);
            }
            ExitCode::SUCCESS
        }
        Ok(Cmd::Relay(opts, json)) => {
            let report = relay::run(&opts);
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
    List,
    Relay(Options, bool),
}

fn parse(args: Vec<String>) -> Result<Cmd, String> {
    let mut it = args.into_iter();
    match it.next().as_deref() {
        Some("list") => return Ok(Cmd::List),
        Some("relay") => {}
        Some("-h" | "--help") | None => return Err("xchonnect-conformance".into()),
        Some(other) => return Err(format!("unknown command {other}")),
    }
    let mut opts = Options {
        api_key: std::env::var("XCHONNECT_CONFORMANCE_API_KEY")
            .ok()
            .filter(|k| !k.is_empty()),
        ..Options::default()
    };
    let mut json = false;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => json = true,
            "--aggressive" => opts.aggressive = true,
            "--slow" => opts.slow = true,
            "--api-key" => opts.api_key = Some(it.next().ok_or("--api-key needs a value")?),
            "--only" => {
                let v = it.next().ok_or("--only needs a check id")?;
                let ids = v.split(',').map(str::trim).filter(|s| !s.is_empty());
                opts.only.extend(ids.map(str::to_owned));
            }
            s if opts.base_url.is_empty() && !s.starts_with("--") => {
                opts.base_url = s.trim_end_matches('/').to_owned();
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if opts.base_url.is_empty() {
        return Err("missing <base-url>".into());
    }
    if !(opts.base_url.starts_with("http://") || opts.base_url.starts_with("https://")) {
        return Err("<base-url> must start with http:// or https://".into());
    }
    let known = relay::checks();
    for id in &opts.only {
        if !known.iter().any(|c| c.id.eq_ignore_ascii_case(id)) {
            return Err(format!(
                "unknown check id {id} (see `xchonnect-conformance list`)"
            ));
        }
    }
    Ok(Cmd::Relay(opts, json))
}
