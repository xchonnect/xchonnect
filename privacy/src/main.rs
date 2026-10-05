//! `xchonnect-privacy-scan` — drive a full session against running services, then scan
//! their database dump, logs and metrics for anything the data inventory forbids.
//!
//! ```text
//! xchonnect-privacy-scan drive --relay URL --gateway-url URL --gateway-pk B64 --out DIR
//! xchonnect-privacy-scan scan --secrets FILE [--allow LITERAL] SURFACE=PATH ...
//! ```
//!
//! `drive` writes `secrets.json` into `DIR`: the synthetic values it planted, which
//! `scan` then looks for. See `scripts/privacy-scan.sh` for the whole sequence.

use std::collections::BTreeMap;
use std::path::PathBuf;
use xchonnect_privacy_check::flow;
use xchonnect_privacy_check::inventory;
use xchonnect_privacy_check::live::HttpTransport;
use xchonnect_privacy_check::scan::{Secrets, Surface};

const USAGE: &str = "usage:\n  \
    xchonnect-privacy-scan drive --relay URL --gateway-url URL --gateway-pk B64 --out DIR\n  \
    xchonnect-privacy-scan scan --secrets FILE [--allow LITERAL] SURFACE=PATH ...";

fn main() {
    if let Err(e) = run() {
        eprintln!("privacy scan: {e}");
        std::process::exit(1);
    }
}

/// Named options and positional arguments.
#[derive(Debug, Default)]
struct Args {
    options: BTreeMap<String, Vec<String>>,
    positional: Vec<String>,
}

impl Args {
    fn parse(args: impl Iterator<Item = String>) -> Args {
        let mut out = Args::default();
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            match arg.strip_prefix("--") {
                Some(name) => {
                    let value = args.next().unwrap_or_default();
                    out.options.entry(name.to_owned()).or_default().push(value);
                }
                None => out.positional.push(arg),
            }
        }
        out
    }

    fn one(&self, name: &str) -> Result<&str, String> {
        self.options
            .get(name)
            .and_then(|v| v.first())
            .map(String::as_str)
            .ok_or_else(|| format!("missing --{name}\n{USAGE}"))
    }

    fn many(&self, name: &str) -> Vec<String> {
        self.options.get(name).cloned().unwrap_or_default()
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let sub = args.next().ok_or(USAGE)?;
    let args = Args::parse(args);
    match sub.as_str() {
        "drive" => drive(&args),
        "scan" => scan(&args),
        other => Err(format!("unknown command {other}\n{USAGE}")),
    }
}

fn drive(args: &Args) -> Result<(), String> {
    let relay = args.one("relay")?;
    let gateway_url = args.one("gateway-url")?.to_owned();
    let gateway_pk = xchonnect_core::b64::decode_array::<32>(args.one("gateway-pk")?)
        .map_err(|_| "--gateway-pk must be base64url of 32 bytes".to_owned())?;
    let out = PathBuf::from(args.one("out")?);
    let uri_relay = args
        .options
        .get("uri-relay")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "https://relay.example".to_owned());

    let transport = HttpTransport::new(relay);
    let params = flow::Params {
        gateway_url,
        gateway_pk,
        uri_relay,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let outcome = runtime.block_on(flow::run(&transport, &params, now))?;
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let path = out.join("secrets.json");
    std::fs::write(&path, outcome.secrets.to_json()).map_err(|e| e.to_string())?;
    for note in &outcome.notes {
        println!("drive: {note}");
    }
    println!(
        "drive: planted {} values across {} classes; wrote {}",
        outcome.secrets.witnesses().len(),
        outcome.secrets.covered().len(),
        path.display()
    );
    if !outcome.secrets.missing().is_empty() {
        let missing: Vec<&str> = outcome.secrets.missing().iter().map(|c| c.id()).collect();
        return Err(format!("no value planted for: {}", missing.join(", ")));
    }
    Ok(())
}

fn load_surface(spec: &str) -> Result<Surface, String> {
    let (name, path) = spec
        .split_once('=')
        .ok_or_else(|| format!("expected SURFACE=PATH, got `{spec}`"))?;
    let mut surface = Surface::new(name);
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    match String::from_utf8(bytes) {
        Ok(text) => surface.text = text,
        Err(e) => surface.raw(e.as_bytes()),
    }
    if surface.is_empty() {
        return Err(format!("{path} is empty: nothing to verify for `{name}`"));
    }
    Ok(surface)
}

fn scan(args: &Args) -> Result<(), String> {
    let secrets = std::fs::read_to_string(args.one("secrets")?)
        .map_err(|e| format!("cannot read the secrets file: {e}"))?;
    let secrets = Secrets::from_json(&secrets)?;
    let mut inv = inventory::load()?;
    for literal in args.many("allow") {
        for policy in &inv.surfaces {
            inv.benign
                .entry(policy.surface.clone())
                .or_default()
                .push(literal.clone());
        }
    }
    let mut surfaces = Vec::new();
    for spec in &args.positional {
        surfaces.push(load_surface(spec)?);
    }
    if surfaces.is_empty() {
        return Err(format!("no surfaces given\n{USAGE}"));
    }
    // Surfaces this invocation cannot see (the in-process checks cover them) are
    // reported but do not fail the run.
    let report = inventory::verify(&inv, &surfaces, &secrets, false);
    print!("{report}");
    if report.ok() {
        return Ok(());
    }
    Err(format!("{} privacy violation(s)", report.violations.len()))
}
