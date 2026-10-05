//! How the suite hands a pairing URI to the wallet under test and watches what it does.
//!
//! Two drivers cover every wallet the suite can reach:
//!
//! - [`Driver::Exec`] runs a shell command template with `{uri}` replaced, so any wallet
//!   with a command-line entry point can be driven unattended. Answers that a wallet asks
//!   for interactively can be piped in by the template itself
//!   (`printf 'y\nn\n' | my-wallet pair {uri}`), which is how the suite gets a wallet that
//!   declines the SAS or rejects a signing request without needing a special build.
//! - [`Driver::Manual`] prints the URI and waits for the operator, for a phone wallet
//!   that is paired by scanning a QR code.
//!
//! Everything the checks assert is observed on the wire, not in the wallet's output, so a
//! wallet that reveals nothing about itself can still be judged. The captured output is
//! used for one thing only: finding the SAS the wallet displayed.

use crate::report::Fail;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Which wallet behaviour a check needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Variant {
    /// Pairs and answers requests (the command given with `--wallet`).
    Normal,
    /// Reports that the codes do not match (`--wallet-sas-mismatch`).
    SasMismatch,
    /// Pairs, but the user declines signing requests (`--wallet-reject`).
    Reject,
}

impl Variant {
    pub(crate) fn flag(self) -> &'static str {
        match self {
            Variant::Normal => "--wallet",
            Variant::SasMismatch => "--wallet-sas-mismatch",
            Variant::Reject => "--wallet-reject",
        }
    }
}

/// How to drive the wallet.
#[derive(Debug, Clone)]
pub(crate) enum Driver {
    /// Shell command templates per variant; `{uri}` is replaced by the pairing URI.
    Exec {
        normal: String,
        sas_mismatch: Option<String>,
        reject: Option<String>,
    },
    /// A human pairs the wallet by hand.
    Manual,
}

impl Driver {
    fn template(&self, v: Variant) -> Option<&str> {
        match (self, v) {
            (Driver::Exec { normal, .. }, Variant::Normal) => Some(normal),
            (Driver::Exec { sas_mismatch, .. }, Variant::SasMismatch) => sas_mismatch.as_deref(),
            (Driver::Exec { reject, .. }, Variant::Reject) => reject.as_deref(),
            (Driver::Manual, _) => None,
        }
    }

    /// Hand `uri` to the wallet. `hint` tells a human operator what to expect.
    pub(crate) fn start(&self, v: Variant, uri: &str, hint: &str) -> Result<Running, Fail> {
        match self {
            Driver::Manual => {
                println!("\n--- the wallet should now: {hint}");
                println!("    pairing URI (scan it, or pipe it to `qrencode -t ANSIUTF8`):\n");
                println!("{uri}\n");
                prompt("    press Enter once the wallet has been given the URI");
                Ok(Running::Manual)
            }
            Driver::Exec { .. } => {
                let template = self.template(v).ok_or_else(|| {
                    Fail::Skip(format!(
                        "needs a wallet that {hint}: pass {} '<command with {{uri}}>'",
                        v.flag()
                    ))
                })?;
                if !template.contains("{uri}") {
                    return Err(Fail::Fail(format!(
                        "the {} command has no {{uri}} placeholder",
                        v.flag()
                    )));
                }
                spawn(&template.replace("{uri}", uri))
            }
        }
    }
}

/// Ask the operator a yes/no question (manual driver only).
pub(crate) fn confirm(question: &str) -> bool {
    matches!(
        prompt(&format!("    {question} [y/N]")).trim(),
        "y" | "Y" | "yes"
    )
}

fn prompt(text: &str) -> String {
    print!("{text} ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    line
}

/// A wallet the suite started, or the operator's device.
#[derive(Debug)]
pub(crate) enum Running {
    /// A child process whose output is being captured.
    Child {
        child: Child,
        output: Arc<Mutex<String>>,
    },
    /// Nothing to supervise.
    Manual,
}

fn spawn(command: &str) -> Result<Running, Fail> {
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        // The wallet must not inherit the suite's stdin: a wallet that waits for input it
        // will never get would hang the run instead of failing the check.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Fail::Fail(format!("cannot start the wallet: {e}")))?;
    let output = Arc::new(Mutex::new(String::new()));
    for stream in [
        child.stdout.take().map(StdStream::Out),
        child.stderr.take().map(StdStream::Err),
    ]
    .into_iter()
    .flatten()
    {
        let sink = Arc::clone(&output);
        std::thread::spawn(move || stream.drain_into(&sink));
    }
    Ok(Running::Child { child, output })
}

/// Either captured stream of the wallet process.
enum StdStream {
    Out(std::process::ChildStdout),
    Err(std::process::ChildStderr),
}

impl StdStream {
    /// Append everything the wallet writes to `sink` until the stream closes. Lines are
    /// read one at a time so a check can look at the output while the wallet still runs.
    fn drain_into(self, sink: &Mutex<String>) {
        let reader: Box<dyn Read> = match self {
            StdStream::Out(o) => Box::new(o),
            StdStream::Err(e) => Box::new(e),
        };
        let mut lines = BufReader::new(reader);
        let mut buf = Vec::new();
        // `read_until` keeps partial lines, so a prompt without a newline is captured too.
        while lines.read_until(b'\n', &mut buf).is_ok_and(|n| n > 0) {
            if let Ok(mut s) = sink.lock() {
                if s.len() < 256 * 1024 {
                    s.push_str(&String::from_utf8_lossy(&buf));
                }
            }
            buf.clear();
        }
    }
}

impl Running {
    /// Everything the wallet has written so far (empty for a manual wallet).
    pub(crate) fn output(&self) -> String {
        match self {
            Running::Child { output, .. } => output
                .lock()
                .map(|s| s.clone())
                .unwrap_or_else(|e| e.into_inner().clone()),
            Running::Manual => String::new(),
        }
    }

    /// Whether the wallet process has exited, and with which status.
    pub(crate) fn exited(&mut self) -> Option<bool> {
        match self {
            Running::Child { child, .. } => child.try_wait().ok().flatten().map(|s| s.success()),
            Running::Manual => None,
        }
    }

    /// Wait up to `timeout` for the wallet to exit; `Some(success)` if it did.
    pub(crate) fn wait(&mut self, timeout: Duration) -> Option<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(ok) = self.exited() {
                return Some(ok);
            }
            if Instant::now() >= deadline || matches!(self, Running::Manual) {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Running::Child { child, .. } = self {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
