//! Data classes, observation surfaces and the scanner.
//!
//! The scanner answers one question: *does this artefact contain this value, in any
//! form a program might plausibly have written it?* A value is expanded into needles
//! (raw bytes, base64url, standard base64, lower and upper hex, the `{:?}` byte-array
//! form) plus, for high-entropy identifiers, truncated prefixes — so a log line that
//! prints only the first few characters of a mailbox id is still a finding.
//!
//! Scanning is deliberately dumb and total: it searches whole artefacts (a database
//! transcript, every captured log line, the metrics exposition, the wake-up payload)
//! rather than a hand-picked struct, so a new field or a new log line is covered the
//! moment it exists.

use std::collections::BTreeSet;
use std::fmt;

/// A class of data with a privacy promise attached to it (spec 13.4 invariant 5, 13.5,
/// 14). The identifiers are the ones used in `docs/privacy/data-inventory.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// Client IP address, however it reached the service (socket, `X-Forwarded-For`, …).
    ClientIp,
    /// Client `User-Agent`.
    UserAgent,
    /// Platform device push token (APNs/FCM), in the clear.
    DeviceToken,
    /// Chia address (bech32m `xch1`/`txch1`).
    ChiaAddress,
    /// A wallet public key (BLS or X25519) in the clear.
    PublicKey,
    /// Capability token value (read or write token), in the clear.
    PlaintextToken,
    /// `SHA-256("xchonnect v1 token" || token)`.
    TokenHash,
    /// Mailbox identifier.
    MailboxId,
    /// Relay-assigned message identifier.
    MsgId,
    /// An encrypted envelope.
    Ciphertext,
    /// Plaintext of an end-to-end encrypted message (method params, amounts, …).
    MessagePlaintext,
    /// Push token sealed to the gateway key.
    SealedPushToken,
    /// Vendor push gateway URL.
    GatewayUrl,
    /// Business customer identifier (billing).
    CustomerId,
    /// Business API key value.
    ApiKey,
}

impl Class {
    /// Every class the checks know about.
    pub const ALL: [Class; 15] = [
        Class::ClientIp,
        Class::UserAgent,
        Class::DeviceToken,
        Class::ChiaAddress,
        Class::PublicKey,
        Class::PlaintextToken,
        Class::TokenHash,
        Class::MailboxId,
        Class::MsgId,
        Class::Ciphertext,
        Class::MessagePlaintext,
        Class::SealedPushToken,
        Class::GatewayUrl,
        Class::CustomerId,
        Class::ApiKey,
    ];

    /// Stable identifier used in the published data inventory.
    pub fn id(self) -> &'static str {
        match self {
            Class::ClientIp => "client_ip",
            Class::UserAgent => "user_agent",
            Class::DeviceToken => "device_token",
            Class::ChiaAddress => "chia_address",
            Class::PublicKey => "public_key",
            Class::PlaintextToken => "plaintext_token",
            Class::TokenHash => "token_hash",
            Class::MailboxId => "mailbox_id",
            Class::MsgId => "msg_id",
            Class::Ciphertext => "ciphertext",
            Class::MessagePlaintext => "message_plaintext",
            Class::SealedPushToken => "sealed_push_token",
            Class::GatewayUrl => "gateway_url",
            Class::CustomerId => "customer_id",
            Class::ApiKey => "api_key",
        }
    }

    /// Parse an identifier from the data inventory.
    pub fn parse(s: &str) -> Option<Class> {
        Class::ALL.into_iter().find(|c| c.id() == s.trim())
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// Shortest needle the scanner accepts. Anything shorter would collide by chance.
const MIN_NEEDLE: usize = 8;
/// Characters of a base64url form kept as a truncation needle.
const B64_PREFIX: usize = 12;
/// Characters of a hex form kept as a truncation needle.
const HEX_PREFIX: usize = 16;

/// One concrete value the project promises not to expose, with every encoding of it.
#[derive(Debug, Clone)]
pub struct Witness {
    /// Class of the value.
    pub class: Class,
    /// Human-readable label, e.g. `wallet mailbox W`.
    pub label: String,
    needles: Vec<(&'static str, Vec<u8>)>,
}

impl Witness {
    /// Encodings searched for.
    pub fn forms(&self) -> impl Iterator<Item = &str> {
        self.needles.iter().map(|(f, _)| *f)
    }
}

fn hex_encode(bytes: &[u8], upper: bool) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let (hi, lo) = (b >> 4, b & 0x0f);
        for nibble in [hi, lo] {
            let c = match (nibble, upper) {
                (0..=9, _) => b'0' + nibble,
                (_, false) => b'a' + nibble - 10,
                (_, true) => b'A' + nibble - 10,
            };
            s.push(char::from(c));
        }
    }
    s
}

/// Standard base64 with padding (`base64::encode`-style), which `b64::encode` never
/// produces but a careless `format!` of a third-party type might.
fn base64_std(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = |i: usize| chunk.get(i).copied().unwrap_or(0);
        let n = (u32::from(b(0)) << 16) | (u32::from(b(1)) << 8) | u32::from(b(2));
        let idx = |shift: u32| usize::try_from((n >> shift) & 0x3f).unwrap_or(0);
        let ch = |i: usize| char::from(ALPHABET.get(i).copied().unwrap_or(b'A'));
        out.push(ch(idx(18)));
        out.push(ch(idx(12)));
        out.push(if chunk.len() > 1 { ch(idx(6)) } else { '=' });
        out.push(if chunk.len() > 2 { ch(idx(0)) } else { '=' });
    }
    out
}

/// The `{:?}` rendering of a byte slice (`[1, 2, 3]`).
fn debug_array(bytes: &[u8]) -> String {
    format!("{bytes:?}")
}

/// How a value was registered, kept so that a set of secrets survives a trip through a
/// file when the flow and the scan run as separate processes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Input {
    Text(String),
    Bytes(Vec<u8>),
    Opaque(Vec<u8>),
}

/// Values the scanner looks for, grouped by class.
#[derive(Debug, Clone, Default)]
pub struct Secrets {
    items: Vec<Witness>,
    inputs: Vec<(Class, String, Input)>,
}

impl Secrets {
    /// Empty set.
    pub fn new() -> Self {
        Secrets::default()
    }

    /// Registered witnesses.
    pub fn witnesses(&self) -> &[Witness] {
        &self.items
    }

    /// Classes that have at least one registered value. A class without a value cannot
    /// be verified, so the checks refuse to run with gaps (see [`Secrets::missing`]).
    pub fn covered(&self) -> BTreeSet<Class> {
        self.items.iter().map(|w| w.class).collect()
    }

    /// Classes with no registered value.
    pub fn missing(&self) -> Vec<Class> {
        let have = self.covered();
        Class::ALL
            .into_iter()
            .filter(|c| !have.contains(c))
            .collect()
    }

    fn push(&mut self, class: Class, label: &str, needles: Vec<(&'static str, Vec<u8>)>) {
        let needles: Vec<_> = needles
            .into_iter()
            .filter(|(_, n)| n.len() >= MIN_NEEDLE)
            .collect();
        if needles.is_empty() {
            return;
        }
        self.items.push(Witness {
            class,
            label: label.to_owned(),
            needles,
        });
    }

    /// Serialise the registered values so a separate process can scan with them.
    pub fn to_json(&self) -> String {
        let items: Vec<serde_json::Value> = self
            .inputs
            .iter()
            .map(|(class, label, input)| {
                let (kind, value) = match input {
                    Input::Text(t) => ("text", t.clone()),
                    Input::Bytes(b) => ("bytes", xchonnect_core::b64::encode(b)),
                    Input::Opaque(b) => ("opaque", xchonnect_core::b64::encode(b)),
                };
                serde_json::json!({ "class": class.id(), "label": label, "kind": kind, "value": value })
            })
            .collect();
        serde_json::Value::Array(items).to_string()
    }

    /// Parse what [`Secrets::to_json`] wrote.
    pub fn from_json(text: &str) -> Result<Secrets, String> {
        let parsed: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("secrets file is not JSON: {e}"))?;
        let items = parsed.as_array().ok_or("secrets file is not an array")?;
        let mut out = Secrets::new();
        for item in items {
            let get = |k: &str| {
                item.get(k)
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| format!("secret without `{k}`"))
            };
            let class = Class::parse(get("class")?)
                .ok_or_else(|| format!("unknown class `{}`", get("class").unwrap_or_default()))?;
            let (label, value) = (get("label")?, get("value")?);
            match get("kind")? {
                "text" => out.text(class, label, value),
                kind @ ("bytes" | "opaque") => {
                    let bytes = xchonnect_core::b64::decode(value)
                        .map_err(|_| format!("secret `{label}` is not base64url"))?;
                    if kind == "bytes" {
                        out.bytes(class, label, &bytes)
                    } else {
                        out.opaque_bytes(class, label, &bytes)
                    }
                }
                other => return Err(format!("unknown secret kind `{other}`")),
            };
        }
        Ok(out)
    }

    /// Register a textual value (an address, a header value, a hex device token).
    pub fn text(&mut self, class: Class, label: &str, value: &str) -> &mut Self {
        self.inputs
            .push((class, label.to_owned(), Input::Text(value.to_owned())));
        let lower = value.to_lowercase();
        let upper = value.to_uppercase();
        let mut needles = vec![("text", value.as_bytes().to_vec())];
        if lower != value {
            needles.push(("text-lowercase", lower.into_bytes()));
        }
        if upper != value {
            needles.push(("text-uppercase", upper.into_bytes()));
        }
        self.push(class, label, needles);
        self
    }

    /// Register a byte string: every encoding plus truncation prefixes.
    pub fn bytes(&mut self, class: Class, label: &str, value: &[u8]) -> &mut Self {
        self.register_bytes(class, label, value, true);
        self
    }

    /// Register a byte string without truncation prefixes. Used for values that share a
    /// fixed header with every other value of their kind (encoded envelopes), where a
    /// prefix is not an identifier.
    pub fn opaque_bytes(&mut self, class: Class, label: &str, value: &[u8]) -> &mut Self {
        self.register_bytes(class, label, value, false);
        self
    }

    fn register_bytes(&mut self, class: Class, label: &str, value: &[u8], prefixes: bool) {
        let input = if prefixes {
            Input::Bytes(value.to_vec())
        } else {
            Input::Opaque(value.to_vec())
        };
        self.inputs.push((class, label.to_owned(), input));
        let b64url = xchonnect_core::b64::encode(value);
        let hex = hex_encode(value, false);
        let mut needles = vec![
            ("raw-bytes", value.to_vec()),
            ("base64url", b64url.clone().into_bytes()),
            ("base64", base64_std(value).into_bytes()),
            ("hex", hex.clone().into_bytes()),
            ("hex-uppercase", hex_encode(value, true).into_bytes()),
            ("debug-array", debug_array(value).into_bytes()),
        ];
        if prefixes {
            let cut = |s: &str, n: usize| s.chars().take(n).collect::<String>().into_bytes();
            if b64url.len() > B64_PREFIX {
                needles.push(("base64url-prefix", cut(&b64url, B64_PREFIX)));
            }
            if hex.len() > HEX_PREFIX {
                needles.push(("hex-prefix", cut(&hex, HEX_PREFIX)));
            }
        }
        self.push(class, label, needles);
    }
}

/// An artefact to scan: text (logs, metrics, a SQL dump) and/or raw bytes.
#[derive(Debug, Clone, Default)]
pub struct Surface {
    /// Inventory name, e.g. `database`.
    pub name: String,
    /// Textual content.
    pub text: String,
    /// Binary content.
    pub bytes: Vec<u8>,
}

impl Surface {
    /// Empty surface.
    pub fn new(name: &str) -> Self {
        Surface {
            name: name.to_owned(),
            text: String::new(),
            bytes: Vec::new(),
        }
    }

    /// Append a line of text.
    pub fn line(&mut self, line: impl fmt::Display) {
        self.text.push_str(&line.to_string());
        self.text.push('\n');
    }

    /// Append raw bytes (also searched for raw needles).
    pub fn raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
        // A separator keeps two adjacent values from forming a third.
        self.bytes.push(0);
    }

    /// Total observed size.
    pub fn len(&self) -> usize {
        self.text.len() + self.bytes.len()
    }

    /// Whether nothing was observed at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One leak: a value of `class` found on `surface`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Surface name.
    pub surface: String,
    /// Class of the value found.
    pub class: Class,
    /// Which value.
    pub label: String,
    /// Encoding it was found in.
    pub form: &'static str,
    /// `text` or `bytes`, with the byte offset.
    pub at: String,
    /// Redacted context around the match.
    pub context: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} ({}) as {} at {} — {}",
            self.surface, self.class, self.label, self.form, self.at, self.context
        )
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .filter(|_| true)
}

/// Printable, bounded context with the match itself replaced.
fn context(haystack: &[u8], at: usize, len: usize, label: &str) -> String {
    const WINDOW: usize = 36;
    let start = at.saturating_sub(WINDOW);
    let end = (at + len + WINDOW).min(haystack.len());
    let show = |range: std::ops::Range<usize>| -> String {
        haystack
            .get(range)
            .unwrap_or_default()
            .iter()
            .map(|b| match b {
                0x20..=0x7e => char::from(*b),
                b'\n' | b'\r' | b'\t' => ' ',
                _ => '.',
            })
            .collect()
    };
    format!(
        "…{}<FOUND {label}>{}…",
        show(start..at),
        show((at + len).min(end)..end)
    )
}

/// Every occurrence of every registered value on one surface.
pub fn scan(surface: &Surface, secrets: &Secrets) -> Vec<Finding> {
    let mut out = Vec::new();
    for w in &secrets.items {
        for (form, needle) in &w.needles {
            for (where_, hay) in [("text", surface.text.as_bytes()), ("bytes", &surface.bytes)] {
                if let Some(at) = find(hay, needle) {
                    out.push(Finding {
                        surface: surface.name.clone(),
                        class: w.class,
                        label: w.label.clone(),
                        form,
                        at: format!("{where_}+{at}"),
                        context: context(hay, at, needle.len(), &w.label),
                    });
                }
            }
        }
    }
    out
}

/// Classes observed on a surface.
pub fn classes(surface: &Surface, secrets: &Secrets) -> BTreeSet<Class> {
    scan(surface, secrets)
        .into_iter()
        .map(|f| f.class)
        .collect()
}

// ---------------------------------------------------------------------------
// Value-independent pattern detectors
// ---------------------------------------------------------------------------

/// A shape of sensitive data, detected without knowing the value. These catch leaks
/// from data the fixture did not plant — a client IP the runtime made up, an address
/// from somebody else's test, a key dumped by a dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
    /// Dotted-quad IPv4 literal.
    Ipv4,
    /// Chia bech32m address (`xch1…`, `txch1…`).
    ChiaAddress,
    /// A run of 64 or 96 hex characters: an X25519/BLS key or an APNs device token.
    HexKey,
    /// `User-Agent` header name or a well-known user-agent fragment.
    UserAgent,
    /// `Authorization: Bearer <value>`.
    BearerToken,
}

impl Pattern {
    /// Stable identifier.
    pub fn id(self) -> &'static str {
        match self {
            Pattern::Ipv4 => "ipv4_literal",
            Pattern::ChiaAddress => "chia_address_shape",
            Pattern::HexKey => "hex_key_shape",
            Pattern::UserAgent => "user_agent_shape",
            Pattern::BearerToken => "bearer_token_shape",
        }
    }
}

/// A pattern match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternHit {
    /// Surface name.
    pub surface: String,
    /// Which shape matched.
    pub pattern: Pattern,
    /// The matched text. Callers must not print it: a real finding means it is somebody's
    /// data. [`PatternHit::redacted`] is what the reports use.
    pub matched: String,
    /// Redacted context.
    pub context: String,
}

impl PatternHit {
    /// The match with all but its first characters removed, so that a failing build
    /// report does not itself publish the data that leaked.
    pub fn redacted(&self) -> String {
        let keep: String = self.matched.chars().take(4).collect();
        format!(
            "{} characters starting {keep:?}",
            self.matched.chars().count()
        )
    }
}

impl fmt::Display for PatternHit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: looks like {} ({}) — {}",
            self.surface,
            self.pattern.id(),
            self.redacted(),
            self.context
        )
    }
}

const BECH32: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// Minimum data part of an address-shaped match; 20 characters of a 32-symbol alphabet
/// inside base64 noise is a one-in-a-million coincidence.
const BECH32_MIN: usize = 20;

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Whether position `i` starts a token (the character before is not part of one).
fn at_boundary(bytes: &[u8], i: usize, extra: &[u8]) -> bool {
    match i.checked_sub(1).and_then(|p| bytes.get(p)) {
        None => true,
        Some(b) => !is_word(*b) && !extra.contains(b),
    }
}

fn ipv4_at(bytes: &[u8], i: usize) -> Option<usize> {
    if !at_boundary(bytes, i, b".") {
        return None;
    }
    let mut pos = i;
    for group in 0..4 {
        let digits = bytes
            .get(pos..)
            .unwrap_or_default()
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if digits == 0 || digits > 3 {
            return None;
        }
        let text = bytes.get(pos..pos + digits).unwrap_or_default();
        let value: u32 = std::str::from_utf8(text).ok()?.parse().ok()?;
        if value > 255 {
            return None;
        }
        pos += digits;
        if group < 3 {
            if bytes.get(pos) != Some(&b'.') {
                return None;
            }
            pos += 1;
        }
    }
    // Not part of a longer dotted or word-ish run (version strings, hashes).
    if bytes.get(pos).is_some_and(|b| *b == b'.' || is_word(*b)) {
        return None;
    }
    Some(pos - i)
}

fn hex_run_at(bytes: &[u8], i: usize) -> Option<usize> {
    if !at_boundary(bytes, i, b"") {
        return None;
    }
    let run = bytes
        .get(i..)
        .unwrap_or_default()
        .iter()
        .take_while(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        .count();
    (run == 64 || run == 96).then_some(run)
}

fn bech32_at(bytes: &[u8], i: usize) -> Option<usize> {
    if !at_boundary(bytes, i, b"") {
        return None;
    }
    let hrp: &[&[u8]] = &[b"txch1", b"xch1"];
    let prefix = hrp
        .iter()
        .find(|p| bytes.get(i..i + p.len()) == Some(**p))?;
    let data = bytes
        .get(i + prefix.len()..)
        .unwrap_or_default()
        .iter()
        .take_while(|b| BECH32.as_bytes().contains(b))
        .count();
    (data >= BECH32_MIN).then_some(prefix.len() + data)
}

fn bearer_at(bytes: &[u8], i: usize) -> Option<usize> {
    let tag = b"Bearer ";
    if bytes.get(i..i + tag.len()) != Some(tag.as_slice()) {
        return None;
    }
    let value = bytes
        .get(i + tag.len()..)
        .unwrap_or_default()
        .iter()
        .take_while(|b| is_word(**b) || **b == b'-' || **b == b'.')
        .count();
    (value >= MIN_NEEDLE).then_some(tag.len() + value)
}

fn user_agent_at(bytes: &[u8], i: usize) -> Option<usize> {
    for needle in [
        "user-agent".as_bytes(),
        "User-Agent".as_bytes(),
        "USER_AGENT".as_bytes(),
        "Mozilla/".as_bytes(),
        "CFNetwork/".as_bytes(),
        "okhttp/".as_bytes(),
    ] {
        if bytes.get(i..i + needle.len()) == Some(needle) {
            return Some(needle.len());
        }
    }
    None
}

/// Scan for sensitive *shapes*. `allow` holds exact matched strings that are known to
/// be benign on this surface (a service's own bind address, for instance); they are
/// declared in the published data inventory, not hidden in the code.
pub fn scan_patterns(surface: &Surface, allow: &[String]) -> Vec<PatternHit> {
    let lossy = String::from_utf8_lossy(&surface.bytes).into_owned();
    let mut out = Vec::new();
    for hay in [surface.text.as_bytes(), lossy.as_bytes()] {
        let mut i = 0;
        while i < hay.len() {
            let found = [
                (Pattern::Ipv4, ipv4_at(hay, i)),
                (Pattern::ChiaAddress, bech32_at(hay, i)),
                (Pattern::HexKey, hex_run_at(hay, i)),
                (Pattern::BearerToken, bearer_at(hay, i)),
                (Pattern::UserAgent, user_agent_at(hay, i)),
            ]
            .into_iter()
            .find_map(|(p, len)| len.map(|l| (p, l)));
            match found {
                Some((pattern, len)) => {
                    let matched = String::from_utf8_lossy(hay.get(i..i + len).unwrap_or_default())
                        .into_owned();
                    if !allow.iter().any(|a| a == &matched) {
                        out.push(PatternHit {
                            surface: surface.name.clone(),
                            pattern,
                            context: context(hay, i, len, pattern.id()),
                            matched,
                        });
                    }
                    i += len;
                }
                None => i += 1,
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn surface(text: &str) -> Surface {
        let mut s = Surface::new("t");
        s.line(text);
        s
    }

    #[test]
    fn every_class_has_a_unique_identifier() {
        let ids: BTreeSet<&str> = Class::ALL.iter().map(|c| c.id()).collect();
        assert_eq!(ids.len(), Class::ALL.len());
        for c in Class::ALL {
            assert_eq!(Class::parse(c.id()), Some(c));
        }
        assert_eq!(Class::parse("nope"), None);
    }

    #[test]
    fn finds_every_encoding_and_a_truncated_prefix() {
        let id = [0x3a_u8; 16];
        let mut s = Secrets::new();
        s.bytes(Class::MailboxId, "mailbox", &id);
        let b64 = xchonnect_core::b64::encode(&id);
        let forms = [
            b64.clone(),
            base64_std(&id),
            hex_encode(&id, false),
            hex_encode(&id, true),
            debug_array(&id),
            b64.chars().take(B64_PREFIX).collect(),
            hex_encode(&id, false).chars().take(HEX_PREFIX).collect(),
        ];
        for form in forms {
            let hit = scan(&surface(&format!("mailbox={form} done")), &s);
            assert!(!hit.is_empty(), "missed {form}");
            assert_eq!(hit[0].class, Class::MailboxId);
        }
        let mut raw = Surface::new("t");
        raw.raw(&id);
        assert_eq!(scan(&raw, &s).len(), 1);
        assert!(scan(&surface("nothing to see"), &s).is_empty());
    }

    #[test]
    fn context_does_not_repeat_the_value() {
        let mut s = Secrets::new();
        s.text(Class::ChiaAddress, "addr", "xch1qqqqqqqqqqqqqqqqqqqq");
        let f = scan(&surface("paying xch1qqqqqqqqqqqqqqqqqqqq now"), &s);
        assert_eq!(f.len(), 1);
        assert!(!f[0].context.contains("xch1qqqq"), "{}", f[0].context);
        assert!(f[0].context.contains("paying"));
    }

    #[test]
    fn short_values_are_refused_rather_than_matched_by_chance() {
        let mut s = Secrets::new();
        s.text(Class::CustomerId, "tiny", "abc");
        s.bytes(Class::MsgId, "tiny", &[1, 2]);
        assert!(s.witnesses().is_empty());
        assert_eq!(s.missing().len(), Class::ALL.len());
    }

    #[test]
    fn patterns_detect_shapes_and_honour_the_allowlist() {
        let cases = [
            ("client 203.0.113.9 connected", Pattern::Ipv4),
            (
                "to xch1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgp now",
                Pattern::ChiaAddress,
            ),
            (&format!("key {}", "ab".repeat(32)), Pattern::HexKey),
            ("Authorization: Bearer abcdefghijkl", Pattern::BearerToken),
            ("user-agent: x", Pattern::UserAgent),
        ];
        for (text, pattern) in cases {
            let hits = scan_patterns(&surface(text), &[]);
            assert_eq!(hits.len(), 1, "{text}: {hits:?}");
            assert_eq!(hits[0].pattern, pattern);
        }
        let allow = vec!["203.0.113.9".to_owned()];
        assert!(scan_patterns(&surface("client 203.0.113.9"), &allow).is_empty());
    }

    #[test]
    fn patterns_do_not_fire_on_versions_hashes_or_short_runs() {
        let benign = [
            "text/plain; version=0.0.4",
            "xchonnect 0.1.0 starting",
            "sha 1.2.3.4.5",
            "digest ab12cd34ef",
            &format!("sha256 {}", "ab".repeat(16)),
            "xch1short",
            "Bearer ",
        ];
        for text in benign {
            let hits = scan_patterns(&surface(text), &[]);
            assert!(hits.is_empty(), "{text}: {hits:?}");
        }
    }

    #[test]
    fn a_pattern_report_does_not_republish_what_leaked() {
        let mut s = Surface::new("service_logs");
        s.line("client 203.0.113.77 connected");
        let hits = scan_patterns(&s, &[]);
        let rendered = hits[0].to_string();
        assert!(!rendered.contains("203.0.113.77"), "{rendered}");
        assert!(
            rendered.contains("12 characters starting \"203.\""),
            "{rendered}"
        );
    }

    #[test]
    fn base64_standard_encoding_matches_the_reference() {
        assert_eq!(
            base64_std(b"any carnal pleasure."),
            "YW55IGNhcm5hbCBwbGVhc3VyZS4="
        );
        assert_eq!(
            base64_std(b"any carnal pleasure"),
            "YW55IGNhcm5hbCBwbGVhc3VyZQ=="
        );
        assert_eq!(
            base64_std(b"any carnal pleasur"),
            "YW55IGNhcm5hbCBwbGVhc3Vy"
        );
    }
}
