//! Static checks on the service sources and the database schema.
//!
//! Runtime scanning can only see what a run happens to execute. Two things are better
//! pinned statically:
//!
//! * no service may read client identity at all (spec 7.1, 13.5) — if the extractor is
//!   not mentioned, no future code path can leak it;
//! * no log or print call may mention an identifier-bearing name. The denylist is of
//!   *names*, not of call sites, so adding a benign log line is free while
//!   `tracing::info!(?mailbox)` fails the build.
//!
//! The database schema is pinned the same way: the columns in the migrations must be
//! exactly those the published data inventory declares.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A source-policy violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFinding {
    /// File it was found in.
    pub file: String,
    /// 1-based line number.
    pub line: usize,
    /// Which rule was broken.
    pub rule: &'static str,
    /// What was found.
    pub detail: String,
}

impl std::fmt::Display for SourceFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}: {}: {}",
            self.file, self.line, self.rule, self.detail
        )
    }
}

/// Ways to learn who the client is. A service that never mentions them cannot log them.
pub const IDENTITY_SOURCES: [&str; 9] = [
    "ConnectInfo",
    "user-agent",
    "USER_AGENT",
    "x-forwarded-for",
    "X_FORWARDED_FOR",
    "x-real-ip",
    "forwarded",
    "remote_addr",
    "peer_addr",
];

/// Names that must not appear inside a log or print call.
pub const LOG_DENYLIST: [&str; 22] = [
    "mailbox",
    "mailbox_id",
    "token",
    "token_hash",
    "read_hash",
    "write_hash",
    "sealed",
    "sealed_token",
    "envelope",
    "ciphertext",
    "ct",
    "plaintext",
    "device",
    "device_token",
    "address",
    "addr",
    "pubkey",
    "public_key",
    "api_key",
    "bearer",
    "secret",
    "seed",
];

/// Macros whose arguments reach an operator's log or terminal.
const LOG_MACROS: [&str; 8] = [
    "trace", "debug", "info", "warn", "error", "println", "eprintln", "panic",
];

/// Service sources the policy applies to, relative to the repository root.
pub const SERVICE_SOURCES: [&str; 4] = [
    "crates/core/src",
    "crates/relay/src",
    "crates/gateway/src",
    "crates/wallet-kit/src",
];

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Whether `needle` occurs in `text` as a whole identifier.
pub fn contains_word(text: &str, needle: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(rel) = text.get(from..).and_then(|t| t.find(needle)) {
        let at = from + rel;
        let before = text
            .get(..at)
            .and_then(|t| t.chars().next_back())
            .is_some_and(is_word);
        let after = bytes
            .get(at + needle.len())
            .map(|b| char::from(*b))
            .is_some_and(is_word);
        if !before && !after {
            return true;
        }
        from = at + needle.len();
    }
    false
}

/// Everything before the first `#[cfg(test)]`. Test modules plant the very values the
/// policy forbids, so the policy applies to production code only.
pub fn production_part(text: &str) -> &str {
    match text.find("#[cfg(test)]") {
        Some(at) => text.get(..at).unwrap_or(text),
        None => text,
    }
}

fn line_of(text: &str, at: usize) -> usize {
    text.get(..at).unwrap_or_default().lines().count().max(1)
}

/// Log and print calls in `text` as `(line, argument text)`.
pub fn log_calls(text: &str) -> Vec<(usize, String)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for macro_name in LOG_MACROS {
        let tag = format!("{macro_name}!(");
        let mut from = 0;
        while let Some(rel) = text.get(from..).and_then(|t| t.find(&tag)) {
            let at = from + rel;
            from = at + tag.len();
            // `tracing::info!` and `info!` both count; `my_info!(` does not.
            let prefix_ok = text
                .get(..at)
                .and_then(|t| t.chars().next_back())
                .is_none_or(|c| !is_word(c) && c != '.');
            if !prefix_ok {
                continue;
            }
            let mut depth = 1_i32;
            let mut end = from;
            while end < bytes.len() && depth > 0 {
                match bytes.get(end) {
                    Some(b'(') => depth += 1,
                    Some(b')') => depth -= 1,
                    _ => {}
                }
                end += 1;
            }
            let args = text
                .get(from..end.saturating_sub(1))
                .unwrap_or_default()
                .to_owned();
            out.push((line_of(text, at), args));
        }
    }
    out.sort_by_key(|(line, _)| *line);
    out
}

/// Blank out Rust comments, keeping every other byte at its own offset so line
/// numbers stay correct. String, char and raw-string literals are left alone, so
/// a `//` inside a URL literal is not mistaken for a comment.
///
/// The policy is about what the code *does*. Prose in a comment reads nothing and
/// logs nothing, so scanning comments only produces false positives — and a false
/// positive teaches people to reword comments to dodge the check.
fn blank_rust_comments(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = vec![b' '; b.len()];
    let mut i = 0;
    // Copy a run of source bytes through unchanged.
    let keep = |out: &mut Vec<u8>, from: usize, to: usize| {
        for k in from..to {
            if let (Some(dst), Some(src)) = (out.get_mut(k), b.get(k)) {
                *dst = *src;
            }
        }
    };
    while i < b.len() {
        match (b.get(i), b.get(i + 1)) {
            (Some(b'/'), Some(b'/')) => {
                while i < b.len() && b.get(i) != Some(&b'\n') {
                    i += 1;
                }
            }
            (Some(b'/'), Some(b'*')) => {
                let mut depth = 1_i32;
                i += 2;
                while i < b.len() && depth > 0 {
                    match (b.get(i), b.get(i + 1)) {
                        (Some(b'/'), Some(b'*')) => {
                            depth += 1;
                            i += 2;
                        }
                        (Some(b'*'), Some(b'/')) => {
                            depth -= 1;
                            i += 2;
                        }
                        _ => i += 1,
                    }
                }
            }
            (Some(b'r'), Some(b'"' | b'#')) => {
                let start = i;
                let mut hashes = 0;
                let mut j = i + 1;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) != Some(&b'"') {
                    keep(&mut out, start, start + 1);
                    i += 1;
                    continue;
                }
                j += 1;
                // Closing is `"` followed by the same number of `#`.
                while j < b.len() {
                    if b.get(j) == Some(&b'"')
                        && (0..hashes).all(|h| b.get(j + 1 + h) == Some(&b'#'))
                    {
                        j += 1 + hashes;
                        break;
                    }
                    j += 1;
                }
                keep(&mut out, start, j.min(b.len()));
                i = j;
            }
            (Some(b'"'), _) => {
                let start = i;
                i += 1;
                while i < b.len() {
                    match b.get(i) {
                        Some(b'\\') => i += 2,
                        Some(b'"') => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
                keep(&mut out, start, i.min(b.len()));
            }
            _ => {
                keep(&mut out, i, i + 1);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_owned())
}

/// True when `args` is a single string literal with no interpolation and no
/// further arguments, so the call can only ever emit that constant text.
///
/// This is the one safe exemption for the log rule: such a call has no runtime
/// value to leak. Anything with a `{` placeholder or a further argument is still
/// scanned in full, so `info!("token {}", tok)` and `info!(token = ?t, "x")`
/// remain violations.
fn is_constant_message(args: &str) -> bool {
    let args = args.trim();
    let (body, close) = match args.strip_prefix('"') {
        Some(rest) => (rest, '"'),
        None => return false,
    };
    let mut chars = body.char_indices();
    let mut end = None;
    while let Some((idx, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            c if c == close => {
                end = Some(idx);
                break;
            }
            _ => {}
        }
    }
    let Some(end) = end else { return false };
    let (literal, rest) = (body.get(..end).unwrap_or_default(), body.get(end + 1..));
    // A `{` means inline interpolation; `{{` is an escaped brace and is literal.
    if literal.replace("{{", "").contains('{') {
        return false;
    }
    rest.unwrap_or_default()
        .trim()
        .trim_end_matches(',')
        .is_empty()
}

/// Check one source file against the policy.
pub fn check_source(path: &str, text: &str) -> Vec<SourceFinding> {
    let production = blank_rust_comments(production_part(text));
    let production = production.as_str();
    let mut out = Vec::new();
    for needle in IDENTITY_SOURCES {
        if let Some(at) = production.find(needle) {
            out.push(SourceFinding {
                file: path.to_owned(),
                line: line_of(production, at),
                rule: "client identity must not be readable",
                detail: format!("mentions `{needle}`"),
            });
        }
    }
    for (line, args) in log_calls(production) {
        if is_constant_message(&args) {
            continue;
        }
        for needle in LOG_DENYLIST {
            if contains_word(&args, needle) {
                out.push(SourceFinding {
                    file: path.to_owned(),
                    line,
                    rule: "log calls must not mention identifier-bearing names",
                    detail: format!("log argument mentions `{needle}`: {}", short(&args)),
                });
            }
        }
    }
    out
}

fn short(s: &str) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= 120 {
        return flat;
    }
    flat.chars().take(117).chain("...".chars()).collect()
}

/// Every `.rs` file under `dir`, recursively.
pub fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Apply the policy to every service source under the repository root.
pub fn check_services(root: &Path) -> Result<Vec<SourceFinding>, String> {
    let mut out = Vec::new();
    for dir in SERVICE_SOURCES {
        let dir = root.join(dir);
        let files = rust_files(&dir);
        if files.is_empty() {
            return Err(format!("no sources found under {}", dir.display()));
        }
        for file in files {
            let text = std::fs::read_to_string(&file)
                .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
            let name = file
                .strip_prefix(root)
                .unwrap_or(&file)
                .display()
                .to_string();
            out.extend(check_source(&name, &text));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Database schema
// ---------------------------------------------------------------------------

fn strip_sql_comments(sql: &str) -> String {
    sql.lines()
        .map(|l| l.split("--").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `table.column` for every column in `CREATE TABLE` statements.
pub fn schema_columns(sql: &str) -> BTreeSet<String> {
    const SKIP: [&str; 5] = ["PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"];
    let sql = strip_sql_comments(sql);
    let mut out = BTreeSet::new();
    let mut rest = sql.as_str();
    while let Some(at) = rest.find("CREATE TABLE") {
        let after = rest.get(at + "CREATE TABLE".len()..).unwrap_or_default();
        let Some(open) = after.find('(') else { break };
        let table = after
            .get(..open)
            .unwrap_or_default()
            .split_whitespace()
            .next_back()
            .unwrap_or_default()
            .to_owned();
        let body = after.get(open + 1..).unwrap_or_default();
        let mut depth = 1_i32;
        let mut parts: Vec<String> = vec![String::new()];
        let mut consumed = 0;
        for c in body.chars() {
            consumed += c.len_utf8();
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                ',' if depth == 1 => {
                    parts.push(String::new());
                    continue;
                }
                _ => {}
            }
            if let Some(last) = parts.last_mut() {
                last.push(c);
            }
        }
        for part in parts {
            let Some(name) = part.split_whitespace().next() else {
                continue;
            };
            if SKIP.contains(&name.to_uppercase().as_str()) {
                continue;
            }
            out.insert(format!("{table}.{name}"));
        }
        rest = body.get(consumed..).unwrap_or_default();
    }
    out
}

/// Compare the schema in the migrations with the one the inventory declares.
pub fn check_schema(declared: &BTreeSet<String>, actual: &BTreeSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    for column in actual.difference(declared) {
        out.push(format!(
            "`{column}` exists in the migrations but is not in the published data inventory: \
             decide what the relay may store before adding a column"
        ));
    }
    for column in declared.difference(actual) {
        out.push(format!(
            "`{column}` is declared in the published data inventory but no migration creates it"
        ));
    }
    out
}

/// Columns of every migration under `dir`.
pub fn migration_columns(dir: &Path) -> Result<BTreeSet<String>, String> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "sql"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("no migrations under {}", dir.display()));
    }
    let mut out = BTreeSet::new();
    for file in files {
        let sql = std::fs::read_to_string(&file)
            .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        out.extend(schema_columns(&sql));
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn word_matching_does_not_fire_on_substrings() {
        assert!(contains_word("a token here", "token"));
        assert!(contains_word("{token}", "token"));
        assert!(!contains_word("tokenize(x)", "token"));
        assert!(!contains_word("my_token", "token"));
        assert!(contains_word("token_hash = 1", "token_hash"));
    }

    #[test]
    fn log_calls_are_extracted_with_nesting_and_line_numbers() {
        let src = "fn f() {\n    tracing::info!(\"a {}\", g(h(1)));\n    warn!(?e, \"b\");\n}\n";
        let calls = log_calls(src);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, 2);
        assert_eq!(calls[0].1, "\"a {}\", g(h(1))");
        assert_eq!(calls[1].1, "?e, \"b\"");
        // A different macro that merely ends in `info!` is not a log call.
        assert!(log_calls("my_info!(mailbox);").is_empty());
    }

    #[test]
    fn a_leaky_log_line_or_identity_read_is_a_finding() {
        let bad = "fn f() { tracing::info!(?mailbox, \"stored\"); }";
        let f = check_source("x.rs", bad);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].detail.contains("mailbox"));
        let bad = "fn f(h: HeaderMap) { let _ = h.get(\"user-agent\"); }";
        let f = check_source("x.rs", bad);
        assert_eq!(f.len(), 1);
        assert!(f[0].rule.contains("client identity"));
        // Formatting the value rather than naming the field is caught as well.
        let bad = "fn f() { tracing::warn!(\"mailbox {} gone\", id.to_b64()); }";
        assert_eq!(check_source("x.rs", bad).len(), 1);
    }

    #[test]
    fn benign_log_lines_and_test_modules_pass() {
        let ok = "fn f() { tracing::info!(\"relay listening on {listen}\"); \
                  tracing::warn!(?e, \"sweep failed\"); }\n\
                  #[cfg(test)]\nmod t { fn g() { println!(\"{}\", mailbox); } }";
        assert!(
            check_source("x.rs", ok).is_empty(),
            "{:?}",
            check_source("x.rs", ok)
        );
    }

    #[test]
    fn schema_columns_are_extracted_without_constraints() {
        let sql = "-- a comment with ip in it\n\
            CREATE TABLE mailboxes (\n\
              id BYTEA PRIMARY KEY, -- 16 bytes\n\
              read_hash BYTEA NOT NULL,\n\
              customer TEXT,\n\
              PRIMARY KEY (id)\n\
            );\n\
            CREATE INDEX mailboxes_x ON mailboxes (customer);\n\
            CREATE TABLE messages (\n\
              mailbox_id BYTEA NOT NULL REFERENCES mailboxes (id) ON DELETE CASCADE,\n\
              envelope BYTEA NOT NULL\n\
            );\n";
        let cols = schema_columns(sql);
        let expected: BTreeSet<String> = [
            "mailboxes.id",
            "mailboxes.read_hash",
            "mailboxes.customer",
            "messages.mailbox_id",
            "messages.envelope",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        assert_eq!(cols, expected);
    }

    #[test]
    fn an_added_identity_column_shows_up() {
        let sql = "CREATE TABLE mailboxes (id BYTEA, client_ip INET);";
        assert!(schema_columns(sql).contains("mailboxes.client_ip"));
    }

    /// Prose in a comment does nothing, so it must not be a finding — but the same
    /// word in real code still must be.
    #[test]
    fn comments_are_not_code_but_code_is_still_checked() {
        let commented = "fn f() {\n    // dropped rather than forwarded\n    g();\n}\n";
        assert!(check_source("a.rs", commented).is_empty());

        let block = "fn f() {\n    /* uses the forwarded header */\n    g();\n}\n";
        assert!(check_source("a.rs", block).is_empty());

        // Negative control: actually reading the header is still refused.
        let real = "fn f(h: &HeaderMap) {\n    let v = h.get(\"x-forwarded-for\");\n}\n";
        assert!(
            check_source("a.rs", real)
                .iter()
                .any(|f| f.rule == "client identity must not be readable"),
            "reading the forwarded header must still be a finding"
        );
    }

    /// A `//` inside a string literal is not a comment.
    #[test]
    fn a_slash_in_a_literal_does_not_start_a_comment() {
        let text = "fn f() {\n    let u = \"https://x/\";\n    let h = get(\"forwarded\");\n}\n";
        assert!(
            !check_source("a.rs", text).is_empty(),
            "the literal must not swallow the rest of the file"
        );
    }

    /// Only a provably constant message is exempt from the log rule.
    #[test]
    fn constant_log_messages_are_exempt_and_nothing_else_is() {
        let constant = "fn f() {\n    tracing::warn!(\"using a pre-issued access token\");\n}\n";
        assert!(check_source("a.rs", constant).is_empty());

        // Negative controls: every way of logging a value is still refused.
        for leak in [
            "tracing::info!(\"token {}\", tok);",
            "tracing::info!(\"mailbox {mailbox_id} fetched\");",
            "tracing::info!(token = ?t, \"sent\");",
            "tracing::info!(\"a\"); tracing::info!(\"device {}\", d);",
        ] {
            let text = format!("fn f() {{\n    {leak}\n}}\n");
            assert!(
                check_source("a.rs", &text)
                    .iter()
                    .any(|f| f.rule == "log calls must not mention identifier-bearing names"),
                "must still be a finding: {leak}"
            );
        }
    }

    #[test]
    fn escaped_braces_stay_constant() {
        assert!(is_constant_message(r#""a token is {{opaque}}""#));
        assert!(!is_constant_message(r#""a token is {opaque}""#));
    }
}
