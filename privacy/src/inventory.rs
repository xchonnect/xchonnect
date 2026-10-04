//! The published data inventory (`docs/privacy/data-inventory.md`), parsed and enforced.
//!
//! The inventory is the contract: for every surface an operator or auditor can look at,
//! it names the data classes that *must* be observable there and the classes that must
//! *never* be. The checks fail both ways — a forbidden class that appears is a leak, and
//! a declared class that does not appear means the fixture stopped exercising the code
//! and the run proved nothing.

use crate::scan::{Class, Finding, PatternHit, Secrets, Surface, scan, scan_patterns};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

/// Default location of the published inventory, relative to the repository root.
pub const PATH: &str = "docs/privacy/data-inventory.md";

/// Repository root (the parent of this crate).
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf()
}

/// What may and must appear on one surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfacePolicy {
    /// Inventory name.
    pub surface: String,
    /// Classes the surface legitimately carries; the checks require each to show up.
    pub present: BTreeSet<Class>,
    /// Classes that must never appear.
    pub absent: BTreeSet<Class>,
    /// Whether to run the value-independent shape detectors on this surface.
    pub shapes: bool,
}

/// The parsed inventory.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    /// Per-surface policies, in document order.
    pub surfaces: Vec<SurfacePolicy>,
    /// Declared relay database columns, `table.column`.
    pub schema: BTreeSet<String>,
    /// Literals that may match a shape detector on a given surface.
    pub benign: BTreeMap<String, Vec<String>>,
    /// Row labels of the spec's own data-inventory table (spec 14) this document covers.
    pub spec_rows: BTreeSet<String>,
}

impl Inventory {
    /// Policy for a surface.
    pub fn policy(&self, surface: &str) -> Option<&SurfacePolicy> {
        self.surfaces.iter().find(|p| p.surface == surface)
    }

    /// Declared surface names.
    pub fn names(&self) -> Vec<&str> {
        self.surfaces.iter().map(|p| p.surface.as_str()).collect()
    }

    /// Literals allowed to match a shape detector on `surface`.
    pub fn benign_for(&self, surface: &str) -> Vec<String> {
        self.benign.get(surface).cloned().unwrap_or_default()
    }
}

/// Rows of the markdown table under `## <heading>`, without the header and separator.
fn table(md: &str, heading: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut inside = false;
    let mut seen_header = false;
    for line in md.lines() {
        let trimmed = line.trim();
        if let Some(h) = trimmed.strip_prefix("## ") {
            inside = h.trim() == heading;
            seen_header = false;
            continue;
        }
        if !inside {
            continue;
        }
        if !trimmed.starts_with('|') {
            continue;
        }
        let cells: Vec<String> = trimmed
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().trim_matches('`').to_owned())
            .collect();
        if cells
            .iter()
            .all(|c| c.chars().all(|ch| ch == '-' || ch == ':'))
        {
            continue;
        }
        if !seen_header {
            seen_header = true;
            continue;
        }
        rows.push(cells);
    }
    rows
}

fn cell(row: &[String], i: usize) -> String {
    row.get(i).cloned().unwrap_or_default()
}

/// Class list of a cell; `none` means the empty set.
fn classes(text: &str) -> Result<BTreeSet<Class>, String> {
    if text.trim() == "none" {
        return Ok(BTreeSet::new());
    }
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| Class::parse(s).ok_or_else(|| format!("unknown data class `{s}`")))
        .collect()
}

/// Parse an inventory document.
pub fn parse(md: &str) -> Result<Inventory, String> {
    let mut inv = Inventory::default();
    for row in table(md, "Surfaces") {
        let surface = cell(&row, 0);
        if surface.is_empty() {
            return Err("surface row without a name".into());
        }
        let present = classes(&cell(&row, 1))?;
        let absent = classes(&cell(&row, 2))?;
        let shapes = match cell(&row, 3).as_str() {
            "yes" => true,
            "no" => false,
            other => {
                return Err(format!(
                    "{surface}: shape scan must be yes or no, got `{other}`"
                ));
            }
        };
        let declared: BTreeSet<Class> = present.union(&absent).copied().collect();
        let missing: Vec<&str> = Class::ALL
            .iter()
            .filter(|c| !declared.contains(c))
            .map(|c| c.id())
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "{surface}: every data class must be declared present or absent; missing {}",
                missing.join(", ")
            ));
        }
        let both: Vec<&str> = present.intersection(&absent).map(|c| c.id()).collect();
        if !both.is_empty() {
            return Err(format!(
                "{surface}: {} declared both present and absent",
                both.join(", ")
            ));
        }
        inv.surfaces.push(SurfacePolicy {
            surface,
            present,
            absent,
            shapes,
        });
    }
    if inv.surfaces.is_empty() {
        return Err("no `## Surfaces` table found".into());
    }
    for row in table(md, "Relay database schema") {
        let t = cell(&row, 0);
        for column in cell(&row, 1).split(',').map(str::trim) {
            if !column.is_empty() {
                inv.schema.insert(format!("{t}.{column}"));
            }
        }
    }
    for row in table(md, "Benign literals") {
        let literal = cell(&row, 1);
        if !literal.is_empty() {
            inv.benign.entry(cell(&row, 0)).or_default().push(literal);
        }
    }
    for row in table(md, "Spec §14 mapping") {
        let label = cell(&row, 0);
        if !label.is_empty() {
            inv.spec_rows.insert(label);
        }
    }
    Ok(inv)
}

/// Load the published inventory from the repository.
pub fn load() -> Result<Inventory, String> {
    let path = repo_root().join(PATH);
    let md = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    parse(&md)
}

/// Outcome of verifying observed surfaces against the inventory.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Forbidden values that were found.
    pub leaks: Vec<Finding>,
    /// Shapes that were found where none is allowed.
    pub shapes: Vec<PatternHit>,
    /// Everything that is wrong, including leaks, shapes and coverage gaps.
    pub violations: Vec<String>,
    /// Surfaces that were checked.
    pub checked: Vec<String>,
    /// Declared surfaces that this run did not observe.
    pub skipped: Vec<String>,
}

impl Report {
    /// Whether the run may pass.
    pub fn ok(&self) -> bool {
        self.violations.is_empty()
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "checked surfaces: {}", self.checked.join(", "))?;
        if !self.skipped.is_empty() {
            writeln!(f, "not observed in this run: {}", self.skipped.join(", "))?;
        }
        if self.violations.is_empty() {
            return writeln!(f, "no privacy violations");
        }
        writeln!(f, "{} privacy violation(s):", self.violations.len())?;
        for v in &self.violations {
            writeln!(f, "  - {v}")?;
        }
        Ok(())
    }
}

/// Verify observed surfaces against the inventory.
///
/// `require_full_coverage` demands that every class has at least one registered value,
/// which is what makes a passing run meaningful: without it, a fixture that stopped
/// planting addresses would silently "prove" that no address is ever logged.
pub fn verify(
    inv: &Inventory,
    surfaces: &[Surface],
    secrets: &Secrets,
    require_full_coverage: bool,
) -> Report {
    let mut r = Report::default();
    if require_full_coverage {
        for class in secrets.missing() {
            r.violations.push(format!(
                "no value registered for data class `{class}`: the check cannot verify it"
            ));
        }
    }
    for surface in surfaces {
        r.checked.push(surface.name.clone());
        let Some(policy) = inv.policy(&surface.name) else {
            r.violations.push(format!(
                "surface `{}` is not declared in {PATH}",
                surface.name
            ));
            continue;
        };
        if surface.is_empty() {
            r.violations.push(format!(
                "surface `{}` is empty: nothing was observed, so nothing was verified",
                surface.name
            ));
            continue;
        }
        let found = scan(surface, secrets);
        let seen: BTreeSet<Class> = found.iter().map(|f| f.class).collect();
        for finding in found {
            if policy.absent.contains(&finding.class) {
                r.violations.push(finding.to_string());
                r.leaks.push(finding);
            }
        }
        for class in &policy.present {
            if !seen.contains(class) {
                r.violations.push(format!(
                    "{}: `{class}` is declared as observed in {PATH} but was not found; \
                     either the fixture no longer exercises it or the inventory is stale",
                    surface.name
                ));
            }
        }
        if policy.shapes {
            for hit in scan_patterns(surface, &inv.benign_for(&surface.name)) {
                r.violations.push(hit.to_string());
                r.shapes.push(hit);
            }
        }
    }
    for name in inv.names() {
        if !r.checked.iter().any(|c| c == name) {
            r.skipped.push(name.to_owned());
        }
    }
    r
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn all_but(keep: &[Class]) -> String {
        Class::ALL
            .iter()
            .filter(|c| !keep.contains(c))
            .map(|c| c.id())
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn doc(present: &[Class], shapes: &str) -> String {
        let absent = all_but(present);
        let present = if present.is_empty() {
            "none".to_owned()
        } else {
            present
                .iter()
                .map(|c| c.id())
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!(
            "# inventory\n\n## Surfaces\n\n| Surface | Must be observed | Must never appear | Shape scan |\n\
             |---|---|---|---|\n| database | {present} | {absent} | {shapes} |\n\n\
             ## Benign literals\n\n| Surface | Literal | Why |\n|---|---|---|\n\
             | database | 127.0.0.1 | loopback |\n"
        )
    }

    #[test]
    fn parses_surfaces_schema_and_literals() {
        let inv = parse(&doc(&[Class::MailboxId], "yes")).unwrap();
        let p = inv.policy("database").unwrap();
        assert!(p.present.contains(&Class::MailboxId) && p.shapes);
        assert_eq!(p.absent.len(), Class::ALL.len() - 1);
        assert_eq!(inv.benign_for("database"), vec!["127.0.0.1".to_owned()]);
        assert_eq!(inv.names(), vec!["database"]);
    }

    #[test]
    fn an_undeclared_class_is_a_parse_error() {
        let md = doc(&[Class::MailboxId], "yes").replace(", api_key", "");
        let err = parse(&md).unwrap_err();
        assert!(err.contains("api_key"), "{err}");
        let md = doc(&[Class::MailboxId], "maybe");
        assert!(parse(&md).unwrap_err().contains("yes or no"));
        assert!(parse("# nothing").unwrap_err().contains("Surfaces"));
    }

    #[test]
    fn verify_reports_leaks_and_missing_coverage() {
        let inv = parse(&doc(&[Class::MailboxId], "no")).unwrap();
        let mut secrets = Secrets::new();
        secrets.bytes(Class::MailboxId, "mailbox", &[7_u8; 16]);
        secrets.text(Class::ChiaAddress, "addr", "xch1qqqqqqqqqqqqqqqqq");
        let mut s = Surface::new("database");
        s.line(format!(
            "mailbox={} addr=xch1qqqqqqqqqqqqqqqqq",
            xchonnect_core::b64::encode(&[7_u8; 16])
        ));
        let r = verify(&inv, &[s], &secrets, false);
        assert!(!r.ok());
        assert_eq!(r.leaks.len(), 1);
        assert_eq!(r.leaks[0].class, Class::ChiaAddress);
        // The declared class was observed, so only the address is a violation.
        assert_eq!(r.violations.len(), 1, "{r}");
    }

    #[test]
    fn verify_fails_when_a_declared_class_is_absent_or_the_surface_is_empty() {
        let inv = parse(&doc(&[Class::MailboxId], "no")).unwrap();
        let mut secrets = Secrets::new();
        secrets.bytes(Class::MailboxId, "mailbox", &[7_u8; 16]);
        let mut s = Surface::new("database");
        s.line("nothing of interest");
        let r = verify(&inv, &[s], &secrets, false);
        assert!(
            r.violations
                .iter()
                .any(|v| v.contains("declared as observed")),
            "{r}"
        );
        let r = verify(&inv, &[Surface::new("database")], &secrets, false);
        assert!(r.violations.iter().any(|v| v.contains("empty")), "{r}");
        let r = verify(&inv, &[Surface::new("mystery")], &secrets, false);
        assert!(
            r.violations.iter().any(|v| v.contains("not declared")),
            "{r}"
        );
    }

    #[test]
    fn verify_requires_a_value_for_every_class() {
        let inv = parse(&doc(&[], "no")).unwrap();
        let mut s = Surface::new("database");
        s.line("quiet");
        let r = verify(&inv, &[s], &Secrets::new(), true);
        assert_eq!(r.violations.len(), Class::ALL.len());
        assert!(
            r.violations
                .iter()
                .all(|v| v.contains("no value registered"))
        );
    }

    #[test]
    fn the_published_inventory_parses() {
        let inv = load().expect("docs/privacy/data-inventory.md must parse");
        assert!(inv.surfaces.len() >= 5, "{:?}", inv.names());
        assert!(!inv.schema.is_empty());
        assert!(!inv.spec_rows.is_empty());
    }
}
