//! Domain display for pairing approval (spec 6.3 step 3): show the punycode-decoded
//! form and flag homograph risk.

/// Warning attached to a displayed domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainWarning {
    /// Contains internationalised (non-ASCII) labels; wallets MUST show the ASCII form too.
    NonAscii,
    /// A label mixes letters from different scripts (e.g. Latin and Cyrillic).
    MixedScript,
    /// The name could not be decoded as an IDN; show only the ASCII form.
    InvalidIdn,
}

/// Result of [`display_domain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainDisplay {
    /// The domain as received (A-labels).
    pub ascii: String,
    /// Unicode form for display (equals `ascii` when there is nothing to decode).
    pub unicode: String,
    /// Warnings the wallet must surface.
    pub warnings: Vec<DomainWarning>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Greek,
    Cyrillic,
    Other,
}

fn script(c: char) -> Option<Script> {
    let u = c as u32;
    // Only letters carry a script; digits, hyphens, dots and port separators are neutral.
    if !c.is_alphabetic() {
        return None;
    }
    Some(match u {
        0x41..=0x5a | 0x61..=0x7a | 0xc0..=0x24f | 0x1e00..=0x1eff => Script::Latin,
        0x370..=0x3ff | 0x1f00..=0x1fff => Script::Greek,
        0x400..=0x52f | 0x2de0..=0x2dff | 0xa640..=0xa69f => Script::Cyrillic,
        _ => Script::Other,
    })
}

/// Decode an ASCII (A-label) domain for display and compute warnings.
pub fn display_domain(ascii: &str) -> DomainDisplay {
    let (unicode, res) = idna::domain_to_unicode(ascii);
    let mut warnings = Vec::new();
    if res.is_err() {
        return DomainDisplay {
            ascii: ascii.to_owned(),
            unicode: ascii.to_owned(),
            warnings: vec![DomainWarning::InvalidIdn],
        };
    }
    if !unicode.is_ascii() {
        warnings.push(DomainWarning::NonAscii);
    }
    let mixed = unicode.split('.').any(|label| {
        let mut seen: Option<Script> = None;
        label.chars().filter_map(script).any(|s| match seen {
            None => {
                seen = Some(s);
                false
            }
            Some(prev) => prev != s,
        })
    });
    if mixed {
        warnings.push(DomainWarning::MixedScript);
    }
    DomainDisplay {
        ascii: ascii.to_owned(),
        unicode,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ascii_has_no_warnings() {
        let d = display_domain("pengui.xyz");
        assert_eq!(d.unicode, "pengui.xyz");
        assert!(d.warnings.is_empty());
    }

    #[test]
    fn ports_and_digits_are_neutral() {
        assert!(display_domain("localhost:5173").warnings.is_empty());
        assert!(display_domain("app-2.example.org").warnings.is_empty());
    }

    #[test]
    fn idn_is_decoded_and_flagged() {
        // "münchen.de"
        let d = display_domain("xn--mnchen-3ya.de");
        assert_eq!(d.unicode, "münchen.de");
        assert_eq!(d.warnings, vec![DomainWarning::NonAscii]);
    }

    #[test]
    fn mixed_latin_cyrillic_flagged() {
        // "pеngui.xyz" with Cyrillic 'е' (U+0435)
        let ascii = idna::domain_to_ascii("p\u{0435}ngui.xyz").unwrap_or_default();
        let d = display_domain(&ascii);
        assert!(d.warnings.contains(&DomainWarning::MixedScript));
        assert!(d.warnings.contains(&DomainWarning::NonAscii));
    }
}
