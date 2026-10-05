//! Origin document (`/.well-known/xchonnect.json`) parsing.
#![no_main]
#![allow(clippy::unwrap_used, clippy::panic)]

use libfuzzer_sys::fuzz_target;
use xchonnect_core::origin::{self, MAX_DOCUMENT_BYTES, OriginDocument};

fuzz_target!(|data: &[u8]| {
    let Ok(doc) = OriginDocument::parse(data) else {
        return;
    };
    assert!(data.len() <= MAX_DOCUMENT_BYTES);
    assert!(!doc.name.is_empty() && doc.name.chars().count() <= 64);
    assert!((1..=8).contains(&doc.keys.len()));
    for (i, k) in doc.keys.iter().enumerate() {
        assert!(origin::valid_kid(&k.kid));
        assert_eq!(
            k.not_after % 86_400,
            86_399,
            "not_after is end of a UTC day"
        );
        assert!(
            doc.keys.iter().skip(i + 1).all(|o| o.kid != k.kid),
            "duplicate kid accepted"
        );
        // Lookup by kid finds this key while it is valid and rejects it afterwards.
        assert_eq!(doc.key(&k.kid, k.not_after).unwrap(), k);
        assert!(doc.key(&k.kid, k.not_after + 1).is_err());
    }
    for url in doc.icon.iter().chain(doc.return_url.iter()) {
        assert!(url.starts_with("https://") && url.len() <= 256);
    }
    // A `return_url` binds the document to exactly one domain: the authority it names,
    // never a parent, a child or a lookalike of it (T18).
    if let Some(u) = &doc.return_url {
        let authority = u
            .strip_prefix("https://")
            .unwrap_or_default()
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
            .to_owned();
        assert!(doc.check_bound_to("").is_err(), "bound to no domain");
        if !authority.is_empty() {
            assert!(doc.check_bound_to(&authority).is_ok(), "{authority}");
            for other in [
                format!("{authority}.evil.example"),
                format!("evil.{authority}"),
                format!("x{authority}"),
                format!("{authority}."),
                format!("{authority}:8443"),
            ] {
                assert!(doc.check_bound_to(&other).is_err(), "{other} accepted");
            }
        }
    } else {
        assert!(doc.check_bound_to("anything.example").is_ok());
    }
});
