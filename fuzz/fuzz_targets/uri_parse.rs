//! Pairing URI parsing in normal and developer mode.
#![no_main]
#![allow(clippy::unwrap_used, clippy::panic)]

use libfuzzer_sys::fuzz_target;
use xchonnect_core::uri::{PairingUri, ParseOptions};

const NORMAL: ParseOptions = ParseOptions {
    developer_mode: false,
};
const DEV: ParseOptions = ParseOptions {
    developer_mode: true,
};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };
    let normal = PairingUri::parse(s, NORMAL);
    let dev = PairingUri::parse(s, DEV);

    // Developer mode only ever relaxes the rules.
    if let Ok(n) = &normal {
        assert_eq!(dev.as_ref().ok(), Some(n), "dev mode rejected a normal URI");
    }

    for (parsed, opts) in [(normal, NORMAL), (dev, DEV)] {
        let Ok(uri) = parsed else { continue };
        // Re-serialising and re-parsing yields the same URI (both forms).
        let again = PairingUri::parse(&uri.to_uri(), opts).unwrap();
        assert_eq!(again, uri, "to_uri round trip");
        let link = uri.to_universal_link("https://wallet.example/pair");
        assert_eq!(
            PairingUri::parse(&link, opts).unwrap(),
            uri,
            "link round trip"
        );
        // Signature input and transcript hash are always computable.
        let _ = uri.h_uri().unwrap();
        let _ = uri.check_time(uri.expires_at);
    }
});
