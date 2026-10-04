//! Outer envelope decoding (what relays run on every POST) and padding removal.
#![no_main]
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use libfuzzer_sys::fuzz_target;
use xchonnect_core::cbor;
use xchonnect_core::envelope::{self, Envelope};

fuzz_target!(|data: &[u8]| {
    // Anything the strict decoder accepts re-encodes byte-identically.
    if let Ok(v) = cbor::decode(data) {
        assert_eq!(cbor::encode(&v).unwrap(), data, "cbor not canonical");
    }

    if let Ok(env) = Envelope::decode(data) {
        assert_eq!(env.encode().unwrap(), data, "envelope not canonical");
        match env.kind {
            envelope::Kind::Session => {
                assert_eq!(env.n.len(), 24);
                assert!(envelope::BUCKETS.contains(&env.ct.len()));
            }
            envelope::Kind::Pairing => {
                assert_eq!(env.n.len(), 32);
                assert_eq!(env.ct.len(), envelope::PAIRING_CT_LEN);
            }
        }
    }

    // unpad: one canonical item followed only by zero bytes.
    if let Ok(v) = envelope::unpad(data) {
        let enc = cbor::encode(&v).unwrap();
        assert!(data.starts_with(&enc), "unpad prefix not canonical");
        assert!(
            data[enc.len()..].iter().all(|b| *b == 0),
            "non-zero padding"
        );
    }
});
