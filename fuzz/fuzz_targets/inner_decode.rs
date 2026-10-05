//! Inner plaintext decoding after decryption: canonical CBOR -> `Inner` / `PairingReply`.
#![no_main]
#![allow(clippy::unwrap_used, clippy::panic)]

use libfuzzer_sys::fuzz_target;
use xchonnect_core::cbor;
use xchonnect_core::message::{Inner, MAX_SEQ, Message, PairingReply};

fuzz_target!(|data: &[u8]| {
    let Ok(v) = cbor::decode(data) else {
        return;
    };
    assert_eq!(cbor::encode(&v).unwrap(), data, "cbor not canonical");

    if let Ok(inner) = Inner::from_value(&v) {
        assert!((1..=MAX_SEQ).contains(&inner.seq));
        // Unknown keys are dropped, so compare the decoded form after one round trip.
        if !matches!(inner.message, Message::Unknown { .. }) {
            let enc = inner.encode().unwrap();
            let back = Inner::from_value(&cbor::decode(&enc).unwrap()).unwrap();
            assert_eq!(back, inner, "inner round trip");
        }
    }

    if let Ok(reply) = PairingReply::from_value(&v) {
        let enc = reply.encode().unwrap();
        let back = PairingReply::from_value(&cbor::decode(&enc).unwrap()).unwrap();
        assert_eq!(back, reply, "pairing reply round trip");
    }
});
