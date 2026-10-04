//! Sealed push token opening (gateway side, spec 7.3.2): arbitrary blobs must never
//! panic, and anything that opens must satisfy the token invariants.
#![no_main]
#![allow(clippy::unwrap_used, clippy::panic)]

use libfuzzer_sys::fuzz_target;
use xchonnect_core::crypto::X25519Secret;
use xchonnect_core::push::{MAX_DEVICE_TOKEN, MAX_LIFETIME_S, PushToken};

const NOW: u64 = 1_790_000_000;

fuzz_target!(|data: &[u8]| {
    let gw = X25519Secret::from_bytes([9; 32]);
    if let Ok(t) = PushToken::open(&gw, data, NOW) {
        assert!(!t.device_token.is_empty() && t.device_token.len() <= MAX_DEVICE_TOKEN);
        assert!(t.exp >= NOW && t.exp - NOW <= MAX_LIFETIME_S);
    }
});
