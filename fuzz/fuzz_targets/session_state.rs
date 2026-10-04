//! Restoring a session from host storage, then driving the restored state.
//!
//! Host storage can be corrupted or tampered with; whatever `Session::from_bytes`
//! accepts must never make later calls panic.
#![no_main]
#![allow(clippy::unwrap_used, clippy::panic)]

use libfuzzer_sys::fuzz_target;
use xchonnect_core::crypto::{MailboxId, TestEntropy, Token};
use xchonnect_core::message::Message;
use xchonnect_core::session::Session;

const NOW: u64 = 1_790_000_000;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = Session::from_bytes(data) else {
        return;
    };
    // Serialisation is a fixed point after one round trip (unknown keys are dropped).
    let bytes = s.to_bytes().unwrap();
    let again = Session::from_bytes(&bytes).unwrap();
    assert_eq!(again.to_bytes().unwrap(), bytes, "state round trip");

    let mut rng = TestEntropy::new([7; 32]);
    let mut s = again;
    let _ = (
        s.role(),
        s.epoch(),
        s.own_mailbox(),
        s.is_active(),
        s.peer_ready(),
    );
    let _ = s.draining_mailbox();
    let _ = s.pending_rotation_mailbox();
    let _ = s.needs_rotation(NOW);
    let _ = s.needs_rotation(u64::MAX);

    if let Ok(out) = s.seal(&mut rng, NOW, Message::SessionPing, 60) {
        assert!(xchonnect_core::envelope::Envelope::decode(&out.envelope).is_ok());
    }
    let _ = s.begin_rotation(
        &mut rng,
        NOW,
        MailboxId([0xa1; 16]),
        Token::from_bytes([0xa2; 32]),
        Token::from_bytes([0xa3; 32]),
    );
    // Opening anything on any mailbox fails cleanly or succeeds; it never panics.
    let own = s.own_mailbox();
    let _ = s.open(NOW, &own, data);
    let _ = s.finish_drain();
    let _ = s.confirm_sas(&mut rng, NOW, None);
    let _ = s.end(&mut rng, NOW, Some("fuzz".into()));
    assert!(Session::from_bytes(&s.to_bytes().unwrap()).is_ok());
});
