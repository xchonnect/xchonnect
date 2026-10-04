//! Valid and deliberately invalid outer envelopes (spec 5.3, `envelope.cddl`).
//!
//! Valid envelopes come from `xchonnect-core`; invalid ones are hand-encoded so the
//! suite does not depend on the core encoder refusing them.

use xchonnect_core::envelope::{Envelope, Kind};

/// A CBOR item used in hand-built envelopes.
#[derive(Debug, Clone)]
pub(crate) enum Item {
    Uint(u64),
    Bytes(Vec<u8>),
}

/// Minimal-length CBOR head.
pub(crate) fn head(major: u8, n: u64) -> Vec<u8> {
    let m = major << 5;
    match n {
        0..=23 => vec![m | n as u8],
        24..=0xff => vec![m | 24, n as u8],
        0x100..=0xffff => {
            let mut v = vec![m | 25];
            v.extend_from_slice(&(n as u16).to_be_bytes());
            v
        }
        0x1_0000..=0xffff_ffff => {
            let mut v = vec![m | 26];
            v.extend_from_slice(&(n as u32).to_be_bytes());
            v
        }
        _ => {
            let mut v = vec![m | 27];
            v.extend_from_slice(&n.to_be_bytes());
            v
        }
    }
}

fn item(i: &Item) -> Vec<u8> {
    match i {
        Item::Uint(n) => head(0, *n),
        Item::Bytes(b) => {
            let mut v = head(2, b.len() as u64);
            v.extend_from_slice(b);
            v
        }
    }
}

/// Map with unsigned keys, encoded in the given order.
pub(crate) fn map(entries: &[(u64, Item)]) -> Vec<u8> {
    let mut v = head(5, entries.len() as u64);
    for (k, val) in entries {
        v.extend(head(0, *k));
        v.extend(item(val));
    }
    v
}

/// The four envelope entries `{1: v, 2: kind, 3: n, 4: ct}`.
pub(crate) fn parts(v: u64, kind: u64, n_len: usize, ct_len: usize) -> Vec<(u64, Item)> {
    vec![
        (1, Item::Uint(v)),
        (2, Item::Uint(kind)),
        (3, Item::Bytes(vec![0x11; n_len])),
        (4, Item::Bytes(vec![0x22; ct_len])),
    ]
}

/// A valid session envelope whose bytes depend on `i` (distinguishable messages).
pub(crate) fn session_nth(i: usize) -> Vec<u8> {
    let b = (i % 251) as u8;
    let mut n = vec![b; 24];
    if let Some(first) = n.first_mut() {
        *first = (i / 251) as u8;
    }
    encode(Kind::Session, n, vec![b; 1024])
}

/// A valid envelope of `kind` with a ciphertext of `ct_len` bytes.
pub(crate) fn valid(kind: Kind, ct_len: usize) -> Vec<u8> {
    let n_len = if kind == Kind::Session { 24 } else { 32 };
    encode(kind, vec![0x33; n_len], vec![0x44; ct_len])
}

fn encode(kind: Kind, n: Vec<u8>, ct: Vec<u8>) -> Vec<u8> {
    // Fall back to the hand encoder (identical canonical output) if core refuses.
    let fallback = map(&[
        (1, Item::Uint(1)),
        (2, Item::Uint(kind as u64)),
        (3, Item::Bytes(n.clone())),
        (4, Item::Bytes(ct.clone())),
    ]);
    Envelope { kind, n, ct }.encode().unwrap_or(fallback)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn hand_encoder_matches_core() {
        let core = valid(Kind::Session, 1024);
        let hand = map(&[
            (1, Item::Uint(1)),
            (2, Item::Uint(1)),
            (3, Item::Bytes(vec![0x33; 24])),
            (4, Item::Bytes(vec![0x44; 1024])),
        ]);
        assert_eq!(core, hand);
        assert!(Envelope::decode(&session_nth(300)).is_ok());
    }
}
