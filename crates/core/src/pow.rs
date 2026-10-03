//! Proof-of-work for keyless mailbox creation (spec 7.4).
//!
//! ```text
//! challenge = 0x01 || u64_be(expires_at) || u8(difficulty) || random(16)
//!             || HMAC-SHA256(relay_pow_key, preceding 26 bytes)[0..16]      // 42 bytes
//! solution  : 8-byte nonce with SHA-256("xchonnect v1 pow" || challenge || nonce)
//!             having at least `difficulty` leading zero bits
//! ```
//! Verification is stateless apart from the relay's in-memory set of spent challenges.

use crate::crypto::{self, Entropy};
use crate::error::{Error, Result};

/// Default difficulty in bits.
pub const DEFAULT_DIFFICULTY: u8 = 18;
/// Clients refuse challenges above this difficulty.
pub const MAX_CLIENT_DIFFICULTY: u8 = 26;
/// Challenge length.
pub const CHALLENGE_LEN: usize = 42;
/// Maximum challenge validity.
pub const VALIDITY_S: u64 = 120;
const LABEL: &[u8] = b"xchonnect v1 pow";

/// Parsed public fields of a challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeInfo {
    /// Expiry (unix seconds).
    pub expires_at: u64,
    /// Required leading zero bits.
    pub difficulty: u8,
}

/// Issue a challenge (relay side).
pub fn issue(
    key: &[u8; 32],
    rng: &mut dyn Entropy,
    now: u64,
    difficulty: u8,
) -> Result<[u8; CHALLENGE_LEN]> {
    let mut c = [0u8; CHALLENGE_LEN];
    let expires_at = now + VALIDITY_S;
    let random: [u8; 16] = crypto::random_array(rng);
    let mut head = Vec::with_capacity(26);
    head.push(1u8);
    head.extend_from_slice(&expires_at.to_be_bytes());
    head.push(difficulty);
    head.extend_from_slice(&random);
    let mac = crypto::hmac_sha256(key, &[&head])?;
    for (dst, src) in c.iter_mut().zip(head.iter().chain(mac.iter().take(16))) {
        *dst = *src;
    }
    Ok(c)
}

/// Read the public fields of a challenge (client side, no MAC check possible).
pub fn parse(challenge: &[u8]) -> Result<ChallengeInfo> {
    if challenge.len() != CHALLENGE_LEN || challenge.first() != Some(&1) {
        return Err(Error::PowInvalid);
    }
    let exp: [u8; 8] = challenge
        .get(1..9)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::PowInvalid)?;
    let difficulty = *challenge.get(9).ok_or(Error::PowInvalid)?;
    Ok(ChallengeInfo {
        expires_at: u64::from_be_bytes(exp),
        difficulty,
    })
}

fn leading_zero_bits(h: &[u8; 32]) -> u32 {
    let mut n = 0;
    for b in h {
        if *b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

fn hash(challenge: &[u8], nonce: &[u8; 8]) -> [u8; 32] {
    crypto::sha256_parts(&[LABEL, challenge, nonce])
}

/// Verify a solution (relay side) against the current and previous PoW keys. Returns
/// the challenge info so the caller can record it as spent until `expires_at`.
pub fn verify(
    keys: &[&[u8; 32]],
    challenge: &[u8],
    nonce: &[u8],
    now: u64,
) -> Result<ChallengeInfo> {
    let info = parse(challenge)?;
    let nonce: [u8; 8] = nonce.try_into().map_err(|_| Error::PowInvalid)?;
    let (head, mac) = challenge.split_at(26);
    let mut mac_ok = false;
    for k in keys {
        let expected = crypto::hmac_sha256(*k, &[head])?;
        mac_ok |= crypto::ct_eq(expected.get(..16).ok_or(Error::PowInvalid)?, mac);
    }
    if !mac_ok || info.expires_at < now || info.expires_at > now + VALIDITY_S {
        return Err(Error::PowInvalid);
    }
    if leading_zero_bits(&hash(challenge, &nonce)) < u32::from(info.difficulty) {
        return Err(Error::PowInvalid);
    }
    Ok(info)
}

/// Solve a challenge (client side). Refuses difficulties above
/// [`MAX_CLIENT_DIFFICULTY`].
pub fn solve(challenge: &[u8]) -> Result<[u8; 8]> {
    let info = parse(challenge)?;
    if info.difficulty > MAX_CLIENT_DIFFICULTY {
        return Err(Error::PowInvalid);
    }
    let target = u32::from(info.difficulty);
    for n in 0u64.. {
        let nonce = n.to_be_bytes();
        if leading_zero_bits(&hash(challenge, &nonce)) >= target {
            return Ok(nonce);
        }
    }
    Err(Error::PowInvalid)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crypto::TestEntropy;

    #[test]
    fn issue_solve_verify() {
        let key = [3u8; 32];
        let mut rng = TestEntropy::new([0; 32]);
        let c = issue(&key, &mut rng, 1000, 10).unwrap();
        assert_eq!(
            parse(&c).unwrap(),
            ChallengeInfo {
                expires_at: 1120,
                difficulty: 10
            }
        );
        let n = solve(&c).unwrap();
        assert_eq!(verify(&[&key], &c, &n, 1000).unwrap().expires_at, 1120);
        // Previous key accepted during rotation.
        assert!(verify(&[&[9; 32], &key], &c, &n, 1000).is_ok());
        // Wrong key, expired, tampered difficulty, wrong nonce.
        assert!(verify(&[&[9; 32]], &c, &n, 1000).is_err());
        assert!(verify(&[&key], &c, &n, 1121).is_err());
        let mut t = c;
        t[9] = 0;
        assert!(
            verify(&[&key], &t, &n, 1000).is_err(),
            "MAC covers difficulty"
        );
        let bad = (u64::from_be_bytes(n) + 1).to_be_bytes();
        let ok_by_chance = leading_zero_bits(&hash(&c, &bad)) >= 10;
        assert_eq!(verify(&[&key], &c, &bad, 1000).is_ok(), ok_by_chance);
    }

    #[test]
    fn client_refuses_excessive_difficulty() {
        let c = issue(&[1; 32], &mut TestEntropy::new([0; 32]), 0, 30).unwrap();
        assert!(solve(&c).is_err());
    }

    #[test]
    fn zero_bits() {
        let mut h = [0u8; 32];
        h[2] = 0b0001_0000;
        assert_eq!(leading_zero_bits(&h), 19);
    }
}
