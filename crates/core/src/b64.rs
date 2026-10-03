//! Strict base64url without padding (RFC 4648 §5), as used in URIs and JSON.

use crate::error::{Error, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Encode bytes.
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode, rejecting padding, invalid characters and non-zero trailing bits.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Error::Malformed("base64url"))
}

/// Decode into an array of exactly `N` bytes.
pub fn decode_array<const N: usize>(s: &str) -> Result<[u8; N]> {
    decode(s)?
        .try_into()
        .map_err(|_| Error::Malformed("base64url length"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn strict() {
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(decode("-_8").unwrap(), vec![0xfb, 0xff]);
        assert!(decode("-_8=").is_err(), "padding rejected");
        assert!(decode("-_9").is_err(), "non-zero trailing bits rejected");
        assert!(decode("+/8").is_err(), "standard alphabet rejected");
        assert!(decode_array::<3>("-_8").is_err());
    }
}
