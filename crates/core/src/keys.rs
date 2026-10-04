//! Key schedule (spec 5.2). All labels are ASCII without terminator.

use crate::crypto::{self, ChainKey, DirectionKey, RootKey};
use crate::error::Result;
use core::fmt;

/// HPKE `info` prefix; followed by `h_uri`.
pub const LABEL_PAIRING_INFO: &[u8] = b"xchonnect v1 pairing";
/// HPKE `psk_id`.
pub const LABEL_PSK_ID: &[u8] = b"xchonnect v1 psk";
/// Pairing reply AAD prefix; followed by the pairing mailbox id.
pub const LABEL_PAIRING_AAD: &[u8] = b"xchonnect v1 pairing reply";
/// Transcript hash prefix.
pub const LABEL_TRANSCRIPT: &[u8] = b"xchonnect v1 transcript";
/// Root export / rotation root label prefix.
pub const LABEL_ROOT: &[u8] = b"xchonnect v1 root";
/// dApp → wallet key label.
pub const LABEL_D2W: &[u8] = b"xchonnect v1 dapp->wallet";
/// wallet → dApp key label.
pub const LABEL_W2D: &[u8] = b"xchonnect v1 wallet->dapp";
/// Chaining key label.
pub const LABEL_CHAIN: &[u8] = b"xchonnect v1 chain";
/// SAS label.
pub const LABEL_SAS: &[u8] = b"xchonnect v1 sas";
/// Rotation transcript prefix.
pub const LABEL_ROTATE: &[u8] = b"xchonnect v1 rotate";

/// Keys of one epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochKeys {
    /// Epoch number (0 after pairing).
    pub epoch: u64,
    /// dApp → wallet.
    pub d2w: DirectionKey,
    /// wallet → dApp.
    pub w2d: DirectionKey,
    /// Chaining key for the next rotation.
    pub chain: ChainKey,
}

/// Derive the direction and chaining keys of an epoch from its root.
pub fn epoch_keys(root: &RootKey, epoch: u64) -> Result<EpochKeys> {
    let r = root.expose();
    Ok(EpochKeys {
        epoch,
        d2w: DirectionKey::from_bytes(crypto::hkdf_expand32(r, &[LABEL_D2W])?),
        w2d: DirectionKey::from_bytes(crypto::hkdf_expand32(r, &[LABEL_W2D])?),
        chain: ChainKey::from_bytes(crypto::hkdf_expand32(r, &[LABEL_CHAIN])?),
    })
}

/// `th = SHA-256("xchonnect v1 transcript" || h_uri || enc || ct_pair)`.
pub fn pairing_transcript(h_uri: &[u8; 32], enc: &[u8; 32], ct_pair: &[u8]) -> [u8; 32] {
    crypto::sha256_parts(&[LABEL_TRANSCRIPT, h_uri, enc, ct_pair])
}

/// Exporter context for `root_0`: `"xchonnect v1 root" || th`.
pub fn root_export_context(th: &[u8; 32]) -> Vec<u8> {
    [LABEL_ROOT, th.as_slice()].concat()
}

/// Rotation: `root_{e+1} = HKDF-Expand(HKDF-Extract(ck_e, dh), "xchonnect v1 root" || th_r, 32)`
/// with `th_r = SHA-256("xchonnect v1 rotate" || u64_be(e+1) || A || B)`.
pub fn rotation_root(
    chain: &ChainKey,
    dh: &[u8; 32],
    new_epoch: u64,
    a_pub: &[u8; 32],
    b_pub: &[u8; 32],
) -> Result<RootKey> {
    let th_r = crypto::sha256_parts(&[LABEL_ROTATE, &new_epoch.to_be_bytes(), a_pub, b_pub]);
    let prk = crypto::hkdf_extract(chain.expose(), dh);
    let root = crypto::hkdf_expand32(&prk, &[LABEL_ROOT, &th_r])?;
    Ok(RootKey::from_bytes(root))
}

/// Six-digit short authentication string.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sas(u32);

impl Sas {
    /// `uint64_be(HKDF-Expand(root_0, "xchonnect v1 sas", 8)) mod 1 000 000`.
    pub fn derive(root0: &RootKey) -> Result<Sas> {
        let b: [u8; 8] = crypto::hkdf_expand(root0.expose(), LABEL_SAS)?;
        Ok(Sas((u64::from_be_bytes(b) % 1_000_000) as u32))
    }

    /// Numeric value (0..=999 999).
    pub fn value(&self) -> u32 {
        self.0
    }

    /// Six digits without separator, e.g. `"042917"`.
    pub fn digits(&self) -> String {
        format!("{:06}", self.0)
    }
}

/// Displays as two groups of three: `042 917`.
impl fmt::Display for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:03} {:03}", self.0 / 1000, self.0 % 1000)
    }
}

impl fmt::Debug for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sas({self})")
    }
}
