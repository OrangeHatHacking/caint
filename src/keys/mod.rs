pub mod identity;
pub mod prekey;
pub mod ratchet;
pub mod x3dh;

pub use identity::IdentityKeyPair;
pub use prekey::{OneTimePreKey, PreKeyBundle, SignedPreKey};
pub use ratchet::{Ratchet, RatchetHeader, MAX_SKIP};
pub use x3dh::{compute_ad, x3dh_initiate, x3dh_respond, InitialMessage};

use std::fmt;

#[derive(Debug)]
pub enum X3DHError {
    InvalidSignature,
    BundleMissing,
    KeyExhausted,
}

impl fmt::Display for X3DHError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            X3DHError::InvalidSignature => write!(f, "SPK signature verification failed"),
            X3DHError::BundleMissing => write!(f, "Pre-key bundle not found"),
            X3DHError::KeyExhausted => write!(f, "One-time pre-keys exhausted"),
        }
    }
}

impl std::error::Error for X3DHError {}

#[derive(Debug)]
pub enum DecryptError {
    AuthenticationFailed,
    SkipLimitExceeded,
    InvalidHeader,
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecryptError::AuthenticationFailed => write!(f, "AEAD authentication failed"),
            DecryptError::SkipLimitExceeded => write!(f, "Skipped message key limit exceeded"),
            DecryptError::InvalidHeader => write!(f, "Invalid ratchet header"),
        }
    }
}

impl std::error::Error for DecryptError {}
