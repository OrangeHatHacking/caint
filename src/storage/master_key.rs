use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::storage::StorageError;

/// Argon2id parameters for passphrase key derivation.
/// High-security: 64 MiB memory, 3 iterations, 1 lane.
pub const ARGON2_M_COST: u32 = 65536; // 64 MiB in KiB
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;
pub const SALT_LEN: usize = 16;

/// Passphrase-derived master key. Root of all storage encryption.
/// Zeroized on drop. Never written to disk.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    key: [u8; 32],
}

impl MasterKey {
    /// Derive from passphrase + salt using Argon2id.
    pub fn derive(
        passphrase: &[u8],
        salt: &[u8; SALT_LEN],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<Self, StorageError> {
        let params = Params::new(m_cost, t_cost, p_cost, Some(32))
            .map_err(|e| StorageError::SerializationError(format!("argon2 params: {}", e)))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(passphrase, salt, &mut key)
            .map_err(|e| StorageError::SerializationError(format!("argon2: {}", e)))?;
        Ok(MasterKey { key })
    }

    /// Derive with default high-security parameters.
    pub fn derive_default(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self, StorageError> {
        Self::derive(
            passphrase,
            salt,
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
        )
    }

    /// Generate a random salt.
    pub fn generate_salt() -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Derive a per-purpose subkey via HKDF.
    pub fn derive_subkey(&self, purpose: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(&self.key), b"caint_master");
        let mut subkey = [0u8; 32];
        hk.expand(purpose.as_bytes(), &mut subkey)
            .expect("HKDF expand for 32 bytes");
        subkey
    }

    /// Raw key bytes (for passing to AEAD constructors).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_passphrase_same_key() {
        let salt = [42u8; SALT_LEN];
        let mk1 = MasterKey::derive_default(b"test", &salt).unwrap();
        let mk2 = MasterKey::derive_default(b"test", &salt).unwrap();
        assert_eq!(mk1.key, mk2.key);
    }

    #[test]
    fn test_different_passphrase_different_key() {
        let salt = [42u8; SALT_LEN];
        let mk1 = MasterKey::derive_default(b"password1", &salt).unwrap();
        let mk2 = MasterKey::derive_default(b"password2", &salt).unwrap();
        assert_ne!(mk1.key, mk2.key);
    }

    #[test]
    fn test_different_salt_different_key() {
        let mk1 = MasterKey::derive_default(b"test", &[1u8; SALT_LEN]).unwrap();
        let mk2 = MasterKey::derive_default(b"test", &[2u8; SALT_LEN]).unwrap();
        assert_ne!(mk1.key, mk2.key);
    }

    #[test]
    fn test_subkeys_distinct() {
        let salt = [42u8; SALT_LEN];
        let mk = MasterKey::derive_default(b"test", &salt).unwrap();
        let sk1 = mk.derive_subkey("identity");
        let sk2 = mk.derive_subkey("ratchet");
        assert_ne!(sk1, sk2);
    }

    #[test]
    fn test_debug_redacts() {
        let salt = [42u8; SALT_LEN];
        let mk = MasterKey::derive_default(b"test", &salt).unwrap();
        let dbg = format!("{:?}", mk);
        assert!(dbg.contains("[REDACTED]"));
    }
}
