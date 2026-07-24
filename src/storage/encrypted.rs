use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::storage::StorageError;

/// Encrypted file-based storage for ratchet states, identity keys, and message history.
pub struct Storage {
    storage_key: [u8; 32],
    base_path: PathBuf,
}

impl Storage {
    /// Create a new Storage instance.
    ///
    /// Derives a storage encryption key from the identity private key bytes
    /// via HKDF-SHA256 with salt="caint_storage" and info="storage_encryption".
    pub fn new(identity_key_bytes: &[u8; 32], base_path: &Path) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"caint_storage"), identity_key_bytes);
        let mut storage_key = [0u8; 32];
        hk.expand(b"storage_encryption", &mut storage_key)
            .expect("HKDF expand for 32 bytes");

        // Ensure base directory exists
        fs::create_dir_all(base_path).ok();

        Storage {
            storage_key,
            base_path: base_path.to_path_buf(),
        }
    }

    /// Create a Storage with an explicit key (for testing).
    pub fn with_key(storage_key: [u8; 32], base_path: &Path) -> Self {
        fs::create_dir_all(base_path).ok();
        Storage {
            storage_key,
            base_path: base_path.to_path_buf(),
        }
    }

    /// Encrypt a plaintext blob.
    ///
    /// Returns: nonce(12) || ciphertext || tag(16)
    pub fn encrypt_blob(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let key = Key::from_slice(&self.storage_key);
        let cipher = ChaCha20Poly1305::new(key);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .expect("AEAD encryption should not fail");

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        result
    }

    /// Decrypt a blob produced by encrypt_blob.
    pub fn decrypt_blob(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        if data.len() < 12 + 16 {
            return Err(StorageError::CorruptedData);
        }

        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        let key = Key::from_slice(&self.storage_key);
        let cipher = ChaCha20Poly1305::new(key);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| StorageError::DecryptionFailed)
    }

    /// Save raw bytes to an encrypted file.
    pub fn save_encrypted(&self, filename: &str, data: &[u8]) -> Result<(), StorageError> {
        let encrypted = self.encrypt_blob(data);
        let path = self.base_path.join(filename);
        fs::write(&path, &encrypted)?;
        Ok(())
    }

    /// Load and decrypt raw bytes from an encrypted file.
    pub fn load_encrypted(&self, filename: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let path = self.base_path.join(filename);
        if !path.exists() {
            return Ok(None);
        }
        let encrypted = fs::read(&path)?;
        let decrypted = self.decrypt_blob(&encrypted)?;
        Ok(Some(decrypted))
    }

    /// Save identity key bytes to encrypted storage.
    pub fn save_identity(&self, identity_bytes: &[u8]) -> Result<(), StorageError> {
        self.save_encrypted("identity.enc", identity_bytes)
    }

    /// Load identity key bytes from encrypted storage.
    pub fn load_identity(&self) -> Result<Option<Vec<u8>>, StorageError> {
        self.load_encrypted("identity.enc")
    }

    /// Save an IdentityKeyPair with self-contained encryption.
    ///
    /// File format: x25519_pub(32) || nonce(12) || encrypted(96) || tag(16)
    /// Encryption key: HKDF(salt="caint_identity", ikm=x25519_pub, info="identity_encryption")
    pub fn save_identity_keypair(
        base_path: &Path,
        keypair_bytes: &[u8; 128],
    ) -> Result<(), StorageError> {
        let x25519_pub = &keypair_bytes[96..128];
        let private_bytes = &keypair_bytes[..96]; // ed25519_signing + ed25519_public + x25519_private

        // Derive encryption key from the public key
        let hk = Hkdf::<Sha256>::new(Some(b"caint_identity"), x25519_pub);
        let mut enc_key = [0u8; 32];
        hk.expand(b"identity_encryption", &mut enc_key)
            .expect("HKDF");

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let key = Key::from_slice(&enc_key);
        let cipher = ChaCha20Poly1305::new(key);
        let ciphertext = cipher
            .encrypt(nonce, private_bytes)
            .map_err(|_| StorageError::CorruptedData)?;

        let path = base_path.join("identity.enc");
        let mut out = Vec::with_capacity(32 + 12 + ciphertext.len());
        out.extend_from_slice(x25519_pub);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        fs::write(&path, &out)?;
        Ok(())
    }

    /// Load an IdentityKeyPair from self-contained encrypted file.
    ///
    /// Returns the 128-byte keypair, or None if file doesn't exist.
    pub fn load_identity_keypair(base_path: &Path) -> Result<Option<[u8; 128]>, StorageError> {
        let path = base_path.join("identity.enc");
        if !path.exists() {
            return Ok(None);
        }

        let data = fs::read(&path)?;
        // Minimum: x25519_pub(32) + nonce(12) + ciphertext(96) + tag(16) = 156
        if data.len() < 156 {
            return Err(StorageError::CorruptedData);
        }

        let x25519_pub = &data[..32];
        let nonce_bytes = &data[32..44];
        let ciphertext = &data[44..];

        let hk = Hkdf::<Sha256>::new(Some(b"caint_identity"), x25519_pub);
        let mut enc_key = [0u8; 32];
        hk.expand(b"identity_encryption", &mut enc_key)
            .expect("HKDF");

        let nonce = Nonce::from_slice(nonce_bytes);
        let key = Key::from_slice(&enc_key);
        let cipher = ChaCha20Poly1305::new(key);
        let private_bytes = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| StorageError::DecryptionFailed)?;

        if private_bytes.len() != 96 {
            return Err(StorageError::CorruptedData);
        }

        let mut out = [0u8; 128];
        out[..96].copy_from_slice(&private_bytes);
        out[96..128].copy_from_slice(x25519_pub);
        Ok(Some(out))
    }

    /// Save ratchet state bytes for a specific peer.
    pub fn save_ratchet(&self, peer_id: &[u8; 32], data: &[u8]) -> Result<(), StorageError> {
        let filename = format!("{}.ratchet", hex_encode(peer_id));
        self.save_encrypted(&filename, data)
    }

    /// Load ratchet state bytes for a specific peer.
    pub fn load_ratchet(&self, peer_id: &[u8; 32]) -> Result<Option<Vec<u8>>, StorageError> {
        let filename = format!("{}.ratchet", hex_encode(peer_id));
        self.load_encrypted(&filename)
    }

    /// Append a decrypted plaintext message (re-encrypted with storage key) to a peer's message log.
    pub fn append_message(&self, peer_id: &[u8; 32], plaintext: &[u8]) -> Result<(), StorageError> {
        let encrypted = self.encrypt_blob(plaintext);
        let len = (encrypted.len() as u32).to_be_bytes();

        let filename = format!("{}.msglog", hex_encode(peer_id));
        let path = self.base_path.join(&filename);

        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;

        file.write_all(&len)?;
        file.write_all(&encrypted)?;
        file.flush()?;

        Ok(())
    }

    /// Load all messages for a peer, decrypting each with the storage key.
    pub fn load_messages(&self, peer_id: &[u8; 32]) -> Result<Vec<Vec<u8>>, StorageError> {
        let filename = format!("{}.msglog", hex_encode(peer_id));
        let path = self.base_path.join(&filename);

        if !path.exists() {
            return Ok(Vec::new());
        }

        let mut file = fs::File::open(&path)?;
        let mut messages = Vec::new();
        let mut len_buf = [0u8; 4];

        loop {
            match file.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(StorageError::IoError(e)),
            }

            let len = u32::from_be_bytes(len_buf) as usize;
            let mut blob = vec![0u8; len];
            file.read_exact(&mut blob)?;

            let plaintext = self.decrypt_blob(&blob)?;
            messages.push(plaintext);
        }

        Ok(messages)
    }
}

impl Drop for Storage {
    fn drop(&mut self) {
        // Zeroize storage key
        self.storage_key.iter_mut().for_each(|b| *b = 0);
    }
}

/// Simple hex encoding for filenames.
fn hex_encode(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("caint_test_{}", rand::random::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_derive_storage_key() {
        let identity_bytes = [42u8; 32];
        let dir = temp_dir();
        let storage = Storage::new(&identity_bytes, &dir);
        assert_ne!(storage.storage_key, [0u8; 32]);
        assert_ne!(storage.storage_key, identity_bytes);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dir = temp_dir();
        let storage = Storage::with_key([1u8; 32], &dir);
        let plaintext = b"hello encrypted world";
        let encrypted = storage.encrypt_blob(plaintext);
        assert_ne!(encrypted.as_slice(), plaintext.as_slice());
        let decrypted = storage.decrypt_blob(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let dir = temp_dir();
        let storage1 = Storage::with_key([1u8; 32], &dir);
        let storage2 = Storage::with_key([2u8; 32], &dir);
        let encrypted = storage1.encrypt_blob(b"secret");
        let result = storage2.decrypt_blob(&encrypted);
        assert!(matches!(result, Err(StorageError::DecryptionFailed)));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_decrypt_tampered_data_fails() {
        let dir = temp_dir();
        let storage = Storage::with_key([1u8; 32], &dir);
        let mut encrypted = storage.encrypt_blob(b"secret");
        encrypted[20] ^= 0xFF;
        let result = storage.decrypt_blob(&encrypted);
        assert!(matches!(result, Err(StorageError::DecryptionFailed)));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_save_load_identity() {
        let dir = temp_dir();
        let storage = Storage::with_key([1u8; 32], &dir);
        let identity_bytes = b"identity key material here!!!!32";
        storage.save_identity(identity_bytes).unwrap();
        let loaded = storage.load_identity().unwrap();
        assert_eq!(loaded.unwrap(), identity_bytes);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_missing_identity() {
        let dir = temp_dir();
        let storage = Storage::with_key([1u8; 32], &dir);
        let loaded = storage.load_identity().unwrap();
        assert!(loaded.is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_save_load_ratchet() {
        let dir = temp_dir();
        let storage = Storage::with_key([1u8; 32], &dir);
        let peer_id = [99u8; 32];
        let ratchet_data = b"ratchet state bytes";
        storage.save_ratchet(&peer_id, ratchet_data).unwrap();
        let loaded = storage.load_ratchet(&peer_id).unwrap();
        assert_eq!(loaded.unwrap(), ratchet_data);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_missing_ratchet() {
        let dir = temp_dir();
        let storage = Storage::with_key([1u8; 32], &dir);
        let peer_id = [99u8; 32];
        let loaded = storage.load_ratchet(&peer_id).unwrap();
        assert!(loaded.is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_append_load_messages() {
        let dir = temp_dir();
        let storage = Storage::with_key([1u8; 32], &dir);
        let peer_id = [99u8; 32];

        storage.append_message(&peer_id, b"message 1").unwrap();
        storage.append_message(&peer_id, b"message 2").unwrap();
        storage.append_message(&peer_id, b"message 3").unwrap();

        let messages = storage.load_messages(&peer_id).unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0], b"message 1");
        assert_eq!(messages[1], b"message 2");
        assert_eq!(messages[2], b"message 3");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_empty_messages() {
        let dir = temp_dir();
        let storage = Storage::with_key([1u8; 32], &dir);
        let peer_id = [99u8; 32];
        let messages = storage.load_messages(&peer_id).unwrap();
        assert!(messages.is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_corrupted_file_returns_error() {
        let dir = temp_dir();
        let storage = Storage::with_key([1u8; 32], &dir);
        fs::write(dir.join("identity.enc"), b"corrupted").unwrap();
        let result = storage.load_identity();
        assert!(result.is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_save_load_identity_keypair_roundtrip() {
        use crate::keys::identity::IdentityKeyPair;
        let dir = temp_dir();
        let original = IdentityKeyPair::generate();
        let bytes = original.to_bytes();

        Storage::save_identity_keypair(&dir, &bytes).unwrap();
        let loaded = Storage::load_identity_keypair(&dir).unwrap().unwrap();
        let restored = IdentityKeyPair::from_bytes(&loaded).unwrap();

        assert_eq!(
            original.ed25519_public_bytes(),
            restored.ed25519_public_bytes()
        );
        assert_eq!(
            original.x25519_public_bytes(),
            restored.x25519_public_bytes()
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_corrupted_identity_keypair_file_returns_error() {
        let dir = temp_dir();
        fs::write(dir.join("identity.enc"), b"not valid data").unwrap();
        let result = Storage::load_identity_keypair(&dir);
        assert!(result.is_err());
        fs::remove_dir_all(&dir).ok();
    }
}
