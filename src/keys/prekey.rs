use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::keys::identity::IdentityKeyPair;

/// Signed pre-key for X3DH. Rotated periodically.
pub struct SignedPreKey {
    pub key_id: u32,
    private: StaticSecret,
    pub public: X25519PublicKey,
    pub signature: Signature,
    pub created_at: u64,
}

impl SignedPreKey {
    /// Generate a new signed pre-key, signed by the identity's Ed25519 key.
    pub fn generate(identity: &IdentityKeyPair, key_id: u32) -> Self {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&private);
        let signature = identity.sign(&public.to_bytes());
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        SignedPreKey {
            key_id,
            private,
            public,
            signature,
            created_at,
        }
    }

    /// Get the private key for DH operations.
    pub fn private_key(&self) -> &StaticSecret {
        &self.private
    }

    /// Perform DH with a peer's public key (non-consuming, for responder in X3DH).
    pub fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> [u8; 32] {
        *self.private.diffie_hellman(peer_public).as_bytes()
    }

    /// Verify the signature on this SPK using the signer's Ed25519 public key.
    pub fn verify_signature(&self, signer_ed25519: &VerifyingKey) -> bool {
        signer_ed25519
            .verify(&self.public.to_bytes(), &self.signature)
            .is_ok()
    }
}

impl std::fmt::Debug for SignedPreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedPreKey")
            .field("key_id", &self.key_id)
            .field("public", &self.public.to_bytes())
            .field("private", &"[REDACTED]")
            .finish()
    }
}

/// One-time pre-key for X3DH forward secrecy.
pub struct OneTimePreKey {
    pub key_id: u32,
    private: StaticSecret,
    pub public: X25519PublicKey,
}

impl OneTimePreKey {
    /// Generate a single one-time pre-key.
    pub fn generate(key_id: u32) -> Self {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&private);
        OneTimePreKey {
            key_id,
            private,
            public,
        }
    }

    /// Perform DH with a peer's public key (consuming, since OPK is single-use).
    pub fn diffie_hellman(self, peer_public: &X25519PublicKey) -> [u8; 32] {
        *self.private.diffie_hellman(peer_public).as_bytes()
    }

    /// Get reference to private key (for non-consuming DH in responder flow).
    pub fn private_key(&self) -> &StaticSecret {
        &self.private
    }
}

impl std::fmt::Debug for OneTimePreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OneTimePreKey")
            .field("key_id", &self.key_id)
            .field("public", &self.public.to_bytes())
            .field("private", &"[REDACTED]")
            .finish()
    }
}

/// Generate a batch of one-time pre-keys with sequential IDs.
pub fn generate_one_time_prekeys(start_id: u32, count: u32) -> Vec<OneTimePreKey> {
    (0..count)
        .map(|i| OneTimePreKey::generate(start_id + i))
        .collect()
}

/// Published pre-key bundle for X3DH offline session establishment.
#[derive(Clone)]
pub struct PreKeyBundle {
    pub identity_ed: VerifyingKey,
    pub identity_x: X25519PublicKey,
    pub signed_prekey: X25519PublicKey,
    pub spk_id: u32,
    pub spk_signature: Signature,
    pub one_time_prekey: Option<X25519PublicKey>,
    pub opk_id: Option<u32>,
}

impl PreKeyBundle {
    /// Build a pre-key bundle from the identity and pre-key material.
    pub fn build(
        identity: &IdentityKeyPair,
        spk: &SignedPreKey,
        opk: Option<&OneTimePreKey>,
    ) -> Self {
        PreKeyBundle {
            identity_ed: *identity.ed25519_public(),
            identity_x: *identity.x25519_public(),
            signed_prekey: spk.public,
            spk_id: spk.key_id,
            spk_signature: spk.signature,
            one_time_prekey: opk.map(|k| k.public),
            opk_id: opk.map(|k| k.key_id),
        }
    }

    /// Verify the SPK signature in this bundle.
    pub fn verify_spk_signature(&self) -> bool {
        self.identity_ed
            .verify(&self.signed_prekey.to_bytes(), &self.spk_signature)
            .is_ok()
    }
}

impl std::fmt::Debug for PreKeyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreKeyBundle")
            .field("identity_ed", &self.identity_ed.to_bytes())
            .field("identity_x", &self.identity_x.to_bytes())
            .field("signed_prekey", &self.signed_prekey.to_bytes())
            .field("spk_id", &self.spk_id)
            .field("opk_id", &self.opk_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_prekey_generation() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(&identity, 1);
        assert_eq!(spk.key_id, 1);
        assert_eq!(spk.public.to_bytes().len(), 32);
    }

    #[test]
    fn test_signed_prekey_signature_valid() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(&identity, 1);
        assert!(spk.verify_signature(identity.ed25519_public()));
    }

    #[test]
    fn test_signed_prekey_signature_fails_with_wrong_key() {
        let identity = IdentityKeyPair::generate();
        let other = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(&identity, 1);
        // Verify with wrong identity should fail
        assert!(!spk.verify_signature(other.ed25519_public()));
    }

    #[test]
    fn test_one_time_prekey_generation() {
        let opk = OneTimePreKey::generate(42);
        assert_eq!(opk.key_id, 42);
        assert_eq!(opk.public.to_bytes().len(), 32);
    }

    #[test]
    fn test_generate_batch_one_time_prekeys() {
        let opks = generate_one_time_prekeys(100, 10);
        assert_eq!(opks.len(), 10);
        for (i, opk) in opks.iter().enumerate() {
            assert_eq!(opk.key_id, 100 + i as u32);
        }
    }

    #[test]
    fn test_prekey_bundle_with_opk() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(&identity, 1);
        let opk = OneTimePreKey::generate(1);
        let bundle = PreKeyBundle::build(&identity, &spk, Some(&opk));
        assert!(bundle.verify_spk_signature());
        assert!(bundle.one_time_prekey.is_some());
        assert_eq!(bundle.opk_id, Some(1));
    }

    #[test]
    fn test_prekey_bundle_without_opk() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(&identity, 1);
        let bundle = PreKeyBundle::build(&identity, &spk, None);
        assert!(bundle.verify_spk_signature());
        assert!(bundle.one_time_prekey.is_none());
        assert_eq!(bundle.opk_id, None);
    }

    #[test]
    fn test_spk_dh() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(&identity, 1);
        let peer = IdentityKeyPair::generate();
        let shared = spk.diffie_hellman(peer.x25519_public());
        assert_eq!(shared.len(), 32);
        assert_ne!(shared, [0u8; 32]);
    }

    #[test]
    fn test_debug_redacts_private_keys() {
        let identity = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(&identity, 1);
        let debug = format!("{:?}", spk);
        assert!(debug.contains("[REDACTED]"));

        let opk = OneTimePreKey::generate(1);
        let debug = format!("{:?}", opk);
        assert!(debug.contains("[REDACTED]"));
    }
}
