use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
#[allow(unused_imports)]
use zeroize::Zeroize;

/// Long-term identity keypair containing both Ed25519 (signing) and X25519 (DH) keys.
///
/// The Ed25519 key is used for signing pre-keys and identity verification.
/// The X25519 key is used for Diffie-Hellman key agreement in X3DH.
pub struct IdentityKeyPair {
    ed25519_signing: SigningKey,
    ed25519_public: VerifyingKey,
    x25519_private: StaticSecret,
    x25519_public: X25519PublicKey,
}

impl IdentityKeyPair {
    /// Generate a new identity keypair with both Ed25519 and X25519 keys.
    ///
    /// Uses OsRng (CSPRNG) for all key generation.
    pub fn generate() -> Self {
        let ed25519_signing = SigningKey::generate(&mut OsRng);
        let ed25519_public = ed25519_signing.verifying_key();
        let x25519_private = StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_private);

        IdentityKeyPair {
            ed25519_signing,
            ed25519_public,
            x25519_private,
            x25519_public,
        }
    }

    /// Get the Ed25519 public verification key.
    pub fn ed25519_public(&self) -> &VerifyingKey {
        &self.ed25519_public
    }

    /// Get the Ed25519 public key bytes.
    pub fn ed25519_public_bytes(&self) -> [u8; 32] {
        self.ed25519_public.to_bytes()
    }

    /// Get the X25519 public key.
    pub fn x25519_public(&self) -> &X25519PublicKey {
        &self.x25519_public
    }

    /// Get the X25519 public key bytes.
    pub fn x25519_public_bytes(&self) -> [u8; 32] {
        self.x25519_public.to_bytes()
    }

    /// Sign a message with the Ed25519 signing key.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.ed25519_signing.sign(msg)
    }

    /// Verify a signature against the Ed25519 public key.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        self.ed25519_public.verify(msg, sig).is_ok()
    }

    /// Perform X25519 Diffie-Hellman with a peer's public key.
    ///
    /// Unlike ephemeral DH, this does NOT consume self because
    /// the identity X25519 key is reused across sessions (for DH1 in X3DH).
    pub fn x25519_dh(&self, peer_public: &X25519PublicKey) -> [u8; 32] {
        *self.x25519_private.diffie_hellman(peer_public).as_bytes()
    }

    /// Serialize to 128 bytes: ed25519_signing(32) || ed25519_public(32) || x25519_private(32) || x25519_public(32)
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[..32].copy_from_slice(&self.ed25519_signing.to_bytes());
        out[32..64].copy_from_slice(&self.ed25519_public.to_bytes());
        out[64..96].copy_from_slice(&self.x25519_private.to_bytes());
        out[96..128].copy_from_slice(&self.x25519_public.to_bytes());
        out
    }

    /// Deserialize from 128 bytes.
    pub fn from_bytes(bytes: &[u8; 128]) -> Result<Self, &'static str> {
        let ed25519_signing = SigningKey::from_bytes(bytes[..32].try_into().unwrap());
        let ed25519_public = VerifyingKey::from_bytes(bytes[32..64].try_into().unwrap())
            .map_err(|_| "invalid ed25519 public key")?;

        // Verify the public key matches the signing key
        if ed25519_signing.verifying_key() != ed25519_public {
            return Err("ed25519 public key does not match signing key");
        }

        let mut x_priv_bytes = [0u8; 32];
        x_priv_bytes.copy_from_slice(&bytes[64..96]);
        let x25519_private = StaticSecret::from(x_priv_bytes);
        let mut x_pub_bytes = [0u8; 32];
        x_pub_bytes.copy_from_slice(&bytes[96..128]);
        let x25519_public = X25519PublicKey::from(x_pub_bytes);

        // Verify x25519 public matches private
        if X25519PublicKey::from(&x25519_private) != x25519_public {
            return Err("x25519 public key does not match private key");
        }

        Ok(IdentityKeyPair {
            ed25519_signing,
            ed25519_public,
            x25519_private,
            x25519_public,
        })
    }

    /// Get reference to the Ed25519 signing key (for serialization).
    pub fn ed25519_signing_key(&self) -> &SigningKey {
        &self.ed25519_signing
    }

    /// Get reference to the X25519 private key (for serialization).
    pub fn x25519_private_key(&self) -> &StaticSecret {
        &self.x25519_private
    }
}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        // SigningKey and StaticSecret should be zeroized.
        // SigningKey from ed25519-dalek implements Zeroize.
        // StaticSecret from x25519-dalek stores bytes internally.
        // We rely on their own Drop implementations + zeroize derives.
    }
}

impl std::fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field("ed25519_public", &self.ed25519_public_bytes())
            .field("x25519_public", &self.x25519_public_bytes())
            .field("ed25519_signing", &"[REDACTED]")
            .field("x25519_private", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let identity = IdentityKeyPair::generate();
        // Keys should be 32 bytes
        assert_eq!(identity.ed25519_public_bytes().len(), 32);
        assert_eq!(identity.x25519_public_bytes().len(), 32);
    }

    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        let identity = IdentityKeyPair::generate();
        let msg = b"test message for signing";
        let sig = identity.sign(msg);
        assert!(identity.verify(msg, &sig));
    }

    #[test]
    fn test_ed25519_verify_fails_with_wrong_message() {
        let identity = IdentityKeyPair::generate();
        let sig = identity.sign(b"correct message");
        assert!(!identity.verify(b"wrong message", &sig));
    }

    #[test]
    fn test_x25519_dh_produces_32_byte_secret() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let shared = alice.x25519_dh(bob.x25519_public());
        assert_eq!(shared.len(), 32);
        // Shared secret should not be all zeros
        assert_ne!(shared, [0u8; 32]);
    }

    #[test]
    fn test_x25519_dh_is_symmetric() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let shared_ab = alice.x25519_dh(bob.x25519_public());
        let shared_ba = bob.x25519_dh(alice.x25519_public());
        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn test_two_identities_have_different_keys() {
        let a = IdentityKeyPair::generate();
        let b = IdentityKeyPair::generate();
        assert_ne!(a.ed25519_public_bytes(), b.ed25519_public_bytes());
        assert_ne!(a.x25519_public_bytes(), b.x25519_public_bytes());
    }

    #[test]
    fn test_identity_serialization_roundtrip() {
        let original = IdentityKeyPair::generate();
        let bytes = original.to_bytes();
        let restored = IdentityKeyPair::from_bytes(&bytes).unwrap();

        assert_eq!(
            original.ed25519_public_bytes(),
            restored.ed25519_public_bytes()
        );
        assert_eq!(
            original.x25519_public_bytes(),
            restored.x25519_public_bytes()
        );

        // Same signatures
        let msg = b"test";
        let sig = original.sign(msg);
        assert!(restored.verify(msg, &sig));

        // Same DH
        let peer = IdentityKeyPair::generate();
        assert_eq!(
            original.x25519_dh(peer.x25519_public()),
            restored.x25519_dh(peer.x25519_public())
        );
    }

    #[test]
    fn test_debug_redacts_private_keys() {
        let identity = IdentityKeyPair::generate();
        let debug_output = format!("{:?}", identity);
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("SigningKey"));
    }
}
