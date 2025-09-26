use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct IdentityKey {
    sign_key: SigningKey,
    ver_key: VerifyingKey,
}

impl IdentityKey {
    pub fn generate() -> Self {
        let mut csprng = OsRng; // cryptographically secure pseudo-rand num gen
        let sign_key = SigningKey::generate(&mut csprng);
        let ver_key = sign_key.verifying_key();
        IdentityKey {
            sign_key: sign_key,
            ver_key: ver_key,
        }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.ver_key.to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.sign_key.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], sig: Signature) -> bool {
        self.ver_key.verify(msg, &sig).is_ok()
    }
}

pub struct X25519EphemeralKeyPair {
    priv_key: EphemeralSecret,
    pub pub_key: PublicKey,
}

impl X25519EphemeralKeyPair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let priv_key = EphemeralSecret::random_from_rng(&mut csprng);
        let pub_key = PublicKey::from(&priv_key);
        X25519EphemeralKeyPair {
            priv_key: priv_key,
            pub_key: pub_key,
        }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.pub_key.to_bytes()
    }

    pub fn diffie_hellman(self, peer_keypair: X25519EphemeralKeyPair) -> [u8; 32] {
        let shared_key = self.priv_key.diffie_hellman(&peer_keypair.pub_key);
        *shared_key.as_bytes()
    }
}
