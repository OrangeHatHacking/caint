use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::keys::DecryptError;

type HmacSha256 = Hmac<Sha256>;

/// Maximum number of skipped message keys to cache per chain.
pub const MAX_SKIP: u32 = 1_000;

/// Per-message header sent alongside ciphertext (unencrypted but authenticated).
#[derive(Clone, Debug)]
pub struct RatchetHeader {
    /// Sender's current ratchet DH public key
    pub dh_public_key: [u8; 32],
    /// Number of messages in the sender's previous sending chain
    pub prev_chain_length: u32,
    /// Message number in the sender's current sending chain (0-indexed)
    pub msg_num: u32,
}

impl RatchetHeader {
    /// Serialize header to 40 bytes: dh_public_key(32) || prev_chain_length(4 BE) || msg_num(4 BE)
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.dh_public_key);
        out[32..36].copy_from_slice(&self.prev_chain_length.to_be_bytes());
        out[36..40].copy_from_slice(&self.msg_num.to_be_bytes());
        out
    }

    /// Deserialize header from 40 bytes.
    pub fn from_bytes(data: &[u8; 40]) -> Self {
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&data[..32]);
        let pn = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
        let n = u32::from_be_bytes([data[36], data[37], data[38], data[39]]);
        RatchetHeader {
            dh_public_key: dh,
            prev_chain_length: pn,
            msg_num: n,
        }
    }
}

/// Double Ratchet state for one session.
pub struct Ratchet {
    /// Root key
    root_key: [u8; 32],
    /// Self ratchet keypair (private)
    dh_self_priv: StaticSecret,
    /// Self ratchet keypair (public)
    dh_self_pub: PublicKey,
    /// Remote ratchet public key
    dh_remote: Option<PublicKey>,
    /// Sending chain key
    chain_send: Option<[u8; 32]>,
    /// Receiving chain key
    chain_recv: Option<[u8; 32]>,
    /// Send message counter
    send_n: u32,
    /// Receive message counter
    recv_n: u32,
    /// Previous send chain length
    prev_chain_len: u32,
    /// Skipped message keys: (ratchet_pubkey_bytes, msg_num) -> message_key
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl Ratchet {
    // ── KDF functions ──────────────────────────────────────────────

    /// KDF_RK: Root key ratchet using HKDF-SHA256.
    ///
    /// Input: root_key (salt), dh_output (ikm)
    /// Output: (new_root_key, chain_key) from 64-byte HKDF expansion
    fn kdf_root_key(root: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(root), dh_output);
        let mut okm = [0u8; 64];
        hk.expand(b"caint_ratchet", &mut okm)
            .expect("HKDF expand for 64 bytes");
        let mut new_root = [0u8; 32];
        let mut chain_key = [0u8; 32];
        new_root.copy_from_slice(&okm[..32]);
        chain_key.copy_from_slice(&okm[32..64]);
        (new_root, chain_key)
    }

    /// KDF_CK: Symmetric chain ratchet using HMAC-SHA256.
    ///
    /// message_key = HMAC(chain_key, 0x01)
    /// next_chain_key = HMAC(chain_key, 0x02)
    fn kdf_chain_key(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        // Message key
        let mut mac = <HmacSha256 as Mac>::new_from_slice(chain_key).expect("HMAC key");
        mac.update(&[0x01]);
        let message_key: [u8; 32] = mac.finalize().into_bytes().into();

        // Next chain key
        let mut mac = <HmacSha256 as Mac>::new_from_slice(chain_key).expect("HMAC key");
        mac.update(&[0x02]);
        let next_chain_key: [u8; 32] = mac.finalize().into_bytes().into();

        (next_chain_key, message_key)
    }

    // ── Initialization ─────────────────────────────────────────────

    /// Initialize as X3DH initiator (Alice).
    ///
    /// Generates a new ratchet keypair, uses peer's SPK as initial DHr,
    /// performs one KDF_RK to derive initial root key and send chain key.
    pub fn init_initiator(shared_secret: [u8; 32], peer_spk_public: &PublicKey) -> Self {
        let dh_self_priv = StaticSecret::random_from_rng(OsRng);
        let dh_self_pub = PublicKey::from(&dh_self_priv);

        // DH with peer's SPK
        let dh_output = *dh_self_priv.diffie_hellman(peer_spk_public).as_bytes();
        let (root_key, chain_send) = Self::kdf_root_key(&shared_secret, &dh_output);

        Ratchet {
            root_key,
            dh_self_priv,
            dh_self_pub,
            dh_remote: Some(*peer_spk_public),
            chain_send: Some(chain_send),
            chain_recv: None,
            send_n: 0,
            recv_n: 0,
            prev_chain_len: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Initialize as X3DH responder (Bob).
    ///
    /// Uses SPK keypair as initial ratchet keypair. RK = SK.
    /// No chain keys until first message received triggers DH ratchet.
    pub fn init_responder(shared_secret: [u8; 32], spk_private: StaticSecret) -> Self {
        let dh_self_pub = PublicKey::from(&spk_private);

        Ratchet {
            root_key: shared_secret,
            dh_self_priv: spk_private,
            dh_self_pub,
            dh_remote: None,
            chain_send: None,
            chain_recv: None,
            send_n: 0,
            recv_n: 0,
            prev_chain_len: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Initialize a symmetric ratchet from a shared secret.
    ///
    /// Both sides derive identical send and receive chain keys from the
    /// shared secret using HKDF. The side with `is_alice=true` uses the
    /// first chain for sending and the second for receiving; the other
    /// side swaps them. This allows immediate bidirectional messaging
    /// without waiting for a DH ratchet step.
    pub fn init_symmetric(shared_secret: [u8; 32], is_alice: bool) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(&shared_secret), b"caint_symmetric_init");
        let mut okm = [0u8; 96];
        hk.expand(b"ratchet_init", &mut okm).expect("HKDF expand");

        let mut root_key = [0u8; 32];
        let mut chain_a = [0u8; 32];
        let mut chain_b = [0u8; 32];
        root_key.copy_from_slice(&okm[..32]);
        chain_a.copy_from_slice(&okm[32..64]);
        chain_b.copy_from_slice(&okm[64..96]);

        let dh_self_priv = StaticSecret::random_from_rng(OsRng);
        let dh_self_pub = PublicKey::from(&dh_self_priv);

        let (chain_send, chain_recv) = if is_alice {
            (chain_a, chain_b)
        } else {
            (chain_b, chain_a)
        };

        Ratchet {
            root_key,
            dh_self_priv,
            dh_self_pub,
            dh_remote: None,
            chain_send: Some(chain_send),
            chain_recv: Some(chain_recv),
            send_n: 0,
            recv_n: 0,
            prev_chain_len: 0,
            skipped_keys: HashMap::new(),
        }
    }

    // ── Encryption ─────────────────────────────────────────────────

    /// Encrypt a plaintext message. Returns (header, ciphertext).
    ///
    /// Derives the next message key from the send chain, encrypts with
    /// ChaCha20-Poly1305, and advances the send chain.
    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> (RatchetHeader, Vec<u8>) {
        // If no send chain, we need to perform a DH ratchet step to create one
        if self.chain_send.is_none() {
            if let Some(dh_remote) = &self.dh_remote {
                let dh_remote_copy = *dh_remote;
                // Generate new ratchet keypair
                let new_priv = StaticSecret::random_from_rng(OsRng);
                let new_pub = PublicKey::from(&new_priv);
                let dh_output = *new_priv.diffie_hellman(&dh_remote_copy).as_bytes();
                let (new_root, chain_send) = Self::kdf_root_key(&self.root_key, &dh_output);

                self.prev_chain_len = self.send_n;
                self.root_key = new_root;
                self.chain_send = Some(chain_send);
                self.dh_self_priv = new_priv;
                self.dh_self_pub = new_pub;
                self.send_n = 0;
            } else {
                panic!("Cannot encrypt: no send chain and no remote DH key");
            }
        }

        let ck = self.chain_send.as_ref().unwrap();
        let (next_ck, message_key) = Self::kdf_chain_key(ck);
        self.chain_send = Some(next_ck);

        let header = RatchetHeader {
            dh_public_key: self.dh_self_pub.to_bytes(),
            prev_chain_length: self.prev_chain_len,
            msg_num: self.send_n,
        };
        self.send_n += 1;

        // Encrypt with ChaCha20-Poly1305
        // AD for AEAD = external AD || serialized header
        let mut full_ad = Vec::with_capacity(ad.len() + 40);
        full_ad.extend_from_slice(ad);
        full_ad.extend_from_slice(&header.to_bytes());

        let key = Key::from_slice(&message_key);
        let cipher = ChaCha20Poly1305::new(key);
        // Use message counter as nonce (padded to 12 bytes)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[8..12].copy_from_slice(&(self.send_n - 1).to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .expect("AEAD encryption should not fail");

        (header, ciphertext)
    }

    // ── Decryption ─────────────────────────────────────────────────

    /// Decrypt a received message. Returns plaintext or error.
    ///
    /// Checks skipped keys first, performs DH ratchet if needed,
    /// then symmetric chain ratchet.
    pub fn decrypt(
        &mut self,
        header: &RatchetHeader,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        // 1. Check skipped keys
        if let Some(mk) = self
            .skipped_keys
            .remove(&(header.dh_public_key, header.msg_num))
        {
            return self.decrypt_with_key(&mk, header, ciphertext, ad);
        }

        // 2. DH ratchet step if header has a new DH key
        let need_dh_ratchet = match &self.dh_remote {
            Some(current) => current.to_bytes() != header.dh_public_key,
            // If dh_remote is None but we already have a recv chain (symmetric init),
            // don't trigger DH ratchet — just use the existing chain.
            None => self.chain_recv.is_none(),
        };

        if need_dh_ratchet {
            // Skip remaining keys in old receiving chain
            if self.chain_recv.is_some() {
                self.skip_message_keys(header.prev_chain_length)?;
            }
            // Perform DH ratchet
            self.dh_ratchet(&header.dh_public_key)?;
        }

        // 3. Skip keys up to header.msg_num in new/current chain
        self.skip_message_keys(header.msg_num)?;

        // 4. Derive message key
        let ck = self
            .chain_recv
            .as_ref()
            .ok_or(DecryptError::InvalidHeader)?;
        let (next_ck, message_key) = Self::kdf_chain_key(ck);
        self.chain_recv = Some(next_ck);
        self.recv_n += 1;

        self.decrypt_with_key(&message_key, header, ciphertext, ad)
    }

    /// Perform the DH ratchet step on receiving a new remote DH key.
    fn dh_ratchet(&mut self, new_remote_bytes: &[u8; 32]) -> Result<(), DecryptError> {
        let new_remote = PublicKey::from(*new_remote_bytes);

        // Step 1: Derive receiving chain from old private + new remote
        let dh_output = *self.dh_self_priv.diffie_hellman(&new_remote).as_bytes();
        let (new_root, chain_recv) = Self::kdf_root_key(&self.root_key, &dh_output);
        self.root_key = new_root;
        self.chain_recv = Some(chain_recv);
        self.dh_remote = Some(new_remote);

        self.prev_chain_len = self.send_n;
        self.send_n = 0;
        self.recv_n = 0;

        // Step 2: Generate new keypair, derive sending chain
        let new_priv = StaticSecret::random_from_rng(OsRng);
        let new_pub = PublicKey::from(&new_priv);
        let dh_output2 = *new_priv.diffie_hellman(&new_remote).as_bytes();
        let (new_root2, chain_send) = Self::kdf_root_key(&self.root_key, &dh_output2);
        self.root_key = new_root2;
        self.chain_send = Some(chain_send);
        self.dh_self_priv = new_priv;
        self.dh_self_pub = new_pub;

        Ok(())
    }

    /// Skip message keys up to (but not including) the target message number.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), DecryptError> {
        if self.chain_recv.is_none() {
            return Ok(());
        }

        if until > self.recv_n + MAX_SKIP {
            return Err(DecryptError::SkipLimitExceeded);
        }

        let dhr_bytes = self.dh_remote.map(|pk| pk.to_bytes()).unwrap_or([0u8; 32]);

        while self.recv_n < until {
            let ck = self.chain_recv.as_ref().unwrap();
            let (next_ck, mk) = Self::kdf_chain_key(ck);
            self.chain_recv = Some(next_ck);
            self.skipped_keys.insert((dhr_bytes, self.recv_n), mk);
            self.recv_n += 1;
        }

        Ok(())
    }

    /// Decrypt ciphertext with a specific message key.
    fn decrypt_with_key(
        &self,
        message_key: &[u8; 32],
        header: &RatchetHeader,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let mut full_ad = Vec::with_capacity(ad.len() + 40);
        full_ad.extend_from_slice(ad);
        full_ad.extend_from_slice(&header.to_bytes());

        let key = Key::from_slice(message_key);
        let cipher = ChaCha20Poly1305::new(key);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[8..12].copy_from_slice(&header.msg_num.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| DecryptError::AuthenticationFailed)
    }

    // ── Accessors ──────────────────────────────────────────────────

    /// Get the current ratchet public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.dh_self_pub
    }

    /// Get the number of skipped keys currently cached.
    pub fn skipped_key_count(&self) -> usize {
        self.skipped_keys.len()
    }
}

impl std::fmt::Debug for Ratchet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ratchet")
            .field("dh_self_pub", &self.dh_self_pub.to_bytes())
            .field("dh_remote", &self.dh_remote.map(|pk| pk.to_bytes()))
            .field("send_n", &self.send_n)
            .field("recv_n", &self.recv_n)
            .field("skipped_keys_count", &self.skipped_keys.len())
            .field("root_key", &"[REDACTED]")
            .field("chain_send", &"[REDACTED]")
            .field("chain_recv", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_chain_key_distinct_outputs() {
        let ck = [42u8; 32];
        let (next_ck, mk) = Ratchet::kdf_chain_key(&ck);
        assert_ne!(next_ck, mk, "Chain key and message key must differ");
        assert_ne!(next_ck, ck, "Next chain key must differ from input");
    }

    #[test]
    fn test_kdf_root_key_distinct_outputs() {
        let root = [1u8; 32];
        let dh = [2u8; 32];
        let (new_root, chain_key) = Ratchet::kdf_root_key(&root, &dh);
        assert_ne!(new_root, chain_key, "Root key and chain key must differ");
        assert_ne!(new_root, root, "New root must differ from old root");
    }

    #[test]
    fn test_init_initiator_responder_compatible() {
        let sk = [99u8; 32];

        // Simulate: Bob's SPK
        let bob_spk_priv = StaticSecret::random_from_rng(OsRng);
        let bob_spk_pub = PublicKey::from(&bob_spk_priv);

        let mut alice = Ratchet::init_initiator(sk, &bob_spk_pub);
        let mut bob = Ratchet::init_responder(sk, bob_spk_priv);

        let ad = b"test_ad";

        // Alice sends to Bob
        let (header, ct) = alice.encrypt(b"hello bob", ad);
        let pt = bob.decrypt(&header, &ct, ad).unwrap();
        assert_eq!(pt, b"hello bob");

        // Bob replies to Alice
        let (header2, ct2) = bob.encrypt(b"hello alice", ad);
        let pt2 = alice.decrypt(&header2, &ct2, ad).unwrap();
        assert_eq!(pt2, b"hello alice");
    }

    #[test]
    fn test_100_sequential_messages_unique_keys() {
        let sk = [77u8; 32];
        let bob_spk_priv = StaticSecret::random_from_rng(OsRng);
        let bob_spk_pub = PublicKey::from(&bob_spk_priv);

        let mut alice = Ratchet::init_initiator(sk, &bob_spk_pub);
        let mut bob = Ratchet::init_responder(sk, bob_spk_priv);

        let ad = b"";
        let mut seen_cts: Vec<Vec<u8>> = Vec::new();

        for i in 0..100 {
            let msg = format!("message {}", i);
            let (header, ct) = alice.encrypt(msg.as_bytes(), ad);
            // Each ciphertext should be unique
            assert!(
                !seen_cts.contains(&ct),
                "Ciphertext must be unique for message {}",
                i
            );
            seen_cts.push(ct.clone());

            let pt = bob.decrypt(&header, &ct, ad).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_dh_ratchet_on_direction_change() {
        let sk = [55u8; 32];
        let bob_spk_priv = StaticSecret::random_from_rng(OsRng);
        let bob_spk_pub = PublicKey::from(&bob_spk_priv);

        let mut alice = Ratchet::init_initiator(sk, &bob_spk_pub);
        let mut bob = Ratchet::init_responder(sk, bob_spk_priv);

        let ad = b"";

        // Alice -> Bob (3 messages)
        for i in 0..3 {
            let (h, ct) = alice.encrypt(format!("a{}", i).as_bytes(), ad);
            bob.decrypt(&h, &ct, ad).unwrap();
        }

        // Bob -> Alice (direction change, triggers DH ratchet)
        let (h, ct) = bob.encrypt(b"b0", ad);
        let pt = alice.decrypt(&h, &ct, ad).unwrap();
        assert_eq!(pt, b"b0");

        // Alice -> Bob again (another DH ratchet)
        let (h, ct) = alice.encrypt(b"a3", ad);
        let pt = bob.decrypt(&h, &ct, ad).unwrap();
        assert_eq!(pt, b"a3");
    }

    #[test]
    fn test_out_of_order_messages() {
        let sk = [44u8; 32];
        let bob_spk_priv = StaticSecret::random_from_rng(OsRng);
        let bob_spk_pub = PublicKey::from(&bob_spk_priv);

        let mut alice = Ratchet::init_initiator(sk, &bob_spk_pub);
        let mut bob = Ratchet::init_responder(sk, bob_spk_priv);

        let ad = b"";

        // Alice sends 5 messages
        let mut messages: Vec<(RatchetHeader, Vec<u8>)> = Vec::new();
        for i in 0..5 {
            let (h, ct) = alice.encrypt(format!("msg{}", i).as_bytes(), ad);
            messages.push((h, ct));
        }

        // Bob receives in order: 0, 2, 4, 1, 3 (skip and backfill)
        let pt0 = bob.decrypt(&messages[0].0, &messages[0].1, ad).unwrap();
        assert_eq!(pt0, b"msg0");

        let pt2 = bob.decrypt(&messages[2].0, &messages[2].1, ad).unwrap();
        assert_eq!(pt2, b"msg2");

        let pt4 = bob.decrypt(&messages[4].0, &messages[4].1, ad).unwrap();
        assert_eq!(pt4, b"msg4");

        // Now receive the skipped messages
        let pt1 = bob.decrypt(&messages[1].0, &messages[1].1, ad).unwrap();
        assert_eq!(pt1, b"msg1");

        let pt3 = bob.decrypt(&messages[3].0, &messages[3].1, ad).unwrap();
        assert_eq!(pt3, b"msg3");
    }

    #[test]
    fn test_skip_limit_exceeded() {
        let sk = [33u8; 32];
        let bob_spk_priv = StaticSecret::random_from_rng(OsRng);
        let bob_spk_pub = PublicKey::from(&bob_spk_priv);

        let mut alice = Ratchet::init_initiator(sk, &bob_spk_pub);
        let mut bob = Ratchet::init_responder(sk, bob_spk_priv);

        let ad = b"";

        // Alice sends MAX_SKIP + 2 messages, Bob only processes the last one
        for _ in 0..(MAX_SKIP + 2) {
            alice.encrypt(b"x", ad);
        }
        let (h, ct) = alice.encrypt(b"final", ad);

        let result = bob.decrypt(&h, &ct, ad);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let sk = [22u8; 32];
        let bob_spk_priv = StaticSecret::random_from_rng(OsRng);
        let bob_spk_pub = PublicKey::from(&bob_spk_priv);

        let mut alice = Ratchet::init_initiator(sk, &bob_spk_pub);
        let mut bob = Ratchet::init_responder(sk, bob_spk_priv);

        let ad = b"";
        let (h, mut ct) = alice.encrypt(b"secret", ad);

        // Tamper with ciphertext
        if let Some(byte) = ct.last_mut() {
            *byte ^= 0xFF;
        }

        let result = bob.decrypt(&h, &ct, ad);
        assert!(matches!(result, Err(DecryptError::AuthenticationFailed)));
    }

    #[test]
    fn test_header_serialization_roundtrip() {
        let header = RatchetHeader {
            dh_public_key: [42u8; 32],
            prev_chain_length: 7,
            msg_num: 99,
        };
        let bytes = header.to_bytes();
        let restored = RatchetHeader::from_bytes(&bytes);
        assert_eq!(header.dh_public_key, restored.dh_public_key);
        assert_eq!(header.prev_chain_length, restored.prev_chain_length);
        assert_eq!(header.msg_num, restored.msg_num);
    }

    #[test]
    fn test_symmetric_init_bidirectional() {
        let sk = [42u8; 32];
        let ad = b"test";

        let mut alice = Ratchet::init_symmetric(sk, true);
        let mut bob = Ratchet::init_symmetric(sk, false);

        // Alice -> Bob
        let (h1, ct1) = alice.encrypt(b"hello bob", ad);
        let pt1 = bob.decrypt(&h1, &ct1, ad).unwrap();
        assert_eq!(pt1, b"hello bob");

        // Bob -> Alice
        let (h2, ct2) = bob.encrypt(b"hello alice", ad);
        let pt2 = alice.decrypt(&h2, &ct2, ad).unwrap();
        assert_eq!(pt2, b"hello alice");
    }

    #[test]
    fn test_debug_redacts_secrets() {
        let sk = [11u8; 32];
        let bob_spk_priv = StaticSecret::random_from_rng(OsRng);
        let bob_spk_pub = PublicKey::from(&bob_spk_priv);
        let ratchet = Ratchet::init_initiator(sk, &bob_spk_pub);
        let debug = format!("{:?}", ratchet);
        assert!(debug.contains("[REDACTED]"));
    }
}
