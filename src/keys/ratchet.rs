use crate::keys::X25519EphemeralKeyPair;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

#[derive(Clone, Debug)]
pub struct RatchetHeader {
    pub dh_public_key: [u8; 32],
    pub prev_chain_length: u32,
    pub msg_num: u32, // message number in current sending chain
}

pub struct RatchetMessage {
    pub header: RatchetHeader,
    pub ciphertext: Vec<u8>,
}

pub struct Ratchet {
    root_key: [u8; 32],

    priv_key: StaticSecret,
    pub_key: PublicKey,

    peer_pub_key: Option<PublicKey>,

    send_chain: Option<[u8; 32]>,
    recv_chain: Option<[u8; 32]>,

    // Message counters
    send_n: u32,
    recv_n: u32,

    prev_send_chain_length: u32, // same as in header

    skipped_msg_keys: HashMap<(Vec<u8>, u32), [u8; 32]>,
}

impl Ratchet {
    /// Create new Ratchet given initial 32-byte root from prior X3DH
    pub fn new(initial_root: [u8; 32]) -> Self {
        let mut csprng = OsRng;
        let priv_key = StaticSecret::random_from_rng(&mut csprng);
        let pub_key = PublicKey::from(&priv_key);

        Ratchet {
            root_key: initial_root,
            priv_key: priv_key,
            pub_key: pub_key,
            peer_pub_key: None,
            send_chain: None,
            recv_chain: None,
            send_n: 0,
            recv_n: 0,
            prev_send_chain_length: 0,
            skipped_msg_keys: HashMap::new(),
        }
    }

    /// Derive new_root and chain_key from current root and DH shared key
    fn kdf_root_key(root: &[u8; 32], dh_shared_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hash_key = Hkdf::<Sha256>::new(Some(root), dh_shared_key); // root is salt, dh_shared_key is input key material
        let mut okm = [0u8; 64]; // output key material

        hash_key.expand(b"DRK", &mut okm).expect("hkdf expand");

        let mut new_root = [0u8; 32];
        let mut chain_key = [0u8; 32];

        new_root.copy_from_slice(&okm[..32]);
        chain_key.copy_from_slice(&okm[..32]);

        (new_root, chain_key)
    }

    /// Produce next_chain_key and message_key frpm chain_key
    fn kdf_chain_key(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hash_key = Hkdf::<Sha256>::new(None, chain_key);
        let mut okm = [0u8; 64];

        hash_key.expand(b"DCK", &mut okm).expect("hkdf expand");

        let mut next_chain_key = [0u8; 32];
        let mut message_key = [0u8; 32];

        next_chain_key.copy_from_slice(&okm[..32]);
        message_key.copy_from_slice(&okm[..32]);

        (next_chain_key, message_key)
    }

    /// Init as caller that has generated and sent public part of ephemeral keypair and consumes private part
    pub fn init_as_initiator(&mut self, priv_key: EphemeralSecret, peer_pub_key: &PublicKey) {
        let shared_key = priv_key.diffie_hellman(peer_pub_key);
        let shared_key_bytes = *shared_key.as_bytes();

        let (new_root, send_chain_key) = Self::kdf_root_key(&self.root_key, &shared_key_bytes);

        self.root_key = new_root;
        self.send_chain = Some(send_chain_key);
        self.peer_pub_key = Some(*peer_pub_key);
        self.send_n = 0;
        self.recv_n = 0;
        self.prev_send_chain_length = 0;
    }

    /// Init as responder to some caller that has used init_as_initiator
    pub fn init_as_responder(&mut self, priv_key: EphemeralSecret, peer_pub_key: &PublicKey) {
        let shared_key = priv_key.diffie_hellman(peer_pub_key);
        let shared_key_bytes = *shared_key.as_bytes();

        let (new_root, recv_chain_key) = Self::kdf_root_key(&self.root_key, &shared_key_bytes);

        self.root_key = new_root;
        self.recv_chain = Some(recv_chain_key);
        self.peer_pub_key = Some(*peer_pub_key);
        self.send_n = 0;
        self.recv_n = 0;
        self.prev_send_chain_length = 0;
    }

    fn dh_ratchet_on_receive(&mut self, peer_pub_key_bytes: [u8; 32], prev_send_chain_length: u32) {
        let peer_pub_key = PublicKey::from(peer_pub_key_bytes);

        let shared_key = self.priv_key.diffie_hellman(&peer_pub_key);
        let shared_key_bytes = *shared_key.as_bytes();

        // get new root & recv chain
        let (new_root, recv_chain_key) = Self::kdf_root_key(&self.root_key, &shared_key_bytes);
        self.root_key = new_root;
        self.recv_chain = Some(recv_chain_key);

        self.prev_send_chain_length = prev_send_chain_length;
        self.peer_pub_key = Some(peer_pub_key);
        self.recv_n = 0;
    }

    fn advance_send_chain(&mut self) -> [u8; 32] {
        let chain_key = self.send_chain.expect("send_chain not initialized");
        let (next_chain_key, message_key) = Self::kdf_chain_key(&chain_key);
        self.send_chain = Some(next_chain_key);
        self.send_n = self.send_n.wrapping_add(1);
        message_key
    }

    fn advance_recv_chain(&mut self) -> [u8; 32] {
        let chain_key = self.recv_chain.expect("recv_chain not initialized");
        let (next_ck, mk) = Self::kdf_chain_key(&chain_key);
        self.recv_chain = Some(next_ck);
        self.recv_n = self.recv_n.wrapping_add(1);
        mk
    }

    pub fn prepare_send(&mut self) -> Result<(RatchetHeader, [u8; 32]), &'static str> {
        if self.send_chain.is_none() {
            let peer_pub_key = match &self.peer_pub_key {
                Some(pub_key) => pub_key.clone(),
                None => return Err("peer_pub_key unknown: cannot derive send chain"),
            };

            // rotate DH private key (generate new StaticSecret)
            let csprng = OsRng;
            let new_priv_key = StaticSecret::random_from_rng(csprng);
            let new_pub_key = PublicKey::from(&new_priv_key);
            let new_shared_key = new_priv_key.diffie_hellman(&peer_pub_key);
            let new_shared_key_bytes = *new_shared_key.as_bytes();
            let (new_root, send_chain_key) =
                Self::kdf_root_key(&self.root_key, &new_shared_key_bytes);

            self.root_key = new_root;
            self.prev_send_chain_length = self.send_n;
            self.send_chain = Some(send_chain_key);
            self.priv_key = new_priv_key;
            self.pub_key = new_pub_key;
            self.send_n = 0;
        }

        let message_key = self.advance_send_chain();
        let msg_num = self.send_n.wrapping_sub(1);

        let header = RatchetHeader {
            dh_public_key: self.pub_key.to_bytes(),
            prev_chain_length: self.prev_send_chain_length,
            msg_num: msg_num,
        };

        Ok((header, message_key))
    }
}
