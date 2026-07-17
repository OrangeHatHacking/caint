use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{x25519, EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

pub const MAX_HOPS: usize = 10;
pub const HOP_PAYLOAD_LEN: usize = 32;
pub const MAC_LEN: usize = 16;
pub const HOP_FIELD_LEN: usize = HOP_PAYLOAD_LEN + MAC_LEN;
pub const HEADER_LEN: usize = MAX_HOPS * HOP_FIELD_LEN;
pub const PAYLOAD_LEN: usize = 4096; // fixed payload ciphertext length

// compile time sanity check, returns zero sized array if ok
const _: () = {
    let _ = [0u8; (HEADER_LEN / HOP_FIELD_LEN) - (MAX_HOPS as usize)];
};

// Sphinx packet (α, β, γ) with payload appended.
// alpha = ephemeral public key bytes (32)
// beta = layered header blob (fixed length HEADER_LEN)
// gamma = overall header MAC (also keep per packet MAC for tamper detection)
// payload = fixed size AEAD ciphertext (PAYLOAD_LEN)

#[derive(Clone, Debug)]
pub struct SphinxPacket {
    pub alpha: [u8; 32],
    pub beta: Vec<u8>,
    pub gamma: [u8; MAC_LEN],
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct HopPayload {
    pub next_hop_pub_key: [u8; 32],
    pub opaque: Vec<u8>, // will be padded/truncated to fit HOP_PAYLOAD_LEN
}

impl HopPayload {
    pub fn serialise_hop_payload(&self) -> [u8; HOP_PAYLOAD_LEN] {
        let mut out = [0u8; HOP_PAYLOAD_LEN];
        out[..32].copy_from_slice(&self.next_hop_pub_key);
        let remaining = HOP_PAYLOAD_LEN - 32;
        let copy = std::cmp::min(remaining, self.opaque.len());
        if copy > 0 {
            out[32..32 + copy].copy_from_slice(&self.opaque[..copy]);
        }
        out
    }
}
