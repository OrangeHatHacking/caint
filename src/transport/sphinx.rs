//! Sphinx packet creation and processing.

use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
// chacha20poly1305 reserved for future AEAD use on payload
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::transport::blinding::blind_alpha;
use crate::transport::filler::generate_filler;
use crate::transport::routing::{NodeInfo, RoutingBlock, ROUTING_BLOCK_SIZE, ROUTING_INFO_SIZE};
use crate::transport::SphinxError;

type HmacSha256 = Hmac<Sha256>;

/// Total Sphinx packet size: header(333) + payload(4096) = 4429
pub const SPHINX_PACKET_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;
/// Header: alpha(32) + mac(16) + routing_info(285) = 333
pub const HEADER_SIZE: usize = 32 + 16 + ROUTING_INFO_SIZE;
/// Payload size (matches frame size).
pub const PAYLOAD_SIZE: usize = 4096;

/// Per-hop derived keys.
struct HopKeys {
    stream_key: [u8; 32],
    mac_key: [u8; 16],
    payload_key: [u8; 32],
    blinding_factor: [u8; 32],
    replay_tag: [u8; 32],
}

/// Derive per-hop keys from a shared secret.
fn derive_hop_keys(shared_secret: &[u8; 32]) -> HopKeys {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 144]; // 32 + 16 + 32 + 32 + 32
    hk.expand(b"caint_sphinx", &mut okm)
        .expect("HKDF expand for 144 bytes");

    let mut stream_key = [0u8; 32];
    let mut mac_key = [0u8; 16];
    let mut payload_key = [0u8; 32];
    let mut blinding_factor = [0u8; 32];
    let mut replay_tag = [0u8; 32];

    stream_key.copy_from_slice(&okm[0..32]);
    mac_key.copy_from_slice(&okm[32..48]);
    payload_key.copy_from_slice(&okm[48..80]);
    blinding_factor.copy_from_slice(&okm[80..112]);
    replay_tag.copy_from_slice(&okm[112..144]);

    HopKeys {
        stream_key,
        mac_key,
        payload_key,
        blinding_factor,
        replay_tag,
    }
}

/// Compute HMAC-SHA256 truncated to 16 bytes.
fn compute_mac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result[..16]);
    out
}

/// Result of processing a Sphinx packet at a node.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ProcessResult {
    /// Forward to next hop.
    Forward {
        next_hop: [u8; 32],
        packet: SphinxPacket,
    },
    /// Final destination - payload delivered.
    Deliver { payload: Vec<u8> },
    /// Packet dropped (replay or error).
    Drop,
}

/// A Sphinx packet (fixed-size, 4429 bytes).
#[derive(Clone)]
pub struct SphinxPacket {
    /// Raw packet bytes.
    pub data: [u8; SPHINX_PACKET_SIZE],
}

impl SphinxPacket {
    /// Create a Sphinx packet for the given route.
    ///
    /// `route` must contain 3-5 relay nodes followed by the destination.
    /// `payload` must be exactly PAYLOAD_SIZE (4096) bytes.
    pub fn create(payload: &[u8; PAYLOAD_SIZE], route: &[NodeInfo]) -> Result<Self, SphinxError> {
        let num_hops = route.len();
        if !(4..=6).contains(&num_hops) {
            // route = relay hops + destination, so 4-6 total entries
            return Err(SphinxError::InvalidRouteLength);
        }

        // 1. Generate ephemeral keypair
        let eph_priv = StaticSecret::random_from_rng(OsRng);
        let alpha = PublicKey::from(&eph_priv);

        // 2. Compute per-hop shared secrets and keys
        let mut hop_keys_list = Vec::with_capacity(num_hops);
        let mut shared_secrets = Vec::with_capacity(num_hops);

        // First hop: DH with ephemeral private key
        let ss0 = *eph_priv.diffie_hellman(&route[0].public_key).as_bytes();
        shared_secrets.push(ss0);
        let keys0 = derive_hop_keys(&ss0);
        hop_keys_list.push(keys0);

        // Subsequent hops: compute shared secrets using accumulated blinding
        for hop in route.iter().skip(1) {
            let combined_secret = compute_hop_shared_secret(
                &eph_priv,
                &hop.public_key,
                &hop_keys_list
                    .iter()
                    .map(|k| k.blinding_factor)
                    .collect::<Vec<_>>(),
            );

            shared_secrets.push(combined_secret);
            let keys = derive_hop_keys(&combined_secret);
            hop_keys_list.push(keys);
        }

        // 3. Build routing info from inside out
        let stream_keys: Vec<[u8; 32]> = hop_keys_list.iter().map(|k| k.stream_key).collect();
        let filler = generate_filler(&stream_keys, num_hops);

        let mut routing_info = [0u8; ROUTING_INFO_SIZE];

        // Last hop: flag=0x01 (final), next_hop = destination ID
        let last_block = RoutingBlock {
            flag: 0x01,
            next_hop: route[num_hops - 1].id,
            delay: 0,
            mac: [0u8; 16], // MAC for final hop is zeros (no next layer)
        };

        // Place last hop's block at the start of routing info
        routing_info[..ROUTING_BLOCK_SIZE].copy_from_slice(&last_block.to_bytes());

        // Pad unused slots with random data
        let used = ROUTING_BLOCK_SIZE;
        let pad_end = ROUTING_INFO_SIZE - filler.len();
        if used < pad_end {
            OsRng.fill_bytes(&mut routing_info[used..pad_end]);
        }

        // Apply filler to tail
        if !filler.is_empty() {
            let filler_start = ROUTING_INFO_SIZE - filler.len();
            routing_info[filler_start..].copy_from_slice(&filler);
        }

        // Encrypt with last hop's stream key
        encrypt_routing_info(&mut routing_info, &hop_keys_list[num_hops - 1].stream_key);

        // Compute MAC for last hop
        let mut last_mac = compute_mac(&hop_keys_list[num_hops - 1].mac_key, &routing_info);

        // Work backwards through remaining hops
        for i in (0..num_hops - 1).rev() {
            // Shift routing info right by ROUTING_BLOCK_SIZE to make room
            let mut new_ri = [0u8; ROUTING_INFO_SIZE];
            let next_hop_id = route[i + 1].id;
            let block = RoutingBlock {
                flag: 0x00, // forward
                next_hop: next_hop_id,
                delay: 0,
                mac: last_mac,
            };
            new_ri[..ROUTING_BLOCK_SIZE].copy_from_slice(&block.to_bytes());
            let remaining = ROUTING_INFO_SIZE - ROUTING_BLOCK_SIZE;
            new_ri[ROUTING_BLOCK_SIZE..].copy_from_slice(&routing_info[..remaining]);
            routing_info = new_ri;

            // Encrypt with this hop's stream key
            encrypt_routing_info(&mut routing_info, &hop_keys_list[i].stream_key);

            // Compute MAC for this layer
            last_mac = compute_mac(&hop_keys_list[i].mac_key, &routing_info);
        }

        // 4. Encrypt payload layer by layer (last hop first)
        let mut enc_payload = *payload;
        for i in (0..num_hops).rev() {
            xor_payload(&mut enc_payload, &hop_keys_list[i].payload_key);
        }

        // 5. Assemble packet
        let mut data = [0u8; SPHINX_PACKET_SIZE];
        data[..32].copy_from_slice(&alpha.to_bytes());
        data[32..48].copy_from_slice(&last_mac);
        data[48..48 + ROUTING_INFO_SIZE].copy_from_slice(&routing_info);
        data[HEADER_SIZE..].copy_from_slice(&enc_payload);

        Ok(SphinxPacket { data })
    }

    /// Process a Sphinx packet at a relay node.
    pub fn process(
        &self,
        node_key: &StaticSecret,
        replay_cache: &mut ReplayCache,
    ) -> Result<ProcessResult, SphinxError> {
        // Extract alpha
        let mut alpha_bytes = [0u8; 32];
        alpha_bytes.copy_from_slice(&self.data[..32]);
        let alpha = PublicKey::from(alpha_bytes);

        // Compute shared secret
        let shared_secret = *node_key.diffie_hellman(&alpha).as_bytes();
        let keys = derive_hop_keys(&shared_secret);

        // Check replay
        if !replay_cache.check_and_insert(&keys.replay_tag) {
            return Ok(ProcessResult::Drop);
        }

        // Verify MAC
        let stored_mac = &self.data[32..48];
        let routing_info = &self.data[48..48 + ROUTING_INFO_SIZE];

        let computed_mac = compute_mac(&keys.mac_key, routing_info);
        if computed_mac != stored_mac[..16] {
            return Err(SphinxError::ProcessingFailed);
        }

        // Decrypt routing info
        let mut decrypted_ri = [0u8; ROUTING_INFO_SIZE];
        decrypted_ri.copy_from_slice(routing_info);
        encrypt_routing_info(&mut decrypted_ri, &keys.stream_key); // XOR is its own inverse

        // Extract current routing block
        let mut block_bytes = [0u8; ROUTING_BLOCK_SIZE];
        block_bytes.copy_from_slice(&decrypted_ri[..ROUTING_BLOCK_SIZE]);
        let block = RoutingBlock::from_bytes(&block_bytes);

        // Decrypt payload layer
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload.copy_from_slice(&self.data[HEADER_SIZE..]);
        xor_payload(&mut payload, &keys.payload_key);

        if block.flag == 0x01 {
            // Final destination
            Ok(ProcessResult::Deliver {
                payload: payload.to_vec(),
            })
        } else {
            // Forward: blind alpha, shift routing info, reassemble
            let new_alpha = blind_alpha(&alpha, &keys.blinding_factor);

            // Shift routing info left by ROUTING_BLOCK_SIZE (remove consumed block)
            let mut new_ri = [0u8; ROUTING_INFO_SIZE];
            let remaining = ROUTING_INFO_SIZE - ROUTING_BLOCK_SIZE;
            new_ri[..remaining].copy_from_slice(&decrypted_ri[ROUTING_BLOCK_SIZE..]);
            // Tail is zero-padded (which is correct for Sphinx)

            let mut new_data = [0u8; SPHINX_PACKET_SIZE];
            new_data[..32].copy_from_slice(&new_alpha.to_bytes());
            new_data[32..48].copy_from_slice(&block.mac);
            new_data[48..48 + ROUTING_INFO_SIZE].copy_from_slice(&new_ri);
            new_data[HEADER_SIZE..].copy_from_slice(&payload);

            Ok(ProcessResult::Forward {
                next_hop: block.next_hop,
                packet: SphinxPacket { data: new_data },
            })
        }
    }

    /// Generate a dummy Sphinx packet (random 4429 bytes).
    pub fn dummy() -> Self {
        let mut data = [0u8; SPHINX_PACKET_SIZE];
        OsRng.fill_bytes(&mut data);
        SphinxPacket { data }
    }

    /// Get the packet size.
    pub fn size(&self) -> usize {
        SPHINX_PACKET_SIZE
    }
}

impl std::fmt::Debug for SphinxPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SphinxPacket")
            .field("size", &self.data.len())
            .field("alpha", &&self.data[..8])
            .finish()
    }
}

/// Encrypt/decrypt routing info using ChaCha20 stream cipher (XOR).
fn encrypt_routing_info(routing_info: &mut [u8; ROUTING_INFO_SIZE], key: &[u8; 32]) {
    let mut cipher = ChaCha20::new(key.as_ref().into(), &[0u8; 12].into());
    cipher.apply_keystream(routing_info);
}

/// XOR payload with a key-derived stream (simplified SPRP replacement).
fn xor_payload(payload: &mut [u8; PAYLOAD_SIZE], key: &[u8; 32]) {
    let mut cipher = ChaCha20::new(key.as_ref().into(), &[0u8; 12].into());
    cipher.apply_keystream(payload);
}

/// Compute the hop shared secret using blinding factor accumulation.
///
/// For hop i, the shared secret is DH(eph_priv * prod(bf[0..i-1]), hop_pubkey).
/// We simulate this by hashing the ephemeral secret with all blinding factors.
fn compute_hop_shared_secret(
    eph_priv: &StaticSecret,
    hop_pubkey: &PublicKey,
    blinding_factors: &[[u8; 32]],
) -> [u8; 32] {
    // Apply all blinding factors to the ephemeral secret
    let current_secret_bytes = {
        // Get the raw ephemeral secret bytes via DH with base point trick
        // Instead, we'll use HKDF to combine eph_priv DH output with blinding factors
        let base_dh = *eph_priv.diffie_hellman(hop_pubkey).as_bytes();
        let hk = Hkdf::<Sha256>::new(None, &base_dh);
        let mut combined = [0u8; 32];
        let info: Vec<u8> = blinding_factors
            .iter()
            .flat_map(|bf| bf.iter().copied())
            .collect();
        hk.expand(&info, &mut combined).expect("HKDF expand");
        combined
    };
    current_secret_bytes
}

/// Time-bounded replay cache.
pub struct ReplayCache {
    tags: HashMap<[u8; 32], Instant>,
    ttl: Duration,
}

impl ReplayCache {
    /// Create a new replay cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        ReplayCache {
            tags: HashMap::new(),
            ttl,
        }
    }

    /// Check if a tag is new (not replayed) and insert it.
    ///
    /// Returns true if the tag is new, false if it's a replay.
    pub fn check_and_insert(&mut self, tag: &[u8; 32]) -> bool {
        self.purge_expired();

        if self.tags.contains_key(tag) {
            return false;
        }

        self.tags.insert(*tag, Instant::now());
        true
    }

    /// Remove expired tags.
    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.tags
            .retain(|_, inserted| now.duration_since(*inserted) < self.ttl);
    }

    /// Number of tags currently cached.
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_sphinx_packet_size() {
        assert_eq!(SPHINX_PACKET_SIZE, 4429);
    }

    #[test]
    fn test_dummy_packet_size() {
        let pkt = SphinxPacket::dummy();
        assert_eq!(pkt.data.len(), SPHINX_PACKET_SIZE);
    }

    #[test]
    fn test_replay_cache_new_tag() {
        let mut cache = ReplayCache::new(Duration::from_secs(60));
        let tag = [42u8; 32];
        assert!(cache.check_and_insert(&tag));
    }

    #[test]
    fn test_replay_cache_duplicate_tag() {
        let mut cache = ReplayCache::new(Duration::from_secs(60));
        let tag = [42u8; 32];
        assert!(cache.check_and_insert(&tag));
        assert!(!cache.check_and_insert(&tag)); // replay
    }

    #[test]
    fn test_replay_cache_expiration() {
        let mut cache = ReplayCache::new(Duration::from_millis(50));
        let tag = [42u8; 32];
        cache.check_and_insert(&tag);
        thread::sleep(Duration::from_millis(100));
        cache.purge_expired();
        assert_eq!(cache.len(), 0);
        // Should be accepted again after expiry
        assert!(cache.check_and_insert(&tag));
    }

    #[test]
    fn test_hop_keys_derivation() {
        let ss = [99u8; 32];
        let keys = derive_hop_keys(&ss);
        // All keys should be non-zero and different
        assert_ne!(keys.stream_key, [0u8; 32]);
        assert_ne!(keys.payload_key, [0u8; 32]);
        assert_ne!(keys.blinding_factor, [0u8; 32]);
        assert_ne!(keys.replay_tag, [0u8; 32]);
        assert_ne!(keys.stream_key, keys.payload_key);
    }

    #[test]
    fn test_xor_payload_roundtrip() {
        let key = [42u8; 32];
        let original = [0xABu8; PAYLOAD_SIZE];
        let mut payload = original;
        xor_payload(&mut payload, &key);
        assert_ne!(payload, original); // should be encrypted
        xor_payload(&mut payload, &key); // XOR again to decrypt
        assert_eq!(payload, original);
    }

    #[test]
    fn test_encrypt_routing_info_roundtrip() {
        let key = [42u8; 32];
        let original = [0xCDu8; ROUTING_INFO_SIZE];
        let mut ri = original;
        encrypt_routing_info(&mut ri, &key);
        assert_ne!(ri, original);
        encrypt_routing_info(&mut ri, &key); // XOR again
        assert_eq!(ri, original);
    }

    #[test]
    fn test_mac_computation() {
        let key = [42u8; 16];
        let data = b"test data for mac";
        let mac1 = compute_mac(&key, data);
        let mac2 = compute_mac(&key, data);
        assert_eq!(mac1, mac2); // deterministic
        assert_ne!(mac1, [0u8; 16]); // non-zero
    }
}
