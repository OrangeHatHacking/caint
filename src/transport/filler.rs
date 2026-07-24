//! Sphinx filler generation.
//!
//! The filler ensures constant header size regardless of actual hop count.
//! Without it, shorter routes would have detectable zero padding.

use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};

use crate::transport::routing::ROUTING_BLOCK_SIZE;

/// Generate Sphinx filler bytes for the given number of hops.
///
/// Filler is built from the stream cipher keys of hops 0 through (num_hops - 2).
/// The resulting filler has length (num_hops - 1) * ROUTING_BLOCK_SIZE.
pub fn generate_filler(stream_keys: &[[u8; 32]], num_hops: usize) -> Vec<u8> {
    assert!(
        stream_keys.len() >= num_hops.saturating_sub(1),
        "Need at least num_hops - 1 stream keys"
    );

    if num_hops <= 1 {
        return Vec::new();
    }

    let routing_info_size = crate::transport::routing::ROUTING_INFO_SIZE;

    let mut filler = Vec::new();

    for i in 1..num_hops {
        // Generate the keystream that hop (i-1) would use
        let key_len = routing_info_size + ROUTING_BLOCK_SIZE;
        let mut keystream = vec![0u8; key_len];

        let mut cipher = ChaCha20::new(stream_keys[i - 1].as_ref().into(), &[0u8; 12].into());
        cipher.apply_keystream(&mut keystream);

        // Extend filler by ROUTING_BLOCK_SIZE zero bytes
        filler.extend(vec![0u8; ROUTING_BLOCK_SIZE]);

        // XOR with the tail of the keystream
        let tail_start = key_len - (i * ROUTING_BLOCK_SIZE);
        let tail = &keystream[tail_start..];

        for (j, byte) in filler.iter_mut().enumerate() {
            *byte ^= tail[j];
        }
    }

    filler
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filler_3_hops_length() {
        let keys = [[1u8; 32], [2u8; 32]];
        let filler = generate_filler(&keys, 3);
        assert_eq!(filler.len(), 2 * ROUTING_BLOCK_SIZE);
        assert_eq!(filler.len(), 114);
    }

    #[test]
    fn test_filler_5_hops_length() {
        let keys = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let filler = generate_filler(&keys, 5);
        assert_eq!(filler.len(), 4 * ROUTING_BLOCK_SIZE);
        assert_eq!(filler.len(), 228);
    }

    #[test]
    fn test_filler_1_hop_empty() {
        let filler = generate_filler(&[], 1);
        assert!(filler.is_empty());
    }

    #[test]
    fn test_filler_not_all_zeros() {
        let keys = [[42u8; 32], [99u8; 32]];
        let filler = generate_filler(&keys, 3);
        // Filler should not be all zeros (XOR'd with keystream)
        assert!(filler.iter().any(|&b| b != 0));
    }
}
