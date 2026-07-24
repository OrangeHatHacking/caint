use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};

use crate::keys::ratchet::RatchetHeader;
use crate::messaging::FrameError;

/// Fixed frame size in bytes.
pub const FRAME_SIZE: usize = 4096;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const HEADER_SIZE: usize = 40;
pub const LENGTH_PREFIX_SIZE: usize = 2;
/// Maximum plaintext size: FRAME_SIZE - NONCE_SIZE - TAG_SIZE - HEADER_SIZE - LENGTH_PREFIX_SIZE
pub const MAX_PLAINTEXT_SIZE: usize =
    FRAME_SIZE - NONCE_SIZE - TAG_SIZE - HEADER_SIZE - LENGTH_PREFIX_SIZE;

/// Fixed-size encrypted message frame (always exactly FRAME_SIZE bytes).
#[derive(Clone)]
pub struct Frame {
    /// Raw frame bytes (nonce || ciphertext_with_tag), always FRAME_SIZE bytes total.
    pub data: [u8; FRAME_SIZE],
}

impl Frame {
    /// Pack a plaintext message with a ratchet header into a fixed-size encrypted frame.
    ///
    /// Layout before encryption: header(40) || length(2) || plaintext || random_padding
    /// The entire block is encrypted with ChaCha20-Poly1305.
    /// Final frame: nonce(12) || ciphertext(4068) || tag(16) = 4096 bytes.
    pub fn pack(
        header: &RatchetHeader,
        plaintext: &[u8],
        message_key: &[u8; 32],
    ) -> Result<Self, FrameError> {
        if plaintext.len() > MAX_PLAINTEXT_SIZE {
            return Err(FrameError::PayloadTooLarge);
        }

        // Build payload: header || length_prefix || plaintext || random_padding
        let payload_size = FRAME_SIZE - NONCE_SIZE - TAG_SIZE;
        let mut payload = vec![0u8; payload_size];

        // Header (40 bytes)
        payload[..HEADER_SIZE].copy_from_slice(&header.to_bytes());

        // Length prefix (2 bytes, big-endian)
        let len = plaintext.len() as u16;
        payload[HEADER_SIZE..HEADER_SIZE + LENGTH_PREFIX_SIZE].copy_from_slice(&len.to_be_bytes());

        // Plaintext
        let pt_start = HEADER_SIZE + LENGTH_PREFIX_SIZE;
        payload[pt_start..pt_start + plaintext.len()].copy_from_slice(plaintext);

        // Random padding for the rest
        let pad_start = pt_start + plaintext.len();
        if pad_start < payload_size {
            OsRng.fill_bytes(&mut payload[pad_start..]);
        }

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let key = Key::from_slice(message_key);
        let cipher = ChaCha20Poly1305::new(key);
        let ciphertext = cipher
            .encrypt(nonce, payload.as_slice())
            .map_err(|_| FrameError::AuthenticationFailed)?;

        // Assemble frame: nonce || ciphertext (includes tag)
        let mut data = [0u8; FRAME_SIZE];
        data[..NONCE_SIZE].copy_from_slice(&nonce_bytes);
        data[NONCE_SIZE..].copy_from_slice(&ciphertext);

        Ok(Frame { data })
    }

    /// Unpack a frame: decrypt and extract the header and plaintext.
    pub fn unpack(&self, message_key: &[u8; 32]) -> Result<(RatchetHeader, Vec<u8>), FrameError> {
        // Split: nonce(12) || ciphertext_with_tag(4084)
        let nonce = Nonce::from_slice(&self.data[..NONCE_SIZE]);
        let ciphertext = &self.data[NONCE_SIZE..];

        let key = Key::from_slice(message_key);
        let cipher = ChaCha20Poly1305::new(key);
        let payload = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| FrameError::AuthenticationFailed)?;

        // Extract header
        let mut header_bytes = [0u8; HEADER_SIZE];
        header_bytes.copy_from_slice(&payload[..HEADER_SIZE]);
        let header = RatchetHeader::from_bytes(&header_bytes);

        // Extract length prefix
        let len = u16::from_be_bytes([payload[HEADER_SIZE], payload[HEADER_SIZE + 1]]) as usize;

        // Extract plaintext
        let pt_start = HEADER_SIZE + LENGTH_PREFIX_SIZE;
        let plaintext = payload[pt_start..pt_start + len].to_vec();

        Ok((header, plaintext))
    }

    /// Generate a dummy frame that is structurally identical to a real frame.
    ///
    /// Uses random plaintext encrypted with a random key via pack(),
    /// producing a valid AEAD-encrypted frame indistinguishable from real frames.
    pub fn dummy() -> Self {
        let mut random_key = [0u8; 32];
        OsRng.fill_bytes(&mut random_key);

        let dummy_header = RatchetHeader {
            dh_public_key: {
                let mut k = [0u8; 32];
                OsRng.fill_bytes(&mut k);
                k
            },
            prev_chain_length: 0,
            msg_num: 0,
        };

        // Random plaintext of random length (1..MAX_PLAINTEXT_SIZE)
        let len = (OsRng.next_u32() as usize % MAX_PLAINTEXT_SIZE).max(1);
        let mut random_plaintext = vec![0u8; len];
        OsRng.fill_bytes(&mut random_plaintext);

        Frame::pack(&dummy_header, &random_plaintext, &random_key)
            .expect("Dummy frame packing should never fail")
    }
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("size", &self.data.len())
            .field("nonce", &&self.data[..NONCE_SIZE])
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [42u8; 32]
    }

    fn test_header() -> RatchetHeader {
        RatchetHeader {
            dh_public_key: [1u8; 32],
            prev_chain_length: 3,
            msg_num: 7,
        }
    }

    #[test]
    fn test_pack_produces_exact_frame_size() {
        let header = test_header();
        let frame = Frame::pack(&header, b"hello world", &test_key()).unwrap();
        assert_eq!(frame.data.len(), FRAME_SIZE);
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        let header = test_header();
        let plaintext = b"hello world";
        let key = test_key();
        let frame = Frame::pack(&header, plaintext, &key).unwrap();
        let (restored_header, restored_pt) = frame.unpack(&key).unwrap();
        assert_eq!(restored_pt, plaintext);
        assert_eq!(restored_header.dh_public_key, header.dh_public_key);
        assert_eq!(restored_header.prev_chain_length, header.prev_chain_length);
        assert_eq!(restored_header.msg_num, header.msg_num);
    }

    #[test]
    fn test_pack_unpack_empty_plaintext() {
        let header = test_header();
        let key = test_key();
        let frame = Frame::pack(&header, b"", &key).unwrap();
        assert_eq!(frame.data.len(), FRAME_SIZE);
        let (_, restored_pt) = frame.unpack(&key).unwrap();
        assert_eq!(restored_pt, b"");
    }

    #[test]
    fn test_pack_unpack_max_plaintext() {
        let header = test_header();
        let key = test_key();
        let plaintext = vec![0xABu8; MAX_PLAINTEXT_SIZE];
        let frame = Frame::pack(&header, &plaintext, &key).unwrap();
        assert_eq!(frame.data.len(), FRAME_SIZE);
        let (_, restored_pt) = frame.unpack(&key).unwrap();
        assert_eq!(restored_pt, plaintext);
    }

    #[test]
    fn test_payload_too_large() {
        let header = test_header();
        let key = test_key();
        let plaintext = vec![0u8; MAX_PLAINTEXT_SIZE + 1];
        let result = Frame::pack(&header, &plaintext, &key);
        assert!(matches!(result, Err(FrameError::PayloadTooLarge)));
    }

    #[test]
    fn test_dummy_frame_exact_size() {
        let frame = Frame::dummy();
        assert_eq!(frame.data.len(), FRAME_SIZE);
    }

    #[test]
    fn test_dummy_frame_has_valid_aead_structure() {
        // Dummy frame has nonce (12 bytes) + ciphertext with tag
        // We can verify it has the right structure by checking the nonce prefix exists
        // and total size is correct. We can't decrypt it (random key) but structure is valid.
        let frame = Frame::dummy();
        assert_eq!(frame.data.len(), FRAME_SIZE);
        // Nonce should not be all zeros (random)
        assert_ne!(&frame.data[..NONCE_SIZE], &[0u8; NONCE_SIZE]);
    }

    #[test]
    fn test_dummy_indistinguishable_from_real_by_size() {
        let real = Frame::pack(&test_header(), b"real message", &test_key()).unwrap();
        let dummy = Frame::dummy();
        assert_eq!(real.data.len(), dummy.data.len());
    }

    #[test]
    fn test_tampered_frame_fails_aead() {
        let header = test_header();
        let key = test_key();
        let mut frame = Frame::pack(&header, b"secret", &key).unwrap();
        // Flip a bit in the ciphertext
        frame.data[NONCE_SIZE + 10] ^= 0xFF;
        let result = frame.unpack(&key);
        assert!(matches!(result, Err(FrameError::AuthenticationFailed)));
    }

    #[test]
    fn test_wrong_key_fails() {
        let header = test_header();
        let frame = Frame::pack(&header, b"secret", &test_key()).unwrap();
        let wrong_key = [99u8; 32];
        let result = frame.unpack(&wrong_key);
        assert!(matches!(result, Err(FrameError::AuthenticationFailed)));
    }

    #[test]
    fn test_unique_frames_for_same_plaintext() {
        let header = test_header();
        let key = test_key();
        let f1 = Frame::pack(&header, b"same", &key).unwrap();
        let f2 = Frame::pack(&header, b"same", &key).unwrap();
        // Different nonces -> different ciphertext
        assert_ne!(f1.data, f2.data);
    }
}
