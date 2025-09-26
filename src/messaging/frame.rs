use serde::{Deserialize, Serialize};

pub const FRAME_BYTES: usize = 4096; // full frame size
pub const HEADER_BYTES: usize = 256; // reserved header area
pub const PAYLOAD_BYTES: usize = FRAME_BYTES - HEADER_BYTES; // encrypted payload area

#[derive(Serialize, Deserialize, Debug)]
pub struct FrameHeader {
    pub version: u8,
    pub flags: u8,
    pub header_nonce: [u8; 12],
    // routing info must be encrypted DO NOT place raw addresses here
    // Header is an opaque blob to be filled by Sphinx or routing layer.
    pub opaque: [u8; HEADER_BYTES - 14], // opaque header area; keep it opaque
}

// Payload (AEAD ciphertext + padding to PAYLOAD_BYTES)
#[derive(Debug)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>, // length = PAYLOAD_BYTES (with padding)
}

// helper function to pack frames
impl Frame {
    pub fn pack(&self) -> Vec<u8> {
        // Serialize header with bincode or a fixed layout
        let mut output = Vec::with_capacity(FRAME_BYTES);
        // Deterministic encoding: version, flags, header_nonce, opaque
        output.push(self.header.version);
        output.push(self.header.flags);
        output.extend_from_slice(&self.header.header_nonce);
        output.extend_from_slice(&self.header.opaque);
        assert_eq!(self.payload.len(), PAYLOAD_BYTES);
        output.extend_from_slice(&self.payload);
        output
    }
}
