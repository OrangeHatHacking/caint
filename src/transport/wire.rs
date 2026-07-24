use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::transport::sphinx::SPHINX_PACKET_SIZE;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),
    #[error("Payload too large: {0} bytes")]
    PayloadTooLarge(u32),
    #[error("Unexpected EOF")]
    UnexpectedEof,
}

/// Message types on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// A Sphinx packet (4429 bytes payload)
    SphinxData = 0x01,
    /// Publish a pre-key bundle to a relay
    PreKeyPublish = 0x02,
    /// Request a pre-key bundle from a relay
    PreKeyFetch = 0x03,
    /// Response containing a pre-key bundle
    PreKeyResponse = 0x04,
    /// X3DH initial message for session establishment
    InitialMessage = 0x05,
    /// Peer announcement (identity + address for discovery)
    PeerAnnounce = 0x06,
    /// Direct encrypted message (ratchet-encrypted frame, no Sphinx)
    DirectMessage = 0x07,
}

impl TryFrom<u8> for MessageType {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MessageType::SphinxData),
            0x02 => Ok(MessageType::PreKeyPublish),
            0x03 => Ok(MessageType::PreKeyFetch),
            0x04 => Ok(MessageType::PreKeyResponse),
            0x05 => Ok(MessageType::InitialMessage),
            0x06 => Ok(MessageType::PeerAnnounce),
            0x07 => Ok(MessageType::DirectMessage),
            other => Err(WireError::InvalidMessageType(other)),
        }
    }
}

/// Maximum wire message payload.
pub const MAX_PAYLOAD_SIZE: u32 = 16384;

/// A framed message on the wire.
///
/// Wire format: type_id (1 byte) || length (4 bytes BE) || payload (length bytes)
#[derive(Debug, Clone)]
pub struct WireMessage {
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

impl WireMessage {
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        WireMessage { msg_type, payload }
    }

    /// Create a SphinxData message from raw packet bytes.
    pub fn sphinx_data(packet_bytes: &[u8; SPHINX_PACKET_SIZE]) -> Self {
        WireMessage {
            msg_type: MessageType::SphinxData,
            payload: packet_bytes.to_vec(),
        }
    }

    /// Write this message to an async writer.
    pub async fn write_to<W: AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), WireError> {
        let type_byte = self.msg_type as u8;
        let length = self.payload.len() as u32;

        writer.write_u8(type_byte).await?;
        writer.write_u32(length).await?;
        writer.write_all(&self.payload).await?;
        writer.flush().await?;

        Ok(())
    }

    /// Read a message from an async reader.
    pub async fn read_from<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Self, WireError> {
        let type_byte = reader.read_u8().await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                WireError::UnexpectedEof
            } else {
                WireError::Io(e)
            }
        })?;

        let msg_type = MessageType::try_from(type_byte)?;
        let length = reader.read_u32().await?;

        if length > MAX_PAYLOAD_SIZE {
            return Err(WireError::PayloadTooLarge(length));
        }

        let mut payload = vec![0u8; length as usize];
        reader.read_exact(&mut payload).await?;

        Ok(WireMessage { msg_type, payload })
    }
}

/// Serialize a PeerAnnounce payload.
///
/// Format: ed25519_pub(32) || x25519_pub(32) || spk_pub(32) || spk_id(4) || spk_sig(64) || addr_len(2) || addr_bytes
pub fn encode_peer_announce(
    ed25519_pub: &[u8; 32],
    x25519_pub: &[u8; 32],
    spk_pub: &[u8; 32],
    spk_id: u32,
    spk_sig: &[u8; 64],
    listen_addr: &str,
) -> Vec<u8> {
    let addr_bytes = listen_addr.as_bytes();
    let mut payload = Vec::with_capacity(32 + 32 + 32 + 4 + 64 + 2 + addr_bytes.len());
    payload.extend_from_slice(ed25519_pub);
    payload.extend_from_slice(x25519_pub);
    payload.extend_from_slice(spk_pub);
    payload.extend_from_slice(&spk_id.to_be_bytes());
    payload.extend_from_slice(spk_sig);
    payload.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(addr_bytes);
    payload
}

/// Deserialize a PeerAnnounce payload.
///
/// Returns (ed25519_pub, x25519_pub, spk_pub, spk_id, spk_sig, listen_addr)
#[allow(clippy::type_complexity)]
pub fn decode_peer_announce(
    payload: &[u8],
) -> Option<([u8; 32], [u8; 32], [u8; 32], u32, [u8; 64], String)> {
    if payload.len() < 32 + 32 + 32 + 4 + 64 + 2 {
        return None;
    }
    let mut ed = [0u8; 32];
    ed.copy_from_slice(&payload[0..32]);
    let mut x = [0u8; 32];
    x.copy_from_slice(&payload[32..64]);
    let mut spk = [0u8; 32];
    spk.copy_from_slice(&payload[64..96]);
    let spk_id = u32::from_be_bytes([payload[96], payload[97], payload[98], payload[99]]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&payload[100..164]);
    let addr_len = u16::from_be_bytes([payload[164], payload[165]]) as usize;
    if payload.len() < 166 + addr_len {
        return None;
    }
    let addr = String::from_utf8(payload[166..166 + addr_len].to_vec()).ok()?;
    Some((ed, x, spk, spk_id, sig, addr))
}

/// Encode a DirectMessage payload.
///
/// Format: sender_x25519_pub(32) || frame_data(4096)
pub fn encode_direct_message(sender_x25519_pub: &[u8; 32], frame_data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32 + frame_data.len());
    payload.extend_from_slice(sender_x25519_pub);
    payload.extend_from_slice(frame_data);
    payload
}

/// Decode a DirectMessage payload.
///
/// Returns (sender_x25519_pub, frame_data)
pub fn decode_direct_message(payload: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    if payload.len() < 33 {
        return None;
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&payload[..32]);
    let frame_data = payload[32..].to_vec();
    Some((sender, frame_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_wire_message_roundtrip() {
        let msg = WireMessage::new(MessageType::SphinxData, vec![1, 2, 3, 4, 5]);
        let mut buf = Vec::new();
        msg.write_to(&mut buf).await.unwrap();
        let mut cursor = Cursor::new(buf);
        let restored = WireMessage::read_from(&mut cursor).await.unwrap();
        assert_eq!(restored.msg_type, MessageType::SphinxData);
        assert_eq!(restored.payload, vec![1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn test_wire_all_types() {
        let types = vec![
            MessageType::SphinxData,
            MessageType::PreKeyPublish,
            MessageType::PreKeyFetch,
            MessageType::PreKeyResponse,
            MessageType::InitialMessage,
            MessageType::PeerAnnounce,
            MessageType::DirectMessage,
        ];
        for msg_type in types {
            let msg = WireMessage::new(msg_type, vec![42]);
            let mut buf = Vec::new();
            msg.write_to(&mut buf).await.unwrap();
            let mut cursor = Cursor::new(buf);
            let restored = WireMessage::read_from(&mut cursor).await.unwrap();
            assert_eq!(restored.msg_type, msg_type);
        }
    }

    #[test]
    fn test_peer_announce_roundtrip() {
        let ed = [1u8; 32];
        let x = [2u8; 32];
        let spk = [3u8; 32];
        let sig = [4u8; 64];
        let encoded = encode_peer_announce(&ed, &x, &spk, 42, &sig, "127.0.0.1:9000");
        let (ed2, x2, spk2, id2, sig2, addr2) = decode_peer_announce(&encoded).unwrap();
        assert_eq!(ed, ed2);
        assert_eq!(x, x2);
        assert_eq!(spk, spk2);
        assert_eq!(42, id2);
        assert_eq!(sig, sig2);
        assert_eq!("127.0.0.1:9000", addr2);
    }

    #[test]
    fn test_direct_message_roundtrip() {
        let sender = [5u8; 32];
        let frame = vec![0xAB; 4096];
        let encoded = encode_direct_message(&sender, &frame);
        let (s2, f2) = decode_direct_message(&encoded).unwrap();
        assert_eq!(sender, s2);
        assert_eq!(frame, f2);
    }

    #[tokio::test]
    async fn test_invalid_message_type() {
        let buf = vec![0xFF, 0, 0, 0, 0];
        let mut cursor = Cursor::new(buf);
        let result = WireMessage::read_from(&mut cursor).await;
        assert!(result.is_err());
    }
}
