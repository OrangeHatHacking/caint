/// Encode bytes as hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode hex string to bytes. Returns None if invalid hex.
pub fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Decode hex string to a fixed-size array. Returns None if wrong length or invalid hex.
pub fn hex_decode_32(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex_decode(hex)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xFF]), "00ff");
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode("deadbeef"), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(hex_decode("00ff"), Some(vec![0x00, 0xFF]));
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert_eq!(hex_decode("xyz"), None); // odd length
        assert_eq!(hex_decode("gg"), None); // invalid hex chars
    }

    #[test]
    fn test_hex_roundtrip() {
        let bytes = [42u8; 32];
        let hex = hex_encode(&bytes);
        let decoded = hex_decode_32(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_hex_decode_32_wrong_length() {
        assert!(hex_decode_32("deadbeef").is_none()); // only 4 bytes
    }
}
