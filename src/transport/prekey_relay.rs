use std::collections::HashMap;
use tracing::debug;

/// Relay-side storage for pre-key bundles.
///
/// Peers publish their bundles here; senders fetch them to establish sessions.
pub struct PreKeyStore {
    /// Stored bundles: peer_id (32 bytes hex) -> serialized bundle bytes
    bundles: HashMap<String, Vec<u8>>,
}

impl PreKeyStore {
    pub fn new() -> Self {
        PreKeyStore {
            bundles: HashMap::new(),
        }
    }

    /// Handle a raw publish request.
    ///
    /// Payload format: peer_id (32 bytes) || bundle_data (remaining bytes)
    pub fn handle_publish_raw(&mut self, payload: &[u8]) {
        if payload.len() < 32 {
            return;
        }
        let peer_id = crate::utils::hex_encode(&payload[..32]);
        let bundle_data = payload[32..].to_vec();
        debug!(peer_id = %peer_id, bundle_size = bundle_data.len(), "Storing pre-key bundle");
        self.bundles.insert(peer_id, bundle_data);
    }

    /// Handle a raw fetch request.
    ///
    /// Payload format: peer_id (32 bytes)
    /// Returns: bundle_data bytes (empty if not found)
    pub fn handle_fetch_raw(&self, payload: &[u8]) -> Vec<u8> {
        if payload.len() < 32 {
            return Vec::new();
        }
        let peer_id = crate::utils::hex_encode(&payload[..32]);
        self.bundles.get(&peer_id).cloned().unwrap_or_default()
    }

    /// Check if a bundle exists for a peer.
    pub fn has_bundle(&self, peer_id_hex: &str) -> bool {
        self.bundles.contains_key(peer_id_hex)
    }

    /// Number of stored bundles.
    pub fn bundle_count(&self) -> usize {
        self.bundles.len()
    }
}

impl Default for PreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_publish_and_fetch() {
        let mut store = PreKeyStore::new();
        let peer_id = [42u8; 32];
        let bundle = b"fake bundle data";

        let mut payload = Vec::new();
        payload.extend_from_slice(&peer_id);
        payload.extend_from_slice(bundle);

        store.handle_publish_raw(&payload);
        assert_eq!(store.bundle_count(), 1);

        let fetched = store.handle_fetch_raw(&peer_id);
        assert_eq!(fetched, bundle);
    }

    #[test]
    fn test_fetch_unknown_peer() {
        let store = PreKeyStore::new();
        let peer_id = [99u8; 32];
        let fetched = store.handle_fetch_raw(&peer_id);
        assert!(fetched.is_empty());
    }

    #[test]
    fn test_publish_overwrites() {
        let mut store = PreKeyStore::new();
        let peer_id = [42u8; 32];

        let mut p1 = Vec::from(peer_id.as_slice());
        p1.extend_from_slice(b"bundle_v1");
        store.handle_publish_raw(&p1);

        let mut p2 = Vec::from(peer_id.as_slice());
        p2.extend_from_slice(b"bundle_v2");
        store.handle_publish_raw(&p2);

        let fetched = store.handle_fetch_raw(&peer_id);
        assert_eq!(fetched, b"bundle_v2");
        assert_eq!(store.bundle_count(), 1);
    }
}
