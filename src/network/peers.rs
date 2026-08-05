use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::keys::ratchet::Ratchet;
use crate::network::NetworkError;

/// A unique peer identifier (X25519 public key bytes).
pub type PeerId = [u8; 32];

/// A known contact in the peer table.
pub struct Peer {
    pub peer_id: PeerId,
    pub identity_ed: VerifyingKey,
    pub identity_x: X25519PublicKey,
    pub address: String,
    pub ratchet: Option<Ratchet>,
    pub trusted_relay: bool,
}

impl Peer {
    pub fn new(identity_ed: VerifyingKey, identity_x: X25519PublicKey, address: String) -> Self {
        let peer_id = identity_x.to_bytes();
        Peer {
            peer_id,
            identity_ed,
            identity_x,
            address,
            ratchet: None,
            trusted_relay: false,
        }
    }

    /// Serialize non-ephemeral peer fields to bytes.
    ///
    /// Format: `identity_ed(32) || identity_x(32) || trusted_relay(1) || addr_len(2, BE) || addr_bytes`
    ///
    /// `ratchet` is intentionally excluded; it is persisted separately.
    pub fn to_bytes(&self) -> Vec<u8> {
        let addr_bytes = self.address.as_bytes();
        let addr_len = addr_bytes.len() as u16;
        let mut out = Vec::with_capacity(32 + 32 + 1 + 2 + addr_bytes.len());
        out.extend_from_slice(self.identity_ed.as_bytes());
        out.extend_from_slice(&self.identity_x.to_bytes());
        out.push(u8::from(self.trusted_relay));
        out.extend_from_slice(&addr_len.to_be_bytes());
        out.extend_from_slice(addr_bytes);
        out
    }

    /// Deserialize a `Peer` from bytes produced by [`Peer::to_bytes`].
    ///
    /// Returns `Err` on truncation or invalid data. `ratchet` is always `None`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, NetworkError> {
        // Minimum: identity_ed(32) + identity_x(32) + trusted_relay(1) + addr_len(2) = 67
        if data.len() < 67 {
            return Err(NetworkError::TransportError(
                "peer record too short".to_string(),
            ));
        }

        let ed_bytes: [u8; 32] = data[..32].try_into().unwrap();
        let x_bytes: [u8; 32] = data[32..64].try_into().unwrap();
        let trusted_relay = data[64] != 0;
        let addr_len = u16::from_be_bytes([data[65], data[66]]) as usize;

        let end = 67 + addr_len;
        if data.len() < end {
            return Err(NetworkError::TransportError(
                "peer record truncated at address".to_string(),
            ));
        }

        let identity_ed = VerifyingKey::from_bytes(&ed_bytes).map_err(|_| {
            NetworkError::TransportError("invalid Ed25519 key in peer record".to_string())
        })?;
        let identity_x = X25519PublicKey::from(x_bytes);

        let address = String::from_utf8(data[67..end].to_vec()).map_err(|_| {
            NetworkError::TransportError("invalid UTF-8 address in peer record".to_string())
        })?;

        let mut peer = Peer::new(identity_ed, identity_x, address);
        peer.trusted_relay = trusted_relay;
        Ok(peer)
    }
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("peer_id", &hex::encode_short(&self.peer_id))
            .field("address", &self.address)
            .field("has_session", &self.ratchet.is_some())
            .field("trusted_relay", &self.trusted_relay)
            .finish()
    }
}

mod hex {
    pub fn encode_short(bytes: &[u8; 32]) -> String {
        bytes[..8]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
            + "..."
    }
}

/// Peer table managing known contacts and message routing.
pub struct Network {
    peers: HashMap<PeerId, Peer>,
}

impl Default for Network {
    fn default() -> Self {
        Self::new()
    }
}

impl Network {
    pub fn new() -> Self {
        Network {
            peers: HashMap::new(),
        }
    }

    /// Add a peer to the table. Returns their peer ID.
    pub fn add_peer(
        &mut self,
        identity_ed: VerifyingKey,
        identity_x: X25519PublicKey,
        address: String,
    ) -> PeerId {
        let peer = Peer::new(identity_ed, identity_x, address);
        let id = peer.peer_id;
        self.peers.insert(id, peer);
        id
    }

    /// Look up a peer by ID (immutable).
    pub fn get_peer(&self, id: &PeerId) -> Option<&Peer> {
        self.peers.get(id)
    }

    /// Look up a peer by ID (mutable).
    pub fn get_peer_mut(&mut self, id: &PeerId) -> Option<&mut Peer> {
        self.peers.get_mut(id)
    }

    /// List all peers.
    pub fn list_peers(&self) -> Vec<&Peer> {
        self.peers.values().collect()
    }

    /// Send a message to a peer: encrypt with their ratchet, return (header, ciphertext).
    ///
    /// The caller is responsible for packing into a Frame and routing via transport.
    pub fn send_message(
        &mut self,
        peer_id: &PeerId,
        plaintext: &[u8],
        ad: &[u8],
    ) -> Result<(crate::keys::ratchet::RatchetHeader, Vec<u8>), NetworkError> {
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or(NetworkError::PeerNotFound)?;
        let ratchet = peer
            .ratchet
            .as_mut()
            .ok_or(NetworkError::SessionNotInitialized)?;
        let (header, ciphertext) = ratchet.encrypt(plaintext, ad);
        Ok((header, ciphertext))
    }

    /// Receive a message from a peer: decrypt with their ratchet, return plaintext.
    pub fn receive_message(
        &mut self,
        peer_id: &PeerId,
        header: &crate::keys::ratchet::RatchetHeader,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, NetworkError> {
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or(NetworkError::PeerNotFound)?;
        let ratchet = peer
            .ratchet
            .as_mut()
            .ok_or(NetworkError::SessionNotInitialized)?;
        let plaintext = ratchet
            .decrypt(header, ciphertext, ad)
            .map_err(|e| NetworkError::TransportError(format!("Decrypt error: {}", e)))?;
        Ok(plaintext)
    }

    /// Number of peers in the table.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Serialize the peer table to bytes.
    ///
    /// Format: `version(1=0x01) || peer_count(4, BE) || [peer.to_bytes()...]`
    ///
    /// Ratchet state is not included.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x01u8); // version
        let count = self.peers.len() as u32;
        out.extend_from_slice(&count.to_be_bytes());
        for peer in self.peers.values() {
            let peer_bytes = peer.to_bytes();
            // Length-prefix each peer entry so the decoder can advance safely
            let entry_len = peer_bytes.len() as u32;
            out.extend_from_slice(&entry_len.to_be_bytes());
            out.extend_from_slice(&peer_bytes);
        }
        out
    }

    /// Deserialize a peer table from bytes produced by [`Network::to_bytes`].
    ///
    /// Returns `Err` on unknown version, truncation, or corrupt peer entries.
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::network::NetworkError> {
        if data.len() < 5 {
            return Err(crate::network::NetworkError::TransportError(
                "peer table too short".to_string(),
            ));
        }

        let version = data[0];
        if version != 0x01 {
            return Err(crate::network::NetworkError::TransportError(format!(
                "unknown peer table version: {version}"
            )));
        }

        let peer_count = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        let mut network = Network::new();
        let mut cursor = 5usize;

        for _ in 0..peer_count {
            if cursor + 4 > data.len() {
                return Err(crate::network::NetworkError::TransportError(
                    "peer table truncated at entry length".to_string(),
                ));
            }
            let entry_len = u32::from_be_bytes([
                data[cursor],
                data[cursor + 1],
                data[cursor + 2],
                data[cursor + 3],
            ]) as usize;
            cursor += 4;

            if cursor + entry_len > data.len() {
                return Err(crate::network::NetworkError::TransportError(
                    "peer table truncated at peer entry".to_string(),
                ));
            }

            let peer = Peer::from_bytes(&data[cursor..cursor + entry_len])?;
            network.peers.insert(peer.peer_id, peer);
            cursor += entry_len;
        }

        Ok(network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::identity::IdentityKeyPair;
    use crate::keys::ratchet::Ratchet;
    use rand::rngs::OsRng;
    use x25519_dalek::StaticSecret;

    fn make_test_peer() -> (IdentityKeyPair, VerifyingKey, X25519PublicKey) {
        let id = IdentityKeyPair::generate();
        let ed = *id.ed25519_public();
        let x = *id.x25519_public();
        (id, ed, x)
    }

    #[test]
    fn test_add_peer() {
        let mut net = Network::new();
        let (_, ed, x) = make_test_peer();
        let id = net.add_peer(ed, x, "127.0.0.1:8080".into());
        assert!(net.get_peer(&id).is_some());
        assert_eq!(net.peer_count(), 1);
    }

    #[test]
    fn test_get_peer_not_found() {
        let net = Network::new();
        let missing = [0u8; 32];
        assert!(net.get_peer(&missing).is_none());
    }

    #[test]
    fn test_list_peers() {
        let mut net = Network::new();
        let (_, ed1, x1) = make_test_peer();
        let (_, ed2, x2) = make_test_peer();
        net.add_peer(ed1, x1, "addr1".into());
        net.add_peer(ed2, x2, "addr2".into());
        assert_eq!(net.list_peers().len(), 2);
    }

    #[test]
    fn test_add_peer_duplicate_updates() {
        let mut net = Network::new();
        let (_, ed, x) = make_test_peer();
        net.add_peer(ed, x, "old_addr".into());
        net.add_peer(ed, x, "new_addr".into());
        assert_eq!(net.peer_count(), 1);
        let peer = net.get_peer(&x.to_bytes()).unwrap();
        assert_eq!(peer.address, "new_addr");
    }

    #[test]
    fn test_send_to_unknown_peer() {
        let mut net = Network::new();
        let missing = [0u8; 32];
        let result = net.send_message(&missing, b"hello", b"");
        assert!(matches!(result, Err(NetworkError::PeerNotFound)));
    }

    #[test]
    fn test_send_without_session() {
        let mut net = Network::new();
        let (_, ed, x) = make_test_peer();
        let id = net.add_peer(ed, x, "addr".into());
        let result = net.send_message(&id, b"hello", b"");
        assert!(matches!(result, Err(NetworkError::SessionNotInitialized)));
    }

    #[test]
    fn test_send_receive_with_session() {
        let mut net = Network::new();

        // Create Alice and Bob
        let alice_id = IdentityKeyPair::generate();
        let bob_id = IdentityKeyPair::generate();

        // Simulate session establishment
        let sk = [42u8; 32];
        let bob_spk_priv = StaticSecret::random_from_rng(OsRng);
        let bob_spk_pub = x25519_dalek::PublicKey::from(&bob_spk_priv);

        let alice_ratchet = Ratchet::init_initiator(sk, &bob_spk_pub);
        let bob_ratchet = Ratchet::init_responder(sk, bob_spk_priv);

        // Add Bob to Alice's network with a session
        let bob_peer_id = net.add_peer(
            *bob_id.ed25519_public(),
            *bob_id.x25519_public(),
            "bob:8080".into(),
        );
        net.get_peer_mut(&bob_peer_id).unwrap().ratchet = Some(alice_ratchet);

        // Alice sends to Bob
        let ad = b"test_ad";
        let (header, ct) = net.send_message(&bob_peer_id, b"hello bob", ad).unwrap();

        // Bob decrypts (using his own ratchet, not through network)
        let mut bob_net = Network::new();
        let alice_peer_id = bob_net.add_peer(
            *alice_id.ed25519_public(),
            *alice_id.x25519_public(),
            "alice:8080".into(),
        );
        bob_net.get_peer_mut(&alice_peer_id).unwrap().ratchet = Some(bob_ratchet);

        let plaintext = bob_net
            .receive_message(&alice_peer_id, &header, &ct, ad)
            .unwrap();
        assert_eq!(plaintext, b"hello bob");
    }

    #[test]
    fn test_peer_serialization_roundtrip() {
        let (_, ed, x) = make_test_peer();
        let mut peer = Peer::new(ed, x, "127.0.0.1:9000".into());
        peer.trusted_relay = true;

        let bytes = peer.to_bytes();
        let restored = Peer::from_bytes(&bytes).unwrap();

        assert_eq!(restored.peer_id, peer.peer_id);
        assert_eq!(restored.identity_ed.as_bytes(), peer.identity_ed.as_bytes());
        assert_eq!(restored.identity_x.to_bytes(), peer.identity_x.to_bytes());
        assert_eq!(restored.address, peer.address);
        assert_eq!(restored.trusted_relay, peer.trusted_relay);
        assert!(restored.ratchet.is_none());
    }

    #[test]
    fn test_network_serialization_roundtrip() {
        let mut net = Network::new();
        let (_, ed1, x1) = make_test_peer();
        let (_, ed2, x2) = make_test_peer();
        net.add_peer(ed1, x1, "peer1:8080".into());
        net.add_peer(ed2, x2, "peer2:9090".into());

        let bytes = net.to_bytes();
        let restored = Network::from_bytes(&bytes).unwrap();

        assert_eq!(restored.peer_count(), 2);
        assert!(restored.get_peer(&x1.to_bytes()).is_some());
        assert!(restored.get_peer(&x2.to_bytes()).is_some());
        assert_eq!(restored.get_peer(&x1.to_bytes()).unwrap().address, "peer1:8080");
        assert_eq!(restored.get_peer(&x2.to_bytes()).unwrap().address, "peer2:9090");
    }

    #[test]
    fn test_network_serialization_empty() {
        let net = Network::new();
        let bytes = net.to_bytes();
        let restored = Network::from_bytes(&bytes).unwrap();
        assert_eq!(restored.peer_count(), 0);
    }

    #[test]
    fn test_peer_deserialization_truncated() {
        // Too short to be valid
        let truncated = vec![0u8; 10];
        let result = Peer::from_bytes(&truncated);
        assert!(result.is_err());

        // Correct header length but address truncated
        let (_, ed, x) = make_test_peer();
        let peer = Peer::new(ed, x, "example:8080".into());
        let mut bytes = peer.to_bytes();
        bytes.truncate(bytes.len() - 3); // cut the end of the address
        let result = Peer::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_peer_from_bytes_has_no_ratchet() {
        let (_, ed, x) = make_test_peer();
        let mut peer = Peer::new(ed, x, "addr:8080".into());

        // Even if the original peer had a ratchet, deserialized peer must not
        let sk = [42u8; 32];
        let spk_priv = StaticSecret::random_from_rng(OsRng);
        let spk_pub = x25519_dalek::PublicKey::from(&spk_priv);
        peer.ratchet = Some(Ratchet::init_initiator(sk, &spk_pub));
        assert!(peer.ratchet.is_some());

        let bytes = peer.to_bytes();
        let restored = Peer::from_bytes(&bytes).unwrap();
        assert!(restored.ratchet.is_none(), "Deserialized peer must have ratchet: None");
    }

    #[test]
    fn test_needs_session_logic() {
        let mut net = Network::new();
        let (_, ed, x) = make_test_peer();
        let peer_id = x.to_bytes();

        // Case 1: peer not in table → needs session
        assert!(net.get_peer(&peer_id).is_none());

        // Case 2: peer in table with ratchet: None → needs session
        net.add_peer(ed, x, "addr:8080".into());
        let needs = net.get_peer(&peer_id)
            .map(|p| p.ratchet.is_none())
            .unwrap_or(false);
        assert!(needs, "Known peer without ratchet needs session");

        // Case 3: peer in table with ratchet: Some → does NOT need session
        {
            let sk = [42u8; 32];
            let spk_priv = StaticSecret::random_from_rng(OsRng);
            let spk_pub = x25519_dalek::PublicKey::from(&spk_priv);
            let p = net.get_peer_mut(&peer_id).unwrap();
            p.ratchet = Some(Ratchet::init_initiator(sk, &spk_pub));
        }
        let needs = net.get_peer(&peer_id)
            .map(|p| p.ratchet.is_none())
            .unwrap_or(false);
        assert!(!needs, "Known peer with active ratchet does not need session");
    }

    #[test]
    fn test_network_roundtrip_all_peers_sessionless() {
        // Simulates the restart scenario: serialize a table with active sessions,
        // deserialize it, verify all ratchets are None (needing re-establishment).
        let mut net = Network::new();
        let (_, ed1, x1) = make_test_peer();
        let (_, ed2, x2) = make_test_peer();
        net.add_peer(ed1, x1, "peer1:8080".into());
        net.add_peer(ed2, x2, "peer2:9090".into());

        // Give both peers active sessions
        let sk = [42u8; 32];
        let spk1 = StaticSecret::random_from_rng(OsRng);
        let spk2 = StaticSecret::random_from_rng(OsRng);
        net.get_peer_mut(&x1.to_bytes()).unwrap().ratchet =
            Some(Ratchet::init_initiator(sk, &x25519_dalek::PublicKey::from(&spk1)));
        net.get_peer_mut(&x2.to_bytes()).unwrap().ratchet =
            Some(Ratchet::init_initiator(sk, &x25519_dalek::PublicKey::from(&spk2)));

        // Serialize and deserialize (simulates shutdown → restart)
        let bytes = net.to_bytes();
        let restored = Network::from_bytes(&bytes).unwrap();

        assert_eq!(restored.peer_count(), 2);
        for peer in restored.list_peers() {
            assert!(
                peer.ratchet.is_none(),
                "All peers loaded from disk must have ratchet: None"
            );
        }
    }

    #[test]
    fn test_different_peers_use_different_ratchets() {
        let mut net = Network::new();

        let sk1 = [11u8; 32];
        let sk2 = [22u8; 32];

        let spk1_priv = StaticSecret::random_from_rng(OsRng);
        let spk1_pub = x25519_dalek::PublicKey::from(&spk1_priv);
        let spk2_priv = StaticSecret::random_from_rng(OsRng);
        let spk2_pub = x25519_dalek::PublicKey::from(&spk2_priv);

        let peer1_id_kp = IdentityKeyPair::generate();
        let peer2_id_kp = IdentityKeyPair::generate();

        let ratchet1 = Ratchet::init_initiator(sk1, &spk1_pub);
        let ratchet2 = Ratchet::init_initiator(sk2, &spk2_pub);

        let id1 = net.add_peer(
            *peer1_id_kp.ed25519_public(),
            *peer1_id_kp.x25519_public(),
            "peer1".into(),
        );
        let id2 = net.add_peer(
            *peer2_id_kp.ed25519_public(),
            *peer2_id_kp.x25519_public(),
            "peer2".into(),
        );

        net.get_peer_mut(&id1).unwrap().ratchet = Some(ratchet1);
        net.get_peer_mut(&id2).unwrap().ratchet = Some(ratchet2);

        let ad = b"";
        let (_, ct1) = net.send_message(&id1, b"msg", ad).unwrap();
        let (_, ct2) = net.send_message(&id2, b"msg", ad).unwrap();

        // Different ratchets produce different ciphertexts
        assert_ne!(ct1, ct2);
    }
}
