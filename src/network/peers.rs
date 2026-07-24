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
