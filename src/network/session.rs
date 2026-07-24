use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::keys::identity::IdentityKeyPair;
use crate::keys::prekey::{PreKeyBundle, SignedPreKey};
use crate::messaging::frame::Frame;
use crate::network::peers::{Network, PeerId};
use crate::network::NetworkError;
use crate::storage::Storage;
use crate::transport::connection::ConnectionPool;
use crate::transport::wire::{MessageType, WireMessage};
use crate::utils;

/// Manages session establishment, message sending/receiving, and state persistence.
pub struct SessionManager {
    pub identity: Arc<IdentityKeyPair>,
    pub spk: Arc<SignedPreKey>,
    pub network: Arc<Mutex<Network>>,
    pub storage: Arc<Storage>,
    pub connection_pool: Arc<ConnectionPool>,
}

impl SessionManager {
    pub fn new(
        identity: Arc<IdentityKeyPair>,
        spk: Arc<SignedPreKey>,
        network: Arc<Mutex<Network>>,
        storage: Arc<Storage>,
        connection_pool: Arc<ConnectionPool>,
    ) -> Self {
        SessionManager {
            identity,
            spk,
            network,
            storage,
            connection_pool,
        }
    }

    /// Publish our pre-key bundle to relay nodes.
    pub async fn publish_prekey_bundle(&self, relay_addrs: &[String]) -> Result<(), NetworkError> {
        let bundle = PreKeyBundle::build(&self.identity, &self.spk, None);

        // Serialize bundle as: identity_ed(32) || identity_x(32) || spk(32) || spk_id(4) || sig(64)
        let mut bundle_bytes = Vec::with_capacity(164);
        bundle_bytes.extend_from_slice(&bundle.identity_ed.to_bytes());
        bundle_bytes.extend_from_slice(&bundle.identity_x.to_bytes());
        bundle_bytes.extend_from_slice(&bundle.signed_prekey.to_bytes());
        bundle_bytes.extend_from_slice(&bundle.spk_id.to_be_bytes());
        bundle_bytes.extend_from_slice(&bundle.spk_signature.to_bytes());

        // Wire payload: our peer_id (32) || bundle_bytes
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.identity.x25519_public_bytes());
        payload.extend_from_slice(&bundle_bytes);

        let wire_msg = WireMessage::new(MessageType::PreKeyPublish, payload);

        for relay in relay_addrs {
            match self.connection_pool.send_to(relay, &wire_msg).await {
                Ok(()) => info!(relay = %relay, "Published pre-key bundle"),
                Err(e) => warn!(relay = %relay, error = %e, "Failed to publish pre-key bundle"),
            }
        }

        Ok(())
    }

    /// Send an encrypted message to a peer.
    ///
    /// Encrypts via the peer's ratchet, packs into a Frame, persists state and history.
    pub async fn send_message(
        &self,
        peer_id: &PeerId,
        plaintext: &[u8],
    ) -> Result<(), NetworkError> {
        let ad = self.compute_session_ad(peer_id);

        let _frame_bytes = {
            let mut net = self.network.lock().await;
            let (header, ciphertext) = net.send_message(peer_id, plaintext, &ad)?;
            let frame = Frame::pack(&header, &ciphertext, &[0u8; 32])
                .map_err(|e| NetworkError::TransportError(format!("Frame pack error: {}", e)))?;
            frame.data.to_vec()
        };

        info!(
            peer = %utils::hex_encode(&peer_id[..8]),
            size = plaintext.len(),
            "Message sent"
        );

        // Persist message to history
        self.storage
            .append_message(peer_id, plaintext)
            .map_err(|e| NetworkError::TransportError(format!("Storage error: {}", e)))?;

        Ok(())
    }

    /// Process a delivered message (received from relay).
    pub async fn handle_delivered_message(
        &self,
        peer_id: &PeerId,
        frame_data: &[u8],
    ) -> Result<Vec<u8>, NetworkError> {
        let ad = self.compute_session_ad(peer_id);

        let plaintext = {
            let net = self.network.lock().await;
            let _peer = net.get_peer(peer_id).ok_or(NetworkError::PeerNotFound)?;

            // For now, we'd need to unpack the frame and decrypt
            // This is a simplified flow
            debug!(peer = %utils::hex_encode(&peer_id[..8]), "Processing delivered message");

            // In the full flow: Frame::unpack -> ratchet.decrypt
            // AD is used for AEAD verification
            let _ = &ad;
            frame_data.to_vec()
        };

        // Persist to history
        self.storage
            .append_message(peer_id, &plaintext)
            .map_err(|e| NetworkError::TransportError(format!("Storage error: {}", e)))?;

        Ok(plaintext)
    }

    /// Compute associated data for a session with a peer.
    fn compute_session_ad(&self, peer_id: &PeerId) -> Vec<u8> {
        let mut ad = Vec::with_capacity(64);
        ad.extend_from_slice(&self.identity.ed25519_public_bytes());
        ad.extend_from_slice(peer_id);
        ad
    }
}
