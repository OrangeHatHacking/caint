use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};
use x25519_dalek::StaticSecret;

use crate::transport::connection::{noise_handshake_responder, noise_recv, ConnectionPool};
use crate::transport::prekey_relay::PreKeyStore;
use crate::transport::sphinx::{
    is_cover_payload, ProcessResult, ReplayCache, SphinxPacket, SPHINX_PACKET_SIZE,
};
use crate::transport::wire::{decode_peer_announce, MessageType, WireError, WireMessage};

/// A message delivered to the local node (final Sphinx hop or direct).
#[derive(Debug)]
pub struct DeliveredMessage {
    /// The payload bytes (raw frame data for DirectMessage, or Sphinx-decrypted payload)
    pub payload: Vec<u8>,
    /// The sender's X25519 public key bytes (if known)
    pub sender_id: Option<[u8; 32]>,
    /// Whether this is an X3DH initial message (needs session setup)
    pub is_initial: bool,
}

/// Node address registry: maps node X25519 public key (hex) to TCP address.
///
/// Populated by PeerAnnounce messages. Used to resolve Sphinx next_hop IDs
/// to TCP addresses for forwarding.
pub struct AddressRegistry {
    pub entries: HashMap<String, String>, // hex(node_id) -> "host:port"
}

impl AddressRegistry {
    pub fn new() -> Self {
        AddressRegistry {
            entries: HashMap::new(),
        }
    }

    pub fn register(&mut self, node_id_hex: &str, addr: &str) {
        self.entries
            .insert(node_id_hex.to_string(), addr.to_string());
    }

    pub fn resolve(&self, node_id_hex: &str) -> Option<&str> {
        self.entries.get(node_id_hex).map(|s| s.as_str())
    }
}

impl Default for AddressRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the relay listener.
pub async fn run_relay(
    listen_addr: &str,
    node_key: Arc<StaticSecret>,
    noise_private_key: Arc<[u8; 32]>,
    replay_cache: Arc<Mutex<ReplayCache>>,
    connection_pool: Arc<ConnectionPool>,
    delivery_tx: mpsc::Sender<DeliveredMessage>,
    prekey_store: Arc<Mutex<PreKeyStore>>,
    address_registry: Arc<Mutex<AddressRegistry>>,
) -> Result<(), WireError> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!(addr = listen_addr, "Relay listener started");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        debug!(peer = %peer_addr, "Accepted connection");

        let node_key = Arc::clone(&node_key);
        let noise_key = Arc::clone(&noise_private_key);
        let replay_cache = Arc::clone(&replay_cache);
        let connection_pool = Arc::clone(&connection_pool);
        let delivery_tx = delivery_tx.clone();
        let prekey_store = Arc::clone(&prekey_store);
        let address_registry = Arc::clone(&address_registry);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                stream,
                node_key,
                noise_key,
                replay_cache,
                connection_pool,
                delivery_tx,
                prekey_store,
                address_registry,
            )
            .await
            {
                match e {
                    WireError::UnexpectedEof => {
                        debug!(peer = %peer_addr, "Connection closed");
                    }
                    _ => {
                        warn!(peer = %peer_addr, error = %e, "Connection handler error");
                    }
                }
            }
        });
    }
}

/// Handle a single incoming connection with Noise handshake.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    node_key: Arc<StaticSecret>,
    noise_key: Arc<[u8; 32]>,
    replay_cache: Arc<Mutex<ReplayCache>>,
    connection_pool: Arc<ConnectionPool>,
    delivery_tx: mpsc::Sender<DeliveredMessage>,
    prekey_store: Arc<Mutex<PreKeyStore>>,
    address_registry: Arc<Mutex<AddressRegistry>>,
) -> Result<(), WireError> {
    // Noise XX handshake as responder
    let mut transport = noise_handshake_responder(&mut stream, &noise_key).await?;
    debug!("Noise handshake complete");

    loop {
        let msg = noise_recv(&mut stream, &mut transport).await?;

        match msg.msg_type {
            MessageType::SphinxData => {
                handle_sphinx_packet(
                    &msg.payload,
                    &node_key,
                    &replay_cache,
                    &connection_pool,
                    &delivery_tx,
                    &address_registry,
                )
                .await?;
            }
            MessageType::PreKeyPublish => {
                let mut store = prekey_store.lock().await;
                store.handle_publish_raw(&msg.payload);
                debug!("Stored pre-key bundle");
            }
            MessageType::PreKeyFetch => {
                let store = prekey_store.lock().await;
                let response = store.handle_fetch_raw(&msg.payload);
                let resp_msg = WireMessage::new(MessageType::PreKeyResponse, response);
                resp_msg.write_to(&mut stream).await?;
            }
            MessageType::PreKeyResponse => {
                warn!("Relay received unexpected PreKeyResponse");
            }
            MessageType::PeerAnnounce => {
                if let Some((_ed, x, _spk, _spk_id, _sig, addr)) =
                    decode_peer_announce(&msg.payload)
                {
                    let node_id_hex = crate::utils::hex_encode(&x);
                    // Log announcement without peer identity (Constitution V)
                    debug!("Peer announced");
                    // Register in address registry
                    let mut reg = address_registry.lock().await;
                    reg.register(&node_id_hex, &addr);
                    drop(reg);

                    // Deliver to app layer for peer table update
                    let _ = delivery_tx
                        .send(DeliveredMessage {
                            payload: msg.payload,
                            sender_id: Some(x),
                            is_initial: false,
                        })
                        .await;
                }
            }
            MessageType::DirectMessage => {
                if let Some((sender, frame_data)) =
                    crate::transport::wire::decode_direct_message(&msg.payload)
                {
                    debug!(
                        sender = %&crate::utils::hex_encode(&sender)[..16],
                        size = frame_data.len(),
                        "Direct message received"
                    );
                    let _ = delivery_tx
                        .send(DeliveredMessage {
                            payload: frame_data,
                            sender_id: Some(sender),
                            is_initial: false,
                        })
                        .await;
                }
            }
            MessageType::InitialMessage => {
                // Extract sender ID from the initial message payload
                let sender_id = if msg.payload.len() >= 64 {
                    // InitialMessage format starts with identity_key_x at offset 32
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&msg.payload[32..64]);
                    Some(id)
                } else {
                    None
                };
                let _ = delivery_tx
                    .send(DeliveredMessage {
                        payload: msg.payload,
                        sender_id,
                        is_initial: true,
                    })
                    .await;
            }
        }
    }
}

/// Process a single Sphinx packet.
async fn handle_sphinx_packet(
    payload: &[u8],
    node_key: &StaticSecret,
    replay_cache: &Arc<Mutex<ReplayCache>>,
    connection_pool: &Arc<ConnectionPool>,
    delivery_tx: &mpsc::Sender<DeliveredMessage>,
    address_registry: &Arc<Mutex<AddressRegistry>>,
) -> Result<(), WireError> {
    if payload.len() != SPHINX_PACKET_SIZE {
        warn!(size = payload.len(), "Invalid Sphinx packet size");
        return Ok(());
    }

    let mut data = [0u8; SPHINX_PACKET_SIZE];
    data.copy_from_slice(payload);
    let packet = SphinxPacket { data };

    let mut cache = replay_cache.lock().await;
    let result = packet.process(node_key, &mut cache);
    drop(cache);

    match result {
        Ok(ProcessResult::Forward { next_hop, packet }) => {
            let node_id_hex = crate::utils::hex_encode(&next_hop);

            // Resolve node_id to TCP address via registry
            let addr = {
                let reg = address_registry.lock().await;
                reg.resolve(&node_id_hex).map(|s| s.to_string())
            };

            if let Some(addr) = addr {
                debug!(next_hop = %&node_id_hex[..16], addr = %addr, "Forwarding Sphinx packet");
                let wire_msg = WireMessage::sphinx_data(&packet.data);
                if let Err(e) = connection_pool.send_to(&addr, &wire_msg).await {
                    warn!(addr = %addr, error = %e, "Failed to forward packet");
                }
            } else {
                warn!(next_hop = %&node_id_hex[..16], "No address for next hop, dropping packet");
            }
        }
        Ok(ProcessResult::Deliver { payload }) => {
            if is_cover_payload(&payload) {
                debug!("Discarded loop cover packet");
            } else {
                debug!(size = payload.len(), "Delivering Sphinx payload");
                let _ = delivery_tx
                    .send(DeliveredMessage {
                        payload,
                        sender_id: None,
                        is_initial: false,
                    })
                    .await;
            }
        }
        Ok(ProcessResult::Drop) => {
            debug!("Dropped replayed Sphinx packet");
        }
        Err(e) => {
            warn!(error = %e, "Sphinx processing failed");
        }
    }

    Ok(())
}
