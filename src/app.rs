use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};
use x25519_dalek::StaticSecret;

use crate::config::AppConfig;
use crate::keys::identity::IdentityKeyPair;
use crate::keys::prekey::{generate_one_time_prekeys, SignedPreKey};
use crate::keys::ratchet::Ratchet;
use crate::network::peers::{Network, Peer, PeerId};
use crate::storage::Storage;
use crate::transport::connection::ConnectionPool;
use crate::transport::epoch::{run_epoch_loop, EpochFlusher};
use crate::transport::prekey_relay::PreKeyStore;
use crate::transport::relay::{run_relay, AddressRegistry, DeliveredMessage};
use crate::transport::routing::NodeInfo;
use crate::transport::sphinx::ReplayCache;
use crate::transport::wire::{
    decode_peer_announce, encode_peer_announce, MessageType, WireMessage,
};

/// The main application tying all subsystems together.
pub struct App {
    pub config: AppConfig,
    pub identity: Arc<IdentityKeyPair>,
    pub spk: Arc<SignedPreKey>,
    pub storage: Arc<Storage>,
    pub network: Arc<Mutex<Network>>,
    pub connection_pool: Arc<ConnectionPool>,
    pub epoch_flusher: Arc<Mutex<EpochFlusher>>,
    pub replay_cache: Arc<Mutex<ReplayCache>>,
    pub prekey_store: Arc<Mutex<PreKeyStore>>,
    pub address_registry: Arc<Mutex<AddressRegistry>>,
    pub available_relays: Arc<Mutex<Vec<NodeInfo>>>,
}

impl App {
    /// Initialize the application. Loads identity from disk or generates a new one.
    pub fn new(config: AppConfig) -> Self {
        let data_path = Path::new(&config.storage_path);
        std::fs::create_dir_all(data_path).ok();

        let identity = match crate::storage::Storage::load_identity_keypair(data_path) {
            Ok(Some(bytes)) => match IdentityKeyPair::from_bytes(&bytes) {
                Ok(id) => {
                    info!("Loaded identity from disk");
                    id
                }
                Err(e) => {
                    warn!(error = %e, "Corrupted identity file, generating new identity");
                    let id = IdentityKeyPair::generate();
                    let _ =
                        crate::storage::Storage::save_identity_keypair(data_path, &id.to_bytes());
                    id
                }
            },
            Ok(None) => {
                let id = IdentityKeyPair::generate();
                if let Err(e) =
                    crate::storage::Storage::save_identity_keypair(data_path, &id.to_bytes())
                {
                    warn!(error = %e, "Failed to save identity");
                }
                info!("Generated and saved new identity");
                id
            }
            Err(e) => {
                warn!(error = %e, "Failed to load identity, generating new");
                let id = IdentityKeyPair::generate();
                let _ = crate::storage::Storage::save_identity_keypair(data_path, &id.to_bytes());
                id
            }
        };

        let storage = Arc::new(Storage::new(&identity.x25519_public_bytes(), data_path));
        let identity = Arc::new(identity);
        let spk = Arc::new(SignedPreKey::generate(&identity, 1));
        let _opks = generate_one_time_prekeys(1, 100);

        let network = Arc::new(Mutex::new(Network::new()));
        let connection_pool = Arc::new(ConnectionPool::new());
        let epoch_flusher = Arc::new(Mutex::new(EpochFlusher::new(config.target_packet_count)));
        let replay_cache = Arc::new(Mutex::new(ReplayCache::new(Duration::from_secs(
            config.replay_ttl_secs,
        ))));
        let prekey_store = Arc::new(Mutex::new(PreKeyStore::new()));
        let address_registry = Arc::new(Mutex::new(AddressRegistry::new()));
        let available_relays = Arc::new(Mutex::new(Vec::new()));

        App {
            config,
            identity,
            spk,
            storage,
            network,
            connection_pool,
            epoch_flusher,
            replay_cache,
            prekey_store,
            address_registry,
            available_relays,
        }
    }

    /// Build our PeerAnnounce payload.
    fn build_announce(&self) -> Vec<u8> {
        encode_peer_announce(
            &self.identity.ed25519_public_bytes(),
            &self.identity.x25519_public_bytes(),
            &self.spk.public.to_bytes(),
            self.spk.key_id,
            &self.spk.signature.to_bytes(),
            &self.config.listen_addr,
        )
    }

    /// Get our self NodeInfo.
    fn self_node_info(&self) -> NodeInfo {
        NodeInfo {
            id: self.identity.x25519_public_bytes(),
            public_key: *self.identity.x25519_public(),
            address: self.config.listen_addr.clone(),
        }
    }

    /// Run the application.
    pub async fn run(&mut self) {
        let (delivery_tx, mut delivery_rx) = mpsc::channel::<DeliveredMessage>(1000);

        info!(addr = %self.config.listen_addr, "Starting caint node");
        info!(
            identity = %crate::utils::hex_encode(&self.identity.x25519_public_bytes()),
            "Node identity"
        );

        // Start relay listener
        let relay_key = Arc::new(StaticSecret::random_from_rng(rand::rngs::OsRng));
        let listen_addr = self.config.listen_addr.clone();
        let replay_cache = Arc::clone(&self.replay_cache);
        let conn_pool = Arc::clone(&self.connection_pool);
        let delivery_tx_relay = delivery_tx.clone();
        let prekey_store = Arc::clone(&self.prekey_store);
        let address_registry = Arc::clone(&self.address_registry);

        tokio::spawn(async move {
            if let Err(e) = run_relay(
                &listen_addr,
                relay_key,
                replay_cache,
                conn_pool,
                delivery_tx_relay,
                prekey_store,
                address_registry,
            )
            .await
            {
                error!(error = %e, "Relay listener failed");
            }
        });

        // Start epoch loop
        let flusher = Arc::clone(&self.epoch_flusher);
        let conn_pool = Arc::clone(&self.connection_pool);
        let interval = Duration::from_millis(self.config.epoch_interval_ms);
        let self_node = Arc::new(self.self_node_info());
        let avail_relays = Arc::clone(&self.available_relays);

        tokio::spawn(async move {
            run_epoch_loop(flusher, conn_pool, interval, self_node, avail_relays).await;
        });

        // Connect to bootstrap peers and announce ourselves
        for peer_addr in &self.config.bootstrap_peers {
            let announce = WireMessage::new(MessageType::PeerAnnounce, self.build_announce());
            match self.connection_pool.send_to(peer_addr, &announce).await {
                Ok(()) => info!(peer = %peer_addr, "Announced to peer"),
                Err(e) => warn!(peer = %peer_addr, error = %e, "Failed to announce"),
            }
        }

        // Print usage
        info!("Node ready. Type a message and press Enter to send.");
        println!("---");
        println!("Commands:");
        println!("  /peers         List known peers");
        println!("  /quit          Shutdown");
        println!("  <text>         Send message to first known peer");
        println!("---");

        // Stdin reader
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut line_buf = String::new();

        // Clone what we need for the message handler
        let _identity = Arc::clone(&self.identity);
        let _spk = Arc::clone(&self.spk);
        let network = Arc::clone(&self.network);
        let _connection_pool = Arc::clone(&self.connection_pool);
        let _storage = Arc::clone(&self.storage);
        let _address_registry_clone = Arc::clone(&self.address_registry);

        loop {
            tokio::select! {
                // Handle delivered messages
                Some(msg) = delivery_rx.recv() => {
                    self.handle_incoming_message(msg).await;
                }

                // Handle stdin input
                result = reader.read_line(&mut line_buf) => {
                    match result {
                        Ok(0) => {
                            // EOF on stdin — if running non-interactively, just
                            // keep the node alive as a relay/listener.
                            // Switch to a mode that only handles deliveries + signals.
                            info!("stdin closed, running as background node");
                            loop {
                                tokio::select! {
                                    Some(msg) = delivery_rx.recv() => {
                                        self.handle_incoming_message(msg).await;
                                    }
                                    _ = tokio::signal::ctrl_c() => {
                                        info!("Shutting down...");
                                        return;
                                    }
                                }
                            }
                        }
                        Ok(_) => {
                            let input = line_buf.trim().to_string();
                            line_buf.clear();

                            if input.is_empty() {
                                continue;
                            }

                            match input.as_str() {
                                "/quit" => {
                                    info!("Shutting down...");
                                    break;
                                }
                                "/peers" => {
                                    let net = network.lock().await;
                                    let peers = net.list_peers();
                                    if peers.is_empty() {
                                        println!("[No peers known yet. Connect with --peer <addr>]");
                                    } else {
                                        println!("[Known peers:]");
                                        for p in peers {
                                            let id_short = &crate::utils::hex_encode(&p.peer_id)[..16];
                                            let has_session = if p.ratchet.is_some() { "session" } else { "no session" };
                                            println!("  {}... @ {} ({})", id_short, p.address, has_session);
                                        }
                                    }
                                }
                                text => {
                                    // Send to first peer with a session, or first peer
                                    let send_result = self.send_text_message(text).await;
                                    if let Err(e) = send_result {
                                        println!("[Send failed: {}]", e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "stdin read error");
                            break;
                        }
                    }
                }

                // Handle Ctrl+C
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutting down...");
                    break;
                }
            }
        }

        info!("Shutdown complete");
    }

    /// Handle an incoming delivered message.
    async fn handle_incoming_message(&self, msg: DeliveredMessage) {
        // Handle PeerAnnounce
        if !msg.is_initial {
            if let Some(sender_id) = &msg.sender_id {
                // Check if this is a peer announce (try to decode)
                if let Some((ed, x, spk_pub, spk_id, spk_sig, addr)) =
                    decode_peer_announce(&msg.payload)
                {
                    self.handle_peer_announce(ed, x, spk_pub, spk_id, spk_sig, &addr)
                        .await;
                    return;
                }

                // It's a direct message frame
                self.handle_direct_frame(sender_id, &msg.payload).await;
                return;
            }
        }

        // Handle initial message (X3DH session setup)
        if msg.is_initial {
            self.handle_initial_message(&msg.payload).await;
            return;
        }

        // Unknown payload
        if let Ok(text) = String::from_utf8(msg.payload.clone()) {
            println!("\n>> {}", text);
        }
    }

    /// Handle a PeerAnnounce: add peer to network, establish session, announce back.
    async fn handle_peer_announce(
        &self,
        ed_bytes: [u8; 32],
        x_bytes: [u8; 32],
        spk_pub_bytes: [u8; 32],
        _spk_id: u32,
        _spk_sig_bytes: [u8; 64],
        addr: &str,
    ) {
        // Skip if this is our own announcement
        if x_bytes == self.identity.x25519_public_bytes() {
            return;
        }

        let ed_key = match ed25519_dalek::VerifyingKey::from_bytes(&ed_bytes) {
            Ok(k) => k,
            Err(_) => {
                warn!("Invalid Ed25519 key in peer announce");
                return;
            }
        };
        let x_key = x25519_dalek::PublicKey::from(x_bytes);
        let _spk_pub = x25519_dalek::PublicKey::from(spk_pub_bytes);

        let peer_id: PeerId = x_bytes;
        let short_id = &crate::utils::hex_encode(&peer_id)[..16];

        // Add to network
        let mut net = self.network.lock().await;
        let already_known = net.get_peer(&peer_id).is_some();

        if !already_known {
            let _peer = Peer::new(ed_key, x_key, addr.to_string());

            // Deterministic role assignment: higher X25519 public key is initiator
            let we_are_initiator = self.identity.x25519_public_bytes() > x_bytes;

            net.add_peer(ed_key, x_key, addr.to_string());
            if let Some(p) = net.get_peer_mut(&peer_id) {
                // Symmetric DH: both sides compute DH(my_identity_priv, peer_identity_pub)
                // X25519 DH is commutative: DH(a, B) == DH(b, A)
                let sk = self.identity.x25519_dh(&x_key);
                debug!(
                    sk = %crate::utils::hex_encode(&sk[..8]),
                    is_alice = we_are_initiator,
                    "Session established"
                );
                p.ratchet = Some(Ratchet::init_symmetric(sk, we_are_initiator));
            }

            drop(net);

            // Register in address registry
            {
                let mut reg = self.address_registry.lock().await;
                reg.register(&crate::utils::hex_encode(&x_bytes), addr);
            }

            // Add to available relays
            {
                let mut relays = self.available_relays.lock().await;
                relays.push(NodeInfo {
                    id: x_bytes,
                    public_key: x_key,
                    address: addr.to_string(),
                });
            }

            println!("[Peer discovered: {}... @ {}]", short_id, addr);

            // Announce ourselves back
            let announce = WireMessage::new(MessageType::PeerAnnounce, self.build_announce());
            if let Err(e) = self.connection_pool.send_to(addr, &announce).await {
                warn!(error = %e, "Failed to announce back to peer");
            }
        }
    }

    /// Handle a direct encrypted message from a known peer.
    ///
    /// The payload format (after sender_id is stripped) is:
    ///   header_bytes(40) || ciphertext(variable)
    async fn handle_direct_frame(&self, sender_id: &[u8; 32], payload: &[u8]) {
        if payload.len() < 41 {
            warn!(size = payload.len(), "Direct message too short");
            return;
        }

        let mut net = self.network.lock().await;
        let peer = match net.get_peer_mut(sender_id) {
            Some(p) => p,
            None => {
                let short = &crate::utils::hex_encode(sender_id)[..16];
                warn!(sender = %short, "Message from unknown peer");
                return;
            }
        };

        let ratchet = match peer.ratchet.as_mut() {
            Some(r) => r,
            None => {
                warn!("No session with sender, cannot decrypt");
                return;
            }
        };

        let mut header_bytes = [0u8; 40];
        header_bytes.copy_from_slice(&payload[..40]);
        let header = crate::keys::ratchet::RatchetHeader::from_bytes(&header_bytes);
        let ciphertext = &payload[40..];

        // AD = sorted(ed25519_pub_a, ed25519_pub_b) — same order both sides
        let my_ed = self.identity.ed25519_public_bytes();
        let peer_ed = peer.identity_ed.to_bytes();
        let ad = compute_sorted_ad(&my_ed, &peer_ed);

        match ratchet.decrypt(&header, ciphertext, &ad) {
            Ok(plaintext) => {
                let short = &crate::utils::hex_encode(sender_id)[..16];
                match String::from_utf8(plaintext.clone()) {
                    Ok(text) => {
                        println!("\n[{}...]: {}", short, text);
                    }
                    Err(_) => {
                        println!("\n[{}...]: [binary, {} bytes]", short, plaintext.len());
                    }
                }
                // Persist
                let _ = self.storage.append_message(sender_id, &plaintext);
            }
            Err(e) => {
                warn!(error = %e, "Failed to decrypt direct message");
            }
        }
    }

    /// Handle an X3DH InitialMessage for session setup.
    async fn handle_initial_message(&self, _payload: &[u8]) {
        // For the MVP, sessions are established via PeerAnnounce + DH with SPK.
        // Full X3DH over the wire would require serializing InitialMessage and
        // doing the proper 4-DH. This is a TODO for the next iteration.
        info!("Received initial message (session setup via announce)");
    }

    /// Send a text message to the first known peer.
    async fn send_text_message(&self, text: &str) -> Result<(), String> {
        let mut net = self.network.lock().await;
        let peers: Vec<PeerId> = net.list_peers().iter().map(|p| p.peer_id).collect();

        if peers.is_empty() {
            return Err("No peers known. Connect with --peer <addr>".to_string());
        }

        // Find first peer with a session
        let target_id = peers[0];
        let peer = net
            .get_peer_mut(&target_id)
            .ok_or("Peer disappeared".to_string())?;

        let ratchet = peer
            .ratchet
            .as_mut()
            .ok_or("No session with peer".to_string())?;

        let peer_addr = peer.address.clone();
        let peer_ed = peer.identity_ed.to_bytes();

        // AD = sorted(ed25519_pub_a, ed25519_pub_b) — deterministic regardless of who sends
        let my_ed = self.identity.ed25519_public_bytes();
        let ad = compute_sorted_ad(&my_ed, &peer_ed);

        let (header, ciphertext) = ratchet.encrypt(text.as_bytes(), &ad);

        drop(net); // release lock before network I/O

        // Build wire message: sender_id(32) || header(40) || ciphertext
        let mut payload = Vec::with_capacity(32 + 40 + ciphertext.len());
        payload.extend_from_slice(&self.identity.x25519_public_bytes());
        payload.extend_from_slice(&header.to_bytes());
        payload.extend_from_slice(&ciphertext);

        let wire_msg = WireMessage::new(MessageType::DirectMessage, payload);
        self.connection_pool
            .send_to(&peer_addr, &wire_msg)
            .await
            .map_err(|e| format!("Send failed: {}", e))?;

        // Persist
        let _ = self.storage.append_message(&target_id, text.as_bytes());

        let short = &crate::utils::hex_encode(&target_id)[..16];
        println!("[sent to {}...]", short);

        Ok(())
    }

    /// Get the node's public identity as hex string.
    pub fn identity_hex(&self) -> String {
        crate::utils::hex_encode(&self.identity.x25519_public_bytes())
    }

    /// Get the node's Ed25519 public key as hex string.
    pub fn identity_ed_hex(&self) -> String {
        crate::utils::hex_encode(&self.identity.ed25519_public_bytes())
    }
}

/// Compute deterministic AD from two Ed25519 public keys.
/// Always sorted so both sides produce the same bytes.
fn compute_sorted_ad(a: &[u8; 32], b: &[u8; 32]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(64);
    if a <= b {
        ad.extend_from_slice(a);
        ad.extend_from_slice(b);
    } else {
        ad.extend_from_slice(b);
        ad.extend_from_slice(a);
    }
    ad
}
