//! Integration test for peer table persistence and reconnect after restart.
//!
//! Scenario:
//! 1. Start Node B first (no --peer), let its listener bind
//! 2. Start Node A with --peer pointing to B
//! 3. Announces propagate, both have active sessions
//! 4. Save Node A's peer table, abort Node A
//! 5. Restart Node A with same storage, NEW port, no --peer
//! 6. Node A re-announces to stored peers, session re-established

use caint::app::App;
use caint::config::AppConfig;
use std::path::PathBuf;
use std::time::Duration;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("caint_integ_{}_{}", name, rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_peer_table_survives_restart() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("caint=warn")
        .try_init();

    let dir_a = temp_dir("node_a");
    let dir_b = temp_dir("node_b");
    let port_b = free_port();
    let addr_b = format!("127.0.0.1:{}", port_b);
    let passphrase = "test_passphrase";

    // ── Phase 1: Start Node B first, then Node A ────────────────────────

    let config_b = AppConfig {
        listen_addr: addr_b.clone(),
        storage_path: dir_b.clone(),
        bootstrap_peers: vec![],
        epoch_interval_ms: 60_000,
        ..AppConfig::default()
    };
    let mut app_b = App::new(config_b, passphrase);
    let identity_b = app_b.identity.clone();
    let peer_id_b = identity_b.x25519_public_bytes();
    let handle_b = tokio::spawn(async move { app_b.run().await });

    // Wait for B's relay listener to bind
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Node A: bootstraps to Node B
    let port_a1 = free_port();
    let addr_a1 = format!("127.0.0.1:{}", port_a1);
    let config_a = AppConfig {
        listen_addr: addr_a1.clone(),
        storage_path: dir_a.clone(),
        bootstrap_peers: vec![addr_b.clone()],
        epoch_interval_ms: 60_000,
        ..AppConfig::default()
    };
    let mut app_a = App::new(config_a, passphrase);
    let net_a = app_a.network.clone();
    let storage_a = app_a.storage.clone();
    let handle_a = tokio::spawn(async move { app_a.run().await });

    // Wait for announce exchange
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Verify Node A discovered Node B with session
    {
        let net = net_a.lock().await;
        assert!(
            net.get_peer(&peer_id_b).is_some(),
            "Node A should have discovered Node B"
        );
        assert!(
            net.get_peer(&peer_id_b).unwrap().ratchet.is_some(),
            "Node A should have an active session with Node B"
        );
    }

    // ── Phase 2: Save peer table and kill Node A ────────────────────────

    {
        let net = net_a.lock().await;
        storage_a.save_peer_table(&net).unwrap();
    }

    assert!(dir_a.join("peers.enc").exists(), "peers.enc should exist");

    handle_a.abort();
    let _ = handle_a.await;

    // ── Phase 3: Restart Node A on a NEW port, no --peer ────────────────

    // Use a new port to avoid address-in-use race
    let port_a2 = free_port();
    let addr_a2 = format!("127.0.0.1:{}", port_a2);

    let config_a_restart = AppConfig {
        listen_addr: addr_a2,
        storage_path: dir_a.clone(),
        bootstrap_peers: vec![], // no --peer flag!
        epoch_interval_ms: 60_000,
        ..AppConfig::default()
    };

    let mut app_a2 = App::new(config_a_restart, passphrase);
    let net_a2 = app_a2.network.clone();

    // Verify peer loaded from disk with no session
    {
        let net = net_a2.lock().await;
        assert!(
            net.get_peer(&peer_id_b).is_some(),
            "Node A should have loaded Node B from peers.enc"
        );
        assert!(
            net.get_peer(&peer_id_b).unwrap().ratchet.is_none(),
            "Loaded peer should have ratchet: None"
        );
    }

    let handle_a2 = tokio::spawn(async move { app_a2.run().await });

    // Wait for re-announce and session re-establishment.
    // This needs extra time because both sides do Noise handshakes.
    tokio::time::sleep(Duration::from_millis(3000)).await;

    // Verify session was re-established
    {
        let net = net_a2.lock().await;
        let peer_b = net.get_peer(&peer_id_b).expect("Node B should be in table");
        assert!(
            peer_b.ratchet.is_some(),
            "Session should be re-established after re-announce"
        );
    }

    // ── Cleanup ─────────────────────────────────────────────────────────

    handle_a2.abort();
    handle_b.abort();
    let _ = handle_a2.await;
    let _ = handle_b.await;

    std::fs::remove_dir_all(&dir_a).ok();
    std::fs::remove_dir_all(&dir_b).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_peer_table_loads_empty_on_first_start() {
    let dir = temp_dir("fresh_node");
    let passphrase = "test";

    let config = AppConfig {
        listen_addr: format!("127.0.0.1:{}", free_port()),
        storage_path: dir.clone(),
        bootstrap_peers: vec![],
        epoch_interval_ms: 60_000,
        ..AppConfig::default()
    };

    let app = App::new(config, passphrase);

    {
        let net = app.network.lock().await;
        assert_eq!(net.peer_count(), 0, "Fresh node should have no peers");
    }

    std::fs::remove_dir_all(&dir).ok();
}
