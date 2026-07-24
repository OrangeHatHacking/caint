use std::path::PathBuf;

/// Application configuration.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Address to listen on (e.g., "0.0.0.0:9000")
    pub listen_addr: String,
    /// Path for encrypted storage
    pub storage_path: PathBuf,
    /// Epoch interval in milliseconds
    pub epoch_interval_ms: u64,
    /// Target packets per epoch (padded with dummies)
    pub target_packet_count: usize,
    /// Replay cache TTL in seconds
    pub replay_ttl_secs: u64,
    /// Bootstrap peer addresses
    pub bootstrap_peers: Vec<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            listen_addr: "0.0.0.0:9000".to_string(),
            storage_path: PathBuf::from("./caint_data"),
            epoch_interval_ms: 1000,
            target_packet_count: 10,
            replay_ttl_secs: 3600,
            bootstrap_peers: Vec::new(),
        }
    }
}
