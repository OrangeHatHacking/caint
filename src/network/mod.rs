pub mod peers;

pub use peers::{Network, Peer, PeerId};

use std::fmt;

#[derive(Debug)]
pub enum NetworkError {
    PeerNotFound,
    SessionNotInitialized,
    TransportError(String),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::PeerNotFound => write!(f, "Peer not found in table"),
            NetworkError::SessionNotInitialized => write!(f, "No active session with peer"),
            NetworkError::TransportError(e) => write!(f, "Transport error: {}", e),
        }
    }
}

impl std::error::Error for NetworkError {}
