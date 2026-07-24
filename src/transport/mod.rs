pub mod blinding;
pub mod connection;
pub mod epoch;
pub mod filler;
pub mod prekey_relay;
pub mod relay;
pub mod routing;
pub mod sphinx;
pub mod wire;

pub use connection::{Connection, ConnectionPool};
pub use epoch::EpochFlusher;
pub use prekey_relay::PreKeyStore;
pub use relay::{AddressRegistry, DeliveredMessage};
pub use routing::{NodeInfo, RoutingBlock};
pub use sphinx::{
    is_cover_payload, ProcessResult, ReplayCache, SphinxPacket, DUMMY_MARKER, SPHINX_PACKET_SIZE,
};
pub use wire::{MessageType, WireError, WireMessage};

use std::fmt;

#[derive(Debug)]
pub enum SphinxError {
    InvalidRouteLength,
    ReplayDetected,
    ProcessingFailed,
}

impl fmt::Display for SphinxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SphinxError::InvalidRouteLength => write!(f, "Route must have 3-5 hops"),
            SphinxError::ReplayDetected => write!(f, "Replay attack detected"),
            SphinxError::ProcessingFailed => write!(f, "Sphinx packet processing failed"),
        }
    }
}

impl std::error::Error for SphinxError {}
