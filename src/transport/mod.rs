pub mod blinding;
pub mod epoch;
pub mod filler;
pub mod routing;
pub mod sphinx;

pub use epoch::EpochFlusher;
pub use routing::{NodeInfo, RoutingBlock};
pub use sphinx::{ProcessResult, ReplayCache, SphinxPacket, SPHINX_PACKET_SIZE};

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
