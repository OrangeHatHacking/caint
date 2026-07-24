pub mod frame;

pub use frame::{Frame, FRAME_SIZE, MAX_PLAINTEXT_SIZE};

use std::fmt;

#[derive(Debug)]
pub enum FrameError {
    PayloadTooLarge,
    AuthenticationFailed,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::PayloadTooLarge => write!(f, "Payload exceeds maximum frame size"),
            FrameError::AuthenticationFailed => write!(f, "Frame AEAD authentication failed"),
        }
    }
}

impl std::error::Error for FrameError {}
