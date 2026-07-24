pub mod encrypted;
pub mod master_key;
pub use encrypted::Storage;
pub use master_key::MasterKey;

use std::fmt;

#[derive(Debug)]
pub enum StorageError {
    IoError(std::io::Error),
    DecryptionFailed,
    CorruptedData,
    SerializationError(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::IoError(e) => write!(f, "Storage I/O error: {}", e),
            StorageError::DecryptionFailed => write!(f, "Storage decryption failed"),
            StorageError::CorruptedData => write!(f, "Stored data is corrupted"),
            StorageError::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError::IoError(e)
    }
}
