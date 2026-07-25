use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::transport::wire::{WireError, WireMessage};

/// Noise protocol pattern for all connections.
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Max Noise message size (65535 per spec, but we cap lower).
const NOISE_MAX_MSG: usize = 65535;

/// A Noise-encrypted TCP connection.
struct NoiseConnection {
    stream: TcpStream,
    transport: snow::TransportState,
}

/// Perform Noise XX handshake as initiator over a TCP stream.
async fn noise_handshake_initiator(
    stream: &mut TcpStream,
    local_private_key: &[u8; 32],
) -> Result<snow::TransportState, WireError> {
    let builder = snow::Builder::new(
        NOISE_PATTERN
            .parse()
            .expect("Noise pattern is a compile-time constant"),
    )
    .local_private_key(local_private_key)
    .map_err(|e| {
        WireError::Io(std::io::Error::other(
            e.to_string(),
        ))
    })?;

    let mut handshake = builder.build_initiator().map_err(|e| {
        WireError::Io(std::io::Error::other(
            e.to_string(),
        ))
    })?;

    let mut buf = [0u8; NOISE_MAX_MSG];
    let mut read_buf = [0u8; NOISE_MAX_MSG];

    // -> e
    let len = handshake.write_message(&[], &mut buf).map_err(|e| {
        WireError::Io(std::io::Error::other(
            e.to_string(),
        ))
    })?;
    stream.write_u16(len as u16).await?;
    stream.write_all(&buf[..len]).await?;
    stream.flush().await?;

    // <- e, ee, s, es
    let msg_len = stream.read_u16().await? as usize;
    stream.read_exact(&mut read_buf[..msg_len]).await?;
    handshake
        .read_message(&read_buf[..msg_len], &mut buf)
        .map_err(|e| {
            WireError::Io(std::io::Error::other(
                e.to_string(),
            ))
        })?;

    // -> s, se
    let len = handshake.write_message(&[], &mut buf).map_err(|e| {
        WireError::Io(std::io::Error::other(
            e.to_string(),
        ))
    })?;
    stream.write_u16(len as u16).await?;
    stream.write_all(&buf[..len]).await?;
    stream.flush().await?;

    handshake.into_transport_mode().map_err(|e| {
        WireError::Io(std::io::Error::other(
            e.to_string(),
        ))
    })
}

/// Perform Noise XX handshake as responder over a TCP stream.
pub async fn noise_handshake_responder(
    stream: &mut TcpStream,
    local_private_key: &[u8; 32],
) -> Result<snow::TransportState, WireError> {
    let builder = snow::Builder::new(
        NOISE_PATTERN
            .parse()
            .expect("Noise pattern is a compile-time constant"),
    )
    .local_private_key(local_private_key)
    .map_err(|e| {
        WireError::Io(std::io::Error::other(
            e.to_string(),
        ))
    })?;

    let mut handshake = builder.build_responder().map_err(|e| {
        WireError::Io(std::io::Error::other(
            e.to_string(),
        ))
    })?;

    let mut buf = [0u8; NOISE_MAX_MSG];
    let mut read_buf = [0u8; NOISE_MAX_MSG];

    // <- e
    let msg_len = stream.read_u16().await? as usize;
    stream.read_exact(&mut read_buf[..msg_len]).await?;
    handshake
        .read_message(&read_buf[..msg_len], &mut buf)
        .map_err(|e| {
            WireError::Io(std::io::Error::other(
                e.to_string(),
            ))
        })?;

    // -> e, ee, s, es
    let len = handshake.write_message(&[], &mut buf).map_err(|e| {
        WireError::Io(std::io::Error::other(
            e.to_string(),
        ))
    })?;
    stream.write_u16(len as u16).await?;
    stream.write_all(&buf[..len]).await?;
    stream.flush().await?;

    // <- s, se
    let msg_len = stream.read_u16().await? as usize;
    stream.read_exact(&mut read_buf[..msg_len]).await?;
    handshake
        .read_message(&read_buf[..msg_len], &mut buf)
        .map_err(|e| {
            WireError::Io(std::io::Error::other(
                e.to_string(),
            ))
        })?;

    handshake.into_transport_mode().map_err(|e| {
        WireError::Io(std::io::Error::other(
            e.to_string(),
        ))
    })
}

/// Send a wire message through a Noise transport over TCP.
/// Format: length(2 BE) || noise_ciphertext
async fn noise_send(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    msg: &WireMessage,
) -> Result<(), WireError> {
    // Serialize the wire message to bytes
    let mut plaintext = Vec::new();
    msg.write_to(&mut plaintext).await?;

    let mut ciphertext = vec![0u8; plaintext.len() + 16]; // AEAD tag overhead
    let len = transport
        .write_message(&plaintext, &mut ciphertext)
        .map_err(|e| {
            WireError::Io(std::io::Error::other(
                e.to_string(),
            ))
        })?;

    stream.write_u16(len as u16).await?;
    stream.write_all(&ciphertext[..len]).await?;
    stream.flush().await?;
    Ok(())
}

/// Receive a wire message through a Noise transport over TCP.
pub async fn noise_recv(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
) -> Result<WireMessage, WireError> {
    let msg_len = stream.read_u16().await? as usize;
    if msg_len == 0 {
        return Err(WireError::UnexpectedEof);
    }
    let mut ciphertext = vec![0u8; msg_len];
    stream.read_exact(&mut ciphertext).await?;

    let mut plaintext = vec![0u8; msg_len];
    let len = transport
        .read_message(&ciphertext, &mut plaintext)
        .map_err(|e| {
            WireError::Io(std::io::Error::other(
                e.to_string(),
            ))
        })?;

    // Parse the decrypted bytes as a WireMessage
    let mut cursor = std::io::Cursor::new(&plaintext[..len]);
    WireMessage::read_from(&mut cursor).await
}

/// Connection pool with Noise transport encryption.
pub struct ConnectionPool {
    connections: Arc<Mutex<HashMap<String, NoiseConnection>>>,
    local_private_key: [u8; 32],
}

impl ConnectionPool {
    pub fn new(local_private_key: [u8; 32]) -> Self {
        ConnectionPool {
            connections: Arc::new(Mutex::new(HashMap::new())),
            local_private_key,
        }
    }

    /// Send a wire message over a Noise-encrypted connection.
    pub async fn send_to(&self, addr: &str, msg: &WireMessage) -> Result<(), WireError> {
        let mut conns = self.connections.lock().await;

        if let Some(nc) = conns.get_mut(addr) {
            match noise_send(&mut nc.stream, &mut nc.transport, msg).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(error = %e, "Noise connection failed, reconnecting");
                    conns.remove(addr);
                }
            }
        }

        debug!("Opening Noise-encrypted connection");
        let mut stream = TcpStream::connect(addr).await?;
        let mut transport = noise_handshake_initiator(&mut stream, &self.local_private_key).await?;

        noise_send(&mut stream, &mut transport, msg).await?;
        conns.insert(addr.to_string(), NoiseConnection { stream, transport });
        Ok(())
    }

    pub async fn remove(&self, addr: &str) {
        let mut conns = self.connections.lock().await;
        conns.remove(addr);
    }

    pub async fn connection_count(&self) -> usize {
        self.connections.lock().await.len()
    }
}
