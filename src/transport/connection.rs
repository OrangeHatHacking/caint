use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::transport::wire::{WireError, WireMessage};

/// A managed TCP connection to a remote node.
pub struct Connection {
    stream: TcpStream,
    remote_addr: String,
}

impl Connection {
    /// Connect to a remote address.
    pub async fn connect(addr: &str) -> Result<Self, WireError> {
        debug!(addr = addr, "Connecting to peer");
        let stream = TcpStream::connect(addr).await?;
        Ok(Connection {
            stream,
            remote_addr: addr.to_string(),
        })
    }

    /// Send a wire message.
    pub async fn send(&mut self, msg: &WireMessage) -> Result<(), WireError> {
        msg.write_to(&mut self.stream).await
    }

    /// Receive a wire message.
    pub async fn recv(&mut self) -> Result<WireMessage, WireError> {
        WireMessage::read_from(&mut self.stream).await
    }

    /// Get the remote address.
    pub fn remote_addr(&self) -> &str {
        &self.remote_addr
    }

    /// Split into owned read/write halves for concurrent use.
    pub fn into_split(
        self,
    ) -> (
        tokio::net::tcp::OwnedReadHalf,
        tokio::net::tcp::OwnedWriteHalf,
    ) {
        self.stream.into_split()
    }
}

/// Connection pool managing persistent connections to peers.
///
/// Thread-safe via Arc<Mutex<>> for use across async tasks.
pub struct ConnectionPool {
    connections: Arc<Mutex<HashMap<String, TcpStream>>>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        ConnectionPool {
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Send a wire message to the given address.
    /// Lazily connects if no existing connection, reconnects on failure.
    pub async fn send_to(&self, addr: &str, msg: &WireMessage) -> Result<(), WireError> {
        let mut conns = self.connections.lock().await;

        // Try existing connection first
        if let Some(stream) = conns.get_mut(addr) {
            match msg.write_to(stream).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(addr = addr, error = %e, "Connection failed, reconnecting");
                    conns.remove(addr);
                }
            }
        }

        // Connect fresh
        debug!(addr = addr, "Opening new connection");
        let mut stream = TcpStream::connect(addr).await?;
        msg.write_to(&mut stream).await?;
        conns.insert(addr.to_string(), stream);
        Ok(())
    }

    /// Remove a connection (e.g., on error).
    pub async fn remove(&self, addr: &str) {
        let mut conns = self.connections.lock().await;
        conns.remove(addr);
    }

    /// Number of active connections.
    pub async fn connection_count(&self) -> usize {
        self.connections.lock().await.len()
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}
