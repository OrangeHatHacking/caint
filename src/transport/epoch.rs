//! Epoch-based batch transmission with constant-rate cover traffic.
//!
//! Each epoch, the flusher drains real queued packets, generates cover
//! (loop) Sphinx packets to pad up to the target count, shuffles the
//! combined batch, and transmits. Cover packets are fully valid Sphinx
//! packets routed through the mixnet back to the sender, indistinguishable
//! from real packets at every intermediate relay.

use std::sync::Arc;
use std::time::Duration;

use rand::{rngs::OsRng, seq::SliceRandom};
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

use crate::transport::connection::ConnectionPool;
use crate::transport::routing::{select_route, NodeInfo};
use crate::transport::sphinx::SphinxPacket;
use crate::transport::wire::WireMessage;

/// Default number of packets to transmit per epoch.
pub const DEFAULT_TARGET_PACKET_COUNT: usize = 10;

/// A queued packet with its first-hop destination address.
pub struct QueuedPacket {
    pub packet: SphinxPacket,
    pub first_hop_addr: String,
}

/// Epoch flusher: buffers outgoing packets, generates loop cover traffic,
/// and transmits in constant-rate batches.
pub struct EpochFlusher {
    outgoing_queue: Vec<QueuedPacket>,
    target_count: usize,
}

impl Default for EpochFlusher {
    fn default() -> Self {
        Self::new(DEFAULT_TARGET_PACKET_COUNT)
    }
}

impl EpochFlusher {
    /// Create a new EpochFlusher with the given target packet count per epoch.
    pub fn new(target_count: usize) -> Self {
        EpochFlusher {
            outgoing_queue: Vec::new(),
            target_count,
        }
    }

    /// Enqueue a real Sphinx packet with its first-hop relay address.
    pub fn enqueue(&mut self, packet: SphinxPacket, first_hop_addr: String) {
        self.outgoing_queue.push(QueuedPacket {
            packet,
            first_hop_addr,
        });
    }

    /// Number of real packets currently queued.
    pub fn queue_len(&self) -> usize {
        self.outgoing_queue.len()
    }

    /// Target packet count per epoch.
    pub fn target_count(&self) -> usize {
        self.target_count
    }

    /// Flush the epoch: drain real packets, generate loop cover packets
    /// to reach the target count, shuffle all packets, and return.
    ///
    /// `self_node` is this node's own NodeInfo (for loop routing).
    /// `available_relays` are the known relay nodes for route selection.
    ///
    /// If fewer than 3 relays are available, no cover packets are generated
    /// (only real packets are returned).
    pub fn flush_with_cover(
        &mut self,
        self_node: &NodeInfo,
        available_relays: &[NodeInfo],
    ) -> Vec<QueuedPacket> {
        let mut batch: Vec<QueuedPacket> = self.outgoing_queue.drain(..).collect();
        let real_count = batch.len();

        // Generate cover packets to reach target count
        let cover_needed = self.target_count.saturating_sub(batch.len());
        let mut cover_generated = 0;

        for _ in 0..cover_needed {
            // Select a loop route: relays -> self_node as destination
            match select_route(available_relays, self_node) {
                Ok(route) => {
                    match SphinxPacket::create_cover_packet(&route) {
                        Ok(cover_pkt) => {
                            // First hop is route[0]
                            let first_hop_addr = route[0].address.clone();
                            batch.push(QueuedPacket {
                                packet: cover_pkt,
                                first_hop_addr,
                            });
                            cover_generated += 1;
                        }
                        Err(e) => {
                            trace!(error = %e, "Failed to create cover packet");
                            break;
                        }
                    }
                }
                Err(_) => {
                    // Not enough relays for cover traffic
                    trace!("Insufficient relays for cover traffic");
                    break;
                }
            }
        }

        // Shuffle all packets (real + cover) so order leaks nothing
        batch.shuffle(&mut OsRng);

        debug!(
            real = real_count,
            cover = cover_generated,
            total = batch.len(),
            target = self.target_count,
            "Epoch flush"
        );

        batch
    }

    /// Flush without cover traffic (for backward compatibility or when
    /// no relay info is available).
    pub fn flush(&mut self) -> Vec<QueuedPacket> {
        let mut batch: Vec<QueuedPacket> = self.outgoing_queue.drain(..).collect();
        batch.shuffle(&mut OsRng);
        batch
    }
}

/// Run the epoch transmission loop with cover traffic.
///
/// Every `interval`, flushes the epoch flusher (padding with loop cover
/// packets), and sends each packet to its first-hop relay.
pub async fn run_epoch_loop(
    flusher: Arc<Mutex<EpochFlusher>>,
    connection_pool: Arc<ConnectionPool>,
    interval: Duration,
    self_node: Arc<NodeInfo>,
    available_relays: Arc<Mutex<Vec<NodeInfo>>>,
) {
    let mut ticker = tokio::time::interval(interval);

    loop {
        ticker.tick().await;

        let batch = {
            let relays = available_relays.lock().await;
            let mut f = flusher.lock().await;
            f.flush_with_cover(&self_node, &relays)
        };

        if batch.is_empty() {
            continue;
        }

        debug!(count = batch.len(), "Sending epoch batch");

        for queued in &batch {
            let wire_msg = WireMessage::sphinx_data(&queued.packet.data);
            if let Err(e) = connection_pool
                .send_to(&queued.first_hop_addr, &wire_msg)
                .await
            {
                warn!(
                    target_addr = %queued.first_hop_addr,
                    error = %e,
                    "Failed to send packet"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::sphinx::SphinxPacket;
    use crate::transport::SPHINX_PACKET_SIZE;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn make_node(id_byte: u8) -> NodeInfo {
        let secret = StaticSecret::from([id_byte; 32]);
        NodeInfo {
            id: [id_byte; 32],
            public_key: PublicKey::from(&secret),
            address: format!("relay_{}:9000", id_byte),
        }
    }

    #[test]
    fn test_flush_with_cover_pads_to_target() {
        let mut flusher = EpochFlusher::new(5);
        // Enqueue 2 real packets (using dummy() for convenience - they have addresses)
        flusher.enqueue(SphinxPacket::dummy(), "addr1:9000".into());
        flusher.enqueue(SphinxPacket::dummy(), "addr2:9000".into());

        let self_node = make_node(99);
        let relays: Vec<NodeInfo> = (1..=10).map(|i| make_node(i)).collect();

        let batch = flusher.flush_with_cover(&self_node, &relays);
        // Should have 5 total: 2 real + 3 cover
        assert_eq!(batch.len(), 5);
    }

    #[test]
    fn test_flush_with_cover_all_correct_size() {
        let mut flusher = EpochFlusher::new(4);
        let self_node = make_node(99);
        let relays: Vec<NodeInfo> = (1..=10).map(|i| make_node(i)).collect();

        let batch = flusher.flush_with_cover(&self_node, &relays);
        assert_eq!(batch.len(), 4);
        for qp in &batch {
            assert_eq!(qp.packet.data.len(), SPHINX_PACKET_SIZE);
        }
    }

    #[test]
    fn test_flush_with_cover_all_have_addresses() {
        let mut flusher = EpochFlusher::new(3);
        let self_node = make_node(99);
        let relays: Vec<NodeInfo> = (1..=10).map(|i| make_node(i)).collect();

        let batch = flusher.flush_with_cover(&self_node, &relays);
        for qp in &batch {
            assert!(
                !qp.first_hop_addr.is_empty(),
                "Every packet must have a first-hop address"
            );
        }
    }

    #[test]
    fn test_flush_with_cover_no_relays_skips_cover() {
        let mut flusher = EpochFlusher::new(5);
        flusher.enqueue(SphinxPacket::dummy(), "addr1:9000".into());

        let self_node = make_node(99);
        let relays: Vec<NodeInfo> = vec![make_node(1), make_node(2)]; // only 2 relays

        let batch = flusher.flush_with_cover(&self_node, &relays);
        // Only 1 real packet, no cover (insufficient relays)
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn test_flush_with_cover_empties_queue() {
        let mut flusher = EpochFlusher::new(3);
        flusher.enqueue(SphinxPacket::dummy(), "addr:9000".into());
        let self_node = make_node(99);
        let relays: Vec<NodeInfo> = (1..=5).map(|i| make_node(i)).collect();

        flusher.flush_with_cover(&self_node, &relays);
        assert_eq!(flusher.queue_len(), 0);
    }

    #[test]
    fn test_flush_with_cover_empty_queue_generates_all_cover() {
        let mut flusher = EpochFlusher::new(4);
        let self_node = make_node(99);
        let relays: Vec<NodeInfo> = (1..=10).map(|i| make_node(i)).collect();

        let batch = flusher.flush_with_cover(&self_node, &relays);
        assert_eq!(batch.len(), 4); // all cover
    }

    #[test]
    fn test_flush_without_cover_backward_compat() {
        let mut flusher = EpochFlusher::new(5);
        flusher.enqueue(SphinxPacket::dummy(), "addr1:9000".into());
        flusher.enqueue(SphinxPacket::dummy(), "addr2:9000".into());

        let batch = flusher.flush();
        assert_eq!(batch.len(), 2); // no padding
    }
}
