//! Epoch-based batch transmission with constant-rate padding.

use rand::{rngs::OsRng, seq::SliceRandom};

use crate::transport::sphinx::SphinxPacket;

/// Default number of packets to transmit per epoch.
pub const DEFAULT_TARGET_PACKET_COUNT: usize = 10;

/// Epoch flusher: buffers outgoing packets and pads with dummies.
pub struct EpochFlusher {
    outgoing_queue: Vec<SphinxPacket>,
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

    /// Enqueue a real Sphinx packet for the next epoch flush.
    pub fn enqueue(&mut self, packet: SphinxPacket) {
        self.outgoing_queue.push(packet);
    }

    /// Number of real packets currently queued.
    pub fn queue_len(&self) -> usize {
        self.outgoing_queue.len()
    }

    /// Flush the epoch: drain real packets, pad with dummies to target count,
    /// shuffle all packets, and return the batch.
    ///
    /// Every returned packet is exactly SPHINX_PACKET_SIZE bytes.
    pub fn flush(&mut self) -> Vec<SphinxPacket> {
        let mut batch: Vec<SphinxPacket> = self.outgoing_queue.drain(..).collect();

        // Pad with dummy packets to reach target count
        while batch.len() < self.target_count {
            batch.push(SphinxPacket::dummy());
        }

        // Shuffle using Fisher-Yates with CSPRNG
        batch.shuffle(&mut OsRng);

        batch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::SPHINX_PACKET_SIZE;

    #[test]
    fn test_flush_pads_to_target_count() {
        let mut flusher = EpochFlusher::new(5);
        // Enqueue only 2 real packets
        flusher.enqueue(SphinxPacket::dummy());
        flusher.enqueue(SphinxPacket::dummy());

        let batch = flusher.flush();
        assert_eq!(batch.len(), 5);
    }

    #[test]
    fn test_flush_all_packets_correct_size() {
        let mut flusher = EpochFlusher::new(3);
        flusher.enqueue(SphinxPacket::dummy());
        let batch = flusher.flush();
        for pkt in &batch {
            assert_eq!(pkt.data.len(), SPHINX_PACKET_SIZE);
        }
    }

    #[test]
    fn test_flush_with_more_real_than_target() {
        let mut flusher = EpochFlusher::new(2);
        for _ in 0..5 {
            flusher.enqueue(SphinxPacket::dummy());
        }
        let batch = flusher.flush();
        assert_eq!(batch.len(), 5); // no truncation
    }

    #[test]
    fn test_flush_empties_queue() {
        let mut flusher = EpochFlusher::new(3);
        flusher.enqueue(SphinxPacket::dummy());
        flusher.flush();
        assert_eq!(flusher.queue_len(), 0);
    }

    #[test]
    fn test_flush_empty_queue_produces_all_dummies() {
        let mut flusher = EpochFlusher::new(4);
        let batch = flusher.flush();
        assert_eq!(batch.len(), 4);
        for pkt in &batch {
            assert_eq!(pkt.data.len(), SPHINX_PACKET_SIZE);
        }
    }
}
