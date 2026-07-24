//! Route selection and Sphinx routing block construction.

use rand::{rngs::OsRng, seq::SliceRandom, Rng};
use x25519_dalek::PublicKey;

use crate::transport::SphinxError;

/// Per-hop routing block size in bytes.
pub const ROUTING_BLOCK_SIZE: usize = 57;

/// Maximum number of hops.
pub const MAX_HOPS: usize = 5;

/// Total routing info size (always sized for MAX_HOPS).
pub const ROUTING_INFO_SIZE: usize = ROUTING_BLOCK_SIZE * MAX_HOPS; // 285 bytes

/// Information about a relay node.
#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub id: [u8; 32],
    pub public_key: PublicKey,
    pub address: String,
}

/// A single routing block for one hop (57 bytes).
#[derive(Clone, Debug)]
pub struct RoutingBlock {
    /// 0x00 = forward, 0x01 = final destination
    pub flag: u8,
    /// Next hop node identifier (or final destination)
    pub next_hop: [u8; 32],
    /// Mix delay in microseconds (reserved for future use)
    pub delay: u64,
    /// MAC for the next layer
    pub mac: [u8; 16],
}

impl RoutingBlock {
    /// Serialize to 57 bytes.
    pub fn to_bytes(&self) -> [u8; ROUTING_BLOCK_SIZE] {
        let mut out = [0u8; ROUTING_BLOCK_SIZE];
        out[0] = self.flag;
        out[1..33].copy_from_slice(&self.next_hop);
        out[33..41].copy_from_slice(&self.delay.to_be_bytes());
        out[41..57].copy_from_slice(&self.mac);
        out
    }

    /// Deserialize from 57 bytes.
    pub fn from_bytes(data: &[u8; ROUTING_BLOCK_SIZE]) -> Self {
        let flag = data[0];
        let mut next_hop = [0u8; 32];
        next_hop.copy_from_slice(&data[1..33]);
        let delay = u64::from_be_bytes([
            data[33], data[34], data[35], data[36], data[37], data[38], data[39], data[40],
        ]);
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&data[41..57]);
        RoutingBlock {
            flag,
            next_hop,
            delay,
            mac,
        }
    }
}

/// Select a random route of 3, 4, or 5 hops from available relay nodes.
///
/// Excludes the sender and destination from the route.
/// Returns an error if fewer than 3 relay nodes are available.
pub fn select_route(
    available_relays: &[NodeInfo],
    destination: &NodeInfo,
) -> Result<Vec<NodeInfo>, SphinxError> {
    // Filter out destination from available relays
    let relays: Vec<&NodeInfo> = available_relays
        .iter()
        .filter(|n| n.id != destination.id)
        .collect();

    if relays.len() < 3 {
        return Err(SphinxError::InvalidRouteLength);
    }

    // Randomly select 3, 4, or 5 hops
    let max_hops = relays.len().min(5);
    let min_hops = 3;
    let num_hops = OsRng.gen_range(min_hops..=max_hops);

    let mut selected: Vec<NodeInfo> = relays
        .choose_multiple(&mut OsRng, num_hops)
        .cloned()
        .cloned()
        .collect();

    // Append destination as final hop
    selected.push(destination.clone());

    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    fn make_node(id_byte: u8) -> NodeInfo {
        let secret = StaticSecret::from([id_byte; 32]);
        NodeInfo {
            id: [id_byte; 32],
            public_key: PublicKey::from(&secret),
            address: format!("node_{}", id_byte),
        }
    }

    #[test]
    fn test_select_route_returns_valid_length() {
        let relays: Vec<NodeInfo> = (1..=10).map(|i| make_node(i)).collect();
        let dest = make_node(99);
        let route = select_route(&relays, &dest).unwrap();
        // 3-5 relay hops + 1 destination
        assert!(route.len() >= 4 && route.len() <= 6);
        // Last hop is destination
        assert_eq!(route.last().unwrap().id, dest.id);
    }

    #[test]
    fn test_select_route_fails_with_too_few_relays() {
        let relays = vec![make_node(1), make_node(2)];
        let dest = make_node(99);
        let result = select_route(&relays, &dest);
        assert!(matches!(result, Err(SphinxError::InvalidRouteLength)));
    }

    #[test]
    fn test_routing_block_serialization() {
        let block = RoutingBlock {
            flag: 0x01,
            next_hop: [42u8; 32],
            delay: 12345,
            mac: [0xAB; 16],
        };
        let bytes = block.to_bytes();
        assert_eq!(bytes.len(), ROUTING_BLOCK_SIZE);
        let restored = RoutingBlock::from_bytes(&bytes);
        assert_eq!(restored.flag, 0x01);
        assert_eq!(restored.next_hop, [42u8; 32]);
        assert_eq!(restored.delay, 12345);
        assert_eq!(restored.mac, [0xAB; 16]);
    }

    #[test]
    fn test_select_route_excludes_destination() {
        let relays: Vec<NodeInfo> = (1..=5).map(|i| make_node(i)).collect();
        let dest = make_node(3); // destination is also in relay list
        let route = select_route(&relays, &dest).unwrap();
        // Intermediate hops should not include destination
        for hop in &route[..route.len() - 1] {
            assert_ne!(hop.id, dest.id);
        }
    }
}
