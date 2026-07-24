//! Integration tests for transport module (Sphinx mixnet)

use caint::transport::routing::NodeInfo;
use caint::transport::sphinx::{
    is_cover_payload, ProcessResult, ReplayCache, SphinxPacket, SPHINX_PACKET_SIZE,
};
use std::time::Duration;
use x25519_dalek::{PublicKey, StaticSecret};

fn make_node(id_byte: u8) -> (StaticSecret, NodeInfo) {
    let secret = StaticSecret::from([id_byte; 32]);
    let public = PublicKey::from(&secret);
    let info = NodeInfo {
        id: [id_byte; 32],
        public_key: public,
        address: format!("relay_{}:9000", id_byte),
    };
    (secret, info)
}

#[test]
#[ignore = "Multi-hop Sphinx blinding chain requires scalar field arithmetic without mod-L reduction. Tracked in ROADMAP Milestone 3."]
fn test_cover_loop_end_to_end() {
    // Create 4 nodes: 3 relays + 1 sender (which is also the destination)
    let (relay1_key, relay1_info) = make_node(10);
    let (relay2_key, relay2_info) = make_node(20);
    let (relay3_key, relay3_info) = make_node(30);
    let (sender_key, sender_info) = make_node(99);

    // Route: relay1 -> relay2 -> relay3 -> sender (loop)
    let route = vec![relay1_info, relay2_info, relay3_info, sender_info];

    // Create cover packet
    let pkt = SphinxPacket::create_cover_packet(&route).unwrap();
    assert_eq!(pkt.data.len(), SPHINX_PACKET_SIZE);

    // Process at relay 1
    let mut cache1 = ReplayCache::new(Duration::from_secs(60));
    let result1 = pkt.process(&relay1_key, &mut cache1).unwrap();
    assert_eq!(cache1.len(), 1, "Relay 1 should have 1 replay tag");
    let pkt2 = match result1 {
        ProcessResult::Forward { next_hop, packet } => {
            assert_eq!(next_hop, [20u8; 32], "Next hop should be relay 2");
            assert_eq!(packet.data.len(), SPHINX_PACKET_SIZE);
            packet
        }
        other => panic!(
            "Relay 1: expected Forward, got {:?}",
            std::mem::discriminant(&other)
        ),
    };

    // Process at relay 2
    let mut cache2 = ReplayCache::new(Duration::from_secs(60));
    let result2 = pkt2.process(&relay2_key, &mut cache2).unwrap();
    assert_eq!(cache2.len(), 1, "Relay 2 should have 1 replay tag");
    let pkt3 = match result2 {
        ProcessResult::Forward { next_hop, packet } => {
            assert_eq!(next_hop, [30u8; 32], "Next hop should be relay 3");
            assert_eq!(packet.data.len(), SPHINX_PACKET_SIZE);
            packet
        }
        other => panic!(
            "Relay 2: expected Forward, got {:?}",
            std::mem::discriminant(&other)
        ),
    };

    // Process at relay 3
    let mut cache3 = ReplayCache::new(Duration::from_secs(60));
    let result3 = pkt3.process(&relay3_key, &mut cache3).unwrap();
    assert_eq!(cache3.len(), 1, "Relay 3 should have 1 replay tag");
    let pkt4 = match result3 {
        ProcessResult::Forward { next_hop, packet } => {
            assert_eq!(next_hop, [99u8; 32], "Next hop should be sender (loop)");
            assert_eq!(packet.data.len(), SPHINX_PACKET_SIZE);
            packet
        }
        other => panic!(
            "Relay 3: expected Forward, got {:?}",
            std::mem::discriminant(&other)
        ),
    };

    // Process at sender (final destination)
    let mut cache4 = ReplayCache::new(Duration::from_secs(60));
    let result4 = pkt4.process(&sender_key, &mut cache4).unwrap();
    match result4 {
        ProcessResult::Deliver { payload } => {
            assert!(
                is_cover_payload(&payload),
                "Final destination must detect cover traffic via dummy marker"
            );
            assert_eq!(
                payload.len(),
                caint::transport::sphinx::PAYLOAD_SIZE,
                "Payload must be full size"
            );
        }
        other => panic!(
            "Sender: expected Deliver, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    // Verify replay: resending the same packet to relay 1 should be dropped
    let replay_result = pkt.process(&relay1_key, &mut cache1).unwrap();
    assert!(
        matches!(replay_result, ProcessResult::Drop),
        "Replayed packet must be dropped"
    );
}
