//! E02 Task 3 bounded Node-offer wire projection tests.

use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::ResourceUnit;
use ptah_node_link::{LinkMessage, NodeOfferFrame, OfferedResource};

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity kind")
}

#[test]
fn node_offer_round_trips_on_existing_e01_message_envelope() {
    let message = LinkMessage::NodeOffer(Box::new(NodeOfferFrame {
        offer_ref: entity("placement.node-offer"),
        node_id: NodeId::new(),
        node_generation: NodeGeneration::new(4),
        connection_epoch: ConnectionEpoch::new(9),
        capability_snapshot_ref: entity("runtime.node-capability-snapshot"),
        resource_snapshot_ref: entity("runtime.node-resource-snapshot"),
        offered_resources: vec![OfferedResource {
            resource_key: "cpu".to_owned(),
            unit: ResourceUnit::Cores,
            quantity: 2.0,
        }],
        load_score: Some(25),
        locality: Some("local".to_owned()),
        valid_until_unix_seconds: 1_800_000_060,
        nonce: 8,
    }));

    assert_eq!(message.kind(), "node_offer");
    let encoded = serde_json::to_vec(&message).expect("serialize offer");
    assert!(encoded.len() < 4_096, "offer wire projection must remain bounded");
    let decoded: LinkMessage = serde_json::from_slice(&encoded).expect("deserialize offer");
    assert_eq!(decoded, message);
}
