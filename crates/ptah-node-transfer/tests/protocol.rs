//! E03 node-transfer protocol identity and serialization contract.

use ptah_identifiers::EntityRef;
use ptah_node_transfer::{
    MAX_CONTROL_FRAME_BYTES, MAX_RANGE_BYTES, PROTOCOL_ID, RangeRequest, TransferControlMessage,
    TransferProtocolVersion,
};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid Ptah entity kind")
}

#[test]
fn protocol_identity_and_bounds_are_frozen() {
    assert_eq!(PROTOCOL_ID, "ptah.node.transfer.v1");
    assert_eq!(MAX_CONTROL_FRAME_BYTES, 65_536);
    assert_eq!(MAX_RANGE_BYTES, 1_048_576);
    assert_eq!(TransferProtocolVersion::CURRENT.major, 1);
    assert_eq!(TransferProtocolVersion::CURRENT.minor, 0);
}

#[test]
fn range_request_round_trips_with_stable_kind() {
    let message = TransferControlMessage::RangeRequest(RangeRequest {
        ticket_ref: reference("transfer.ticket"),
        start: 0,
        len: 1_048_576,
    });
    let encoded = serde_json::to_vec(&message).expect("serialize E03 control message");
    let json: serde_json::Value =
        serde_json::from_slice(&encoded).expect("decode E03 control JSON shape");
    assert_eq!(json["kind"], "range_request");
    let decoded: TransferControlMessage =
        serde_json::from_slice(&encoded).expect("deserialize E03 control message");
    assert_eq!(decoded, message);
    assert_eq!(decoded.kind(), "range_request");
}
