//! E03 node-transfer protocol identity and serialization contract.

use ptah_identifiers::EntityRef;
use ptah_node_transfer::{
    MAX_CONTROL_FRAME_BYTES, MAX_RANGE_BYTES, PROTOCOL_ID, RangeAck, RangeDataHeader, RangeRequest,
    TransferComplete, TransferControlMessage, TransferErrorFrame, TransferHello, TransferHelloAck,
    TransferPeerRole, TransferProtocolVersion,
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
fn every_control_message_round_trips_with_stable_kind() {
    let ticket_ref = reference("transfer.ticket");
    let version = TransferProtocolVersion::CURRENT;
    let messages = vec![
        TransferControlMessage::Hello(TransferHello {
            protocol: version,
            ticket_ref: ticket_ref.clone(),
            role: TransferPeerRole::Source,
        }),
        TransferControlMessage::HelloAck(TransferHelloAck {
            protocol: version,
            ticket_ref: ticket_ref.clone(),
            accepted: true,
        }),
        TransferControlMessage::RangeRequest(RangeRequest {
            ticket_ref: ticket_ref.clone(),
            start: 0,
            len: 1_048_576,
        }),
        TransferControlMessage::RangeDataHeader(RangeDataHeader {
            ticket_ref: ticket_ref.clone(),
            start: 0,
            len: 1_048_576,
            sha256: "ab".repeat(32),
        }),
        TransferControlMessage::RangeAck(RangeAck {
            ticket_ref: ticket_ref.clone(),
            start: 0,
            len: 1_048_576,
            sha256: "ab".repeat(32),
        }),
        TransferControlMessage::Complete(TransferComplete {
            ticket_ref: ticket_ref.clone(),
            size: 1_048_576,
            canonical_sha256: "cd".repeat(32),
        }),
        TransferControlMessage::Error(TransferErrorFrame {
            ticket_ref: Some(ticket_ref),
            code: "range_rejected".to_owned(),
            message: "range rejected".to_owned(),
        }),
    ];

    let expected_kinds = [
        "hello",
        "hello_ack",
        "range_request",
        "range_data_header",
        "range_ack",
        "complete",
        "error",
    ];

    for (message, expected_kind) in messages.into_iter().zip(expected_kinds) {
        let encoded = serde_json::to_vec(&message).expect("serialize E03 control message");
        let json: serde_json::Value =
            serde_json::from_slice(&encoded).expect("decode E03 control JSON shape");
        assert_eq!(json["kind"], expected_kind);
        let decoded: TransferControlMessage =
            serde_json::from_slice(&encoded).expect("deserialize E03 control message");
        assert_eq!(decoded, message);
        assert_eq!(decoded.kind(), expected_kind);
    }
}
