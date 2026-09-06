//! E02 Task 7 dispatch-authority wire projection tests.

use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_link::{
    DispatchLeaseFrame, DispatchRequestFrame, DispatchReservationFrame, LinkMessage,
};

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity kind")
}

#[test]
fn reservation_lease_and_dispatch_authority_round_trip_on_existing_e01_envelope() {
    let node_id = NodeId::new();
    let attempt_ref = entity("activity.attempt");
    let reservation_ref = entity("resource.reservation");
    let lease_ref = entity("isolation.lease");
    let reservation = DispatchReservationFrame {
        reservation_ref: reservation_ref.clone(),
        attempt_ref: attempt_ref.clone(),
        node_id,
        node_generation: NodeGeneration::new(7),
        connection_epoch: ConnectionEpoch::new(11),
        expires_at_unix_seconds: 1_800_000_100,
    };
    let lease = DispatchLeaseFrame {
        lease_ref: lease_ref.clone(),
        reservation_ref: reservation_ref.clone(),
        attempt_ref: attempt_ref.clone(),
        node_id,
        node_generation: NodeGeneration::new(7),
        connection_epoch: ConnectionEpoch::new(11),
        fence: 4,
        expires_at_unix_seconds: 1_800_000_090,
    };
    let dispatch = DispatchRequestFrame {
        dispatch_ref: entity("runtime.dispatch"),
        operation_ref: entity("activity.operation"),
        attempt_ref,
        reservation_ref,
        lease_ref,
        node_id,
        node_generation: NodeGeneration::new(7),
        connection_epoch: ConnectionEpoch::new(11),
        fence: 4,
    };

    for (message, kind) in [
        (LinkMessage::DispatchReservation(reservation), "dispatch_reservation"),
        (LinkMessage::DispatchLease(lease), "dispatch_lease"),
        (LinkMessage::DispatchRequest(dispatch), "dispatch_request"),
    ] {
        assert_eq!(message.kind(), kind);
        let encoded = serde_json::to_vec(&message).expect("serialize");
        let decoded: LinkMessage = serde_json::from_slice(&encoded).expect("deserialize");
        assert_eq!(decoded, message);
    }
}
