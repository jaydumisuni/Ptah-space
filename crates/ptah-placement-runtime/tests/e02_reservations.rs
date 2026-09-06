//! E02 Task 4 atomic Reservation accounting and lifecycle tests.

use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::{
    NodeResourceSnapshot, ResourcePressure, ResourceQuantity, ResourceUnit, SnapshotOutcome,
};
use ptah_node_link::{CredentialFingerprint, ProtocolVersion, SessionBinding};
use ptah_placement_runtime::{
    AuthorityBinding, ReservationError, ReservationRegistry, ReservationState, ReservedResource,
};

const NOW: u64 = 1_800_000_000;
const FUTURE: u64 = NOW + 60;

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid test entity kind")
}

fn make_session() -> SessionBinding {
    SessionBinding {
        node_id: NodeId::new(),
        node_generation: NodeGeneration::new(7),
        connection_epoch: ConnectionEpoch::new(11),
        enrollment_ref: entity("security.node-enrollment"),
        credential_fingerprint: CredentialFingerprint::from_der(b"e02-reservation-credential"),
        negotiated_protocol: ProtocolVersion { major: 1, minor: 0 },
    }
}

fn resource_snapshot(session: &SessionBinding, available: f64) -> NodeResourceSnapshot {
    NodeResourceSnapshot::new(
        session
            .node_id
            .entity_ref(session.node_generation, session.connection_epoch),
        session.node_generation,
        session.connection_epoch,
        SnapshotOutcome::Complete,
        vec![ResourceQuantity {
            resource_key: "cpu".to_owned(),
            unit: ResourceUnit::Cores,
            observed_total: 8.0,
            administratively_allocatable: 8.0,
            reserved: 0.0,
            consumed: 8.0 - available,
            currently_available: available,
            pressure: ResourcePressure::Normal,
            observation_refs: vec![entity("runtime.node-observation")],
        }],
        vec![entity("runtime.node-observation")],
        vec![entity("proof.receipt")],
        Vec::new(),
    )
    .expect("resource snapshot")
}

fn binding(session: &SessionBinding) -> AuthorityBinding {
    AuthorityBinding::new(
        entity("activity.attempt"),
        session.node_id,
        session.node_generation,
        session.connection_epoch,
    )
}

fn cpu(quantity: f64) -> ReservedResource {
    ReservedResource::new("cpu", ResourceUnit::Cores, quantity).expect("valid reservation amount")
}

#[test]
fn competing_attempts_cannot_double_allocate_bounded_capacity() {
    let session = make_session();
    let snapshot = resource_snapshot(&session, 8.0);
    let mut registry = ReservationRegistry::new(&session, &snapshot).expect("registry");

    registry
        .reserve(
            entity("resource.reservation"),
            binding(&session),
            snapshot.snapshot_ref.clone(),
            vec![cpu(6.0)],
            NOW,
            FUTURE,
        )
        .expect("first hold");

    assert_eq!(
        registry.reserve(
            entity("resource.reservation"),
            binding(&session),
            snapshot.snapshot_ref.clone(),
            vec![cpu(4.0)],
            NOW,
            FUTURE,
        ),
        Err(ReservationError::InsufficientCapacity)
    );
    assert_eq!(registry.remaining("cpu", ResourceUnit::Cores), Some(2.0));

    registry
        .reserve(
            entity("resource.reservation"),
            binding(&session),
            snapshot.snapshot_ref.clone(),
            vec![cpu(2.0)],
            NOW,
            FUTURE,
        )
        .expect("remaining capacity may be held exactly");
    assert_eq!(registry.remaining("cpu", ResourceUnit::Cores), Some(0.0));
}

#[test]
fn failed_reservation_is_atomic_and_does_not_consume_partial_capacity() {
    let session = make_session();
    let snapshot = resource_snapshot(&session, 8.0);
    let mut registry = ReservationRegistry::new(&session, &snapshot).expect("registry");

    let invalid = vec![
        cpu(2.0),
        ReservedResource::new("memory", ResourceUnit::Bytes, 1024.0).expect("valid amount"),
    ];
    assert_eq!(
        registry.reserve(
            entity("resource.reservation"),
            binding(&session),
            snapshot.snapshot_ref.clone(),
            invalid,
            NOW,
            FUTURE,
        ),
        Err(ReservationError::InsufficientCapacity)
    );
    assert_eq!(registry.remaining("cpu", ResourceUnit::Cores), Some(8.0));
}

#[test]
fn release_returns_capacity_and_records_terminal_state() {
    let session = make_session();
    let snapshot = resource_snapshot(&session, 8.0);
    let mut registry = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let reservation = registry
        .reserve(
            entity("resource.reservation"),
            binding(&session),
            snapshot.snapshot_ref.clone(),
            vec![cpu(5.0)],
            NOW,
            FUTURE,
        )
        .expect("hold");

    assert_eq!(registry.remaining("cpu", ResourceUnit::Cores), Some(3.0));
    registry
        .release(reservation.reservation_ref(), NOW + 1)
        .expect("release");
    assert_eq!(registry.remaining("cpu", ResourceUnit::Cores), Some(8.0));
    assert_eq!(
        registry
            .reservation(reservation.reservation_ref())
            .expect("record")
            .state(),
        ReservationState::Released
    );
}

#[test]
fn expiry_returns_capacity_and_expired_authority_cannot_be_released_again() {
    let session = make_session();
    let snapshot = resource_snapshot(&session, 8.0);
    let mut registry = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let reservation = registry
        .reserve(
            entity("resource.reservation"),
            binding(&session),
            snapshot.snapshot_ref.clone(),
            vec![cpu(5.0)],
            NOW,
            NOW + 5,
        )
        .expect("hold");

    assert_eq!(registry.expire(NOW + 5), 1);
    assert_eq!(registry.remaining("cpu", ResourceUnit::Cores), Some(8.0));
    assert_eq!(
        registry
            .reservation(reservation.reservation_ref())
            .expect("record")
            .state(),
        ReservationState::Expired
    );
    assert_eq!(
        registry.release(reservation.reservation_ref(), NOW + 6),
        Err(ReservationError::NotActive)
    );
}

#[test]
fn reservation_binding_is_immutable_for_its_lifetime() {
    let session = make_session();
    let snapshot = resource_snapshot(&session, 8.0);
    let expected = binding(&session);
    let mut registry = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let reservation = registry
        .reserve(
            entity("resource.reservation"),
            expected.clone(),
            snapshot.snapshot_ref.clone(),
            vec![cpu(1.0)],
            NOW,
            FUTURE,
        )
        .expect("hold");

    let record = registry
        .reservation(reservation.reservation_ref())
        .expect("record");
    assert_eq!(record.binding(), &expected);
    assert_eq!(record.resource_snapshot_ref(), &snapshot.snapshot_ref);
    assert_eq!(record.state(), ReservationState::Active);
}

#[test]
fn stale_or_foreign_resource_evidence_cannot_expand_capacity() {
    let session = make_session();
    let current = resource_snapshot(&session, 4.0);
    let stale = resource_snapshot(&session, 8.0);
    let mut registry = ReservationRegistry::new(&session, &current).expect("registry");

    assert_eq!(
        registry.reserve(
            entity("resource.reservation"),
            binding(&session),
            stale.snapshot_ref.clone(),
            vec![cpu(6.0)],
            NOW,
            FUTURE,
        ),
        Err(ReservationError::EvidenceMismatch)
    );
    assert_eq!(registry.remaining("cpu", ResourceUnit::Cores), Some(4.0));
}

#[test]
fn duplicate_reservation_identity_is_rejected_without_mutation() {
    let session = make_session();
    let snapshot = resource_snapshot(&session, 8.0);
    let mut registry = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let reservation_ref = entity("resource.reservation");

    registry
        .reserve(
            reservation_ref.clone(),
            binding(&session),
            snapshot.snapshot_ref.clone(),
            vec![cpu(2.0)],
            NOW,
            FUTURE,
        )
        .expect("first hold");

    assert_eq!(
        registry.reserve(
            reservation_ref,
            binding(&session),
            snapshot.snapshot_ref.clone(),
            vec![cpu(2.0)],
            NOW,
            FUTURE,
        ),
        Err(ReservationError::DuplicateReservation)
    );
    assert_eq!(registry.remaining("cpu", ResourceUnit::Cores), Some(6.0));
}
