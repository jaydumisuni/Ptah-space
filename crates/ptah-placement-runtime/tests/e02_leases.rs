//! E02 Task 5 Lease/Fence allocator and current-owner tests.

use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::{
    NodeResourceSnapshot, ResourcePressure, ResourceQuantity, ResourceUnit, SnapshotOutcome,
};
use ptah_node_link::{CredentialFingerprint, ProtocolVersion, SessionBinding};
use ptah_placement_runtime::{
    AuthorityBinding, LeaseError, LeaseRegistry, LeaseState, ReservationRegistry, ReservedResource,
};

const NOW: u64 = 1_800_000_000;
const FUTURE: u64 = NOW + 120;

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid test entity kind")
}

fn make_session() -> SessionBinding {
    SessionBinding {
        node_id: NodeId::new(),
        node_generation: NodeGeneration::new(7),
        connection_epoch: ConnectionEpoch::new(11),
        enrollment_ref: entity("security.node-enrollment"),
        credential_fingerprint: CredentialFingerprint::from_der(b"e02-lease-credential"),
        negotiated_protocol: ProtocolVersion { major: 1, minor: 0 },
    }
}

fn resource_snapshot(session: &SessionBinding) -> NodeResourceSnapshot {
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
            consumed: 0.0,
            currently_available: 8.0,
            pressure: ResourcePressure::Normal,
            observation_refs: vec![entity("runtime.node-observation")],
        }],
        vec![entity("runtime.node-observation")],
        vec![entity("proof.receipt")],
        Vec::new(),
    )
    .expect("resource snapshot")
}

fn cpu(quantity: f64) -> ReservedResource {
    ReservedResource::new("cpu", ResourceUnit::Cores, quantity).expect("valid reservation amount")
}

fn reserve_for_attempt(
    registry: &mut ReservationRegistry,
    snapshot: &NodeResourceSnapshot,
    session: &SessionBinding,
    attempt_ref: EntityRef,
) -> EntityRef {
    let reservation_ref = entity("resource.reservation");
    registry
        .reserve(
            reservation_ref.clone(),
            AuthorityBinding::new(
                attempt_ref,
                session.node_id,
                session.node_generation,
                session.connection_epoch,
            ),
            snapshot.snapshot_ref.clone(),
            vec![cpu(1.0)],
            NOW,
            FUTURE,
        )
        .expect("reservation");
    reservation_ref
}

#[test]
fn only_active_reservation_can_receive_lease() {
    let session = make_session();
    let snapshot = resource_snapshot(&session);
    let mut reservations = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let reservation_ref = reserve_for_attempt(
        &mut reservations,
        &snapshot,
        &session,
        entity("activity.attempt"),
    );
    reservations
        .release(&reservation_ref, NOW + 1)
        .expect("release");
    let record = reservations
        .reservation(&reservation_ref)
        .expect("record")
        .clone();
    let mut leases = LeaseRegistry::new();

    assert_eq!(
        leases.issue(&record, entity("isolation.lease"), NOW + 2, NOW + 30),
        Err(LeaseError::ReservationNotActive)
    );
}

#[test]
fn renewal_advances_fence_and_never_reuses_previous_value() {
    let session = make_session();
    let snapshot = resource_snapshot(&session);
    let mut reservations = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let attempt_ref = entity("activity.attempt");
    let reservation_ref =
        reserve_for_attempt(&mut reservations, &snapshot, &session, attempt_ref.clone());
    let record = reservations
        .reservation(&reservation_ref)
        .expect("record")
        .clone();
    let mut leases = LeaseRegistry::new();

    let first = leases
        .issue(&record, entity("isolation.lease"), NOW, NOW + 20)
        .expect("first lease");
    let second = leases
        .issue(&record, entity("isolation.lease"), NOW + 1, NOW + 30)
        .expect("renewal");

    assert_eq!(first.fence().value(), 1);
    assert_eq!(second.fence().value(), 2);
    assert_eq!(
        leases.validate_current(&first, NOW + 2),
        Err(LeaseError::StaleFence)
    );
    assert!(leases.validate_current(&second, NOW + 2).is_ok());
    assert_eq!(
        leases
            .current(&attempt_ref)
            .expect("current lease")
            .lease_ref(),
        second.lease_ref()
    );
}

#[test]
fn transfer_between_reservations_for_same_attempt_keeps_monotonic_fence() {
    let session = make_session();
    let snapshot = resource_snapshot(&session);
    let mut reservations = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let attempt_ref = entity("activity.attempt");
    let first_ref =
        reserve_for_attempt(&mut reservations, &snapshot, &session, attempt_ref.clone());
    let second_ref =
        reserve_for_attempt(&mut reservations, &snapshot, &session, attempt_ref.clone());
    let first_record = reservations.reservation(&first_ref).expect("first").clone();
    let second_record = reservations
        .reservation(&second_ref)
        .expect("second")
        .clone();
    let mut leases = LeaseRegistry::new();

    let first = leases
        .issue(&first_record, entity("isolation.lease"), NOW, NOW + 20)
        .expect("first owner");
    let second = leases
        .issue(&second_record, entity("isolation.lease"), NOW + 1, NOW + 30)
        .expect("transferred owner");

    assert_eq!(first.fence().value(), 1);
    assert_eq!(second.fence().value(), 2);
    assert_eq!(
        leases.state(first.lease_ref()),
        Some(LeaseState::Superseded)
    );
    assert_eq!(leases.state(second.lease_ref()), Some(LeaseState::Active));
    assert_eq!(
        leases.current(&attempt_ref).expect("one owner").lease_ref(),
        second.lease_ref()
    );
}

#[test]
fn expired_and_revoked_leases_reject_new_dispatch() {
    let session = make_session();
    let snapshot = resource_snapshot(&session);
    let mut reservations = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let reservation_ref = reserve_for_attempt(
        &mut reservations,
        &snapshot,
        &session,
        entity("activity.attempt"),
    );
    let record = reservations
        .reservation(&reservation_ref)
        .expect("record")
        .clone();
    let mut leases = LeaseRegistry::new();

    let expiring = leases
        .issue(&record, entity("isolation.lease"), NOW, NOW + 5)
        .expect("lease");
    assert_eq!(leases.expire(NOW + 5), 1);
    assert_eq!(
        leases.validate_current(&expiring, NOW + 5),
        Err(LeaseError::ExpiredLease)
    );

    let revoked = leases
        .issue(&record, entity("isolation.lease"), NOW + 6, NOW + 20)
        .expect("new lease");
    leases.revoke(revoked.lease_ref()).expect("revoke");
    assert_eq!(
        leases.validate_current(&revoked, NOW + 7),
        Err(LeaseError::RevokedLease)
    );
}

#[test]
fn higher_fence_permanently_rejects_delayed_lower_fence_replay() {
    let session = make_session();
    let snapshot = resource_snapshot(&session);
    let mut reservations = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let reservation_ref = reserve_for_attempt(
        &mut reservations,
        &snapshot,
        &session,
        entity("activity.attempt"),
    );
    let record = reservations
        .reservation(&reservation_ref)
        .expect("record")
        .clone();
    let mut leases = LeaseRegistry::new();

    let old = leases
        .issue(&record, entity("isolation.lease"), NOW, NOW + 50)
        .expect("old owner");
    let current = leases
        .issue(&record, entity("isolation.lease"), NOW + 1, NOW + 60)
        .expect("new owner");

    assert!(leases.validate_current(&current, NOW + 2).is_ok());
    for replay_time in [NOW + 2, NOW + 10, NOW + 40] {
        assert_eq!(
            leases.validate_current(&old, replay_time),
            Err(LeaseError::StaleFence)
        );
    }
}

#[test]
fn duplicate_lease_identity_is_rejected_without_advancing_fence() {
    let session = make_session();
    let snapshot = resource_snapshot(&session);
    let mut reservations = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let attempt_ref = entity("activity.attempt");
    let reservation_ref =
        reserve_for_attempt(&mut reservations, &snapshot, &session, attempt_ref.clone());
    let record = reservations
        .reservation(&reservation_ref)
        .expect("record")
        .clone();
    let mut leases = LeaseRegistry::new();
    let lease_ref = entity("isolation.lease");

    let first = leases
        .issue(&record, lease_ref.clone(), NOW, NOW + 20)
        .expect("first lease");
    assert_eq!(
        leases.issue(&record, lease_ref, NOW + 1, NOW + 30),
        Err(LeaseError::DuplicateLease)
    );
    assert_eq!(
        leases
            .current(&attempt_ref)
            .expect("current")
            .fence()
            .value(),
        1
    );
    assert_eq!(leases.state(first.lease_ref()), Some(LeaseState::Active));
}
