//! E02 Task 8 durable authority recovery proofs.

use ptah_identifiers::{ConnectionEpoch, EntityId, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::{
    NodeResourceSnapshot, ResourcePressure, ResourceQuantity, ResourceUnit, SnapshotOutcome,
};
use ptah_node_link::{CredentialFingerprint, ProtocolVersion, SessionBinding};
use ptah_placement_runtime::{
    AuthorityBinding, DurableAuthorityStore, LeaseError, LeaseRegistry, ReservationError,
    ReservationRegistry, ReservedResource,
};
use rusqlite::Connection;
use serde_json::Value;
use std::{fs, path::PathBuf, process};

const NOW: u64 = 1_800_000_000;
const FUTURE: u64 = NOW + 120;

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid test entity kind")
}

fn temp_db(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ptah-e02-{label}-{}-{}.sqlite3",
        process::id(),
        EntityId::new_v7()
    ))
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_file(path);
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    let _ = fs::remove_file(PathBuf::from(wal));
    let mut shm = path.as_os_str().to_owned();
    shm.push("-shm");
    let _ = fs::remove_file(PathBuf::from(shm));
}

fn session(node_id: NodeId, generation: u64, epoch: u64) -> SessionBinding {
    SessionBinding {
        node_id,
        node_generation: NodeGeneration::new(generation),
        connection_epoch: ConnectionEpoch::new(epoch),
        enrollment_ref: entity("security.node-enrollment"),
        credential_fingerprint: CredentialFingerprint::from_der(b"e02-recovery-credential"),
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
    ReservedResource::new("cpu", ResourceUnit::Cores, quantity).expect("cpu reservation")
}

fn reserve(
    registry: &mut ReservationRegistry,
    snapshot: &NodeResourceSnapshot,
    session: &SessionBinding,
    attempt_ref: EntityRef,
    quantity: f64,
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
            vec![cpu(quantity)],
            NOW,
            FUTURE,
        )
        .expect("reservation");
    reservation_ref
}

#[test]
fn canonical_journal_timestamp_matches_reservation_creation_time() {
    let path = temp_db("canonical-time");
    let session = session(NodeId::new(), 7, 11);
    let snapshot = resource_snapshot(&session);
    let mut reservations = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let reservation_ref = reserve(
        &mut reservations,
        &snapshot,
        &session,
        entity("activity.attempt"),
        1.0,
    );
    let record = reservations
        .reservation(&reservation_ref)
        .expect("record")
        .clone();
    let mut store = DurableAuthorityStore::open(&path).expect("store");
    store
        .persist_reservation(&record)
        .expect("persist reservation");
    drop(store);

    let connection = Connection::open(&path).expect("ledger connection");
    let document_json: String = connection
        .query_row(
            "SELECT document_json FROM ptah_entity_records WHERE entity_kind = ?1",
            ["runtime.e02-authority-journal"],
            |row| row.get(0),
        )
        .expect("journal row");
    let document: Value = serde_json::from_str(&document_json).expect("canonical JSON");
    assert_eq!(document["created_at"], "2027-01-15T08:00:00Z");
    assert_eq!(document["updated_at"], "2027-01-15T08:00:00Z");
    cleanup(&path);
}

#[test]
fn restart_preserves_higher_fence_and_next_issue_is_strictly_newer() {
    let path = temp_db("fence");
    let session = session(NodeId::new(), 7, 11);
    let snapshot = resource_snapshot(&session);
    let attempt_ref = entity("activity.attempt");
    let mut reservations = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let reservation_ref = reserve(
        &mut reservations,
        &snapshot,
        &session,
        attempt_ref.clone(),
        1.0,
    );
    let record = reservations
        .reservation(&reservation_ref)
        .expect("record")
        .clone();
    let mut leases = LeaseRegistry::new();
    let mut store = DurableAuthorityStore::open(&path).expect("store");
    store
        .persist_reservation(&record)
        .expect("persist reservation");

    let first = leases
        .issue(&record, entity("isolation.lease"), NOW, NOW + 30)
        .expect("first");
    store
        .persist_lease(leases.current(&attempt_ref).expect("first record"))
        .expect("persist first");
    let second = leases
        .issue(&record, entity("isolation.lease"), NOW + 1, NOW + 40)
        .expect("second");
    store
        .persist_lease(leases.current(&attempt_ref).expect("second record"))
        .expect("persist second");
    assert_eq!((first.fence().value(), second.fence().value()), (1, 2));
    drop(store);

    let store = DurableAuthorityStore::open(&path).expect("reopen");
    let mut recovered = store
        .recover(&session, &snapshot, NOW + 2)
        .expect("recover");
    assert_eq!(
        recovered
            .leases()
            .highest_fence(&attempt_ref)
            .expect("fence")
            .value(),
        2
    );
    let recovered_reservation = recovered
        .reservations()
        .reservation(&reservation_ref)
        .expect("reservation")
        .clone();
    let third = recovered
        .leases_mut()
        .issue(
            &recovered_reservation,
            entity("isolation.lease"),
            NOW + 2,
            NOW + 50,
        )
        .expect("third");
    assert_eq!(third.fence().value(), 3);
    cleanup(&path);
}

#[test]
fn expired_authority_stays_expired_after_restart() {
    let path = temp_db("expiry");
    let session = session(NodeId::new(), 7, 11);
    let snapshot = resource_snapshot(&session);
    let attempt_ref = entity("activity.attempt");
    let mut reservations = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let reservation_ref = reserve(
        &mut reservations,
        &snapshot,
        &session,
        attempt_ref.clone(),
        1.0,
    );
    let record = reservations
        .reservation(&reservation_ref)
        .expect("record")
        .clone();
    let mut leases = LeaseRegistry::new();
    let lease = leases
        .issue(&record, entity("isolation.lease"), NOW, NOW + 5)
        .expect("lease");
    let mut store = DurableAuthorityStore::open(&path).expect("store");
    store.persist_reservation(&record).expect("reservation");
    store
        .persist_lease(leases.current(&attempt_ref).expect("lease record"))
        .expect("lease persist");
    drop(store);

    let store = DurableAuthorityStore::open(&path).expect("reopen");
    let recovered = store
        .recover(&session, &snapshot, NOW + 6)
        .expect("recover");
    assert_eq!(
        recovered.leases().validate_current(&lease, NOW + 6),
        Err(LeaseError::ExpiredLease)
    );
    cleanup(&path);
}

#[test]
fn recovered_active_reservation_still_consumes_capacity() {
    let path = temp_db("capacity");
    let session = session(NodeId::new(), 7, 11);
    let snapshot = resource_snapshot(&session);
    let mut reservations = ReservationRegistry::new(&session, &snapshot).expect("registry");
    let reservation_ref = reserve(
        &mut reservations,
        &snapshot,
        &session,
        entity("activity.attempt"),
        6.0,
    );
    let record = reservations
        .reservation(&reservation_ref)
        .expect("record")
        .clone();
    let mut store = DurableAuthorityStore::open(&path).expect("store");
    store.persist_reservation(&record).expect("persist");
    drop(store);

    let store = DurableAuthorityStore::open(&path).expect("reopen");
    let mut recovered = store
        .recover(&session, &snapshot, NOW + 1)
        .expect("recover");
    let result = recovered.reservations_mut().reserve(
        entity("resource.reservation"),
        AuthorityBinding::new(
            entity("activity.attempt"),
            session.node_id,
            session.node_generation,
            session.connection_epoch,
        ),
        snapshot.snapshot_ref.clone(),
        vec![cpu(3.0)],
        NOW + 1,
        FUTURE,
    );
    assert_eq!(result, Err(ReservationError::InsufficientCapacity));
    cleanup(&path);
}

#[test]
fn newer_node_session_keeps_old_fence_stale_and_cannot_reset_ownership() {
    let path = temp_db("reconnect");
    let node_id = NodeId::new();
    let old_session = session(node_id, 7, 11);
    let old_snapshot = resource_snapshot(&old_session);
    let attempt_ref = entity("activity.attempt");
    let mut reservations = ReservationRegistry::new(&old_session, &old_snapshot).expect("registry");
    let old_reservation_ref = reserve(
        &mut reservations,
        &old_snapshot,
        &old_session,
        attempt_ref.clone(),
        1.0,
    );
    let old_record = reservations
        .reservation(&old_reservation_ref)
        .expect("record")
        .clone();
    let mut leases = LeaseRegistry::new();
    let old_lease = leases
        .issue(&old_record, entity("isolation.lease"), NOW, NOW + 60)
        .expect("old lease");
    let mut store = DurableAuthorityStore::open(&path).expect("store");
    store.persist_reservation(&old_record).expect("reservation");
    store
        .persist_lease(leases.current(&attempt_ref).expect("lease"))
        .expect("lease persist");
    drop(store);

    let new_session = session(node_id, 8, 12);
    let new_snapshot = resource_snapshot(&new_session);
    let store = DurableAuthorityStore::open(&path).expect("reopen");
    let mut recovered = store
        .recover(&new_session, &new_snapshot, NOW + 1)
        .expect("recover newer session");
    assert_eq!(
        recovered
            .leases()
            .highest_fence(&attempt_ref)
            .expect("old floor")
            .value(),
        1
    );
    assert!(
        recovered
            .reservations()
            .reservation(&old_reservation_ref)
            .is_none()
    );

    let new_reservation_ref = reserve(
        recovered.reservations_mut(),
        &new_snapshot,
        &new_session,
        attempt_ref.clone(),
        1.0,
    );
    let new_record = recovered
        .reservations()
        .reservation(&new_reservation_ref)
        .expect("new record")
        .clone();
    let new_lease = recovered
        .leases_mut()
        .issue(&new_record, entity("isolation.lease"), NOW + 1, NOW + 70)
        .expect("new lease");
    assert_eq!(new_lease.fence().value(), 2);
    assert_eq!(
        recovered.leases().validate_current(&old_lease, NOW + 2),
        Err(LeaseError::StaleFence)
    );
    cleanup(&path);
}

#[test]
fn corrupt_durable_state_fails_closed() {
    let path = temp_db("corrupt");
    drop(DurableAuthorityStore::open(&path).expect("initialize"));
    fs::write(&path, b"not-a-sqlite-ledger").expect("corrupt file");
    assert!(DurableAuthorityStore::open(&path).is_err());
    cleanup(&path);
}
