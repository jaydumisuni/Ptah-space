//! E02 Task 7 Node-side dispatch authority guard tests.

use ptah_identifiers::EntityRef;
use ptah_node::NodeDispatchGuard;
use ptah_node::NodeDispatchError;
use ptah_node_agent::NodeAgent;
use ptah_node_link::{DispatchLeaseFrame, DispatchRequestFrame, DispatchReservationFrame};

const NOW: u64 = 1_800_000_000;

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity kind")
}

fn reservation(agent: &NodeAgent, attempt_ref: EntityRef) -> DispatchReservationFrame {
    DispatchReservationFrame {
        reservation_ref: entity("resource.reservation"),
        attempt_ref,
        node_id: agent.node_id(),
        node_generation: agent.generation(),
        connection_epoch: agent.connection_epoch(),
        expires_at_unix_seconds: NOW + 100,
    }
}

fn lease(
    agent: &NodeAgent,
    reservation: &DispatchReservationFrame,
    fence: u64,
) -> DispatchLeaseFrame {
    DispatchLeaseFrame {
        lease_ref: entity("isolation.lease"),
        reservation_ref: reservation.reservation_ref.clone(),
        attempt_ref: reservation.attempt_ref.clone(),
        node_id: agent.node_id(),
        node_generation: agent.generation(),
        connection_epoch: agent.connection_epoch(),
        fence,
        expires_at_unix_seconds: NOW + 90,
    }
}

fn dispatch(
    agent: &NodeAgent,
    reservation: &DispatchReservationFrame,
    lease: &DispatchLeaseFrame,
) -> DispatchRequestFrame {
    DispatchRequestFrame {
        dispatch_ref: entity("runtime.dispatch"),
        operation_ref: entity("activity.operation"),
        attempt_ref: reservation.attempt_ref.clone(),
        reservation_ref: reservation.reservation_ref.clone(),
        lease_ref: lease.lease_ref.clone(),
        node_id: agent.node_id(),
        node_generation: agent.generation(),
        connection_epoch: agent.connection_epoch(),
        fence: lease.fence,
    }
}

#[test]
fn capability_only_and_reservation_only_cannot_reach_invocation() {
    let agent = NodeAgent::bootstrap().expect("node");
    let attempt_ref = entity("activity.attempt");
    let reservation = reservation(&agent, attempt_ref);
    let lease = lease(&agent, &reservation, 1);
    let request = dispatch(&agent, &reservation, &lease);
    let mut guard = NodeDispatchGuard::for_agent(&agent);
    let mut invoked = 0_u64;

    assert_eq!(
        guard.invoke_if_authorized(&agent, &request, NOW, || invoked += 1),
        Err(NodeDispatchError::UnknownReservation)
    );
    assert_eq!(invoked, 0);

    guard
        .accept_reservation(&agent, &reservation, NOW)
        .expect("reservation accepted");
    assert_eq!(
        guard.invoke_if_authorized(&agent, &request, NOW, || invoked += 1),
        Err(NodeDispatchError::MissingCurrentLease)
    );
    assert_eq!(invoked, 0);
}

#[test]
fn exact_current_reservation_lease_and_fence_invoke_once() {
    let agent = NodeAgent::bootstrap().expect("node");
    let reservation = reservation(&agent, entity("activity.attempt"));
    let lease = lease(&agent, &reservation, 1);
    let request = dispatch(&agent, &reservation, &lease);
    let mut guard = NodeDispatchGuard::for_agent(&agent);
    guard
        .accept_reservation(&agent, &reservation, NOW)
        .expect("reservation accepted");
    guard
        .accept_lease(&agent, &lease, NOW)
        .expect("lease accepted");
    let mut invoked = 0_u64;

    assert_eq!(
        guard.invoke_if_authorized(&agent, &request, NOW + 1, || {
            invoked += 1;
            "invoked"
        }),
        Ok("invoked")
    );
    assert_eq!(invoked, 1);
}

#[test]
fn wrong_authority_fields_reject_before_invocation() {
    let agent = NodeAgent::bootstrap().expect("node");
    let reservation = reservation(&agent, entity("activity.attempt"));
    let lease = lease(&agent, &reservation, 1);
    let request = dispatch(&agent, &reservation, &lease);
    let mut guard = NodeDispatchGuard::for_agent(&agent);
    guard
        .accept_reservation(&agent, &reservation, NOW)
        .expect("reservation accepted");
    guard
        .accept_lease(&agent, &lease, NOW)
        .expect("lease accepted");
    let mut invoked = 0_u64;

    let mut wrong_attempt = request.clone();
    wrong_attempt.attempt_ref = entity("activity.attempt");
    assert_eq!(
        guard.invoke_if_authorized(&agent, &wrong_attempt, NOW + 1, || invoked += 1),
        Err(NodeDispatchError::AttemptMismatch)
    );

    let mut wrong_generation = request.clone();
    wrong_generation.node_generation = agent.generation().next().expect("generation");
    assert_eq!(
        guard.invoke_if_authorized(&agent, &wrong_generation, NOW + 1, || invoked += 1),
        Err(NodeDispatchError::NodeGenerationMismatch)
    );

    let mut wrong_epoch = request.clone();
    wrong_epoch.connection_epoch = agent.connection_epoch().next().expect("epoch");
    assert_eq!(
        guard.invoke_if_authorized(&agent, &wrong_epoch, NOW + 1, || invoked += 1),
        Err(NodeDispatchError::ConnectionEpochMismatch)
    );

    let mut wrong_lease = request.clone();
    wrong_lease.lease_ref = entity("isolation.lease");
    assert_eq!(
        guard.invoke_if_authorized(&agent, &wrong_lease, NOW + 1, || invoked += 1),
        Err(NodeDispatchError::LeaseMismatch)
    );

    let mut future_fence = request;
    future_fence.fence = 2;
    assert_eq!(
        guard.invoke_if_authorized(&agent, &future_fence, NOW + 1, || invoked += 1),
        Err(NodeDispatchError::FutureFence)
    );
    assert_eq!(invoked, 0);
}

#[test]
fn superseded_e01_session_rejects_before_invocation() {
    let mut agent = NodeAgent::bootstrap().expect("node");
    let reservation = reservation(&agent, entity("activity.attempt"));
    let lease = lease(&agent, &reservation, 1);
    let request = dispatch(&agent, &reservation, &lease);
    let mut guard = NodeDispatchGuard::for_agent(&agent);
    guard
        .accept_reservation(&agent, &reservation, NOW)
        .expect("reservation accepted");
    guard
        .accept_lease(&agent, &lease, NOW)
        .expect("lease accepted");
    agent.reconnect().expect("new E01 epoch");
    let mut invoked = 0_u64;

    assert_eq!(
        guard.invoke_if_authorized(&agent, &request, NOW + 1, || invoked += 1),
        Err(NodeDispatchError::SupersededSession)
    );
    assert_eq!(invoked, 0);
}

#[test]
fn delayed_lower_fence_remains_stale_after_newer_lease() {
    let agent = NodeAgent::bootstrap().expect("node");
    let reservation = reservation(&agent, entity("activity.attempt"));
    let first_lease = lease(&agent, &reservation, 1);
    let first_request = dispatch(&agent, &reservation, &first_lease);
    let second_lease = lease(&agent, &reservation, 2);
    let second_request = dispatch(&agent, &reservation, &second_lease);
    let mut guard = NodeDispatchGuard::for_agent(&agent);
    guard
        .accept_reservation(&agent, &reservation, NOW)
        .expect("reservation accepted");
    guard
        .accept_lease(&agent, &first_lease, NOW)
        .expect("first lease");
    guard
        .accept_lease(&agent, &second_lease, NOW + 1)
        .expect("higher fence");
    let mut invoked = 0_u64;

    assert_eq!(
        guard.invoke_if_authorized(&agent, &first_request, NOW + 2, || invoked += 1),
        Err(NodeDispatchError::StaleFence)
    );
    assert_eq!(invoked, 0);
    assert_eq!(
        guard.invoke_if_authorized(&agent, &second_request, NOW + 2, || invoked += 1),
        Ok(())
    );
    assert_eq!(invoked, 1);
}
