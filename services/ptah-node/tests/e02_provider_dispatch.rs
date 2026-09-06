//! E02 Task 9 real Provider-dispatch integration proof.

use native_process::{
    DisconnectPolicy, NativeProcessProvider, NativeProcessProviderConfig, ProcessMode, ProcessSpec,
};
use ptah_identifiers::EntityRef;
use ptah_node::{
    NodeDispatchError, NodeDispatchGuard, NodeProviderDispatchError,
    spawn_native_process_if_authorized,
};
use ptah_node_agent::NodeAgent;
use ptah_node_link::{DispatchLeaseFrame, DispatchRequestFrame, DispatchReservationFrame};
use ptah_provider_api::{
    ProviderGeneration, ProviderHealth, ProviderInstance, ProviderKind, ProviderReachability,
    ProviderReadiness, ProviderRevision,
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

const NOW: u64 = 1_800_000_000;

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity kind")
}

fn active_agent() -> NodeAgent {
    let bootstrap = NodeAgent::bootstrap().expect("bootstrap node");
    NodeAgent::restart(bootstrap.restart_seed()).expect("post-bootstrap node generation")
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

fn provider(agent: &NodeAgent) -> NativeProcessProvider {
    let revision_ref = entity("runtime.provider_revision");
    let revision = ProviderRevision {
        revision_ref: revision_ref.clone(),
        provider_ref: entity("runtime.provider"),
        provider_kind: ProviderKind::Process,
        implementation_name: "native-process".to_owned(),
        implementation_version: "0.1.0".to_owned(),
        build_or_package_digest: "sha256:e02-native-process".to_owned(),
        configuration_digest: "sha256:e02-native-process-config".to_owned(),
        supported_facility_refs: vec![entity("runtime.facility")],
        capability_claim_refs: Vec::new(),
        dependency_refs: Vec::new(),
        node_requirements: Vec::new(),
        security_requirements: Vec::new(),
        known_limitations: Vec::new(),
    };
    let instance = ProviderInstance {
        instance_ref: entity("runtime.provider_instance"),
        provider_revision_ref: revision_ref,
        node_ref: agent
            .node_id()
            .entity_ref(agent.generation(), agent.connection_epoch()),
        node_generation: agent.generation().value(),
        provider_generation: ProviderGeneration::new(1).expect("provider generation"),
        connection_epoch: agent.connection_epoch().value(),
        reachability: ProviderReachability::Reachable,
        readiness: ProviderReadiness::Ready,
        health: ProviderHealth::Healthy,
        endpoint_aliases: Vec::new(),
        process_or_service_refs: Vec::new(),
        observation_refs: vec![entity("proof.evidence")],
        started_at: "2026-09-06T00:00:00Z".to_owned(),
        limitations: Vec::new(),
    };
    NativeProcessProvider::new(NativeProcessProviderConfig {
        revision,
        instance,
        clock: Arc::new(|| "2026-09-06T00:00:00Z".to_owned()),
    })
    .expect("native process provider")
}

fn process_spec(program: &str, args: &[&str]) -> ProcessSpec {
    ProcessSpec {
        program: program.to_owned(),
        args: args.iter().map(|value| (*value).to_owned()).collect(),
        env: BTreeMap::new(),
        clear_env: false,
        cwd: None,
        mode: ProcessMode::Pipes,
        max_stream_bytes: 4096,
        disconnect_policy: DisconnectPolicy::Retain,
    }
}

#[cfg(unix)]
#[test]
fn stale_e02_authority_never_enters_real_provider_path() {
    let agent = active_agent();
    let reservation = reservation(&agent, entity("activity.attempt"));
    let first = lease(&agent, &reservation, 1);
    let second = lease(&agent, &reservation, 2);
    let stale_request = dispatch(&agent, &reservation, &first);
    let mut guard = NodeDispatchGuard::for_agent(&agent);
    guard
        .accept_reservation(&agent, &reservation, NOW)
        .expect("reservation");
    guard.accept_lease(&agent, &first, NOW).expect("first lease");
    guard
        .accept_lease(&agent, &second, NOW + 1)
        .expect("new owner");
    let provider = provider(&agent);
    let expected = provider
        .attempt_context(1, entity("runtime.facility"))
        .expect("attempt context");

    let result = spawn_native_process_if_authorized(
        &guard,
        &agent,
        &stale_request,
        NOW + 2,
        &provider,
        &expected,
        process_spec("/definitely/not/a/provider/program", &[]),
    );
    assert!(matches!(
        result,
        Err(NodeProviderDispatchError::Authority(NodeDispatchError::StaleFence))
    ));
}

#[cfg(unix)]
#[test]
fn current_e02_authority_reaches_real_provider_but_a05_generation_still_fences() {
    let agent = active_agent();
    let reservation = reservation(&agent, entity("activity.attempt"));
    let lease = lease(&agent, &reservation, 1);
    let request = dispatch(&agent, &reservation, &lease);
    let mut guard = NodeDispatchGuard::for_agent(&agent);
    guard
        .accept_reservation(&agent, &reservation, NOW)
        .expect("reservation");
    guard.accept_lease(&agent, &lease, NOW).expect("lease");
    let provider = provider(&agent);
    let expected = provider
        .attempt_context(1, entity("runtime.facility"))
        .expect("attempt context");

    let process_id = spawn_native_process_if_authorized(
        &guard,
        &agent,
        &request,
        NOW + 1,
        &provider,
        &expected,
        process_spec("/bin/sh", &["-c", "exit 0"]),
    )
    .expect("authorized native process");
    let exit = provider
        .wait_for_exit(process_id, Duration::from_secs(2))
        .expect("real Provider exit");
    assert!(exit.success);
    let snapshot = provider.snapshot(process_id).expect("process snapshot");
    assert_eq!(
        snapshot.record.provider_generation.value(),
        expected.provider_generation
    );
    assert_eq!(snapshot.record.node_generation, expected.node_generation);

    provider
        .advance_provider_generation()
        .expect("advance A05 generation");
    let result = spawn_native_process_if_authorized(
        &guard,
        &agent,
        &request,
        NOW + 2,
        &provider,
        &expected,
        process_spec("/bin/sh", &["-c", "exit 0"]),
    );
    assert!(matches!(
        result,
        Err(NodeProviderDispatchError::ProviderContextMismatch)
    ));
}
