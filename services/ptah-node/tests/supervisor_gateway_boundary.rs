//! Supervisor E05 gateway seam — Ptah-owned TEST-ONLY authority composition.
//!
//! Runs real A05 provider work after E01-session/A02-observation/E05-admission/
//! E02-control-issued Reservation+Lease+Fence / node-local dispatch checks.
//!
//! All credentials and snapshots here are explicitly hermetic TEST FIXTURES,
//! not production enrollment and not a persistent daemon.
#![forbid(unsafe_code)]

use native_process::{
    DisconnectPolicy, NativeProcessProvider, NativeProcessProviderConfig, ProcessMode, ProcessSpec,
};
use ptah_control::node_link::{NodeLinkControl, build_dispatch_frames};
use ptah_control::placement::{PlacementAuthorityOwner, PlacementAuthorityTiming};
use ptah_identifiers::EntityRef;
use ptah_node::{
    NodeDispatchError, NodeDispatchGuard, NodeProviderDispatchError,
    spawn_native_process_if_authorized,
};
use ptah_node_agent::{
    Architecture, NodeAgent, NodeCapabilitySnapshot, NodeHealth, NodeLifecycleState,
    NodeReachability, NodeResourceSnapshot, NodeStateProjection, OsFamily, PlatformFacts,
    ResourcePressure, ResourceQuantity, ResourceUnit, SnapshotOutcome,
};
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle, NodeHello, ProtocolVersion,
};
use ptah_placement_runtime::{
    PlacementPolicy, PlacementRequirement, ReservedResource, ResourceRequirement,
};
use ptah_platform_admission::{PlatformAdmissionProfile, PlatformNodeClass};
use ptah_provider_api::{
    ProviderGeneration, ProviderHealth, ProviderInstance, ProviderKind, ProviderReachability,
    ProviderReadiness, ProviderRevision,
};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid Ptah canonical identity")
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
}
fn agent() -> NodeAgent {
    let bootstrap = NodeAgent::bootstrap().expect("Node bootstrap");
    NodeAgent::restart(bootstrap.restart_seed()).expect("positive current generation")
}

fn snapshot(
    node: &NodeAgent,
    capability: EntityRef,
    provider: EntityRef,
) -> NodeCapabilitySnapshot {
    NodeCapabilitySnapshot::new(
        node.node_ref(),
        node.generation(),
        node.connection_epoch(),
        SnapshotOutcome::Complete,
        "supervisor-e05-gateway-test-fixture",
        PlatformFacts {
            os_family: OsFamily::Linux,
            os_name: Some(String::from("test-linux")),
            os_version: None,
            kernel_name: None,
            kernel_version: None,
            architecture: Architecture::X86_64,
            architecture_detail: None,
        },
        vec![capability],
        vec![entity("runtime.capability-verification")],
        vec![provider],
        vec![entity("core.node_observation")],
        vec![entity("proof.receipt")],
        Vec::new(),
    )
    .expect("A02 capability fixture")
}

fn resource(node: &NodeAgent) -> NodeResourceSnapshot {
    NodeResourceSnapshot::new(
        node.node_ref(),
        node.generation(),
        node.connection_epoch(),
        SnapshotOutcome::Complete,
        vec![ResourceQuantity {
            resource_key: String::from("cpu"),
            unit: ResourceUnit::Cores,
            observed_total: 2.0,
            administratively_allocatable: 2.0,
            reserved: 0.0,
            consumed: 0.0,
            currently_available: 2.0,
            pressure: ResourcePressure::Normal,
            observation_refs: vec![entity("core.node_observation")],
        }],
        vec![entity("core.node_observation")],
        vec![entity("proof.receipt")],
        Vec::new(),
    )
    .expect("A02 resource fixture")
}

fn provider(node: &NodeAgent) -> NativeProcessProvider {
    let revision_ref = entity("runtime.provider_revision");
    let facility = entity("runtime.facility");
    let revision = ProviderRevision {
        revision_ref: revision_ref.clone(),
        provider_ref: entity("runtime.provider"),
        provider_kind: ProviderKind::Process,
        implementation_name: String::from("native-process"),
        implementation_version: String::from("0.1.0"),
        build_or_package_digest: String::from("sha256:supervisor-test-fixture"),
        configuration_digest: String::from("sha256:supervisor-test-config"),
        supported_facility_refs: vec![facility],
        capability_claim_refs: Vec::new(),
        dependency_refs: Vec::new(),
        node_requirements: Vec::new(),
        security_requirements: Vec::new(),
        known_limitations: Vec::new(),
    };
    let instance = ProviderInstance {
        instance_ref: entity("runtime.provider_instance"),
        provider_revision_ref: revision_ref,
        node_ref: node
            .node_id()
            .entity_ref(node.generation(), node.connection_epoch()),
        node_generation: node.generation().value(),
        provider_generation: ProviderGeneration::new(1).expect("positive generation"),
        connection_epoch: node.connection_epoch().value(),
        reachability: ProviderReachability::Reachable,
        readiness: ProviderReadiness::Ready,
        health: ProviderHealth::Healthy,
        endpoint_aliases: Vec::new(),
        process_or_service_refs: Vec::new(),
        observation_refs: vec![entity("proof.evidence")],
        started_at: String::from("2026-10-13T00:00:00Z"),
        limitations: Vec::new(),
    };
    NativeProcessProvider::new(NativeProcessProviderConfig {
        revision,
        instance,
        clock: Arc::new(|| String::from("2026-10-13T00:00:00Z")),
    })
    .expect("A05 provider")
}
fn process_spec(program: &str) -> ProcessSpec {
    ProcessSpec {
        program: String::from(program),
        args: Vec::new(),
        env: BTreeMap::new(),
        clear_env: false,
        cwd: None,
        mode: ProcessMode::Pipes,
        max_stream_bytes: 4096,
        disconnect_policy: DisconnectPolicy::Retain,
    }
}

struct Fixture {
    node: NodeAgent,
    control: PlacementAuthorityOwner,
    capability: EntityRef,
    provider_revision: EntityRef,
}
impl Fixture {
    fn new() -> Self {
        let node = agent();
        // Only a test enrollment. Production must accept a real authenticated
        // E01 mTLS peer, not a locally constructed fingerprint.
        let fingerprint = CredentialFingerprint::from_der(b"supervisor-e05-gateway-fixture");
        let approved = ApprovedNodeEnrollment::new(
            entity("core.node_enrollment"),
            node.node_id(),
            EnrollmentLifecycle::Approved,
            vec![String::from("node.connect")],
            vec![fingerprint],
            None,
        )
        .expect("test enrollment");
        let enrollment_ref = approved.enrollment_ref().clone();
        let mut control = PlacementAuthorityOwner::new(NodeLinkControl::new(
            ProtocolVersion { major: 1, minor: 0 },
            vec![approved],
        ));
        let hello = NodeHello {
            supported_major: 1,
            minimum_minor: 0,
            maximum_minor: 0,
            node_id: node.node_id(),
            node_generation: node.generation(),
            connection_epoch: node.connection_epoch(),
            enrollment_ref,
            agent_revision: String::from("supervisor-gateway-test-fixture"),
            capability_snapshot_ref: None,
        };
        let session = control
            .accept_hello(&hello, fingerprint, now())
            .expect("E01 current fixture session");
        let capability = entity("runtime.capability");
        let provider_revision = entity("runtime.provider_revision");
        let caps = snapshot(&node, capability.clone(), provider_revision.clone());
        control
            .accept_capability(&session, &caps)
            .expect("E01/A02 bound capability");
        control
            .accept_resource(&session, &resource(&node))
            .expect("E01/A02 bound resources");
        let state = NodeStateProjection {
            node_ref: node.node_ref(),
            lifecycle: NodeLifecycleState::Active,
            node_generation: node.generation(),
            connection_epoch: node.connection_epoch(),
            current_reachability: NodeReachability::Online,
            current_health: NodeHealth::Healthy,
            capability_snapshot_refs: vec![caps.snapshot_ref.clone()],
            resource_snapshot_refs: Vec::new(),
            observation_refs: vec![entity("core.node_observation")],
        };
        control
            .admit_platform_node(
                &session,
                &state,
                &PlatformAdmissionProfile::new(
                    PlatformNodeClass::AlwaysOnLinux,
                    vec![capability.clone()],
                    vec![provider_revision.clone()],
                    vec![Architecture::X86_64],
                    false,
                ),
            )
            .expect("E05 platform admission");
        Self {
            node,
            control,
            capability,
            provider_revision,
        }
    }

    fn issue(&mut self) -> ptah_control::node_link::DispatchAuthorityFrames {
        let requirement = PlacementRequirement::new(
            entity("activity.attempt"),
            vec![self.capability.clone()],
            vec![self.provider_revision.clone()],
            vec![ResourceRequirement::new("cpu", ResourceUnit::Cores, 1.0).expect("cpu")],
            Some(OsFamily::Linux),
        );
        let moment = now();
        let grant = self
            .control
            .place_admitted_and_issue(
                PlatformNodeClass::AlwaysOnLinux,
                &requirement,
                PlacementPolicy::strict(),
                vec![ReservedResource::new("cpu", ResourceUnit::Cores, 1.0).expect("cpu")],
                PlacementAuthorityTiming::new(moment, moment + 120, moment + 90),
            )
            .expect("control-issued E02 authority");
        build_dispatch_frames(
            &grant,
            entity("runtime.dispatch"),
            entity("activity.operation"),
        )
    }
}

#[cfg(unix)]
#[test]
fn e05_admitted_e02_issued_authority_reaches_real_native_provider() {
    let mut fixture = Fixture::new();
    let frames = fixture.issue();
    let mut guard = NodeDispatchGuard::for_agent(&fixture.node);
    guard
        .accept_reservation(&fixture.node, &frames.reservation, now())
        .expect("reservation accepted");
    guard
        .accept_lease(&fixture.node, &frames.lease, now())
        .expect("lease accepted");
    let provider = provider(&fixture.node);
    let expected = provider
        .attempt_context(1, entity("runtime.facility"))
        .expect("provider context");
    let id = spawn_native_process_if_authorized(
        &guard,
        &fixture.node,
        &frames.request,
        now(),
        &provider,
        &expected,
        process_spec("/bin/true"),
    )
    .expect("E02-authorized A05 process");
    let exit = provider
        .wait_for_exit(id, Duration::from_secs(5))
        .expect("process wait");
    assert!(exit.success);
    let observed = provider.snapshot(id).expect("read-back actual A05 process");
    assert_eq!(observed.record.node_generation, expected.node_generation);
    assert_eq!(
        observed.record.provider_generation.value(),
        expected.provider_generation
    );
}

#[cfg(unix)]
#[test]
fn missing_node_side_lease_cannot_execute_a05() {
    let mut fixture = Fixture::new();
    let frames = fixture.issue();
    let guard = NodeDispatchGuard::for_agent(&fixture.node);
    let provider = provider(&fixture.node);
    let expected = provider
        .attempt_context(1, entity("runtime.facility"))
        .expect("provider context");
    let result = spawn_native_process_if_authorized(
        &guard,
        &fixture.node,
        &frames.request,
        now(),
        &provider,
        &expected,
        process_spec("/bin/true"),
    );
    assert!(matches!(
        result,
        Err(NodeProviderDispatchError::Authority(
            NodeDispatchError::UnknownReservation
        ))
    ));
}

#[cfg(unix)]
#[test]
fn stale_or_expired_lease_cannot_execute_a05() {
    let mut fixture = Fixture::new();
    let frames = fixture.issue();
    let mut guard = NodeDispatchGuard::for_agent(&fixture.node);
    guard
        .accept_reservation(&fixture.node, &frames.reservation, now())
        .expect("reservation");
    guard
        .accept_lease(&fixture.node, &frames.lease, now())
        .expect("lease");
    let provider = provider(&fixture.node);
    let expected = provider
        .attempt_context(1, entity("runtime.facility"))
        .expect("provider");
    let after_expiry = frames.lease.expires_at_unix_seconds + 1;
    let result = spawn_native_process_if_authorized(
        &guard,
        &fixture.node,
        &frames.request,
        after_expiry,
        &provider,
        &expected,
        process_spec("/bin/true"),
    );
    assert!(matches!(
        result,
        Err(NodeProviderDispatchError::Authority(
            NodeDispatchError::ExpiredLease
        ))
    ));
}

// An explicitly opted-in KRATOS consumer proof. It uses actual Ptah E02/A05
// process execution, but the E01 identity/Node evidence remain TEST FIXTURES.
// It cannot be used to claim production enrollment or an installed gateway.
#[cfg(unix)]
#[test]
#[ignore = "requires explicit TTG_PTAH_SIM_REPO and local TTG-Simulation fixture"]
fn ptah_gateway_executes_real_ttg_simulation_as_candidate_only() {
    use sha2::{Digest, Sha256};
    let root = std::env::var("TTG_PTAH_SIM_REPO").expect("explicit simulation root required");
    let repo = std::path::Path::new(&root)
        .canonicalize()
        .expect("simulation root");
    assert!(repo.join("pyproject.toml").is_file());
    assert!(repo.join("src/ttg_simulation/cli.py").is_file());
    assert!(repo.join("contracts").is_dir());
    let runner = repo.join(".tmp/ci-proof-venv/bin/ttg-sim");
    let request = repo.join(".tmp/ptah-e05-consumption-sim-20261001.json");
    assert!(
        runner.is_file() && request.is_file(),
        "frozen local consumer missing"
    );
    let mut fixture = Fixture::new();
    let frames = fixture.issue();
    let mut guard = NodeDispatchGuard::for_agent(&fixture.node);
    guard
        .accept_reservation(&fixture.node, &frames.reservation, now())
        .expect("reservation");
    guard
        .accept_lease(&fixture.node, &frames.lease, now())
        .expect("lease");
    let provider = provider(&fixture.node);
    let expected = provider
        .attempt_context(1, entity("runtime.facility"))
        .expect("provider");
    let mut env = BTreeMap::new();
    env.insert(String::from("TTG_SIM_ROOT"), root.clone());
    let id = spawn_native_process_if_authorized(
        &guard,
        &fixture.node,
        &frames.request,
        now(),
        &provider,
        &expected,
        ProcessSpec {
            program: runner.to_string_lossy().into_owned(),
            args: vec![
                String::from("simulate"),
                request.to_string_lossy().into_owned(),
            ],
            env,
            clear_env: false,
            cwd: Some(root),
            mode: ProcessMode::Pipes,
            max_stream_bytes: 100_000,
            disconnect_policy: DisconnectPolicy::Retain,
        },
    )
    .expect("Ptah-issued authority reaches Simulation process");
    let exit = provider
        .wait_for_exit(id, Duration::from_secs(30))
        .expect("consumer exit");
    assert!(exit.success, "consumer execution must succeed");
    let snapshot = provider.snapshot(id).expect("actual provider receipt");
    let stdout = snapshot.stdout.expect("stdout");
    assert_eq!(
        stdout.truncated_bytes, 0,
        "no silently truncated Simulation proof"
    );
    let output: serde_json::Value = serde_json::from_slice(&stdout.bytes).expect("Simulation JSON");
    assert_eq!(output["schema"], "ttg.simulation-result.v2");
    assert_eq!(output["qualification_status"], "candidate");
    assert_eq!(output["authority_granted"], false);
    assert_eq!(
        output["candidate_inference"]["winner"]["authority_violations"],
        0
    );
    let digest = Sha256::digest(&stdout.bytes);
    let digest_text = format!("{digest:x}");
    eprintln!("PTAH_SIMULATION_ACTUAL_A05_SHA256={digest_text}");
    eprintln!("PTAH_SIMULATION_PROOF_STATUS=TEST_FIXTURE_AUTHORITY_ONLY");
}
