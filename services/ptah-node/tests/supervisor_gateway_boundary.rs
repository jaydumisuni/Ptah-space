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
    session: ptah_node_link::SessionBinding,
}
impl Fixture {
    fn new() -> Self {
        Self::with_fingerprint(CredentialFingerprint::from_der(
            b"supervisor-e05-gateway-fixture",
        ))
    }
    fn with_fingerprint(fingerprint: CredentialFingerprint) -> Self {
        let node = agent();
        // Only a test enrollment. Production must accept a real authenticated
        // E01 mTLS peer, not a locally constructed fingerprint.
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
            session,
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
#[allow(clippy::too_many_lines)]
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

    let req_path = std::env::var("TTG_PTAH_SHADOW_REQUEST").expect("shadow request path required");
    let shadow: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&req_path).expect("shadow request file"))
            .expect("shadow JSON");
    let digest = verify_shadow_digest(&shadow).expect("exact shadow request");
    assert_eq!(shadow["schema"], "ttg.cookpit.ptah-shadow-preflight.v1");
    assert_eq!(shadow["mode"], "SHADOW_PREPARE_ONLY");
    assert_eq!(shadow["project_id"], "ptah");
    assert_eq!(shadow["ptah_execution_status"], "NOT_DISPATCHED");
    assert_eq!(shadow["authority_granted"], false);
    assert_eq!(shadow["promotion_authorized"], false);
    assert_eq!(shadow["requested_effect"], "TTG_SIMULATION_CANDIDATE_ONLY");
    assert_eq!(
        shadow["simulation_repo"].as_str().unwrap(),
        repo.to_string_lossy()
    );
    let sim_head = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&repo)
        .output()
        .expect("source Git check");
    assert!(sim_head.status.success());
    assert_eq!(
        String::from_utf8_lossy(&sim_head.stdout).trim(),
        shadow["simulation_head"].as_str().unwrap()
    );
    let ptah_root = shadow["ptah_repo"]
        .as_str()
        .expect("Ptah construction repo");
    let ptah_head = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(ptah_root)
        .output()
        .expect("Ptah Git check");
    assert!(ptah_head.status.success());
    assert_eq!(
        String::from_utf8_lossy(&ptah_head.stdout).trim(),
        shadow["ptah_head"].as_str().unwrap()
    );
    assert_eq!(shadow["ptah_remote_head"], shadow["ptah_head"]);
    eprintln!("PTAH_SUPERVISOR_SHADOW_REQUEST_DIGEST={digest}");
    let mut fixture = Fixture::new();
    let frames = fixture.issue();
    let mut guard = NodeDispatchGuard::for_agent(&fixture.node);
    guard
        .accept_reservation(&fixture.node, &frames.reservation, now())
        .expect("reservation");
    guard
        .accept_lease(&fixture.node, &frames.lease, now())
        .expect("lease");
    // Commit the attempt ownership before the provider can execute.
    let journal_path = temporary_gateway_database();
    let mut journal = ptah_node::gateway_journal::GatewayJournal::open(&journal_path)
        .expect("durable attempt journal");
    let provider = provider(&fixture.node);
    let expected = provider
        .attempt_context(1, entity("runtime.facility"))
        .expect("provider");
    let mut env = BTreeMap::new();
    env.insert(String::from("TTG_SIM_ROOT"), root.clone());
    let id = journal
        .spawn_once(
            &fixture.node,
            &guard,
            &frames.request,
            now(),
            &digest,
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
    let stdout_hash = Sha256::digest(&stdout.bytes);
    let durable_readback = journal
        .complete_from_process(&fixture.node, &frames.request, &digest, &provider, id)
        .expect("persist actual A05 receipt");
    assert_eq!(durable_readback, format!("sha256:{stdout_hash:x}"));
    drop(journal);
    let recovered = ptah_node::gateway_journal::GatewayJournal::open(&journal_path)
        .expect("durable readback after restart");
    assert_eq!(
        recovered
            .get(&frames.request)
            .expect("readback")
            .expect("attempt")
            .phase,
        "completed"
    );
    drop(recovered);
    cleanup_gateway_database(&journal_path);
    let digest_text = format!("{stdout_hash:x}");
    eprintln!("PTAH_SIMULATION_ACTUAL_A05_SHA256={digest_text}");
    eprintln!("PTAH_SIMULATION_PROOF_STATUS=TEST_FIXTURE_AUTHORITY_ONLY");
}

// Explicit opt-in specialist consumption proof. All E01/A02/E05/E02 authority
// in this test is fixture-created. Do not use it as production enrollment.
#[cfg(unix)]
#[test]
#[ignore = "requires TTG_PTAH_CREATIVE_REPO and a local Pillow-enabled interpreter"]
#[allow(clippy::too_many_lines)]
fn e02_fixture_grant_dispatches_real_creative_studio_and_preserves_node_receipt() {
    use ptah_node::gateway_journal::GatewayJournal;
    use sha2::{Digest as _, Sha256};
    let root =
        std::env::var("TTG_PTAH_CREATIVE_REPO").expect("explicit Creative Studio path required");
    let repo = std::path::Path::new(&root)
        .canonicalize()
        .expect("Creative Studio checkout");
    assert!(repo.join("src/ttg_project_schema.py").is_file());
    let worker = repo.join("integrations/ptah/creative_worker.py");
    let verifier = repo.join("integrations/ptah/verify_output.py");
    assert!(worker.is_file() && verifier.is_file());

    let proof = repo.join(".workspace/scratch").join(format!(
        "e07-creative-node-{}",
        ptah_identifiers::EntityId::new_v7()
    ));
    std::fs::create_dir_all(&proof).expect("isolated Studio-owned proof directory");
    let request = proof.join("creative_request.json");
    let output = proof.join("output");
    let request_id = String::from("ptah_e02_creative");
    let payload = serde_json::json!({
        "schema": "ttg.creative.ptah.request.v1",
        "operation": "scene_edit",
        "request_id": request_id,
        "text": "THETECHGUY",
        "move_x": 108
    });
    let request_bytes = serde_json::to_vec_pretty(&payload).expect("request JSON");
    std::fs::write(&request, &request_bytes).expect("local bounded job request");
    let digest = format!("sha256:{:x}", Sha256::digest(&request_bytes));

    let mut fixture = Fixture::new();
    let frames = fixture.issue();
    let mut guard = NodeDispatchGuard::for_agent(&fixture.node);
    guard
        .accept_reservation(&fixture.node, &frames.reservation, now())
        .expect("Control-issued test Reservation");
    guard
        .accept_lease(&fixture.node, &frames.lease, now())
        .expect("Control-issued test Lease/Fence");
    let provider = provider(&fixture.node);
    let expected = provider
        .attempt_context(1, entity("runtime.facility"))
        .expect("Node-local A05 attempt");
    let journal_path = temporary_gateway_database();
    let mut journal = GatewayJournal::open(&journal_path).expect("durable Node journal");
    let interpreter = std::env::var("TTG_PTAH_CREATIVE_PYTHON")
        .unwrap_or_else(|_| String::from("/usr/bin/python3"));
    let spec = ProcessSpec {
        program: interpreter.clone(),
        args: vec![
            String::from("-B"),
            worker.to_string_lossy().into_owned(),
            String::from("--request"),
            request.to_string_lossy().into_owned(),
            String::from("--output"),
            output.to_string_lossy().into_owned(),
        ],
        env: BTreeMap::new(),
        clear_env: false,
        cwd: Some(repo.to_string_lossy().into_owned()),
        mode: ProcessMode::Pipes,
        max_stream_bytes: 64 * 1024,
        disconnect_policy: DisconnectPolicy::Retain,
    };
    let process = journal
        .spawn_once(
            &fixture.node,
            &guard,
            &frames.request,
            now(),
            &digest,
            &provider,
            &expected,
            spec.clone(),
        )
        .expect("Ptah E02 fixture-authorized real Creative Studio A05");
    let exit = provider
        .wait_for_exit(process, Duration::from_secs(40))
        .expect("independent provider exit");
    let snapshot = provider.snapshot(process).expect("actual stream");
    let stdout = snapshot.stdout.expect("stdio observation");
    assert!(
        exit.success,
        "Creative Studio worker must exit successfully"
    );
    assert_eq!(stdout.truncated_bytes, 0, "no truncated proof bytes");
    let worker_record: serde_json::Value =
        serde_json::from_slice(&stdout.bytes).expect("actual Studio result");
    assert_eq!(
        worker_record["schema"],
        "ttg.creative.ptah.worker_result.v1"
    );
    assert_eq!(worker_record["request_id"], request_id);
    assert!(output.join("editable.ttgstudio.json").is_file());
    assert!(output.join("preview.png").is_file());
    assert!(output.join("project_bundle.zip").is_file());

    let check_result = std::process::Command::new(&interpreter)
        .args([
            "-B",
            verifier.to_str().expect("verification path"),
            "--request",
            request.to_str().expect("request path"),
            "--output",
            output.to_str().expect("output path"),
        ])
        .current_dir(&repo)
        .output()
        .expect("separate independent Studio verifier");
    assert!(
        check_result.status.success(),
        "Creative output verification rejected: {}",
        String::from_utf8_lossy(&check_result.stderr)
    );
    let output_receipt: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join("independent_verification.json"))
            .expect("observed verifier report"),
    )
    .expect("verifier JSON");
    assert_eq!(output_receipt["passed"], true);
    assert_eq!(
        output_receipt["registered_files"].as_array().unwrap().len(),
        3
    );

    let stdout_digest = journal
        .complete_from_process(&fixture.node, &frames.request, &digest, &provider, process)
        .expect("actual A05 completion receipt");
    assert_eq!(
        stdout_digest,
        format!("sha256:{:x}", Sha256::digest(&stdout.bytes))
    );
    drop(journal);
    let mut reopened = GatewayJournal::open(&journal_path).expect("durable Node restart recovery");
    assert_eq!(
        reopened.get(&frames.request).unwrap().unwrap().phase,
        "completed"
    );
    assert!(
        reopened
            .spawn_once(
                &fixture.node,
                &guard,
                &frames.request,
                now(),
                &digest,
                &provider,
                &expected,
                spec,
            )
            .is_err(),
        "reopened Node journal may not execute an already consumed Attempt"
    );
    drop(reopened);
    cleanup_gateway_database(&journal_path);
    eprintln!("PTAH_CREATIVE_STUDIO_E02_A05_RESULT=FIXTURE_AUTHORITY_PASS");
    eprintln!("PTAH_CREATIVE_STUDIO_E07_PRODUCTION_ADMISSION=NOT_PROVEN");
}

fn verify_shadow_digest(value: &serde_json::Value) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let mut canonical = value.clone();
    let map = canonical
        .as_object_mut()
        .ok_or("request must be JSON object")?;
    let claimed = map
        .remove("request_digest")
        .and_then(|v| v.as_str().map(ToOwned::to_owned))
        .ok_or("missing shadow digest")?;
    let actual = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&canonical).map_err(|e| e.to_string())?)
    );
    if claimed != actual {
        return Err(String::from("shadow digest mismatch"));
    }
    Ok(actual)
}

#[test]
fn shadow_digest_rejects_tampered_payload() {
    use sha2::{Digest, Sha256};
    let mut payload = serde_json::json!({"mode":"SHADOW_PREPARE_ONLY","authority_granted":false});
    let original = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&payload).unwrap())
    );
    payload["request_digest"] = original.clone().into();
    assert_eq!(verify_shadow_digest(&payload), Ok(original));
    payload["authority_granted"] = true.into();
    assert!(verify_shadow_digest(&payload).is_err());
}

#[cfg(unix)]
fn temporary_gateway_database() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "ptah-gateway-test-{}.sqlite3",
        ptah_identifiers::EntityId::new_v7()
    ))
}
#[cfg(unix)]
fn cleanup_gateway_database(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn e07_sigkill_after_durable_node_stage_requires_reconciliation() {
    use ptah_node::gateway_journal::{GatewayJournal, StageResult};
    use ptah_node_link::{DispatchLeaseFrame, DispatchRequestFrame, DispatchReservationFrame};
    let folder = std::env::temp_dir().join(format!(
        "ptah-e07-sigkill-{}",
        ptah_identifiers::EntityId::new_v7()
    ));
    if let Ok(path) = std::env::var("PTAH_E07_SIGKILL_CHILD") {
        let path = std::path::PathBuf::from(path);
        let mut fixture = Fixture::new();
        let frames = fixture.issue();
        let mut guard = NodeDispatchGuard::for_agent(&fixture.node);
        guard
            .accept_reservation(&fixture.node, &frames.reservation, now())
            .unwrap();
        guard
            .accept_lease(&fixture.node, &frames.lease, now())
            .unwrap();
        let digest = format!("sha256:{}", "c".repeat(64));
        let journal_path = path.join("attempt.sqlite3");
        let mut journal = GatewayJournal::open(&journal_path).unwrap();
        assert_eq!(
            journal
                .stage(&fixture.node, &guard, &frames.request, now(), &digest)
                .unwrap(),
            StageResult::StagedNew
        );
        let frames_bytes = serde_json::to_vec(&(
            fixture.node,
            frames.reservation,
            frames.lease,
            frames.request,
        ))
        .unwrap();
        std::fs::write(path.join("authority-fixture.json"), frames_bytes).unwrap();
        std::fs::write(path.join("committed.marker"), b"staged_after_sqlite_commit").unwrap();
        std::fs::File::open(path.join("committed.marker"))
            .unwrap()
            .sync_all()
            .unwrap();
        std::thread::sleep(Duration::from_secs(30));
        panic!("the test parent must terminate the child before its normal exit");
    }
    std::fs::create_dir_all(&folder).unwrap();
    let executable = std::env::current_exe().unwrap();
    let mut child = std::process::Command::new(executable)
        .arg("--exact")
        .arg("e07_sigkill_after_durable_node_stage_requires_reconciliation")
        .arg("--nocapture")
        .env("PTAH_E07_SIGKILL_CHILD", &folder)
        .spawn()
        .expect("bounded gateway test child");
    let marker = folder.join("committed.marker");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !marker.is_file() && std::time::Instant::now() < deadline {
        assert!(
            child.try_wait().unwrap().is_none(),
            "gateway child died before recording the durable stage"
        );
        std::thread::sleep(Duration::from_millis(30));
    }
    assert!(marker.is_file(), "Node stage marker missing");
    child.kill().expect("SIGKILL the exact test child");
    let status = child.wait().expect("reap only the test child");
    assert!(
        !status.success(),
        "SIGKILL must not be mistaken for success"
    );

    let record = std::fs::read(folder.join("authority-fixture.json")).unwrap();
    let (node, reservation, lease, request): (
        NodeAgent,
        DispatchReservationFrame,
        DispatchLeaseFrame,
        DispatchRequestFrame,
    ) = serde_json::from_slice(&record).unwrap();
    let mut guard = NodeDispatchGuard::for_agent(&node);
    guard
        .accept_reservation(&node, &reservation, now())
        .unwrap();
    guard.accept_lease(&node, &lease, now()).unwrap();
    let digest = format!("sha256:{}", "c".repeat(64));
    let database = folder.join("attempt.sqlite3");
    let mut recovered = GatewayJournal::open(&database).expect("reopen after OS SIGKILL");
    let attempt = recovered
        .get(&request)
        .unwrap()
        .expect("retained exact dispatch");
    assert_eq!(attempt.phase, "needs_reconciliation");
    assert!(
        attempt.exit_code.is_none(),
        "no invented process completion"
    );
    assert!(attempt.stdout_digest.is_none(), "no invented stdout");
    assert_eq!(attempt.digest, digest);
    assert_eq!(recovered.unresolved().unwrap().len(), 1);
    assert_eq!(
        recovered
            .stage(&node, &guard, &request, now(), &digest)
            .unwrap(),
        StageResult::AlreadyRegistered
    );
    // A new external side effect cannot be inferred from the old durable record.
    assert_eq!(recovered.unresolved().unwrap().len(), 1);
    drop(recovered);
    cleanup_gateway_database(&database);
    let _ = std::fs::remove_file(format!("{}.lock", database.display()));
    let _ = std::fs::remove_dir_all(folder);
    eprintln!("PTAH_E07_SIGKILL_RECONCILIATION=PASS; PRODUCTION_HARD_REBOOT=NOT_PROVEN");
}

#[cfg(unix)]
#[test]
fn gateway_journal_preserves_pre_effect_state_and_never_replays_on_restart() {
    use ptah_node::gateway_journal::{GatewayJournal, StageResult};
    let path = temporary_gateway_database();
    let mut fixture = Fixture::new();
    let frames = fixture.issue();
    let mut guard = NodeDispatchGuard::for_agent(&fixture.node);
    guard
        .accept_reservation(&fixture.node, &frames.reservation, now())
        .expect("reservation");
    guard
        .accept_lease(&fixture.node, &frames.lease, now())
        .expect("lease");
    let digest = format!("sha256:{}", "a".repeat(64));
    {
        let mut journal = GatewayJournal::open(&path).expect("durable journal");
        assert_eq!(
            journal
                .stage(&fixture.node, &guard, &frames.request, now(), &digest)
                .expect("stage"),
            StageResult::StagedNew
        );
        assert_eq!(
            journal
                .get(&frames.request)
                .expect("readback")
                .expect("attempt")
                .phase,
            "in_flight"
        );
    }
    {
        let mut recovered = GatewayJournal::open(&path).expect("reopen after crash");
        assert_eq!(
            recovered
                .get(&frames.request)
                .expect("readback")
                .expect("attempt")
                .phase,
            "needs_reconciliation"
        );
        let queue = recovered.unresolved().expect("recovery inventory");
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].digest, digest);
        assert_eq!(queue[0].fence, frames.request.fence);

        assert_eq!(
            recovered
                .stage(&fixture.node, &guard, &frames.request, now(), &digest)
                .expect("retry"),
            StageResult::AlreadyRegistered
        );
        assert!(
            recovered
                .stage(
                    &fixture.node,
                    &guard,
                    &frames.request,
                    now(),
                    &format!("sha256:{}", "b".repeat(64))
                )
                .is_err()
        );
    }
    cleanup_gateway_database(&path);
}
#[cfg(unix)]
#[test]
fn gateway_journal_retains_actual_a05_completion_and_rejects_second_completion() {
    use ptah_node::gateway_journal::{GatewayJournal, StageResult};
    use sha2::Digest as _;
    let path = temporary_gateway_database();
    let mut fixture = Fixture::new();
    let frames = fixture.issue();
    let mut guard = NodeDispatchGuard::for_agent(&fixture.node);
    guard
        .accept_reservation(&fixture.node, &frames.reservation, now())
        .expect("reservation");
    guard
        .accept_lease(&fixture.node, &frames.lease, now())
        .expect("lease");
    let digest = format!("sha256:{}", "c".repeat(64));
    let mut journal = GatewayJournal::open(&path).expect("journal");
    assert_eq!(
        journal
            .stage(&fixture.node, &guard, &frames.request, now(), &digest)
            .expect("stage"),
        StageResult::StagedNew
    );
    let provider = provider(&fixture.node);
    let expected = provider
        .attempt_context(1, entity("runtime.facility"))
        .expect("context");
    let id = spawn_native_process_if_authorized(
        &guard,
        &fixture.node,
        &frames.request,
        now(),
        &provider,
        &expected,
        process_spec("/bin/true"),
    )
    .expect("actual A05 spawn");
    provider
        .wait_for_exit(id, Duration::from_secs(3))
        .expect("observed exit");
    let observed = journal
        .complete_from_process(&fixture.node, &frames.request, &digest, &provider, id)
        .expect("receipt");
    assert_eq!(observed, format!("sha256:{:x}", sha2::Sha256::digest(b"")));
    assert!(
        journal
            .complete_from_process(&fixture.node, &frames.request, &digest, &provider, id)
            .is_err()
    );
    drop(journal);
    let reopened = GatewayJournal::open(&path).expect("reopen");
    let record = reopened
        .get(&frames.request)
        .expect("read")
        .expect("durable result");
    assert_eq!(record.phase, "completed");
    assert_eq!(record.exit_code, Some(0));
    assert_eq!(record.stdout_digest.as_deref(), Some(observed.as_str()));
    drop(reopened);
    cleanup_gateway_database(&path);
}

#[cfg(unix)]
#[test]
fn gateway_journal_single_writer_ownership_is_exclusive() {
    use ptah_node::gateway_journal::GatewayJournal;
    let path = temporary_gateway_database();
    let first = GatewayJournal::open(&path).expect("first owner");
    assert!(
        GatewayJournal::open(&path).is_err(),
        "second owner must fail closed"
    );
    drop(first);
    let reopened = GatewayJournal::open(&path).expect("lock released on close");
    assert!(reopened.unresolved().expect("inventory").is_empty());
    drop(reopened);
    cleanup_gateway_database(&path);
    let _ = std::fs::remove_file(format!("{}.lock", path.display()));
}

#[cfg(unix)]
#[test]
fn journaled_e02_spawn_is_idempotent_and_durably_completed() {
    use ptah_node::gateway_journal::GatewayJournal;
    let path = temporary_gateway_database();
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
        .expect("context");
    let digest = format!("sha256:{}", "d".repeat(64));
    let mut journal = GatewayJournal::open(&path).expect("owner journal");
    let id = journal
        .spawn_once(
            &fixture.node,
            &guard,
            &frames.request,
            now(),
            &digest,
            &provider,
            &expected,
            process_spec("/bin/true"),
        )
        .expect("durable E02-authorized launch");
    assert_eq!(
        journal
            .get(&frames.request)
            .expect("lookup")
            .expect("durably staged")
            .phase,
        "in_flight"
    );
    assert!(
        journal
            .spawn_once(
                &fixture.node,
                &guard,
                &frames.request,
                now(),
                &digest,
                &provider,
                &expected,
                process_spec("/bin/true"),
            )
            .is_err(),
        "duplicate must not relaunch"
    );
    assert!(
        provider
            .wait_for_exit(id, Duration::from_secs(5))
            .expect("real exit")
            .success
    );
    journal
        .complete_from_process(&fixture.node, &frames.request, &digest, &provider, id)
        .expect("actual receipt");
    drop(journal);
    let journal = GatewayJournal::open(&path).expect("reopen after completion");
    assert_eq!(
        journal
            .get(&frames.request)
            .expect("lookup")
            .expect("receipt")
            .phase,
        "completed"
    );
    drop(journal);
    cleanup_gateway_database(&path);
}

const E02_CA: &[u8] = include_bytes!("../../../crates/ptah-node-link/tests/fixtures/ca.cert.der");
const E02_SERVER: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.cert.der");
const E02_SERVER_KEY: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.key.der");
const E02_CLIENT: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.cert.der");
const E02_CLIENT_KEY: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.key.der");

#[cfg(unix)]
#[allow(clippy::too_many_lines)]
async fn tls_e02_authority_exchange(mode: u8) -> Result<(), String> {
    use ptah_node::gateway_e02_wire::receive_one;
    use ptah_node::{NodeLinkClientConfig, connect_node_link};
    use ptah_node_link::{
        HelloAck, LinkMessage, TlsClientConfig, TlsIdentity, TlsServerConfig, TlsTrustRoots,
        accept_tls, read_frame, write_frame,
    };
    use tokio::net::TcpListener;
    let mut fixture = Fixture::with_fingerprint(CredentialFingerprint::from_der(E02_CLIENT));
    let frames = fixture.issue();
    let expected = frames.request.clone();
    let mut control = fixture.control;
    let current_session = fixture.session;
    let capability = fixture.capability;
    let provider_revision = fixture.provider_revision;
    let roots = || TlsTrustRoots::from_der(vec![E02_CA.to_vec()]).unwrap();
    let server_config = TlsServerConfig::new(
        TlsIdentity::from_der(vec![E02_SERVER.to_vec()], E02_SERVER_KEY.to_vec()).unwrap(),
        roots(),
    )
    .unwrap();
    let client_config = TlsClientConfig::new(
        TlsIdentity::from_der(vec![E02_CLIENT.to_vec()], E02_CLIENT_KEY.to_vec()).unwrap(),
        roots(),
    )
    .unwrap();
    let control_journal_path = temporary_gateway_database();
    let service_journal_path = control_journal_path.clone();
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = server.local_addr().unwrap();
    let service = tokio::spawn(async move {
        let (socket, _) = server.accept().await.unwrap();
        let mut tls = accept_tls(socket, &server_config).await.unwrap();
        let LinkMessage::Hello(hello) = read_frame(tls.stream_mut()).await.unwrap() else {
            panic!("Node must first send Hello")
        };
        assert_eq!(hello.node_id, frames.request.node_id);
        let ack = LinkMessage::HelloAck(HelloAck {
            selected_version: ProtocolVersion { major: 1, minor: 0 },
            node_id: hello.node_id,
            node_generation: hello.node_generation,
            connection_epoch: hello.connection_epoch,
        });
        write_frame(tls.stream_mut(), &ack).await.unwrap();
        if mode == 0 {
            use ptah_control::gateway_e02_dispatch::issue_and_send;
            let requirement = PlacementRequirement::new(
                entity("activity.attempt"),
                vec![capability],
                vec![provider_revision],
                vec![ResourceRequirement::new("cpu", ResourceUnit::Cores, 1.0).unwrap()],
                Some(OsFamily::Linux),
            );
            let instant = now();
            let mut journal = ptah_control::gateway_control_journal::ControlDispatchJournal::open(
                &service_journal_path,
            )
            .expect("Control durable writer");
            let grant = issue_and_send(
                &mut control,
                &current_session,
                &mut tls,
                PlatformNodeClass::AlwaysOnLinux,
                &requirement,
                PlacementPolicy::strict(),
                vec![ReservedResource::new("cpu", ResourceUnit::Cores, 1.0).unwrap()],
                PlacementAuthorityTiming::new(instant, instant + 120, instant + 90),
                entity("runtime.dispatch"),
                entity("activity.operation"),
                &mut journal,
                &format!("sha256:{}", "7".repeat(64)),
            )
            .await
            .expect("Control-owned live E02 issuance");
            assert_eq!(grant.request.node_id, hello.node_id);
            assert_eq!(
                journal.lookup(&grant).unwrap().unwrap().phase,
                "sent_unconfirmed"
            );
            return;
        }
        let first = LinkMessage::DispatchReservation(Box::new(frames.reservation));
        let mut second = LinkMessage::DispatchLease(Box::new(frames.lease));
        let third = LinkMessage::DispatchRequest(Box::new(frames.request));
        if mode == 2
            && let LinkMessage::DispatchLease(ref mut item) = second
        {
            item.expires_at_unix_seconds = now().saturating_sub(1);
        }
        let ordered = if mode == 1 {
            vec![second, first, third]
        } else {
            vec![first, second, third]
        };
        for msg in ordered {
            if write_frame(tls.stream_mut(), &msg).await.is_err() {
                break;
            }
        }
    });
    let config = NodeLinkClientConfig::new(
        endpoint,
        "localhost".into(),
        client_config,
        entity("core.node_enrollment"),
        "e02-tls-fixture".into(),
        ProtocolVersion { major: 1, minor: 0 },
    );
    let (_, mut stream) = connect_node_link(&fixture.node, &config)
        .await
        .map_err(|err| format!("{err:?}"))?;
    let got = receive_one(&fixture.node, &mut stream).await;
    service.await.expect("TLS control fixture join");
    if mode == 0 {
        let recovered = ptah_control::gateway_control_journal::ControlDispatchJournal::open(
            &control_journal_path,
        )
        .expect("Control restart");
        let entries = recovered
            .unresolved()
            .expect("Control uncertainty receipts");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].phase, "needs_reconciliation");
        drop(recovered);
    }
    cleanup_gateway_database(&control_journal_path);
    let _ = std::fs::remove_file(format!("{}.lock", control_journal_path.display()));

    if mode != 0 {
        assert!(
            got.is_err(),
            "untrusted/order-invalid E02 authority must fail"
        );
        return Ok(());
    }
    let (guard, frame) = got.map_err(|err| format!("{err:?}"))?;
    assert_eq!(frame.node_id, expected.node_id);
    assert_eq!(
        frame.attempt_ref.entity_kind,
        expected.attempt_ref.entity_kind
    );
    let path = temporary_gateway_database();
    let digest = format!("sha256:{}", "7".repeat(64));
    let mut journal = ptah_node::gateway_journal::GatewayJournal::open(&path).unwrap();
    let provider = provider(&fixture.node);
    let expected_context = provider
        .attempt_context(1, entity("runtime.facility"))
        .unwrap();
    let process = journal
        .spawn_once(
            &fixture.node,
            &guard,
            &frame,
            now(),
            &digest,
            &provider,
            &expected_context,
            process_spec("/bin/true"),
        )
        .map_err(|err| format!("{err:?}"))?;
    assert!(
        provider
            .wait_for_exit(process, Duration::from_secs(5))
            .unwrap()
            .success
    );
    journal
        .complete_from_process(&fixture.node, &frame, &digest, &provider, process)
        .unwrap();
    drop(journal);
    let reopened = ptah_node::gateway_journal::GatewayJournal::open(&path).unwrap();
    assert_eq!(reopened.get(&frame).unwrap().unwrap().phase, "completed");
    drop(reopened);
    cleanup_gateway_database(&path);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn authenticated_tls_e02_authority_executes_only_with_local_provider() {
    tls_e02_authority_exchange(0).await.expect("TLS dispatch");
}
#[cfg(unix)]
#[tokio::test]
async fn tls_e02_out_of_order_lease_is_denied() {
    tls_e02_authority_exchange(1)
        .await
        .expect("deny wrong order");
}
#[cfg(unix)]
#[tokio::test]
async fn tls_e02_expired_lease_is_denied() {
    tls_e02_authority_exchange(2)
        .await
        .expect("deny expired lease");
}

#[cfg(unix)]
#[test]
fn fence_increment_never_replays_unresolved_attempt_after_restart() {
    use ptah_node::gateway_journal::GatewayJournal;
    let path = temporary_gateway_database();
    let mut fixture = Fixture::new();
    let frames = fixture.issue();
    let mut guard = NodeDispatchGuard::for_agent(&fixture.node);
    guard
        .accept_reservation(&fixture.node, &frames.reservation, now())
        .unwrap();
    guard
        .accept_lease(&fixture.node, &frames.lease, now())
        .unwrap();
    let digest = format!("sha256:{}", "f".repeat(64));
    let mut first = GatewayJournal::open(&path).unwrap();
    first
        .stage(&fixture.node, &guard, &frames.request, now(), &digest)
        .unwrap();
    drop(first);
    let mut again = GatewayJournal::open(&path).unwrap();
    assert_eq!(again.unresolved().unwrap().len(), 1);
    let mut elevated = frames.lease.clone();
    elevated.lease_ref = entity("isolation.lease");
    elevated.fence += 1;
    guard.accept_lease(&fixture.node, &elevated, now()).unwrap();
    let mut next = frames.request.clone();
    next.dispatch_ref = entity("runtime.dispatch");
    next.lease_ref = elevated.lease_ref.clone();
    next.fence = elevated.fence;
    assert!(
        again
            .stage(&fixture.node, &guard, &next, now(), &digest)
            .is_err(),
        "a fresh fence must not replay an unresolved external effect"
    );
    assert_eq!(again.unresolved().unwrap().len(), 1);
    drop(again);
    cleanup_gateway_database(&path);
}

#[cfg(unix)]
#[test]
fn control_durable_journal_rejects_duplicate_and_replays_uncertainty_only() {
    use ptah_control::gateway_control_journal::ControlDispatchJournal;
    let path = temporary_gateway_database();
    let mut fixture = Fixture::new();
    let frames = fixture.issue();
    let digest = format!("sha256:{}", "d".repeat(64));
    let mut writer = ControlDispatchJournal::open(&path).expect("Control journal");
    assert!(
        ControlDispatchJournal::open(&path).is_err(),
        "exclusive Control writer"
    );
    writer
        .stage_issued(&frames, &digest)
        .expect("issue before send");
    assert!(
        writer.stage_issued(&frames, &digest).is_err(),
        "duplicate Attempt"
    );
    let mut changed = frames.clone();
    changed.request.dispatch_ref = entity("runtime.dispatch");
    assert!(
        writer.stage_issued(&changed, &digest).is_err(),
        "same Attempt different Dispatch"
    );
    assert!(
        writer.stage_issued(&frames, "sha256:INVALID").is_err(),
        "invalid digest"
    );
    let issued = writer.lookup(&frames).unwrap().unwrap();
    assert_eq!(issued.phase, "issued_unknown");
    assert_eq!(issued.request_digest, digest);
    writer
        .mark_sent(&frames)
        .expect("transport is not completion");
    assert_eq!(
        writer.lookup(&frames).unwrap().unwrap().phase,
        "sent_unconfirmed"
    );
    assert!(
        writer.mark_sent(&frames).is_err(),
        "cannot acknowledge twice"
    );
    drop(writer);
    let mut recovered = ControlDispatchJournal::open(&path).expect("restart");
    let unresolved = recovered.unresolved().unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].phase, "needs_reconciliation");
    assert_eq!(unresolved[0].request_digest, digest);
    assert!(
        recovered.stage_issued(&frames, &digest).is_err(),
        "no replay after crash"
    );
    drop(recovered);
    cleanup_gateway_database(&path);
    let _ = std::fs::remove_file(format!("{}.lock", path.display()));
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn signed_external_effect_receipt_survives_control_restart_without_replay() {
    use ptah_control::gateway_control_journal::ControlDispatchJournal;
    use ptah_control::gateway_witness::{
        EffectObservation, NodeCompletion, SignedEffectObservation, TrustedWitness,
        canonical_message,
    };
    use ptah_node::gateway_journal::GatewayJournal;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let mut fixture = Fixture::new();
    let frames = fixture.issue();
    let digest = format!("sha256:{}", "a".repeat(64));
    let control_path = temporary_gateway_database();
    let node_path = temporary_gateway_database();
    let mut control = ControlDispatchJournal::open(&control_path).unwrap();
    control.stage_issued(&frames, &digest).unwrap();
    control.mark_sent(&frames).unwrap();
    drop(control);
    let mut guard = NodeDispatchGuard::for_agent(&fixture.node);
    guard
        .accept_reservation(&fixture.node, &frames.reservation, now())
        .unwrap();
    guard
        .accept_lease(&fixture.node, &frames.lease, now())
        .unwrap();
    let provider = provider(&fixture.node);
    let expected = provider
        .attempt_context(1, entity("runtime.facility"))
        .unwrap();
    let mut journal = GatewayJournal::open(&node_path).unwrap();
    let process = journal
        .spawn_once(
            &fixture.node,
            &guard,
            &frames.request,
            now(),
            &digest,
            &provider,
            &expected,
            process_spec("/bin/true"),
        )
        .unwrap();
    assert!(
        provider
            .wait_for_exit(process, Duration::from_secs(5))
            .unwrap()
            .success
    );
    journal
        .complete_from_process(&fixture.node, &frames.request, &digest, &provider, process)
        .unwrap();
    let retained = journal.get(&frames.request).unwrap().unwrap();
    drop(journal);
    let observation = EffectObservation {
        schema: "ptah.external-effect-witness.v1".into(),
        witness_id: "independent-observer-test-only".into(),
        dispatch: serde_json::to_string(&frames.request.dispatch_ref).unwrap(),
        attempt: retained.attempt.clone(),
        request_digest: retained.digest.clone(),
        node: retained.node.clone(),
        generation: retained.generation,
        connection_epoch: retained.connection_epoch,
        fence: retained.fence,
        provider_generation: 1,
        process_identity: format!("test-process:{process:?}"),
        boot_identity: "test-boot-not-physical".into(),
        observed_exit_code: retained.exit_code.unwrap(),
        observed_stdout_digest: retained.stdout_digest.clone().unwrap(),
        observation_source: "signed hermetic test observation".into(),
    };
    let keypair = Ed25519KeyPair::from_seed_unchecked(&[21_u8; 32]).unwrap();
    let key: [u8; 32] = keypair.public_key().as_ref().try_into().unwrap();
    let signed = SignedEffectObservation {
        signature: keypair
            .sign(&canonical_message(&observation).unwrap())
            .as_ref()
            .to_vec(),
        observation,
    };
    let trusted = TrustedWitness {
        witness_id: "independent-observer-test-only",
        ed25519_public_key: &key,
    };
    let completion = NodeCompletion {
        attempt: retained.attempt,
        node: retained.node,
        generation: retained.generation,
        connection_epoch: retained.connection_epoch,
        request_digest: retained.digest,
        phase: retained.phase,
        fence: retained.fence,
        exit_code: retained.exit_code,
        stdout_digest: retained.stdout_digest,
    };
    let mut control = ControlDispatchJournal::open(&control_path).unwrap();
    assert_eq!(
        control.lookup(&frames).unwrap().unwrap().phase,
        "needs_reconciliation"
    );
    let mut unknown = completion.clone();
    unknown.phase = "needs_reconciliation".into();
    assert!(
        control
            .record_verified_effect(&frames, &unknown, &signed, &trusted)
            .is_err()
    );
    assert!(control.verified_effect(&frames).unwrap().is_none());
    let mut forged = signed.clone();
    forged.signature[0] ^= 1;
    assert!(
        control
            .record_verified_effect(&frames, &completion, &forged, &trusted)
            .is_err()
    );
    assert!(control.verified_effect(&frames).unwrap().is_none());
    let verified = control
        .record_verified_effect(&frames, &completion, &signed, &trusted)
        .unwrap();
    assert_eq!(
        control
            .record_verified_effect(&frames, &completion, &signed, &trusted)
            .unwrap(),
        verified
    );
    assert_eq!(
        control.lookup(&frames).unwrap().unwrap().phase,
        "needs_reconciliation"
    );
    drop(control);
    let after = ControlDispatchJournal::open(&control_path).unwrap();
    assert_eq!(after.verified_effect(&frames).unwrap(), Some(verified));
    assert_eq!(
        after.lookup(&frames).unwrap().unwrap().phase,
        "needs_reconciliation"
    );
    drop(after);
    cleanup_gateway_database(&control_path);
    cleanup_gateway_database(&node_path);
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)] // parent and killed-child proof kept adjacent for audit
fn e07_sigkill_after_actual_a05_effect_does_not_invent_completion_or_replay() {
    use ptah_node::gateway_journal::{GatewayJournal, StageResult};
    use ptah_node_link::{DispatchLeaseFrame, DispatchRequestFrame, DispatchReservationFrame};
    let folder = std::env::temp_dir().join(format!(
        "ptah-e07-post-effect-{}",
        ptah_identifiers::EntityId::new_v7()
    ));
    if let Ok(parent) = std::env::var("PTAH_E07_KILL_POST_EFFECT_CHILD") {
        let folder = std::path::PathBuf::from(parent);
        let mut fixture = Fixture::new();
        let frames = fixture.issue();
        let mut guard = NodeDispatchGuard::for_agent(&fixture.node);
        guard
            .accept_reservation(&fixture.node, &frames.reservation, now())
            .unwrap();
        guard
            .accept_lease(&fixture.node, &frames.lease, now())
            .unwrap();
        let digest = format!("sha256:{}", "f".repeat(64));
        let mut journal = GatewayJournal::open(&folder.join("attempt.sqlite3")).unwrap();
        let provider = provider(&fixture.node);
        let expected = provider
            .attempt_context(1, entity("runtime.facility"))
            .unwrap();
        let effect = folder.join("external-effect.txt");
        let mut spec = process_spec("/usr/bin/python3");
        spec.args=vec![
            "-c".into(),
            "import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_text('REAL_EXTERNAL_EFFECT_COMMITTED'); print('effect-captured')".into(),
            effect.to_string_lossy().into_owned(),
        ];
        let process = journal
            .spawn_once(
                &fixture.node,
                &guard,
                &frames.request,
                now(),
                &digest,
                &provider,
                &expected,
                spec,
            )
            .expect("stage and launch real A05 provider");
        assert!(
            provider
                .wait_for_exit(process, Duration::from_secs(5))
                .unwrap()
                .success
        );
        assert_eq!(
            std::fs::read_to_string(&effect).unwrap(),
            "REAL_EXTERNAL_EFFECT_COMMITTED"
        );
        let bytes = serde_json::to_vec(&(
            fixture.node,
            frames.reservation,
            frames.lease,
            frames.request,
        ))
        .unwrap();
        std::fs::write(folder.join("authority-fixture.json"), bytes).unwrap();
        // Marker is written only after the external effect genuinely happened;
        // the final Node journal completion intentionally has not been written.
        let marker = folder.join("effect-observed.marker");
        std::fs::write(&marker, b"effect_exists_before_receipt").unwrap();
        std::fs::File::open(&marker).unwrap().sync_all().unwrap();
        std::thread::sleep(Duration::from_secs(30));
        panic!("parent should kill exact child after effect before receipt");
    }
    std::fs::create_dir_all(&folder).unwrap();
    let binary = std::env::current_exe().unwrap();
    let mut child = std::process::Command::new(binary)
        .arg("--exact")
        .arg("e07_sigkill_after_actual_a05_effect_does_not_invent_completion_or_replay")
        .arg("--nocapture")
        .env("PTAH_E07_KILL_POST_EFFECT_CHILD", &folder)
        .spawn()
        .expect("spawn isolated bounded Node test child");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let marker = folder.join("effect-observed.marker");
    while !marker.is_file() && std::time::Instant::now() < deadline {
        assert!(
            child.try_wait().unwrap().is_none(),
            "child stopped before effect"
        );
        std::thread::sleep(Duration::from_millis(30));
    }
    assert!(marker.is_file(), "A05 external effect marker missing");
    child.kill().expect("kill only the owned test process");
    assert!(!child.wait().unwrap().success());
    let evidence = std::fs::read(folder.join("authority-fixture.json")).unwrap();
    let (node, reservation, lease, request): (
        NodeAgent,
        DispatchReservationFrame,
        DispatchLeaseFrame,
        DispatchRequestFrame,
    ) = serde_json::from_slice(&evidence).unwrap();
    let mut guard = NodeDispatchGuard::for_agent(&node);
    guard
        .accept_reservation(&node, &reservation, now())
        .unwrap();
    guard.accept_lease(&node, &lease, now()).unwrap();
    let digest = format!("sha256:{}", "f".repeat(64));
    let database = folder.join("attempt.sqlite3");
    let mut recovered = GatewayJournal::open(&database).expect("recover killed Node journal");
    let retained = recovered.get(&request).unwrap().expect("same A04 Attempt");
    assert_eq!(retained.phase, "needs_reconciliation");
    assert!(retained.exit_code.is_none(), "never invent A05 completion");
    assert!(
        retained.stdout_digest.is_none(),
        "never invent output digest"
    );
    assert_eq!(retained.digest, digest);
    assert_eq!(recovered.unresolved().unwrap().len(), 1);
    assert_eq!(
        recovered
            .stage(&node, &guard, &request, now(), &digest)
            .unwrap(),
        StageResult::AlreadyRegistered
    );
    let external = folder.join("external-effect.txt");
    assert_eq!(
        std::fs::read_to_string(&external).unwrap(),
        "REAL_EXTERNAL_EFFECT_COMMITTED"
    );
    // A subsequent execution through spawn_once must fail even though the
    // external effect exists; only an independent witness can reconcile it.
    let provider = provider(&node);
    let expected = provider
        .attempt_context(1, entity("runtime.facility"))
        .unwrap();
    assert!(
        recovered
            .spawn_once(
                &node,
                &guard,
                &request,
                now(),
                &digest,
                &provider,
                &expected,
                process_spec("/bin/true"),
            )
            .is_err(),
        "uncertain Attempt may never launch twice"
    );
    assert_eq!(recovered.unresolved().unwrap().len(), 1);
    drop(recovered);
    cleanup_gateway_database(&database);
    let _ = std::fs::remove_file(format!("{}.lock", database.display()));
    let _ = std::fs::remove_dir_all(folder);
    eprintln!("PTAH_E07_POST_EFFECT_SIGKILL_UNCERTAIN=PASS; INDEPENDENT_WITNESS_NOT_ASSERTED");
}
