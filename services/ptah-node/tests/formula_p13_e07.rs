//! E07 native execution through real E01 mTLS + Control-minted E02
//! reservation/lease/fence + actual Node A05 provider process.
//! This is an internal loopback proof and makes no cross-host claim.
#![cfg(unix)]
use native_process::{
    DisconnectPolicy, NativeProcessProvider, NativeProcessProviderConfig, ProcessMode, ProcessSpec,
};
use ptah_control::{
    gateway_control_journal::ControlDispatchJournal,
    gateway_e02_dispatch::issue_and_send,
    gateway_session,
    node_link::NodeLinkControl,
    placement::{PlacementAuthorityOwner, PlacementAuthorityTiming},
};
use ptah_identifiers::EntityRef;
use ptah_node::{
    NodeLinkClientConfig, connect_node_link, gateway_e02_wire::receive_one,
    gateway_journal::GatewayJournal,
};
use ptah_node_agent::{
    Architecture, NodeAgent, NodeCapabilitySnapshot, NodeHealth, NodeLifecycleState,
    NodeReachability, NodeResourceSnapshot, NodeStateProjection, OsFamily, PlatformFacts,
    ResourcePressure, ResourceQuantity, ResourceUnit, SnapshotOutcome,
};
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle, ProtocolVersion,
    TlsClientConfig, TlsIdentity, TlsServerConfig, TlsTrustRoots,
};
use ptah_placement_runtime::{
    PlacementPolicy, PlacementRequirement, ReservedResource, ResourceRequirement,
};
use ptah_platform_admission::{PlatformAdmissionProfile, PlatformNodeClass};
use ptah_provider_api::{
    ProviderGeneration, ProviderHealth, ProviderInstance, ProviderKind, ProviderReachability,
    ProviderReadiness, ProviderRevision,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::Mutex};
const CA: &[u8] = include_bytes!("../../../crates/ptah-node-link/tests/fixtures/ca.cert.der");
const SERVER: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.cert.der");
const SERVER_KEY: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.key.der");
const CLIENT: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.cert.der");
const CLIENT_KEY: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.key.der");
fn configs() -> (TlsServerConfig, TlsClientConfig) {
    let roots = || TlsTrustRoots::from_der(vec![CA.to_vec()]).unwrap();
    (
        TlsServerConfig::new(
            TlsIdentity::from_der(vec![SERVER.to_vec()], SERVER_KEY.to_vec()).unwrap(),
            roots(),
        )
        .unwrap(),
        TlsClientConfig::new(
            TlsIdentity::from_der(vec![CLIENT.to_vec()], CLIENT_KEY.to_vec()).unwrap(),
            roots(),
        )
        .unwrap(),
    )
}

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity kind")
}

fn capability(
    agent: &NodeAgent,
    capabilities: Vec<EntityRef>,
    providers: Vec<EntityRef>,
) -> NodeCapabilitySnapshot {
    let verification_refs = if capabilities.is_empty() {
        Vec::new()
    } else {
        vec![entity("runtime.capability-verification")]
    };
    NodeCapabilitySnapshot::new(
        agent.node_ref(),
        agent.generation(),
        agent.connection_epoch(),
        SnapshotOutcome::Complete,
        "e05-control-test",
        PlatformFacts {
            os_family: OsFamily::Linux,
            os_name: Some(String::from("Test Linux")),
            os_version: Some(String::from("1")),
            kernel_name: Some(String::from("linux")),
            kernel_version: Some(String::from("1")),
            architecture: Architecture::X86_64,
            architecture_detail: None,
        },
        capabilities,
        verification_refs,
        providers,
        vec![entity("core.node_observation")],
        vec![entity("proof.receipt")],
        Vec::new(),
    )
    .expect("capability snapshot")
}

fn resources(agent: &NodeAgent, available: f64) -> NodeResourceSnapshot {
    NodeResourceSnapshot::new(
        agent.node_ref(),
        agent.generation(),
        agent.connection_epoch(),
        SnapshotOutcome::Complete,
        vec![ResourceQuantity {
            resource_key: String::from("cpu"),
            unit: ResourceUnit::Cores,
            observed_total: 8.0,
            administratively_allocatable: 8.0,
            reserved: 0.0,
            consumed: 8.0 - available,
            currently_available: available,
            pressure: ResourcePressure::Normal,
            observation_refs: vec![entity("core.node_observation")],
        }],
        vec![entity("core.node_observation")],
        vec![entity("proof.receipt")],
        Vec::new(),
    )
    .expect("resource snapshot")
}

fn state(agent: &NodeAgent, snapshot: &NodeCapabilitySnapshot) -> NodeStateProjection {
    NodeStateProjection {
        node_ref: agent.node_ref(),
        lifecycle: NodeLifecycleState::Active,
        node_generation: agent.generation(),
        connection_epoch: agent.connection_epoch(),
        current_reachability: NodeReachability::Online,
        current_health: NodeHealth::Healthy,
        capability_snapshot_refs: vec![snapshot.snapshot_ref.clone()],
        resource_snapshot_refs: Vec::new(),
        observation_refs: vec![entity("core.node_observation")],
    }
}

fn profile(capability_ref: EntityRef, provider_ref: EntityRef) -> PlatformAdmissionProfile {
    PlatformAdmissionProfile::new(
        PlatformNodeClass::AlwaysOnLinux,
        vec![capability_ref],
        vec![provider_ref],
        vec![Architecture::X86_64],
        false,
    )
}

fn requirement(capability_ref: EntityRef, provider_ref: EntityRef) -> PlacementRequirement {
    PlacementRequirement::new(
        entity("activity.attempt"),
        vec![capability_ref],
        vec![provider_ref],
        vec![ResourceRequirement::new("cpu", ResourceUnit::Cores, 1.0).expect("requirement")],
        Some(OsFamily::Linux),
    )
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

// Keep the real end-to-end handshake, grant, process and journal sequence
// visible as one audit trail instead of hiding proof steps in helper mocks.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn p13_formula_workcell_executes_over_real_e01_e02_a05_tls_and_checks_count() {
    let bootstrap = NodeAgent::bootstrap().unwrap();
    let agent = NodeAgent::restart(bootstrap.restart_seed()).unwrap();
    let enrollment_ref = entity("core.node_enrollment");
    let (tls, client_tls) = configs();
    let fp = CredentialFingerprint::from_der(CLIENT);
    let owner = Arc::new(Mutex::new(PlacementAuthorityOwner::new(
        NodeLinkControl::new(
            ProtocolVersion { major: 1, minor: 0 },
            vec![
                ApprovedNodeEnrollment::new(
                    enrollment_ref.clone(),
                    agent.node_id(),
                    EnrollmentLifecycle::Approved,
                    vec!["node.connect".into()],
                    vec![fp],
                    None,
                )
                .unwrap(),
            ],
        ),
    )));
    let cap_ref = entity("runtime.capability");
    let provider_ref = entity("runtime.provider-revision");
    let cap = capability(&agent, vec![cap_ref.clone()], vec![provider_ref.clone()]);
    let res = resources(&agent, 8.0);
    let state = state(&agent, &cap);
    let profile = profile(cap_ref.clone(), provider_ref.clone());
    let need = requirement(cap_ref, provider_ref);
    let (a, b) = (
        std::env::temp_dir().join(format!(
            "ptah-e07-control-{}.db",
            ptah_identifiers::EntityId::new_v7()
        )),
        std::env::temp_dir().join(format!(
            "ptah-e07-node-{}.db",
            ptah_identifiers::EntityId::new_v7()
        )),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let ctrl = owner.clone();
    let cert = tls.clone();
    let envelope = include_bytes!(
        "../../../adapters/formula-workcells/tests/fixtures/formula-generated-handoff.json"
    )
    .trim_ascii_end();
    let checked = ptah_formula_work_cells::validate_handoff(envelope).unwrap();
    let work_custody = ptah_formula_work_cells::FormulaDispatchCustody {
        manifest_digest: checked.manifest_digest.clone(),
        work_cell_digest: checked.work_cell_digest.clone(),
        required_authority: checked.required_authority.clone(),
    };
    let admitted =
        ptah_formula_work_cells::preflight_with_custody(envelope, &work_custody).unwrap();
    assert_eq!(admitted.work_cell_digest, checked.work_cell_digest);
    assert_eq!(checked.requested_result_class, "COUNT");
    let p9_input = serde_json::json!({"schema":"formula-p9-canonical-u8-vector-v1","values":[0,1,2,3,4,7,8,15,16,31,32,63,64,127,128,129,255,1,3]});
    let p9_digest = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&p9_input).unwrap())
    );
    assert!(checked.known_input_digests.contains(&p9_digest));
    let digest = checked.manifest_digest.clone();
    let issued_digest = digest.clone();
    let journal_path = a.clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (binding, mut peer) = gateway_session::establish(
            socket,
            &cert,
            &ctrl,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .await
        .unwrap();
        let mut guard = ctrl.lock().await;
        guard.accept_capability(&binding, &cap).unwrap();
        guard.accept_resource(&binding, &res).unwrap();
        guard
            .admit_platform_node(&binding, &state, &profile)
            .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut journal = ControlDispatchJournal::open(&journal_path).unwrap();
        let frames = issue_and_send(
            &mut guard,
            &binding,
            &mut peer,
            PlatformNodeClass::AlwaysOnLinux,
            &need,
            PlacementPolicy::strict(),
            vec![ReservedResource::new("cpu", ResourceUnit::Cores, 1.0).unwrap()],
            PlacementAuthorityTiming::new(now, now + 90, now + 70),
            entity("runtime.dispatch"),
            entity("activity.operation"),
            &mut journal,
            &issued_digest,
        )
        .await
        .unwrap();
        let pending = journal.lookup(&frames).unwrap().unwrap();
        assert_eq!(pending.phase, "sent_unconfirmed");
        assert!(journal.verified_effect(&frames).unwrap().is_none());
        frames.request
    });
    let config = NodeLinkClientConfig::new(
        address,
        "localhost".into(),
        client_tls,
        enrollment_ref,
        "e07-native-process-physical-test".into(),
        ProtocolVersion { major: 1, minor: 0 },
    );
    let (_, mut tls) = connect_node_link(&agent, &config).await.unwrap();
    let (guard, request) = receive_one(&agent, &mut tls).await.unwrap();
    let provider = provider(&agent);
    let expected = provider
        .attempt_context(1, entity("runtime.facility"))
        .unwrap();
    let mut journal = GatewayJournal::open(&b).unwrap();
    let spec = ProcessSpec {
        program: "/usr/bin/python3".into(),
        args: vec![
            "-I".into(), "-S".into(), "-c".into(),
            // P9 canonical second-query vector, admitted as an immutable local test profile.
            // No executable or script is received over Ptah's E02 transport.
            "v=(0,1,2,3,4,7,8,15,16,31,32,63,64,127,128,129,255,1,3);print(sum(1 for n in v if n>0 and n&(n-1)==0))".into(),
        ],
        env: BTreeMap::new(),
        clear_env: false,
        cwd: None,
        mode: ProcessMode::Pipes,
        max_stream_bytes: 4096,
        disconnect_policy: DisconnectPolicy::Retain,
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let process = journal
        .spawn_once(
            &agent, &guard, &request, now, &digest, &provider, &expected, spec,
        )
        .unwrap();
    let exit = provider
        .wait_for_exit(process, Duration::from_secs(4))
        .unwrap();
    assert!(exit.success);
    let stdout_digest = journal
        .complete_from_process(&agent, &request, &digest, &provider, process)
        .unwrap();
    let stdout = provider.snapshot(process).unwrap().stdout.unwrap();
    assert_eq!(stdout.truncated_bytes, 0);
    assert_eq!(stdout.bytes, b"9\n");
    assert_eq!(
        stdout_digest,
        format!("sha256:{:x}", Sha256::digest(&stdout.bytes))
    );
    // A separate, local Rust computation checks the mathematical count; the
    // Python process was executed through real authenticated E02/A05.
    let canonical_p9_vector: [u8; 19] = [
        0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 129, 255, 1, 3,
    ];
    let local_count = canonical_p9_vector
        .iter()
        .filter(|&&n| n.is_power_of_two())
        .count();
    assert_eq!(local_count, 9);
    assert_eq!(stdout.bytes, format!("{local_count}\n").into_bytes());
    let candidate =
        ptah_formula_work_cells::candidate_only_receipt(&admitted, stdout.bytes.clone()).unwrap();
    assert_eq!(candidate.claimed_digest, stdout_digest);
    assert_eq!(candidate.manifest_digest, digest);
    assert_eq!(candidate.work_cell_digest, checked.work_cell_digest);
    let retained = journal.get(&request).unwrap().unwrap();
    assert_eq!(retained.phase, "completed");
    assert_eq!(retained.exit_code, Some(0));
    let duplicate = journal
        .stage(&agent, &guard, &request, now, &digest)
        .unwrap();
    assert_eq!(
        duplicate,
        ptah_node::gateway_journal::StageResult::AlreadyRegistered
    );
    drop(journal);
    assert_eq!(
        GatewayJournal::open(&b)
            .unwrap()
            .get(&request)
            .unwrap()
            .unwrap()
            .phase,
        "completed"
    );
    let control_req = server.await.unwrap();
    assert_eq!(control_req, request);
    drop(provider);
    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
    println!("FORMULA_P13_E07_TLS_A05_COUNT_EQUIVALENCE_PASSED");
    println!("FORMULA_P13_RESULT_SHA256={stdout_digest}");
    println!("FORMULA_P13_MANIFEST={}", admitted.manifest_digest);
    println!("FORMULA_P13_WORK_CELL={}", admitted.work_cell_digest);
}
