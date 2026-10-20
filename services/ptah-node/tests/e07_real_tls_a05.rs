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
async fn authentic_tls_e02_dispatch_runs_real_a05_process_and_persists_both_journals() {
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
    let digest = format!(
        "sha256:{:x}",
        Sha256::digest(b"ptah-e07-native-real-process")
    );
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
        program: "/usr/bin/printf".into(),
        args: vec!["PTAH_E07_A05_REMOTE_ACTUAL\\n".into()],
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
    assert!(stdout_digest.starts_with("sha256:"));
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
    println!("E07_NATIVE_TLS_E02_A05_PROCESS_EXECUTION_PASSED");
}
