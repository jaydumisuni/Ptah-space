//! E05 proof that Android Platform Node admission does not replace C08/C10 Device authority.

use ptah_android_runtime::{
    AndroidRuntimeError, DeviceSessionRequest, DeviceSessionState, open_device_session,
};
use ptah_control::node_link::NodeLinkControl;
use ptah_control::placement::PlacementAuthorityOwner;
use ptah_device_runtime::{
    DeviceError, DeviceInterfaceRecord, DeviceKind, DeviceLease, DeviceLeaseRequest, DeviceRecord,
    InterfaceLocality, InterfaceTransport, Reachability,
};
use ptah_identifiers::EntityRef;
use ptah_node_agent::{
    Architecture, NodeAgent, NodeCapabilitySnapshot, NodeHealth, NodeLifecycleState,
    NodeReachability, NodeStateProjection, OsFamily, PlatformFacts, SnapshotOutcome,
};
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle, NodeHello, ProtocolVersion,
};
use ptah_platform_admission::{PlatformAdmissionProfile, PlatformNodeClass};
use ptah_provider_api::ProviderGeneration;

const NOW: u64 = 1_800_200_000;

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity kind")
}

fn enrollment(agent: &NodeAgent, fingerprint: CredentialFingerprint) -> ApprovedNodeEnrollment {
    ApprovedNodeEnrollment::new(
        entity("core.node_enrollment"),
        agent.node_id(),
        EnrollmentLifecycle::Approved,
        vec![String::from("node.connect")],
        vec![fingerprint],
        None,
    )
    .expect("approved enrollment")
}

fn hello(agent: &NodeAgent, enrollment_ref: EntityRef) -> NodeHello {
    NodeHello {
        supported_major: 1,
        minimum_minor: 0,
        maximum_minor: 0,
        node_id: agent.node_id(),
        node_generation: agent.generation(),
        connection_epoch: agent.connection_epoch(),
        enrollment_ref,
        agent_revision: String::from("e05-c10-boundary"),
        capability_snapshot_ref: None,
    }
}

fn android_capability(
    agent: &NodeAgent,
    capability_ref: EntityRef,
    provider_ref: EntityRef,
) -> NodeCapabilitySnapshot {
    NodeCapabilitySnapshot::new(
        agent.node_ref(),
        agent.generation(),
        agent.connection_epoch(),
        SnapshotOutcome::Complete,
        "e05-c10-boundary",
        PlatformFacts {
            os_family: OsFamily::Android,
            os_name: None,
            os_version: None,
            kernel_name: None,
            kernel_version: None,
            architecture: Architecture::X86_64,
            architecture_detail: None,
        },
        vec![capability_ref],
        vec![entity("runtime.capability-verification")],
        vec![provider_ref],
        vec![entity("core.node_observation")],
        vec![entity("proof.receipt")],
        Vec::new(),
    )
    .expect("Android Platform Node capability snapshot")
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

fn device() -> DeviceRecord {
    DeviceRecord {
        device_ref: entity("device.device"),
        device_kind: DeviceKind::PhysicalAndroid,
        identity_basis_refs: vec![entity("proof.evidence")],
        current_profile_revision_ref: entity("device.profile_revision"),
        profile_revision_refs: vec![entity("device.profile_revision")],
        limitations: Vec::new(),
    }
}

fn interface(device_ref: EntityRef) -> DeviceInterfaceRecord {
    DeviceInterfaceRecord {
        interface_ref: entity("device.interface"),
        device_ref,
        transport: InterfaceTransport::AdbUsb,
        mode_or_protocol: String::from("adb"),
        protocol_version: Some(String::from("1.0.41")),
        observed_aliases: vec![String::from("E05-C10-BOUNDARY")],
        topology_or_address: Some(String::from("usb:e05-boundary")),
        endpoint_claims: vec![String::from("18d1:4ee7")],
        provider_instance_ref: entity("runtime.provider_instance"),
        provider_generation: ProviderGeneration::new(4).expect("provider generation"),
        locality: InterfaceLocality::NodeLocal,
        node_ref: entity("core.node"),
        node_generation: 1,
        provider_connection_epoch: 7,
        connection_epoch: 7,
        connection_ref: entity("device.connection"),
        continuity_basis_refs: vec![entity("proof.evidence")],
        capability_claim_refs: vec![entity("proof.evidence")],
        reachability: Reachability::Reachable,
        evidence_refs: vec![entity("proof.evidence")],
        first_observed_at: String::from("2026-09-23T09:00:00Z"),
        last_observed_at: String::from("2026-09-23T09:01:00Z"),
    }
}

#[test]
fn android_platform_admission_does_not_replace_c10_device_lease_and_fence_authority() {
    let agent = NodeAgent::bootstrap().expect("node");
    let fingerprint = CredentialFingerprint::from_der(b"e05-c10-boundary");
    let approved = enrollment(&agent, fingerprint);
    let enrollment_ref = approved.enrollment_ref().clone();
    let mut control = PlacementAuthorityOwner::new(NodeLinkControl::new(
        ProtocolVersion { major: 1, minor: 0 },
        vec![approved],
    ));
    let binding = control
        .accept_hello(&hello(&agent, enrollment_ref), fingerprint, NOW)
        .expect("session");
    let capability_ref = entity("runtime.capability");
    let provider_ref = entity("runtime.provider_revision");
    let snapshot = android_capability(&agent, capability_ref.clone(), provider_ref.clone());
    control
        .accept_capability(&binding, &snapshot)
        .expect("capability");

    let admission = control
        .admit_platform_node(
            &binding,
            &state(&agent, &snapshot),
            &PlatformAdmissionProfile::new(
                PlatformNodeClass::AndroidDevice,
                vec![capability_ref],
                vec![provider_ref],
                vec![Architecture::X86_64],
                false,
            ),
        )
        .expect("E05 Android Platform Node admission");
    assert_eq!(admission.platform_class(), PlatformNodeClass::AndroidDevice);

    let device = device();
    let interface = interface(device.device_ref.clone());
    let lease = DeviceLease::issue(DeviceLeaseRequest {
        device_ref: device.device_ref.clone(),
        holder_ref: entity("core.workspace"),
        scope: vec![String::from("android.session.control")],
        fence_token: 2,
        provider_generation: interface.provider_generation,
        connection_epoch: interface.connection_epoch,
        issued_at: String::from("2026-09-23T09:02:00Z"),
        expires_at: String::from("2026-09-23T10:02:00Z"),
    })
    .expect("C08 Device lease");

    let stale = open_device_session(DeviceSessionRequest {
        workspace_ref: entity("core.workspace"),
        device: &device,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 1,
        capability_snapshot_ref: snapshot.snapshot_ref.clone(),
        privacy_policy_refs: vec![entity("policy.privacy")],
        evidence_refs: vec![entity("proof.evidence")],
        started_at: String::from("2026-09-23T09:03:00Z"),
    });
    assert_eq!(
        stale,
        Err(AndroidRuntimeError::Device(DeviceError::StaleFence))
    );

    let session = open_device_session(DeviceSessionRequest {
        workspace_ref: entity("core.workspace"),
        device: &device,
        interface: &interface,
        lease: &lease,
        observed_fence_token: 2,
        capability_snapshot_ref: snapshot.snapshot_ref,
        privacy_policy_refs: vec![entity("policy.privacy")],
        evidence_refs: vec![entity("proof.evidence")],
        started_at: String::from("2026-09-23T09:03:01Z"),
    })
    .expect("C10 retains its own Device Session authority");

    assert_eq!(session.state, DeviceSessionState::Connected);
    assert_eq!(session.device_ref, device.device_ref);
    assert_eq!(session.lease_ref, lease.lease_ref);
}
