//! E05 composition proofs for D08 remote Application authority and C10 Android Device authority.

use ptah_android_runtime::{
    AndroidRuntimeError, DeviceSessionRequest, DeviceSessionState, open_device_session,
};
use ptah_application_runtime::{
    ApplicationOperation, CompatibilityDecision, CompatibilityRequirement, ExecutionDisposition,
    NodeLocalCompatibility, PlatformClass, RequirementOutcome,
};
use ptah_control::node_link::NodeLinkControl;
use ptah_control::placement::{
    PlacementAuthorityOwner, PlacementAuthorityTiming, PlacementControlError,
};
use ptah_device_runtime::{
    DeviceError, DeviceInterfaceRecord, DeviceKind, DeviceLease, DeviceLeaseRequest, DeviceRecord,
    InterfaceLocality, InterfaceTransport, Reachability,
};
use ptah_identifiers::EntityRef;
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
use ptah_provider_api::ProviderGeneration;

const AUTH_NOW: u64 = 1_800_200_000;
const D08_NOW: &str = "2026-09-23T10:00:00Z";

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
        agent_revision: String::from("e05-owner-composition"),
        capability_snapshot_ref: None,
    }
}

fn capability(
    agent: &NodeAgent,
    os_family: OsFamily,
    capability_ref: EntityRef,
    provider_ref: EntityRef,
) -> NodeCapabilitySnapshot {
    NodeCapabilitySnapshot::new(
        agent.node_ref(),
        agent.generation(),
        agent.connection_epoch(),
        SnapshotOutcome::Complete,
        "e05-owner-composition",
        PlatformFacts {
            os_family,
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
    .expect("capability snapshot")
}

fn resources(agent: &NodeAgent) -> NodeResourceSnapshot {
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
            consumed: 0.0,
            currently_available: 8.0,
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

fn profile(
    platform_class: PlatformNodeClass,
    capability_ref: EntityRef,
    provider_ref: EntityRef,
) -> PlatformAdmissionProfile {
    PlatformAdmissionProfile::new(
        platform_class,
        vec![capability_ref],
        vec![provider_ref],
        vec![Architecture::X86_64],
        false,
    )
}

fn requirement(
    os_family: OsFamily,
    capability_ref: EntityRef,
    provider_ref: EntityRef,
) -> PlacementRequirement {
    PlacementRequirement::new(
        entity("activity.attempt"),
        vec![capability_ref],
        vec![provider_ref],
        vec![ResourceRequirement::new("cpu", ResourceUnit::Cores, 1.0).expect("requirement")],
        Some(os_family),
    )
}

fn compatible_remote_node(
    grant: &ptah_control::placement::PlacementGrant,
    operation: ApplicationOperation,
) -> NodeLocalCompatibility {
    let binding = grant.dispatch_authority().binding();
    NodeLocalCompatibility {
        compatibility_ref: entity("application.compatibility"),
        application_revision_ref: entity("application.application_revision"),
        operation,
        provider_revision_ref: entity("runtime.provider_revision"),
        provider_instance_ref: entity("runtime.provider_instance"),
        provider_generation: ProviderGeneration::new(1).expect("provider generation"),
        node_ref: binding
            .node_id()
            .entity_ref(binding.node_generation(), binding.connection_epoch()),
        node_generation: binding.node_generation().value(),
        node_capability_snapshot_ref: entity("runtime.node-capability-snapshot"),
        node_resource_snapshot_ref: entity("runtime.node-resource-snapshot"),
        requirements: vec![CompatibilityRequirement {
            key: String::from("e05_platform_node_current"),
            mandatory: true,
            outcome: RequirementOutcome::Satisfied,
            condition_refs: Vec::new(),
            evidence_refs: vec![entity("proof.evidence")],
            reason: None,
        }],
        decision: CompatibilityDecision::Compatible,
        condition_refs: Vec::new(),
        evaluated_at: String::from("2026-09-23T09:00:00Z"),
        valid_until: String::from("2026-09-23T11:00:00Z"),
        evidence_refs: vec![entity("proof.evidence")],
        limitations: Vec::new(),
    }
}

fn prove_remote_chain(
    platform_class: PlatformNodeClass,
    os_family: OsFamily,
    d08_platform: PlatformClass,
    fingerprint_seed: &'static [u8],
) {
    let bootstrap = NodeAgent::bootstrap().expect("bootstrap node");
    let agent = NodeAgent::restart(bootstrap.restart_seed()).expect("generation-1 node");
    let fingerprint = CredentialFingerprint::from_der(fingerprint_seed);
    let approved = enrollment(&agent, fingerprint);
    let enrollment_ref = approved.enrollment_ref().clone();
    let mut control = PlacementAuthorityOwner::new(NodeLinkControl::new(
        ProtocolVersion { major: 1, minor: 0 },
        vec![approved],
    ));
    let binding = control
        .accept_hello(&hello(&agent, enrollment_ref), fingerprint, AUTH_NOW)
        .expect("session");
    let capability_ref = entity("runtime.capability");
    let provider_ref = entity("runtime.provider-revision");
    let snapshot = capability(
        &agent,
        os_family,
        capability_ref.clone(),
        provider_ref.clone(),
    );
    control
        .accept_capability(&binding, &snapshot)
        .expect("capability");
    control
        .accept_resource(&binding, &resources(&agent))
        .expect("resources");

    let placement_requirement =
        requirement(os_family, capability_ref.clone(), provider_ref.clone());
    assert_eq!(
        control.place_admitted_and_issue(
            platform_class,
            &placement_requirement,
            PlacementPolicy::strict(),
            vec![ReservedResource::new("cpu", ResourceUnit::Cores, 1.0).expect("cpu")],
            PlacementAuthorityTiming::new(AUTH_NOW + 1, AUTH_NOW + 60, AUTH_NOW + 30),
        ),
        Err(PlacementControlError::PlatformAdmissionRequired)
    );

    control
        .admit_platform_node(
            &binding,
            &state(&agent, &snapshot),
            &profile(platform_class, capability_ref, provider_ref),
        )
        .expect("E05 admission");

    let grant = control
        .place_admitted_and_issue(
            platform_class,
            &placement_requirement,
            PlacementPolicy::strict(),
            vec![ReservedResource::new("cpu", ResourceUnit::Cores, 1.0).expect("cpu")],
            PlacementAuthorityTiming::new(AUTH_NOW + 2, AUTH_NOW + 60, AUTH_NOW + 30),
        )
        .expect("E02 authority");

    let compatibility = compatible_remote_node(&grant, ApplicationOperation::LaunchGraphical);
    let disposition = ExecutionDisposition::for_remote_platform_with_authority(
        d08_platform,
        ApplicationOperation::LaunchGraphical,
        compatibility,
        grant.dispatch_authority().clone(),
        D08_NOW,
    )
    .expect("D08 must accept exact E02 authority for the admitted remote Node");

    let ExecutionDisposition::RemoteNodeReady(ready) = disposition else {
        panic!("D08 must retain remote-node readiness only after exact E02 authority");
    };
    assert_eq!(ready.dispatch_authority(), grant.dispatch_authority());
    assert_eq!(
        ready.dispatch_authority().binding().node_id(),
        agent.node_id()
    );
}

#[test]
fn windows_and_macos_follow_e05_then_e02_then_d08_authority_chain() {
    prove_remote_chain(
        PlatformNodeClass::Windows,
        OsFamily::Windows,
        PlatformClass::WindowsNode,
        b"e05-owner-windows",
    );
    prove_remote_chain(
        PlatformNodeClass::Macos,
        OsFamily::Macos,
        PlatformClass::MacOsNode,
        b"e05-owner-macos",
    );
}

fn android_device() -> DeviceRecord {
    DeviceRecord {
        device_ref: entity("device.device"),
        device_kind: DeviceKind::PhysicalAndroid,
        identity_basis_refs: vec![entity("proof.evidence")],
        current_profile_revision_ref: entity("device.profile_revision"),
        profile_revision_refs: vec![entity("device.profile_revision")],
        limitations: Vec::new(),
    }
}

fn android_interface(device_ref: EntityRef) -> DeviceInterfaceRecord {
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
fn android_platform_node_admission_does_not_replace_c10_device_lease_and_fence_authority() {
    let agent = NodeAgent::bootstrap().expect("node");
    let fingerprint = CredentialFingerprint::from_der(b"e05-owner-android");
    let approved = enrollment(&agent, fingerprint);
    let enrollment_ref = approved.enrollment_ref().clone();
    let mut control = PlacementAuthorityOwner::new(NodeLinkControl::new(
        ProtocolVersion { major: 1, minor: 0 },
        vec![approved],
    ));
    let binding = control
        .accept_hello(&hello(&agent, enrollment_ref), fingerprint, AUTH_NOW)
        .expect("session");
    let capability_ref = entity("runtime.capability");
    let provider_ref = entity("runtime.provider-revision");
    let snapshot = capability(
        &agent,
        OsFamily::Android,
        capability_ref.clone(),
        provider_ref.clone(),
    );
    control
        .accept_capability(&binding, &snapshot)
        .expect("capability");
    let admission = control
        .admit_platform_node(
            &binding,
            &state(&agent, &snapshot),
            &profile(
                PlatformNodeClass::AndroidDevice,
                capability_ref,
                provider_ref,
            ),
        )
        .expect("E05 Android Platform Node admission");
    assert_eq!(admission.platform_class(), PlatformNodeClass::AndroidDevice);

    let device = android_device();
    let interface = android_interface(device.device_ref.clone());
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
    .expect("C10 retains and enforces its own Device Session authority");

    assert_eq!(session.state, DeviceSessionState::Connected);
    assert_eq!(session.device_ref, device.device_ref);
    assert_eq!(session.lease_ref, lease.lease_ref);
}
