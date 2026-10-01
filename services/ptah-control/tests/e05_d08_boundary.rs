//! E05 composition proof with D08 remote execution and the existing E02 authority owner.

use ptah_application_runtime::{
    ApplicationOperation, CompatibilityDecision, CompatibilityRequirement, ExecutionDisposition,
    NodeLocalCompatibility, PlatformClass, RemoteNodeExecution, RequirementOutcome,
};
use ptah_control::node_link::NodeLinkControl;
use ptah_control::placement::{
    PlacementAuthorityOwner, PlacementAuthorityTiming, PlacementControlError,
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

const NOW: u64 = 1_800_200_000;
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
        agent_revision: String::from("e05-d08-test"),
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
        "e05-d08-test",
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

fn requirement(
    capability_ref: EntityRef,
    provider_ref: EntityRef,
    os_family: OsFamily,
) -> PlacementRequirement {
    PlacementRequirement::new(
        entity("activity.attempt"),
        vec![capability_ref],
        vec![provider_ref],
        vec![ResourceRequirement::new("cpu", ResourceUnit::Cores, 1.0).expect("cpu requirement")],
        Some(os_family),
    )
}

fn compatibility(
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
        evaluated_at: String::from("2026-09-23T09:59:00Z"),
        valid_until: String::from("2026-09-23T11:00:00Z"),
        evidence_refs: vec![entity("proof.evidence")],
        limitations: Vec::new(),
    }
}

fn admitted_remote(
    platform_node_class: PlatformNodeClass,
    d08_platform: PlatformClass,
    os_family: OsFamily,
) {
    let agent = NodeAgent::restart(NodeAgent::bootstrap().expect("bootstrap").restart_seed())
        .expect("current generation node");
    let fingerprint = CredentialFingerprint::from_der(b"e05-d08-remote");
    let approved = enrollment(&agent, fingerprint);
    let enrollment_ref = approved.enrollment_ref().clone();
    let mut control = PlacementAuthorityOwner::new(NodeLinkControl::new(
        ProtocolVersion { major: 1, minor: 0 },
        vec![approved],
    ));
    let binding = control
        .accept_hello(&hello(&agent, enrollment_ref), fingerprint, NOW)
        .expect("current session");
    let capability_ref = entity("runtime.capability");
    let provider_ref = entity("runtime.provider_revision");
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
    control
        .admit_platform_node(
            &binding,
            &state(&agent, &snapshot),
            &PlatformAdmissionProfile::new(
                platform_node_class,
                vec![capability_ref.clone()],
                vec![provider_ref.clone()],
                vec![Architecture::X86_64],
                false,
            ),
        )
        .expect("E05 admission");

    let grant = control
        .place_admitted_and_issue(
            platform_node_class,
            &requirement(capability_ref, provider_ref, os_family),
            PlacementPolicy::strict(),
            vec![ReservedResource::new("cpu", ResourceUnit::Cores, 1.0).expect("cpu")],
            PlacementAuthorityTiming::new(NOW + 1, NOW + 60, NOW + 30),
        )
        .expect("E02 dispatch authority");

    let compatibility = compatibility(&grant, ApplicationOperation::LaunchGraphical);
    let disposition = ExecutionDisposition::for_remote_platform_with_authority(
        d08_platform,
        ApplicationOperation::LaunchGraphical,
        compatibility.clone(),
        grant.dispatch_authority().clone(),
        D08_NOW,
    )
    .expect("D08 must consume exact E02 authority after E05 admission");

    let ExecutionDisposition::RemoteNodeReady(ready) = disposition else {
        panic!("E05-admitted E02-authorized remote Node must become D08 remote-ready");
    };
    let ready: RemoteNodeExecution = *ready;
    assert_eq!(ready.platform(), d08_platform);
    assert_eq!(ready.compatibility(), &compatibility);
    assert_eq!(ready.dispatch_authority(), grant.dispatch_authority());
}

#[test]
fn admitted_windows_and_macos_reach_d08_only_through_e02_dispatch_authority() {
    admitted_remote(
        PlatformNodeClass::Windows,
        PlatformClass::WindowsNode,
        OsFamily::Windows,
    );
    admitted_remote(
        PlatformNodeClass::Macos,
        PlatformClass::MacOsNode,
        OsFamily::Macos,
    );
}

#[test]
fn d08_is_unreachable_from_e05_admission_when_e02_eligibility_still_fails() {
    let agent = NodeAgent::restart(NodeAgent::bootstrap().expect("bootstrap").restart_seed())
        .expect("current generation node");
    let fingerprint = CredentialFingerprint::from_der(b"e05-d08-no-e02");
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
    let snapshot = capability(
        &agent,
        OsFamily::Windows,
        capability_ref.clone(),
        provider_ref.clone(),
    );
    control
        .accept_capability(&binding, &snapshot)
        .expect("capability");
    control
        .accept_resource(&binding, &resources(&agent))
        .expect("resources");
    control
        .admit_platform_node(
            &binding,
            &state(&agent, &snapshot),
            &PlatformAdmissionProfile::new(
                PlatformNodeClass::Windows,
                vec![capability_ref.clone()],
                vec![provider_ref.clone()],
                vec![Architecture::X86_64],
                false,
            ),
        )
        .expect("E05 admission");

    let missing_e02_capability = entity("runtime.capability");
    assert_ne!(missing_e02_capability, capability_ref);
    assert_eq!(
        control.place_admitted_and_issue(
            PlatformNodeClass::Windows,
            &requirement(missing_e02_capability, provider_ref, OsFamily::Windows),
            PlacementPolicy::strict(),
            vec![ReservedResource::new("cpu", ResourceUnit::Cores, 1.0).expect("cpu")],
            PlacementAuthorityTiming::new(NOW + 1, NOW + 60, NOW + 30),
        ),
        Err(PlacementControlError::NoEligibleNode)
    );
}
