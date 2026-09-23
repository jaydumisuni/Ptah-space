//! E05 control-plane composition tests: admission gates E02 authority without replacing it.

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

const NOW: u64 = 1_800_100_000;

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
        agent_revision: String::from("e05-control-test"),
        capability_snapshot_ref: None,
    }
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

fn cpu() -> Vec<ReservedResource> {
    vec![ReservedResource::new("cpu", ResourceUnit::Cores, 1.0).expect("cpu")]
}

fn one_node_control(
    agent: &NodeAgent,
    fingerprint: CredentialFingerprint,
) -> (PlacementAuthorityOwner, EntityRef) {
    let approved = enrollment(agent, fingerprint);
    let enrollment_ref = approved.enrollment_ref().clone();
    (
        PlacementAuthorityOwner::new(NodeLinkControl::new(
            ProtocolVersion { major: 1, minor: 0 },
            vec![approved],
        )),
        enrollment_ref,
    )
}

#[test]
fn admitted_placement_requires_e05_but_e02_still_mints_the_authority() {
    let agent = NodeAgent::bootstrap().expect("node");
    let fingerprint = CredentialFingerprint::from_der(b"e05-control-admit");
    let (mut control, enrollment_ref) = one_node_control(&agent, fingerprint);
    let binding = control
        .accept_hello(&hello(&agent, enrollment_ref), fingerprint, NOW)
        .expect("session");
    let cap_ref = entity("runtime.capability");
    let provider_ref = entity("runtime.provider-revision");
    let snapshot = capability(&agent, vec![cap_ref.clone()], vec![provider_ref.clone()]);
    control
        .accept_capability(&binding, &snapshot)
        .expect("capability");
    control
        .accept_resource(&binding, &resources(&agent, 8.0))
        .expect("resources");

    assert_eq!(
        control.place_admitted_and_issue(
            PlatformNodeClass::AlwaysOnLinux,
            &requirement(cap_ref.clone(), provider_ref.clone()),
            PlacementPolicy::strict(),
            cpu(),
            PlacementAuthorityTiming::new(NOW + 1, NOW + 60, NOW + 30,),
        ),
        Err(PlacementControlError::PlatformAdmissionRequired)
    );

    let decision = control
        .admit_platform_node(
            &binding,
            &state(&agent, &snapshot),
            &profile(cap_ref.clone(), provider_ref.clone()),
        )
        .expect("platform admission");
    assert_eq!(decision.platform_class(), PlatformNodeClass::AlwaysOnLinux);

    let grant = control
        .place_admitted_and_issue(
            PlatformNodeClass::AlwaysOnLinux,
            &requirement(cap_ref, provider_ref),
            PlacementPolicy::strict(),
            cpu(),
            PlacementAuthorityTiming::new(NOW + 2, NOW + 60, NOW + 30),
        )
        .expect("E02 authority after E05 gate");

    assert_eq!(grant.node_id(), agent.node_id());
    assert_eq!(grant.lease().fence().value(), 1);
    assert_eq!(grant.dispatch_authority().fence(), grant.lease().fence());
}

#[test]
fn capability_refresh_invalidates_cached_platform_admission() {
    let agent = NodeAgent::bootstrap().expect("node");
    let fingerprint = CredentialFingerprint::from_der(b"e05-control-cap-refresh");
    let (mut control, enrollment_ref) = one_node_control(&agent, fingerprint);
    let binding = control
        .accept_hello(&hello(&agent, enrollment_ref), fingerprint, NOW)
        .expect("session");
    let cap_ref = entity("runtime.capability");
    let provider_ref = entity("runtime.provider-revision");
    let first = capability(&agent, vec![cap_ref.clone()], vec![provider_ref.clone()]);
    control
        .accept_capability(&binding, &first)
        .expect("first cap");
    control
        .accept_resource(&binding, &resources(&agent, 8.0))
        .expect("resources");
    control
        .admit_platform_node(
            &binding,
            &state(&agent, &first),
            &profile(cap_ref.clone(), provider_ref.clone()),
        )
        .expect("admit first snapshot");

    let second = capability(&agent, vec![cap_ref.clone()], vec![provider_ref.clone()]);
    assert_ne!(first.snapshot_ref, second.snapshot_ref);
    control
        .accept_capability(&binding, &second)
        .expect("refreshed capability");

    assert_eq!(
        control.place_admitted_and_issue(
            PlatformNodeClass::AlwaysOnLinux,
            &requirement(cap_ref, provider_ref),
            PlacementPolicy::strict(),
            cpu(),
            PlacementAuthorityTiming::new(NOW + 1, NOW + 60, NOW + 30,),
        ),
        Err(PlacementControlError::PlatformAdmissionRequired)
    );
}

#[test]
fn superseding_e01_session_invalidates_cached_platform_admission() {
    let mut agent = NodeAgent::bootstrap().expect("node");
    let fingerprint = CredentialFingerprint::from_der(b"e05-control-reconnect");
    let (mut control, enrollment_ref) = one_node_control(&agent, fingerprint);
    let first_binding = control
        .accept_hello(&hello(&agent, enrollment_ref.clone()), fingerprint, NOW)
        .expect("first session");
    let cap_ref = entity("runtime.capability");
    let provider_ref = entity("runtime.provider-revision");
    let first = capability(&agent, vec![cap_ref.clone()], vec![provider_ref.clone()]);
    control
        .accept_capability(&first_binding, &first)
        .expect("first cap");
    control
        .accept_resource(&first_binding, &resources(&agent, 8.0))
        .expect("first resources");
    control
        .admit_platform_node(
            &first_binding,
            &state(&agent, &first),
            &profile(cap_ref.clone(), provider_ref.clone()),
        )
        .expect("first admission");

    agent.reconnect().expect("new epoch");
    let current = control
        .accept_hello(&hello(&agent, enrollment_ref), fingerprint, NOW + 1)
        .expect("new session");
    let refreshed = capability(&agent, vec![cap_ref.clone()], vec![provider_ref.clone()]);
    control
        .accept_capability(&current, &refreshed)
        .expect("new capability");
    control
        .accept_resource(&current, &resources(&agent, 8.0))
        .expect("new resources");

    assert_eq!(
        control.place_admitted_and_issue(
            PlatformNodeClass::AlwaysOnLinux,
            &requirement(cap_ref, provider_ref),
            PlacementPolicy::strict(),
            cpu(),
            PlacementAuthorityTiming::new(NOW + 2, NOW + 60, NOW + 30,),
        ),
        Err(PlacementControlError::PlatformAdmissionRequired)
    );
}

#[test]
fn admitted_filter_excludes_otherwise_e02_eligible_nodes() {
    let first = NodeAgent::bootstrap().expect("first");
    let second = NodeAgent::bootstrap().expect("second");
    let first_fp = CredentialFingerprint::from_der(b"e05-control-first");
    let second_fp = CredentialFingerprint::from_der(b"e05-control-second");
    let first_enrollment = enrollment(&first, first_fp);
    let second_enrollment = enrollment(&second, second_fp);
    let first_ref = first_enrollment.enrollment_ref().clone();
    let second_ref = second_enrollment.enrollment_ref().clone();
    let mut control = PlacementAuthorityOwner::new(NodeLinkControl::new(
        ProtocolVersion { major: 1, minor: 0 },
        vec![first_enrollment, second_enrollment],
    ));
    let first_binding = control
        .accept_hello(&hello(&first, first_ref), first_fp, NOW)
        .expect("first session");
    let second_binding = control
        .accept_hello(&hello(&second, second_ref), second_fp, NOW)
        .expect("second session");
    let cap_ref = entity("runtime.capability");
    let provider_ref = entity("runtime.provider-revision");
    let first_cap = capability(&first, vec![cap_ref.clone()], vec![provider_ref.clone()]);
    let second_cap = capability(&second, vec![cap_ref.clone()], vec![provider_ref.clone()]);

    control
        .accept_capability(&first_binding, &first_cap)
        .expect("first cap");
    control
        .accept_resource(&first_binding, &resources(&first, 8.0))
        .expect("first resources");
    control
        .accept_capability(&second_binding, &second_cap)
        .expect("second cap");
    control
        .accept_resource(&second_binding, &resources(&second, 8.0))
        .expect("second resources");

    control
        .admit_platform_node(
            &second_binding,
            &state(&second, &second_cap),
            &profile(cap_ref.clone(), provider_ref.clone()),
        )
        .expect("second admitted");

    let grant = control
        .place_admitted_and_issue(
            PlatformNodeClass::AlwaysOnLinux,
            &requirement(cap_ref, provider_ref),
            PlacementPolicy::strict(),
            cpu(),
            PlacementAuthorityTiming::new(NOW + 1, NOW + 60, NOW + 30),
        )
        .expect("admitted second wins");

    assert_eq!(grant.node_id(), second.node_id());
}
