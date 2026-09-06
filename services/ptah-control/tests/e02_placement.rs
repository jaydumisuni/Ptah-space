//! E02 Task 6 control-plane placement authority ownership tests.

use ptah_control::node_link::NodeLinkControl;
use ptah_control::placement::{PlacementAuthorityOwner, PlacementControlError};
use ptah_identifiers::EntityRef;
use ptah_node_agent::{
    Architecture, NodeAgent, NodeCapabilitySnapshot, NodeResourceSnapshot, OsFamily, PlatformFacts,
    ResourcePressure, ResourceQuantity, ResourceUnit, SnapshotOutcome,
};
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle, LinkError, NodeHello,
    ProtocolVersion,
};
use ptah_placement_runtime::{
    LeaseError, PlacementPolicy, PlacementRequirement, ReservedResource, ResourceRequirement,
};

const NOW: u64 = 1_800_000_000;

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
        agent_revision: String::from("e02-control-test"),
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
        "e02-control-test",
        PlatformFacts {
            os_family: OsFamily::Linux,
            os_name: Some(String::from("Test Linux")),
            os_version: Some(String::from("1")),
            kernel_name: Some(String::from("test")),
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

fn requirement(
    attempt_ref: EntityRef,
    capability_ref: EntityRef,
    provider_ref: EntityRef,
) -> PlacementRequirement {
    PlacementRequirement::new(
        attempt_ref,
        vec![capability_ref],
        vec![provider_ref],
        vec![ResourceRequirement::new("cpu", ResourceUnit::Cores, 1.0).expect("requirement")],
        Some(OsFamily::Linux),
    )
}

fn cpu(quantity: f64) -> ReservedResource {
    ReservedResource::new("cpu", ResourceUnit::Cores, quantity).expect("reserved cpu")
}

#[test]
fn control_accepts_evidence_only_for_current_e01_session() {
    let mut agent = NodeAgent::bootstrap().expect("node");
    let fingerprint = CredentialFingerprint::from_der(b"e02-control-session");
    let approved = enrollment(&agent, fingerprint);
    let enrollment_ref = approved.enrollment_ref().clone();
    let link = NodeLinkControl::new(ProtocolVersion { major: 1, minor: 0 }, vec![approved]);
    let mut control = PlacementAuthorityOwner::new(link);

    let old = control
        .accept_hello(&hello(&agent, enrollment_ref.clone()), fingerprint, NOW)
        .expect("initial session");
    control
        .accept_capability(&old, &capability(&agent, Vec::new(), Vec::new()))
        .expect("current capability");
    control
        .accept_resource(&old, &resources(&agent, 8.0))
        .expect("current resources");

    agent.reconnect().expect("new epoch");
    control
        .accept_hello(&hello(&agent, enrollment_ref), fingerprint, NOW + 1)
        .expect("new current session");

    assert_eq!(
        control.accept_capability(&old, &capability(&agent, Vec::new(), Vec::new())),
        Err(LinkError::SupersededConnection)
    );
    assert_eq!(
        control.accept_resource(&old, &resources(&agent, 8.0)),
        Err(LinkError::SupersededConnection)
    );
}

#[test]
fn placement_mints_authority_only_after_deterministic_eligibility() {
    let first = NodeAgent::bootstrap().expect("first node");
    let second = NodeAgent::bootstrap().expect("second node");
    let first_fp = CredentialFingerprint::from_der(b"e02-control-first");
    let second_fp = CredentialFingerprint::from_der(b"e02-control-second");
    let first_enrollment = enrollment(&first, first_fp);
    let second_enrollment = enrollment(&second, second_fp);
    let first_ref = first_enrollment.enrollment_ref().clone();
    let second_ref = second_enrollment.enrollment_ref().clone();
    let link = NodeLinkControl::new(
        ProtocolVersion { major: 1, minor: 0 },
        vec![first_enrollment, second_enrollment],
    );
    let mut control = PlacementAuthorityOwner::new(link);
    let first_binding = control
        .accept_hello(&hello(&first, first_ref), first_fp, NOW)
        .expect("first session");
    let second_binding = control
        .accept_hello(&hello(&second, second_ref), second_fp, NOW)
        .expect("second session");
    let capability_ref = entity("runtime.capability");
    let provider_ref = entity("runtime.provider-revision");

    control
        .accept_capability(
            &first_binding,
            &capability(&first, Vec::new(), vec![provider_ref.clone()]),
        )
        .expect("first capability evidence");
    control
        .accept_resource(&first_binding, &resources(&first, 8.0))
        .expect("first resources");
    control
        .accept_capability(
            &second_binding,
            &capability(
                &second,
                vec![capability_ref.clone()],
                vec![provider_ref.clone()],
            ),
        )
        .expect("second capability evidence");
    control
        .accept_resource(&second_binding, &resources(&second, 8.0))
        .expect("second resources");

    let grant = control
        .place_and_issue(
            &requirement(entity("activity.attempt"), capability_ref, provider_ref),
            PlacementPolicy::strict(),
            vec![cpu(1.0)],
            NOW + 1,
            NOW + 60,
            NOW + 30,
        )
        .expect("eligible placement authority");

    assert_eq!(grant.node_id(), second.node_id());
    assert_eq!(grant.lease().fence().value(), 1);
    assert_eq!(grant.dispatch_authority().fence(), grant.lease().fence());
}

#[test]
fn superseded_session_immediately_invalidates_existing_dispatch_grant() {
    let mut agent = NodeAgent::bootstrap().expect("node");
    let fingerprint = CredentialFingerprint::from_der(b"e02-control-supersede");
    let approved = enrollment(&agent, fingerprint);
    let enrollment_ref = approved.enrollment_ref().clone();
    let link = NodeLinkControl::new(ProtocolVersion { major: 1, minor: 0 }, vec![approved]);
    let mut control = PlacementAuthorityOwner::new(link);
    let binding = control
        .accept_hello(&hello(&agent, enrollment_ref.clone()), fingerprint, NOW)
        .expect("session");
    let capability_ref = entity("runtime.capability");
    let provider_ref = entity("runtime.provider-revision");
    control
        .accept_capability(
            &binding,
            &capability(
                &agent,
                vec![capability_ref.clone()],
                vec![provider_ref.clone()],
            ),
        )
        .expect("capabilities");
    control
        .accept_resource(&binding, &resources(&agent, 8.0))
        .expect("resources");
    let grant = control
        .place_and_issue(
            &requirement(entity("activity.attempt"), capability_ref, provider_ref),
            PlacementPolicy::strict(),
            vec![cpu(1.0)],
            NOW + 1,
            NOW + 60,
            NOW + 30,
        )
        .expect("grant");
    assert!(control.validate_dispatch(&grant, NOW + 2).is_ok());

    agent.reconnect().expect("advance session");
    control
        .accept_hello(&hello(&agent, enrollment_ref), fingerprint, NOW + 3)
        .expect("superseding session");

    assert_eq!(
        control.validate_dispatch(&grant, NOW + 4),
        Err(PlacementControlError::SupersededSession)
    );
}

#[test]
fn fence_is_control_allocated_and_advances_without_client_projection_input() {
    let agent = NodeAgent::bootstrap().expect("node");
    let fingerprint = CredentialFingerprint::from_der(b"e02-control-fence");
    let approved = enrollment(&agent, fingerprint);
    let enrollment_ref = approved.enrollment_ref().clone();
    let link = NodeLinkControl::new(ProtocolVersion { major: 1, minor: 0 }, vec![approved]);
    let mut control = PlacementAuthorityOwner::new(link);
    let binding = control
        .accept_hello(&hello(&agent, enrollment_ref), fingerprint, NOW)
        .expect("session");
    let capability_ref = entity("runtime.capability");
    let provider_ref = entity("runtime.provider-revision");
    control
        .accept_capability(
            &binding,
            &capability(
                &agent,
                vec![capability_ref.clone()],
                vec![provider_ref.clone()],
            ),
        )
        .expect("capabilities");
    control
        .accept_resource(&binding, &resources(&agent, 8.0))
        .expect("resources");
    let attempt_ref = entity("activity.attempt");
    let placement = requirement(attempt_ref, capability_ref, provider_ref);

    let first = control
        .place_and_issue(
            &placement,
            PlacementPolicy::strict(),
            vec![cpu(1.0)],
            NOW + 1,
            NOW + 80,
            NOW + 30,
        )
        .expect("first authority");
    let second = control
        .place_and_issue(
            &placement,
            PlacementPolicy::strict(),
            vec![cpu(1.0)],
            NOW + 2,
            NOW + 80,
            NOW + 40,
        )
        .expect("second authority");

    assert_eq!(first.lease().fence().value(), 1);
    assert_eq!(second.lease().fence().value(), 2);
    assert_eq!(
        control.validate_dispatch(&first, NOW + 3),
        Err(PlacementControlError::Lease(LeaseError::StaleFence))
    );
    assert!(control.validate_dispatch(&second, NOW + 3).is_ok());
}
