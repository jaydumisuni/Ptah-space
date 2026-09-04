//! E01 control-plane secure Node-link integration tests.

use ptah_control::node_link::NodeLinkControl;
use ptah_identifiers::EntityRef;
use ptah_node_agent::{
    Architecture, NodeAgent, NodeCapabilitySnapshot, OsFamily, PlatformFacts, SnapshotOutcome,
};
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle, LinkError, NodeHello,
    ProtocolVersion,
};

fn enrollment(agent: &NodeAgent, fingerprint: CredentialFingerprint) -> ApprovedNodeEnrollment {
    ApprovedNodeEnrollment::new(
        EntityRef::new("core.node_enrollment").expect("enrollment ref"),
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
        agent_revision: String::from("e01-service-test"),
        capability_snapshot_ref: None,
    }
}

fn capability(agent: &NodeAgent) -> NodeCapabilitySnapshot {
    NodeCapabilitySnapshot::new(
        agent.node_ref(),
        agent.generation(),
        agent.connection_epoch(),
        SnapshotOutcome::Complete,
        "e01-service-test",
        PlatformFacts {
            os_family: OsFamily::Linux,
            os_name: Some(String::from("Test Linux")),
            os_version: Some(String::from("24.04")),
            kernel_name: Some(String::from("Linux")),
            kernel_version: Some(String::from("6.8")),
            architecture: Architecture::X86_64,
            architecture_detail: None,
        },
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![EntityRef::new("core.node_observation").expect("observation ref")],
        vec![EntityRef::new("proof.receipt").expect("receipt ref")],
        Vec::new(),
    )
    .expect("capability snapshot")
}

#[test]
fn two_nodes_are_accepted_as_independent_current_sessions() {
    let first = NodeAgent::bootstrap().expect("first node");
    let second = NodeAgent::bootstrap().expect("second node");
    let first_fp = CredentialFingerprint::from_der(b"first-credential");
    let second_fp = CredentialFingerprint::from_der(b"second-credential");
    let first_enrollment = enrollment(&first, first_fp);
    let second_enrollment = enrollment(&second, second_fp);
    let first_hello = hello(&first, first_enrollment.enrollment_ref().clone());
    let second_hello = hello(&second, second_enrollment.enrollment_ref().clone());
    let mut control = NodeLinkControl::new(
        ProtocolVersion { major: 1, minor: 0 },
        vec![first_enrollment, second_enrollment],
    );

    let first_binding = control
        .accept_hello(&first_hello, first_fp, 0)
        .expect("first accepted");
    let second_binding = control
        .accept_hello(&second_hello, second_fp, 0)
        .expect("second accepted");

    assert_eq!(control.current_session(first.node_id()), Some(&first_binding));
    assert_eq!(control.current_session(second.node_id()), Some(&second_binding));
}

#[test]
fn capability_must_match_authenticated_node_authority() {
    let first = NodeAgent::bootstrap().expect("first node");
    let second = NodeAgent::bootstrap().expect("second node");
    let first_fp = CredentialFingerprint::from_der(b"first-credential");
    let first_enrollment = enrollment(&first, first_fp);
    let first_hello = hello(&first, first_enrollment.enrollment_ref().clone());
    let mut control = NodeLinkControl::new(
        ProtocolVersion { major: 1, minor: 0 },
        vec![first_enrollment],
    );
    let binding = control
        .accept_hello(&first_hello, first_fp, 0)
        .expect("accepted");

    assert_eq!(
        control.accept_capability(&binding, &capability(&second)),
        Err(LinkError::NodeIdentityMismatch)
    );
}

#[test]
fn superseded_session_cannot_publish_capability() {
    let mut agent = NodeAgent::bootstrap().expect("node");
    let fingerprint = CredentialFingerprint::from_der(b"credential");
    let approved = enrollment(&agent, fingerprint);
    let enrollment_ref = approved.enrollment_ref().clone();
    let mut control = NodeLinkControl::new(
        ProtocolVersion { major: 1, minor: 0 },
        vec![approved],
    );

    let first_binding = control
        .accept_hello(&hello(&agent, enrollment_ref.clone()), fingerprint, 0)
        .expect("first accepted");
    agent.reconnect().expect("advance epoch");
    control
        .accept_hello(&hello(&agent, enrollment_ref), fingerprint, 1)
        .expect("reconnect accepted");

    assert_eq!(
        control.accept_capability(&first_binding, &capability(&agent)),
        Err(LinkError::SupersededConnection)
    );
}
