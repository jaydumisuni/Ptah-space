//! E01 enrollment authority, credential rotation and session-fencing tests.

use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle, LinkError, NodeHello,
    ProtocolVersion, SessionRegistry,
};

fn enrollment(node_id: NodeId, fingerprint: CredentialFingerprint) -> ApprovedNodeEnrollment {
    ApprovedNodeEnrollment::new(
        EntityRef::new("core.node_enrollment").expect("enrollment ref"),
        node_id,
        EnrollmentLifecycle::Approved,
        vec![String::from("node.executor")],
        vec![fingerprint],
        Some(10_000),
    )
    .expect("approved enrollment")
}

fn hello(
    node_id: NodeId,
    enrollment_ref: EntityRef,
    generation: u64,
    epoch: u64,
) -> NodeHello {
    NodeHello {
        supported_major: 1,
        minimum_minor: 0,
        maximum_minor: 0,
        node_id,
        node_generation: NodeGeneration::new(generation),
        connection_epoch: ConnectionEpoch::new(epoch),
        enrollment_ref,
        agent_revision: String::from("e01-session-test"),
        capability_snapshot_ref: None,
    }
}

#[test]
fn approved_bound_credential_is_accepted() {
    let node_id = NodeId::new();
    let fingerprint = CredentialFingerprint::from_der(b"credential-one");
    let enrollment = enrollment(node_id, fingerprint);
    let request = hello(node_id, enrollment.enrollment_ref().clone(), 1, 1);
    let mut registry = SessionRegistry::new(ProtocolVersion { major: 1, minor: 0 });

    let binding = registry
        .accept_hello(&request, &enrollment, fingerprint, 1_000)
        .expect("accepted session");
    assert_eq!(binding.node_id, node_id);
    registry.assert_current(&binding).expect("current session");
}

#[test]
fn lifecycle_and_identity_fail_closed() {
    let node_id = NodeId::new();
    let other_node = NodeId::new();
    let fingerprint = CredentialFingerprint::from_der(b"credential-two");
    let mut enrollment = enrollment(node_id, fingerprint);
    let mut registry = SessionRegistry::new(ProtocolVersion { major: 1, minor: 0 });

    let wrong_node = hello(other_node, enrollment.enrollment_ref().clone(), 1, 1);
    assert_eq!(
        registry.accept_hello(&wrong_node, &enrollment, fingerprint, 1_000),
        Err(LinkError::NodeIdentityMismatch)
    );

    let unbound = CredentialFingerprint::from_der(b"not-approved");
    let valid_hello = hello(node_id, enrollment.enrollment_ref().clone(), 1, 1);
    assert_eq!(
        registry.accept_hello(&valid_hello, &enrollment, unbound, 1_000),
        Err(LinkError::CredentialNotBound)
    );

    enrollment.set_lifecycle(EnrollmentLifecycle::Revoked);
    assert_eq!(
        registry.accept_hello(&valid_hello, &enrollment, fingerprint, 1_000),
        Err(LinkError::EnrollmentRevoked)
    );
    enrollment.set_lifecycle(EnrollmentLifecycle::Expired);
    assert_eq!(
        registry.accept_hello(&valid_hello, &enrollment, fingerprint, 1_000),
        Err(LinkError::EnrollmentExpired)
    );
    enrollment.set_lifecycle(EnrollmentLifecycle::Requested);
    assert_eq!(
        registry.accept_hello(&valid_hello, &enrollment, fingerprint, 1_000),
        Err(LinkError::UnapprovedEnrollment)
    );
}

#[test]
fn reconnect_supersedes_old_epoch_and_generation() {
    let node_id = NodeId::new();
    let fingerprint = CredentialFingerprint::from_der(b"credential-three");
    let enrollment = enrollment(node_id, fingerprint);
    let mut registry = SessionRegistry::new(ProtocolVersion { major: 1, minor: 0 });

    let first = registry
        .accept_hello(
            &hello(node_id, enrollment.enrollment_ref().clone(), 1, 1),
            &enrollment,
            fingerprint,
            1_000,
        )
        .expect("first session");
    let second = registry
        .accept_hello(
            &hello(node_id, enrollment.enrollment_ref().clone(), 1, 2),
            &enrollment,
            fingerprint,
            1_000,
        )
        .expect("reconnected session");

    assert_eq!(registry.assert_current(&first), Err(LinkError::SupersededConnection));
    registry.assert_current(&second).expect("second current");
    assert_eq!(
        registry.accept_hello(
            &hello(node_id, enrollment.enrollment_ref().clone(), 1, 2),
            &enrollment,
            fingerprint,
            1_000,
        ),
        Err(LinkError::StaleConnectionEpoch { current: 2, requested: 2 })
    );

    let third = registry
        .accept_hello(
            &hello(node_id, enrollment.enrollment_ref().clone(), 2, 1),
            &enrollment,
            fingerprint,
            1_000,
        )
        .expect("new generation");
    assert_eq!(registry.assert_current(&second), Err(LinkError::SupersededConnection));
    registry.assert_current(&third).expect("third current");
    assert_eq!(
        registry.accept_hello(
            &hello(node_id, enrollment.enrollment_ref().clone(), 1, 9),
            &enrollment,
            fingerprint,
            1_000,
        ),
        Err(LinkError::StaleNodeGeneration { current: 2, requested: 1 })
    );
}

#[test]
fn credential_rotation_preserves_node_identity_and_fences_revoked_key() {
    let node_id = NodeId::new();
    let old = CredentialFingerprint::from_der(b"credential-old");
    let new = CredentialFingerprint::from_der(b"credential-new");
    let mut enrollment = enrollment(node_id, old);
    enrollment.add_credential(new);
    let mut registry = SessionRegistry::new(ProtocolVersion { major: 1, minor: 0 });

    let old_binding = registry
        .accept_hello(
            &hello(node_id, enrollment.enrollment_ref().clone(), 1, 1),
            &enrollment,
            old,
            1_000,
        )
        .expect("old credential accepted during overlap");
    let new_binding = registry
        .accept_hello(
            &hello(node_id, enrollment.enrollment_ref().clone(), 1, 2),
            &enrollment,
            new,
            1_000,
        )
        .expect("new credential accepted");
    assert_eq!(old_binding.node_id, new_binding.node_id);

    assert!(enrollment.revoke_credential(&old));
    registry.revoke_credential(&old);
    assert_eq!(registry.assert_current(&old_binding), Err(LinkError::SupersededConnection));
    assert_eq!(
        registry.accept_hello(
            &hello(node_id, enrollment.enrollment_ref().clone(), 1, 3),
            &enrollment,
            old,
            1_000,
        ),
        Err(LinkError::CredentialNotBound)
    );
}
