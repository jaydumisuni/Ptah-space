//! E03 control-issued transfer ticket authority tests.

use ptah_control::node_link::NodeLinkControl;
use ptah_control::transfer::{TransferAuthorityError, TransferAuthorityOwner, TransferTicketSpec};
use ptah_identifiers::EntityRef;
use ptah_node_agent::NodeAgent;
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle, NodeHello, ProtocolVersion,
};
use ptah_transfer::{TransferRouteCandidate, TransferRouteKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("reference")
}

fn enrollment(agent: &NodeAgent, fingerprint: CredentialFingerprint) -> ApprovedNodeEnrollment {
    ApprovedNodeEnrollment::new(
        reference("core.node_enrollment"),
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
        agent_revision: String::from("e03-transfer-authority-test"),
        capability_snapshot_ref: None,
    }
}

fn direct_route(fingerprint: CredentialFingerprint) -> TransferRouteCandidate {
    TransferRouteCandidate {
        kind: TransferRouteKind::Direct,
        endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7443),
        server_name: String::from("target.test"),
        expected_peer_fingerprint: *fingerprint.as_bytes(),
        relay_ref: None,
    }
}

fn relay_route(fingerprint: CredentialFingerprint) -> TransferRouteCandidate {
    TransferRouteCandidate {
        kind: TransferRouteKind::Relay,
        endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443),
        server_name: String::from("relay.test"),
        expected_peer_fingerprint: *fingerprint.as_bytes(),
        relay_ref: Some(reference("core.node_relay")),
    }
}

fn spec(source: &NodeAgent, target: &NodeAgent, routes: Vec<TransferRouteCandidate>) -> TransferTicketSpec {
    TransferTicketSpec {
        request_ref: reference("transfer.request"),
        run_ref: reference("transfer.run"),
        attempt_ref: reference("activity.attempt"),
        source_node_id: source.node_id(),
        target_node_id: target.node_id(),
        content_ref: Some(reference("storage.content")),
        artifact_ref: None,
        expected_size: 5 * 1024 * 1024,
        canonical_sha256: "a".repeat(64),
        range_size: 1024 * 1024,
        routes,
        expires_at_unix_seconds: 200,
    }
}

fn owner_with_two_nodes() -> (
    TransferAuthorityOwner,
    NodeAgent,
    NodeAgent,
    CredentialFingerprint,
    CredentialFingerprint,
    EntityRef,
    EntityRef,
) {
    let source = NodeAgent::bootstrap().expect("source");
    let target = NodeAgent::bootstrap().expect("target");
    let source_fp = CredentialFingerprint::from_der(b"e03-source-credential");
    let target_fp = CredentialFingerprint::from_der(b"e03-target-credential");
    let source_enrollment = enrollment(&source, source_fp);
    let target_enrollment = enrollment(&target, target_fp);
    let source_enrollment_ref = source_enrollment.enrollment_ref().clone();
    let target_enrollment_ref = target_enrollment.enrollment_ref().clone();
    let node_link = NodeLinkControl::new(
        ProtocolVersion { major: 1, minor: 0 },
        vec![source_enrollment, target_enrollment],
    );
    let mut owner = TransferAuthorityOwner::new(node_link);
    owner
        .accept_hello(&hello(&source, source_enrollment_ref.clone()), source_fp, 0)
        .expect("source accepted");
    owner
        .accept_hello(&hello(&target, target_enrollment_ref.clone()), target_fp, 0)
        .expect("target accepted");
    (
        owner,
        source,
        target,
        source_fp,
        target_fp,
        source_enrollment_ref,
        target_enrollment_ref,
    )
}

#[test]
fn issuance_binds_exact_current_sessions_and_preserves_explicit_routes() {
    let (mut owner, source, target, source_fp, target_fp, _, _) = owner_with_two_nodes();
    let routes = vec![direct_route(target_fp), relay_route(target_fp)];
    let ticket = owner
        .issue_ticket(spec(&source, &target, routes.clone()), 100)
        .expect("ticket issued");

    assert_eq!(ticket.source().node_id, source.node_id());
    assert_eq!(ticket.source().node_generation, source.generation());
    assert_eq!(ticket.source().connection_epoch, source.connection_epoch());
    assert_eq!(ticket.source().credential_fingerprint, *source_fp.as_bytes());
    assert_eq!(ticket.target().node_id, target.node_id());
    assert_eq!(ticket.target().credential_fingerprint, *target_fp.as_bytes());
    assert_eq!(ticket.routes(), routes.as_slice());
    assert_eq!(ticket.issued_at_unix_seconds(), 100);
    assert_eq!(ticket.expires_at_unix_seconds(), 200);
    assert!(owner.assert_current(&ticket).is_ok());
}

#[test]
fn issuance_rejects_same_node_missing_session_and_expired_spec() {
    let (mut owner, source, target, _, target_fp, _, _) = owner_with_two_nodes();
    let routes = vec![direct_route(target_fp)];

    let mut same = spec(&source, &target, routes.clone());
    same.target_node_id = source.node_id();
    assert_eq!(
        owner.issue_ticket(same, 100),
        Err(TransferAuthorityError::SameNode)
    );

    let missing = NodeAgent::bootstrap().expect("missing node");
    let mut no_source = spec(&source, &target, routes.clone());
    no_source.source_node_id = missing.node_id();
    assert_eq!(
        owner.issue_ticket(no_source, 100),
        Err(TransferAuthorityError::SourceSessionNotCurrent)
    );

    let mut expired = spec(&source, &target, routes);
    expired.expires_at_unix_seconds = 100;
    assert_eq!(
        owner.issue_ticket(expired, 100),
        Err(TransferAuthorityError::InvalidExpiry)
    );
}

#[test]
fn supersession_reissue_and_revocation_fence_ticket_authority() {
    let (mut owner, mut source, target, source_fp, target_fp, source_enrollment_ref, _) =
        owner_with_two_nodes();
    let stable_run = reference("transfer.run");
    let mut original_spec = spec(&source, &target, vec![direct_route(target_fp)]);
    original_spec.run_ref = stable_run.clone();
    let ticket = owner.issue_ticket(original_spec, 100).expect("ticket issued");

    source.reconnect().expect("source reconnect");
    owner
        .accept_hello(&hello(&source, source_enrollment_ref), source_fp, 101)
        .expect("new source session accepted");
    assert_eq!(
        owner.assert_current(&ticket),
        Err(TransferAuthorityError::SupersededSourceSession)
    );

    let mut reissue_spec = spec(&source, &target, vec![direct_route(target_fp)]);
    reissue_spec.run_ref = stable_run.clone();
    let reissued = owner.issue_ticket(reissue_spec, 102).expect("reissued");
    assert_eq!(ticket.run_ref(), &stable_run);
    assert_eq!(reissued.run_ref(), &stable_run);
    assert_ne!(ticket.ticket_ref(), reissued.ticket_ref());
    assert_ne!(ticket.nonce(), reissued.nonce());
    assert!(owner.assert_current(&reissued).is_ok());

    assert!(owner.revoke_ticket(reissued.ticket_ref()));
    assert_eq!(
        owner.assert_current(&reissued),
        Err(TransferAuthorityError::RevokedTicket)
    );
}
