//! E03 Node-local transfer ticket guard tests.

use ptah_identifiers::EntityRef;
use ptah_node::transfer::{NodeTransferError, NodeTransferGuard};
use ptah_node_agent::NodeAgent;
use ptah_node_link::CredentialFingerprint;
use ptah_transfer::{
    TransferPeerBinding, TransferPeerRole, TransferRouteCandidate, TransferRouteKind, TransferTicket,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("reference")
}

fn binding(agent: &NodeAgent, fingerprint: CredentialFingerprint) -> TransferPeerBinding {
    TransferPeerBinding {
        node_id: agent.node_id(),
        node_generation: agent.generation(),
        connection_epoch: agent.connection_epoch(),
        credential_fingerprint: *fingerprint.as_bytes(),
    }
}

fn ticket(
    source: &NodeAgent,
    target: &NodeAgent,
    source_fp: CredentialFingerprint,
    target_fp: CredentialFingerprint,
) -> TransferTicket {
    TransferTicket::new(
        reference("transfer.ticket"),
        reference("transfer.request"),
        reference("transfer.run"),
        reference("activity.attempt"),
        binding(source, source_fp),
        binding(target, target_fp),
        Some(reference("storage.content")),
        None,
        2 * 1024 * 1024,
        "a".repeat(64),
        1024 * 1024,
        vec![TransferRouteCandidate {
            kind: TransferRouteKind::Direct,
            endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7443),
            server_name: String::from("target.test"),
            expected_peer_fingerprint: *target_fp.as_bytes(),
            relay_ref: None,
        }],
        10,
        100,
        1,
    )
    .expect("ticket")
}

#[test]
fn source_and_target_accept_only_their_exact_ticket_side() {
    let source = NodeAgent::bootstrap().expect("source");
    let target = NodeAgent::bootstrap().expect("target");
    let source_fp = CredentialFingerprint::from_der(b"source");
    let target_fp = CredentialFingerprint::from_der(b"target");
    let ticket = ticket(&source, &target, source_fp, target_fp);
    let mut source_guard = NodeTransferGuard::for_agent(&source);
    let mut target_guard = NodeTransferGuard::for_agent(&target);

    assert!(source_guard
        .accept_ticket(&source, TransferPeerRole::Source, &ticket, 11)
        .is_ok());
    assert!(target_guard
        .accept_ticket(&target, TransferPeerRole::Target, &ticket, 11)
        .is_ok());
    assert_eq!(
        NodeTransferGuard::for_agent(&source)
            .accept_ticket(&source, TransferPeerRole::Target, &ticket, 11),
        Err(NodeTransferError::WrongRole)
    );
    assert_eq!(source_guard.ticket(ticket.ticket_ref()), Some(&ticket));
}

#[test]
fn wrong_peer_fingerprint_and_stale_live_session_fail_closed() {
    let mut source = NodeAgent::bootstrap().expect("source");
    let target = NodeAgent::bootstrap().expect("target");
    let source_fp = CredentialFingerprint::from_der(b"source");
    let target_fp = CredentialFingerprint::from_der(b"target");
    let wrong_fp = CredentialFingerprint::from_der(b"wrong-target");
    let ticket = ticket(&source, &target, source_fp, target_fp);
    let mut guard = NodeTransferGuard::for_agent(&source);
    guard
        .accept_ticket(&source, TransferPeerRole::Source, &ticket, 11)
        .expect("accepted");

    assert_eq!(
        guard.authorize_peer(&source, &ticket, wrong_fp, 12),
        Err(NodeTransferError::PeerFingerprintMismatch)
    );
    assert!(guard
        .authorize_peer(&source, &ticket, target_fp, 12)
        .is_ok());

    source.reconnect().expect("reconnect");
    assert_eq!(
        guard.authorize_peer(&source, &ticket, target_fp, 13),
        Err(NodeTransferError::SupersededSession)
    );
    assert_eq!(
        guard.accept_ticket(&source, TransferPeerRole::Source, &ticket, 13),
        Err(NodeTransferError::SupersededSession)
    );
}

#[test]
fn expired_ticket_is_rejected_before_admission() {
    let source = NodeAgent::bootstrap().expect("source");
    let target = NodeAgent::bootstrap().expect("target");
    let source_fp = CredentialFingerprint::from_der(b"source");
    let target_fp = CredentialFingerprint::from_der(b"target");
    let ticket = ticket(&source, &target, source_fp, target_fp);
    let mut guard = NodeTransferGuard::for_agent(&source);

    assert_eq!(
        guard.accept_ticket(&source, TransferPeerRole::Source, &ticket, 100),
        Err(NodeTransferError::ExpiredTicket)
    );
}
