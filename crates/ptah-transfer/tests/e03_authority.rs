//! E03 transfer-ticket authority contract tests.

use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_transfer::{
    E03TransferError, TransferMode, TransferPeerBinding, TransferPeerRole, TransferRouteCandidate,
    TransferRouteKind, TransferTicket,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid Ptah entity kind")
}

fn fingerprint(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn source_binding() -> TransferPeerBinding {
    TransferPeerBinding {
        node_id: NodeId::new(),
        node_generation: NodeGeneration::new(4),
        connection_epoch: ConnectionEpoch::new(8),
        credential_fingerprint: fingerprint(0x11),
    }
}

fn target_binding() -> TransferPeerBinding {
    TransferPeerBinding {
        node_id: NodeId::new(),
        node_generation: NodeGeneration::new(3),
        connection_epoch: ConnectionEpoch::new(9),
        credential_fingerprint: fingerprint(0x22),
    }
}

fn direct_route() -> TransferRouteCandidate {
    TransferRouteCandidate {
        kind: TransferRouteKind::Direct,
        endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44003),
        server_name: "target.e03.test".to_owned(),
        expected_peer_fingerprint: fingerprint(0x22),
        relay_ref: None,
    }
}

fn relay_route() -> TransferRouteCandidate {
    TransferRouteCandidate {
        kind: TransferRouteKind::Relay,
        endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44004),
        server_name: "relay.e03.test".to_owned(),
        expected_peer_fingerprint: fingerprint(0x33),
        relay_ref: Some(reference("network.relay")),
    }
}

fn ticket(
    source: TransferPeerBinding,
    target: TransferPeerBinding,
    routes: Vec<TransferRouteCandidate>,
) -> Result<TransferTicket, E03TransferError> {
    TransferTicket::new(
        reference("transfer.ticket"),
        reference("transfer.request"),
        reference("transfer.run"),
        reference("activity.attempt"),
        source,
        target,
        Some(reference("storage.content")),
        Some(reference("storage.artifact")),
        5 * 1024 * 1024,
        "ab".repeat(32),
        1024 * 1024,
        routes,
        100,
        200,
        7,
    )
}

#[test]
fn ticket_authorizes_only_exact_current_peer_binding() {
    let source = source_binding();
    let target = target_binding();
    let ticket = ticket(
        source.clone(),
        target.clone(),
        vec![direct_route(), relay_route()],
    )
    .expect("valid E03 ticket");

    assert_eq!(ticket.transfer_mode(), TransferMode::NodeToNode);
    assert_eq!(
        ticket.authorize_peer(TransferPeerRole::Source, &source, 150),
        Ok(())
    );
    assert_eq!(
        ticket.authorize_peer(TransferPeerRole::Target, &target, 150),
        Ok(())
    );

    let stale_source = TransferPeerBinding {
        node_generation: NodeGeneration::new(source.node_generation.value() + 1),
        ..source.clone()
    };
    assert_eq!(
        ticket.authorize_peer(TransferPeerRole::Source, &stale_source, 150),
        Err(E03TransferError::NodeGenerationMismatch)
    );

    let stale_target = TransferPeerBinding {
        connection_epoch: ConnectionEpoch::new(target.connection_epoch.value() + 1),
        ..target.clone()
    };
    assert_eq!(
        ticket.authorize_peer(TransferPeerRole::Target, &stale_target, 150),
        Err(E03TransferError::ConnectionEpochMismatch)
    );

    let wrong_credential = TransferPeerBinding {
        credential_fingerprint: fingerprint(0x99),
        ..target.clone()
    };
    assert_eq!(
        ticket.authorize_peer(TransferPeerRole::Target, &wrong_credential, 150),
        Err(E03TransferError::CredentialFingerprintMismatch)
    );

    assert_eq!(
        ticket.authorize_peer(TransferPeerRole::Target, &target, 200),
        Err(E03TransferError::ExpiredTicket)
    );
}

#[test]
fn ticket_rejects_invalid_geometry_digest_lifetime_and_route_set() {
    let source = source_binding();
    let target = target_binding();

    let invalid_size = TransferTicket::new(
        reference("transfer.ticket"),
        reference("transfer.request"),
        reference("transfer.run"),
        reference("activity.attempt"),
        source.clone(),
        target.clone(),
        None,
        None,
        0,
        "ab".repeat(32),
        1024,
        vec![direct_route()],
        100,
        200,
        1,
    );
    assert_eq!(invalid_size, Err(E03TransferError::InvalidGeometry));

    let invalid_range = TransferTicket::new(
        reference("transfer.ticket"),
        reference("transfer.request"),
        reference("transfer.run"),
        reference("activity.attempt"),
        source.clone(),
        target.clone(),
        None,
        None,
        1,
        "ab".repeat(32),
        0,
        vec![direct_route()],
        100,
        200,
        1,
    );
    assert_eq!(invalid_range, Err(E03TransferError::InvalidGeometry));

    let invalid_digest = TransferTicket::new(
        reference("transfer.ticket"),
        reference("transfer.request"),
        reference("transfer.run"),
        reference("activity.attempt"),
        source.clone(),
        target.clone(),
        None,
        None,
        1,
        "not-a-sha256".to_owned(),
        1,
        vec![direct_route()],
        100,
        200,
        1,
    );
    assert_eq!(
        invalid_digest,
        Err(E03TransferError::InvalidCanonicalDigest)
    );

    let invalid_lifetime = TransferTicket::new(
        reference("transfer.ticket"),
        reference("transfer.request"),
        reference("transfer.run"),
        reference("activity.attempt"),
        source.clone(),
        target.clone(),
        None,
        None,
        1,
        "ab".repeat(32),
        1,
        vec![direct_route()],
        200,
        200,
        1,
    );
    assert_eq!(invalid_lifetime, Err(E03TransferError::InvalidLifetime));

    let no_routes = ticket(source.clone(), target.clone(), Vec::new());
    assert_eq!(no_routes, Err(E03TransferError::NoAuthorizedRoute));

    let duplicate = ticket(source, target, vec![direct_route(), direct_route()]);
    assert_eq!(duplicate, Err(E03TransferError::DuplicateRoute));
}

#[test]
fn ticket_authorizes_only_routes_frozen_into_ticket() {
    let direct = direct_route();
    let relay = relay_route();
    let ticket = ticket(
        source_binding(),
        target_binding(),
        vec![direct.clone(), relay.clone()],
    )
    .expect("valid E03 ticket");

    assert_eq!(ticket.authorize_route(&direct), Ok(()));
    assert_eq!(ticket.authorize_route(&relay), Ok(()));

    let unauthorized = TransferRouteCandidate {
        endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44999),
        ..direct
    };
    assert_eq!(
        ticket.authorize_route(&unauthorized),
        Err(E03TransferError::UnauthorizedRoute)
    );
}
