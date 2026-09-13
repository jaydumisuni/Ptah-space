//! E03 explicit single-hop relay authorization contract.

use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_transfer::{RangeDataHeader, RangeRequest, RelayAdmissionError, RelayBroker};
use ptah_transfer::{
    TransferPeerBinding, TransferRouteCandidate, TransferRouteKind, TransferTicket,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const RELAY_FINGERPRINT: [u8; 32] = [0x33; 32];

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("reference")
}

fn binding(fingerprint: [u8; 32]) -> TransferPeerBinding {
    TransferPeerBinding {
        node_id: NodeId::new(),
        node_generation: NodeGeneration::INITIAL,
        connection_epoch: ConnectionEpoch::INITIAL,
        credential_fingerprint: fingerprint,
    }
}

fn relay_route(relay_ref: EntityRef) -> TransferRouteCandidate {
    TransferRouteCandidate {
        kind: TransferRouteKind::Relay,
        endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9443),
        server_name: String::from("relay.localhost"),
        expected_peer_fingerprint: RELAY_FINGERPRINT,
        relay_ref: Some(relay_ref),
    }
}

fn ticket_with_route(
    ticket_ref: EntityRef,
    source: TransferPeerBinding,
    target: TransferPeerBinding,
    route: TransferRouteCandidate,
) -> TransferTicket {
    TransferTicket::new(
        ticket_ref,
        reference("transfer.request"),
        reference("transfer.run"),
        reference("activity.attempt"),
        source,
        target,
        Some(reference("storage.content")),
        None,
        4096,
        "11".repeat(32),
        1024,
        vec![route],
        10,
        20,
        7,
    )
    .expect("ticket")
}

#[test]
fn relay_rejects_ticket_without_its_exact_relay_candidate() {
    let source = binding([0x10; 32]);
    let target = binding([0x20; 32]);
    let authorized = relay_route(reference("relay.authorized"));
    let ticket = ticket_with_route(
        reference("transfer.ticket"),
        source.clone(),
        target,
        authorized,
    );
    let mut broker = RelayBroker::new(vec![ticket.clone()]);
    let ambient = relay_route(reference("relay.ambient"));

    assert_eq!(
        broker.register_source(
            ticket.ticket_ref(),
            &ambient,
            &source,
            RELAY_FINGERPRINT,
            11,
        ),
        Err(RelayAdmissionError::UnauthorizedRelayRoute),
    );
}

#[test]
fn relay_rejects_wrong_relay_tls_fingerprint() {
    let source = binding([0x10; 32]);
    let target = binding([0x20; 32]);
    let route = relay_route(reference("relay.authorized"));
    let ticket = ticket_with_route(
        reference("transfer.ticket"),
        source.clone(),
        target,
        route.clone(),
    );
    let mut broker = RelayBroker::new(vec![ticket.clone()]);

    assert_eq!(
        broker.register_source(ticket.ticket_ref(), &route, &source, [0x44; 32], 11),
        Err(RelayAdmissionError::RelayFingerprintMismatch),
    );
}

#[test]
fn relay_rejects_two_source_peers_for_one_ticket() {
    let source = binding([0x10; 32]);
    let target = binding([0x20; 32]);
    let route = relay_route(reference("relay.authorized"));
    let ticket = ticket_with_route(
        reference("transfer.ticket"),
        source.clone(),
        target,
        route.clone(),
    );
    let mut broker = RelayBroker::new(vec![ticket.clone()]);

    broker
        .register_source(ticket.ticket_ref(), &route, &source, RELAY_FINGERPRINT, 11)
        .expect("first source");
    assert_eq!(
        broker.register_source(ticket.ticket_ref(), &route, &source, RELAY_FINGERPRINT, 11,),
        Err(RelayAdmissionError::SourceAlreadyRegistered),
    );
}

#[test]
fn relay_rejects_target_for_another_ticket() {
    let source_a = binding([0x10; 32]);
    let target_a = binding([0x20; 32]);
    let source_b = binding([0x30; 32]);
    let target_b = binding([0x40; 32]);
    let route = relay_route(reference("relay.authorized"));
    let ticket_a = ticket_with_route(
        reference("transfer.ticket"),
        source_a,
        target_a,
        route.clone(),
    );
    let ticket_b = ticket_with_route(
        reference("transfer.ticket"),
        source_b,
        target_b.clone(),
        route.clone(),
    );
    let mut broker = RelayBroker::new(vec![ticket_a.clone(), ticket_b]);

    assert_eq!(
        broker.register_target(
            ticket_a.ticket_ref(),
            &route,
            &target_b,
            RELAY_FINGERPRINT,
            11,
        ),
        Err(RelayAdmissionError::TicketPeerMismatch),
    );
}

#[test]
fn relay_rejects_expired_ticket() {
    let source = binding([0x10; 32]);
    let target = binding([0x20; 32]);
    let route = relay_route(reference("relay.authorized"));
    let ticket = ticket_with_route(
        reference("transfer.ticket"),
        source.clone(),
        target,
        route.clone(),
    );
    let mut broker = RelayBroker::new(vec![ticket.clone()]);

    assert_eq!(
        broker.register_source(
            ticket.ticket_ref(),
            &route,
            &source,
            RELAY_FINGERPRINT,
            ticket.expires_at_unix_seconds(),
        ),
        Err(RelayAdmissionError::ExpiredTicket),
    );
}

#[test]
fn relay_forwards_one_exact_range_only_after_both_ticket_peers_are_paired() {
    let source = binding([0x10; 32]);
    let target = binding([0x20; 32]);
    let route = relay_route(reference("relay.authorized"));
    let ticket = ticket_with_route(
        reference("transfer.ticket"),
        source.clone(),
        target.clone(),
        route.clone(),
    );
    let mut broker = RelayBroker::new(vec![ticket.clone()]);

    broker
        .register_source(ticket.ticket_ref(), &route, &source, RELAY_FINGERPRINT, 11)
        .expect("source");
    broker
        .register_target(ticket.ticket_ref(), &route, &target, RELAY_FINGERPRINT, 11)
        .expect("target");

    let payload = b"relay-range".to_vec();
    let request = RangeRequest {
        ticket_ref: ticket.ticket_ref().clone(),
        start: 1024,
        len: payload.len() as u64,
    };
    let header = RangeDataHeader {
        ticket_ref: ticket.ticket_ref().clone(),
        start: request.start,
        len: request.len,
        sha256: "22".repeat(32),
    };

    let forwarded = broker
        .forward_range(
            ticket.ticket_ref(),
            request.clone(),
            header.clone(),
            &payload,
        )
        .expect("forward exact range");

    assert_eq!(forwarded.request, request);
    assert_eq!(forwarded.header, header);
    assert_eq!(forwarded.payload, payload);
}
