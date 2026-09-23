//! E04 composition of exact E03 transfer authority and A08 read-back truth.

use ptah_checkpoint::{
    CaptureRequest, CapturedComponent, CheckpointBackend, CheckpointError, ComponentRestoreRequest,
    ReadbackVerification, RestoredComponent,
};
use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_placement_runtime::{AuthorityBinding, FenceToken};
use ptah_transfer::{
    E03TransferError, TransferPeerBinding, TransferRouteCandidate, TransferRouteKind,
    TransferTicket, TransferVerificationReport,
};
use ptah_workspace_movement::{
    AuthorizedWorkspaceMove, TargetAuthorityEvidence, WorkspaceMoveError, WorkspaceMoveEvidence,
    WorkspaceMovePhase, WorkspaceMover,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const NOW: u64 = 1_800_000_000;
const EXPIRES: u64 = NOW + 60;
const SIZE: u64 = 4096;

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity kind")
}

fn source_digest() -> String {
    "ab".repeat(32)
}

fn target_authority() -> TargetAuthorityEvidence {
    TargetAuthorityEvidence {
        binding: AuthorityBinding::new(
            entity("activity.attempt"),
            NodeId::new(),
            NodeGeneration::new(7),
            ConnectionEpoch::new(11),
        ),
        reservation_ref: entity("resource.reservation"),
        lease_ref: entity("isolation.lease"),
        fence: FenceToken::new(9).expect("positive fence"),
    }
}

fn authorized() -> AuthorizedWorkspaceMove {
    AuthorizedWorkspaceMove {
        phase: WorkspaceMovePhase::Transferring,
        source: WorkspaceMoveEvidence {
            source_archive_sha256: source_digest(),
            checkpoint_bundle_ref: "checkpoint:e04".to_owned(),
            workspace_ref: "workspace:e04".to_owned(),
            workspace_revision_ref: "workspace-revision:e04".to_owned(),
        },
        target: target_authority(),
    }
}

fn peer(seed: u8, node_id: NodeId, generation: u64, epoch: u64) -> TransferPeerBinding {
    TransferPeerBinding {
        node_id,
        node_generation: NodeGeneration::new(generation),
        connection_epoch: ConnectionEpoch::new(epoch),
        credential_fingerprint: [seed; 32],
    }
}

fn direct_route() -> TransferRouteCandidate {
    TransferRouteCandidate {
        kind: TransferRouteKind::Direct,
        endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44103),
        server_name: "target.e04.test".to_owned(),
        expected_peer_fingerprint: [0x22; 32],
        relay_ref: None,
    }
}

fn relay_route() -> TransferRouteCandidate {
    TransferRouteCandidate {
        kind: TransferRouteKind::Relay,
        endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44104),
        server_name: "relay.e04.test".to_owned(),
        expected_peer_fingerprint: [0x33; 32],
        relay_ref: Some(entity("network.relay")),
    }
}

fn ticket(
    movement: &AuthorizedWorkspaceMove,
    routes: Vec<TransferRouteCandidate>,
) -> TransferTicket {
    let binding = &movement.target.binding;
    TransferTicket::new(
        entity("transfer.ticket"),
        entity("transfer.request"),
        entity("transfer.run"),
        binding.attempt_ref().clone(),
        peer(0x11, NodeId::new(), 3, 4),
        peer(
            0x22,
            binding.node_id(),
            binding.node_generation().value(),
            binding.connection_epoch().value(),
        ),
        Some(entity("storage.content")),
        Some(entity("storage.artifact")),
        SIZE,
        movement.source.source_archive_sha256.clone(),
        1024,
        routes,
        NOW - 10,
        EXPIRES,
        17,
    )
    .expect("valid E03 ticket")
}

fn verified(ticket: &TransferTicket) -> TransferVerificationReport {
    TransferVerificationReport {
        run_ref: ticket.run_ref().clone(),
        verification_ref: entity("transfer.verification"),
        verification_state: "verified".to_owned(),
        source_sha256: Some(ticket.canonical_sha256().to_owned()),
        destination_sha256: ticket.canonical_sha256().to_owned(),
        observed_size: ticket.expected_size(),
        materialized_path: None,
    }
}

#[test]
fn exact_direct_transfer_advances_only_after_a08_readback() {
    let movement = authorized();
    let route = direct_route();
    let ticket = ticket(&movement, vec![route.clone()]);
    let report = verified(&ticket);

    let moved = WorkspaceMover::accept_transfer(movement, &ticket, &route, &report, NOW)
        .expect("exact E03/A08 transfer proof");

    assert_eq!(moved.phase, WorkspaceMovePhase::Reverifying);
    assert_eq!(moved.transfer.route_kind, TransferRouteKind::Direct);
    assert_eq!(moved.transfer.ticket_ref, ticket.ticket_ref().clone());
    assert_eq!(moved.transfer.run_ref, ticket.run_ref().clone());
    assert_eq!(moved.transfer.verification_ref, report.verification_ref);
    assert_eq!(moved.transfer.destination_sha256, source_digest());
    assert_eq!(moved.transfer.observed_size, SIZE);
}

#[test]
fn exact_explicit_relay_uses_the_same_owner_proof_boundary() {
    let movement = authorized();
    let route = relay_route();
    let ticket = ticket(&movement, vec![route.clone()]);
    let report = verified(&ticket);

    let moved = WorkspaceMover::accept_transfer(movement, &ticket, &route, &report, NOW)
        .expect("authorized relay with final A08 readback");

    assert_eq!(moved.phase, WorkspaceMovePhase::Reverifying);
    assert_eq!(moved.transfer.route_kind, TransferRouteKind::Relay);
}

#[test]
fn ambient_route_cannot_be_substituted_for_ticket_authority() {
    let movement = authorized();
    let ticket = ticket(&movement, vec![direct_route()]);
    let ambient = relay_route();
    let report = verified(&ticket);

    assert_eq!(
        WorkspaceMover::accept_transfer(movement, &ticket, &ambient, &report, NOW),
        Err(WorkspaceMoveError::Transfer(
            E03TransferError::UnauthorizedRoute
        ))
    );
}

#[test]
fn transport_ack_without_a08_readback_cannot_advance() {
    let movement = authorized();
    let route = direct_route();
    let ticket = ticket(&movement, vec![route.clone()]);
    let mut report = verified(&ticket);
    report.verification_state = "transport_completed".to_owned();

    assert_eq!(
        WorkspaceMover::accept_transfer(movement, &ticket, &route, &report, NOW),
        Err(WorkspaceMoveError::TransferNotVerified)
    );
}

#[test]
fn corrupt_destination_digest_fails_closed() {
    let movement = authorized();
    let route = direct_route();
    let ticket = ticket(&movement, vec![route.clone()]);
    let mut report = verified(&ticket);
    report.destination_sha256 = "cd".repeat(32);

    assert_eq!(
        WorkspaceMover::accept_transfer(movement, &ticket, &route, &report, NOW),
        Err(WorkspaceMoveError::TransferDigestMismatch)
    );
}

#[test]
fn verification_must_belong_to_the_exact_a08_run() {
    let movement = authorized();
    let route = direct_route();
    let ticket = ticket(&movement, vec![route.clone()]);
    let mut report = verified(&ticket);
    report.run_ref = entity("transfer.other-run");

    assert_eq!(
        WorkspaceMover::accept_transfer(movement, &ticket, &route, &report, NOW),
        Err(WorkspaceMoveError::TransferRunMismatch)
    );
}

#[test]
fn destination_size_must_match_the_e03_ticket() {
    let movement = authorized();
    let route = direct_route();
    let ticket = ticket(&movement, vec![route.clone()]);
    let mut report = verified(&ticket);
    report.observed_size += 1;

    assert_eq!(
        WorkspaceMover::accept_transfer(movement, &ticket, &route, &report, NOW),
        Err(WorkspaceMoveError::TransferSizeMismatch)
    );
}

#[test]
fn e03_ticket_target_must_match_the_exact_e02_target_session() {
    let movement = authorized();
    let route = direct_route();
    let binding = &movement.target.binding;
    let ticket = TransferTicket::new(
        entity("transfer.ticket"),
        entity("transfer.request"),
        entity("transfer.run"),
        binding.attempt_ref().clone(),
        peer(0x11, NodeId::new(), 3, 4),
        peer(
            0x22,
            binding.node_id(),
            binding.node_generation().value() + 1,
            binding.connection_epoch().value(),
        ),
        None,
        None,
        SIZE,
        movement.source.source_archive_sha256.clone(),
        1024,
        vec![route.clone()],
        NOW - 10,
        EXPIRES,
        18,
    )
    .expect("mechanically valid ticket with wrong target generation");
    let report = verified(&ticket);

    assert_eq!(
        WorkspaceMover::accept_transfer(movement, &ticket, &route, &report, NOW),
        Err(WorkspaceMoveError::TransferTargetAuthorityMismatch)
    );
}

#[test]
fn transfer_ticket_must_name_the_exact_session_vault_digest() {
    let movement = authorized();
    let route = direct_route();
    let binding = &movement.target.binding;
    let ticket = TransferTicket::new(
        entity("transfer.ticket"),
        entity("transfer.request"),
        entity("transfer.run"),
        binding.attempt_ref().clone(),
        peer(0x11, NodeId::new(), 3, 4),
        peer(
            0x22,
            binding.node_id(),
            binding.node_generation().value(),
            binding.connection_epoch().value(),
        ),
        None,
        None,
        SIZE,
        "ef".repeat(32),
        1024,
        vec![route.clone()],
        NOW - 10,
        EXPIRES,
        19,
    )
    .expect("mechanically valid ticket for different bytes");
    let report = verified(&ticket);

    assert_eq!(
        WorkspaceMover::accept_transfer(movement, &ticket, &route, &report, NOW),
        Err(WorkspaceMoveError::TransferSourceDigestMismatch)
    );
}

#[test]
fn expired_e03_ticket_cannot_be_reused_after_resume_boundary() {
    let movement = authorized();
    let route = direct_route();
    let ticket = ticket(&movement, vec![route.clone()]);
    let report = verified(&ticket);

    assert_eq!(
        WorkspaceMover::accept_transfer(movement, &ticket, &route, &report, EXPIRES),
        Err(WorkspaceMoveError::Transfer(
            E03TransferError::ExpiredTicket
        ))
    );
}

struct RejectingCheckpointBackend;

impl CheckpointBackend for RejectingCheckpointBackend {
    fn capture(&mut self, _request: &CaptureRequest) -> Result<CapturedComponent, CheckpointError> {
        Err(CheckpointError::CaptureFailed(
            "unexpected capture".to_owned(),
        ))
    }

    fn verify_readback(
        &self,
        _component_ref: &str,
        _expected_sha256: &str,
    ) -> Result<ReadbackVerification, CheckpointError> {
        Err(CheckpointError::CaptureFailed(
            "unexpected readback".to_owned(),
        ))
    }

    fn restore(
        &mut self,
        _request: &ComponentRestoreRequest,
    ) -> Result<RestoredComponent, CheckpointError> {
        Err(CheckpointError::CaptureFailed(
            "unexpected restore".to_owned(),
        ))
    }
}

#[test]
fn target_import_failure_cannot_manufacture_reverified_movement() {
    let movement = authorized();
    let route = direct_route();
    let ticket = ticket(&movement, vec![route.clone()]);
    let report = verified(&ticket);
    let transferred = WorkspaceMover::accept_transfer(movement, &ticket, &route, &report, NOW)
        .expect("exact E03/A08 transfer proof");

    let malformed_vault = vec![0u8; SIZE as usize];
    let error = WorkspaceMover::reverify_target(
        transferred,
        &malformed_vault,
        &RejectingCheckpointBackend,
    )
    .err()
    .expect("malformed target vault must fail closed");

    assert!(matches!(error, WorkspaceMoveError::Checkpoint(_)));
}


#[test]
fn target_import_requires_exact_a08_observed_vault_size_before_b06_import() {
    let movement = authorized();
    let route = direct_route();
    let ticket = ticket(&movement, vec![route.clone()]);
    let report = verified(&ticket);
    let transferred = WorkspaceMover::accept_transfer(movement, &ticket, &route, &report, NOW)
        .expect("exact E03/A08 transfer proof");

    let error = WorkspaceMover::reverify_target(
        transferred,
        b"not-a-session-vault",
        &RejectingCheckpointBackend,
    )
    .err()
    .expect("A08 size mismatch must fail before B06 import");

    assert_eq!(error, WorkspaceMoveError::TransferSizeMismatch);
}
