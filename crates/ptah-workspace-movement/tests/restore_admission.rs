//! E04 Task 5 restore admission through current B06/A13 and E02 authority.

use ptah_checkpoint::{
    export_session_vault, import_session_vault, CaptureRequest, CapturedComponent,
    CheckpointBackend, CheckpointClass, CheckpointEngine, CheckpointError, CheckpointRequest,
    CompatibilityOutcome, ComponentRestoreRequest, Consistency, ProviderRecoveryTarget,
    ReadbackVerification, RecoverySnapshot, RestoreTarget, RestoredComponent, SessionVaultError,
    SessionVaultExportSpec, VerificationState, WorkspaceVersionRecord,
};
use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::{
    NodeResourceSnapshot, ResourcePressure, ResourceQuantity, ResourceUnit, SnapshotOutcome,
};
use ptah_node_link::{CredentialFingerprint, ProtocolVersion, SessionBinding};
use ptah_placement_runtime::{
    AuthorityBinding, Lease, LeaseError, LeaseRegistry, PlacementMetadata, ReservationError,
    ReservationRegistry, ReservedResource,
};
use ptah_transfer::{
    TransferPeerBinding, TransferRouteCandidate, TransferRouteKind, TransferTicket,
    TransferVerificationReport,
};
use ptah_workspace_movement::{WorkspaceMoveError, WorkspaceMovePhase, WorkspaceMover};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const NOW: u64 = 1_800_000_000;
const RESERVATION_EXPIRES: u64 = NOW + 120;
const LEASE_EXPIRES: u64 = NOW + 60;
const COMPAT_EVALUATED_MS: u64 = 1_000_000;
const COMPAT_VALID_UNTIL_MS: u64 = 1_100_000;
const RESTORE_NOW_MS: u64 = 1_050_000;
const A13_CAP: &str = "capability:a13";
const B06_CAP: &str = "capability:b06";

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity kind")
}

#[derive(Default)]
struct Backend {
    restore_calls: usize,
}

impl CheckpointBackend for Backend {
    fn capture(&mut self, request: &CaptureRequest) -> Result<CapturedComponent, CheckpointError> {
        Ok(CapturedComponent {
            subject_refs: vec![format!("subject:{:?}", request.class)],
            bytes: b"ptah-e04-task5-workspace".to_vec(),
            provider_revision_ref: "provider-revision:e04".to_owned(),
            provider_instance_ref: "provider:e04".to_owned(),
            provider_generation: 7,
            connection_epoch: 4,
            consistency: Consistency::CrashConsistent,
            compatibility_requirement_refs: vec![A13_CAP.to_owned()],
            evidence_refs: vec!["evidence:capture:e04-task5".to_owned()],
            limitations: Vec::new(),
        })
    }

    fn verify_readback(
        &self,
        component_ref: &str,
        expected_sha256: &str,
    ) -> Result<ReadbackVerification, CheckpointError> {
        assert!(!component_ref.is_empty());
        assert_eq!(expected_sha256.len(), 64);
        Ok(ReadbackVerification {
            verified: true,
            evidence_refs: vec![format!("readback:{component_ref}")],
            limitations: Vec::new(),
        })
    }

    fn restore(
        &mut self,
        request: &ComponentRestoreRequest,
    ) -> Result<RestoredComponent, CheckpointError> {
        self.restore_calls += 1;
        Ok(RestoredComponent {
            output_refs: vec!["restored:workspace:e04-task5".to_owned()],
            evidence_refs: vec!["evidence:restore:e04-task5".to_owned()],
            limitations: Vec::new(),
            observed_provider_instance_ref: request.target_provider_instance_ref.clone(),
            observed_provider_generation: request.target_provider_generation,
            observed_connection_epoch: request.target_connection_epoch,
            observed_materialization_generation: request.target_materialization_generation,
        })
    }
}

fn source_request() -> CheckpointRequest {
    CheckpointRequest {
        request_ref: "checkpoint-request:e04-task5".to_owned(),
        workspace_ref: "workspace:e04-task5".to_owned(),
        workspace_revision_ref: "workspace-revision:e04-task5".to_owned(),
        workspace_materialization_ref: "materialization:e04-task5".to_owned(),
        materialization_generation: 9,
        requested_classes: vec![CheckpointClass::Workspace],
        requested_consistency: Consistency::CrashConsistent,
        privacy_policy_ref: "policy:privacy:e04".to_owned(),
        credential_policy_ref: "policy:credential:e04".to_owned(),
        destination_or_retention_refs: vec!["retention:vault:e04".to_owned()],
        requested_proof_refs: vec!["proof:e04-task5".to_owned()],
    }
}

fn verified_vault_bytes(conflicts: Vec<String>) -> Vec<u8> {
    let mut engine = CheckpointEngine::default();
    let mut backend = Backend::default();
    let request = source_request();
    let bundle = engine
        .create_checkpoint(
            request.clone(),
            RecoverySnapshot::default(),
            "activity:checkpoint:e04-task5",
            "attempt:checkpoint:e04-task5",
            vec!["receipt:capture:e04-task5".to_owned()],
            &mut backend,
        )
        .expect("A13 checkpoint");
    let verification = engine
        .verify_checkpoint(&bundle.bundle_id, &request.requested_classes, &backend)
        .expect("A13 source verification");
    assert_eq!(verification.state, VerificationState::Verified);

    export_session_vault(
        &engine,
        &bundle,
        SessionVaultExportSpec {
            workspace_versions: vec![WorkspaceVersionRecord {
                workspace_revision_ref: request.workspace_revision_ref,
                materialization_generation: request.materialization_generation,
                parent_revision_ref: None,
                evidence_refs: vec!["evidence:workspace-version:e04-task5".to_owned()],
            }],
            sessions: Vec::new(),
            objects: Vec::new(),
            artifacts: Vec::new(),
            conflicts,
            additional_required_capability_refs: vec![B06_CAP.to_owned()],
            export_evidence_refs: vec!["evidence:vault-export:e04-task5".to_owned()],
        },
    )
    .expect("B06 export")
}

fn session() -> SessionBinding {
    SessionBinding {
        node_id: NodeId::new(),
        node_generation: NodeGeneration::new(7),
        connection_epoch: ConnectionEpoch::new(11),
        enrollment_ref: entity("security.node-enrollment"),
        credential_fingerprint: CredentialFingerprint::from_der(b"e04-task5-session"),
        negotiated_protocol: ProtocolVersion { major: 1, minor: 0 },
    }
}

fn snapshot(session: &SessionBinding) -> NodeResourceSnapshot {
    NodeResourceSnapshot::new(
        session
            .node_id
            .entity_ref(session.node_generation, session.connection_epoch),
        session.node_generation,
        session.connection_epoch,
        SnapshotOutcome::Complete,
        vec![ResourceQuantity {
            resource_key: "cpu".to_owned(),
            unit: ResourceUnit::Cores,
            observed_total: 8.0,
            administratively_allocatable: 8.0,
            reserved: 0.0,
            consumed: 0.0,
            currently_available: 8.0,
            pressure: ResourcePressure::Normal,
            observation_refs: vec![entity("runtime.node-observation")],
        }],
        vec![entity("runtime.node-observation")],
        vec![entity("proof.receipt")],
        Vec::new(),
    )
    .expect("resource snapshot")
}

fn peer(seed: u8, node_id: NodeId, generation: u64, epoch: u64) -> TransferPeerBinding {
    TransferPeerBinding {
        node_id,
        node_generation: NodeGeneration::new(generation),
        connection_epoch: ConnectionEpoch::new(epoch),
        credential_fingerprint: [seed; 32],
    }
}

struct Fixture {
    reverified: ptah_workspace_movement::ReverifiedWorkspaceMove,
    reservations: ReservationRegistry,
    leases: LeaseRegistry,
    lease: Lease,
    backend: Backend,
}

fn fixture(conflicts: Vec<String>) -> Fixture {
    let bytes = verified_vault_bytes(conflicts);
    let imported = import_session_vault(&bytes).expect("source B06 import for source evidence");
    let prepared = WorkspaceMover::prepare_source(imported.archive());

    let session = session();
    let snapshot = snapshot(&session);
    let mut reservations =
        ReservationRegistry::new(&session, &snapshot).expect("reservation registry");
    let binding = AuthorityBinding::new(
        entity("activity.attempt"),
        session.node_id,
        session.node_generation,
        session.connection_epoch,
    );
    let reservation = reservations
        .reserve(
            entity("resource.reservation"),
            binding.clone(),
            snapshot.snapshot_ref.clone(),
            vec![ReservedResource::new("cpu", ResourceUnit::Cores, 1.0).expect("cpu hold")],
            NOW,
            RESERVATION_EXPIRES,
        )
        .expect("reservation");
    let record = reservations
        .reservation(reservation.reservation_ref())
        .expect("reservation record")
        .clone();
    let mut leases = LeaseRegistry::new();
    let lease = leases
        .issue(&record, entity("isolation.lease"), NOW, LEASE_EXPIRES)
        .expect("lease");
    let placement = PlacementMetadata::new(binding.clone());

    let authorized = WorkspaceMover::admit_target(
        prepared,
        &placement,
        &reservation,
        Some(&lease),
        &binding,
        lease.fence(),
        NOW + 1,
    )
    .expect("E02 target admission");

    let route = TransferRouteCandidate {
        kind: TransferRouteKind::Direct,
        endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44103),
        server_name: "target.e04-task5.test".to_owned(),
        expected_peer_fingerprint: [0x22; 32],
        relay_ref: None,
    };
    let expected_size = u64::try_from(bytes.len()).expect("vault length");
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
        Some(entity("storage.content")),
        Some(entity("storage.artifact")),
        expected_size,
        authorized.source.source_archive_sha256.clone(),
        1024,
        vec![route.clone()],
        NOW,
        RESERVATION_EXPIRES,
        51,
    )
    .expect("E03 ticket");
    let report = TransferVerificationReport {
        run_ref: ticket.run_ref().clone(),
        verification_ref: entity("transfer.verification"),
        verification_state: "verified".to_owned(),
        source_sha256: Some(ticket.canonical_sha256().to_owned()),
        destination_sha256: ticket.canonical_sha256().to_owned(),
        observed_size: ticket.expected_size(),
        materialized_path: None,
    };
    let transferred =
        WorkspaceMover::accept_transfer(authorized, &ticket, &route, &report, NOW + 2)
            .expect("E03/A08 transfer");

    let backend = Backend::default();
    let reverified = WorkspaceMover::reverify_target(transferred, &bytes, &backend)
        .expect("target B06/A13 reverification");

    Fixture {
        reverified,
        reservations,
        leases,
        lease,
        backend,
    }
}

fn exact_target() -> RestoreTarget {
    RestoreTarget {
        workspace_ref: "workspace:e04-task5".to_owned(),
        workspace_revision_ref: "workspace-revision:e04-task5".to_owned(),
        target_materialization_generation: 10,
        provider_targets: vec![ProviderRecoveryTarget {
            source_provider_instance_ref: "provider:e04".to_owned(),
            target_provider_instance_ref: "provider:e04:target".to_owned(),
            target_provider_generation: 8,
            target_connection_epoch: 12,
        }],
        compatibility_refs: vec![A13_CAP.to_owned(), B06_CAP.to_owned()],
        restart_evidence_refs: vec!["evidence:restart:e04-task5".to_owned()],
        authorization_refs: vec!["authorization:e04-task5".to_owned()],
        executor_ref: "executor:e04-task5".to_owned(),
    }
}

fn restore(
    mut f: Fixture,
    target: RestoreTarget,
    evaluated_ms: u64,
    valid_until_ms: u64,
    restore_now_ms: u64,
    authority_now: u64,
) -> Result<(ptah_workspace_movement::RestoredWorkspaceMove, Backend), WorkspaceMoveError> {
    let restored = WorkspaceMover::restore_target(
        f.reverified,
        "attempt:restore:e04-task5",
        target,
        vec!["evidence:compatibility:e04-task5".to_owned()],
        evaluated_ms,
        valid_until_ms,
        restore_now_ms,
        &f.reservations,
        &f.lease,
        &f.leases,
        authority_now,
        &mut f.backend,
    )?;
    Ok((restored, f.backend))
}

#[test]
fn exact_compatible_target_restores_but_does_not_claim_recovered() {
    let (restored, backend) = restore(
        fixture(Vec::new()),
        exact_target(),
        COMPAT_EVALUATED_MS,
        COMPAT_VALID_UNTIL_MS,
        RESTORE_NOW_MS,
        NOW + 5,
    )
    .expect("exact current restore");

    assert_eq!(restored.phase, WorkspaceMovePhase::VerifyingRecovery);
    assert_eq!(
        restored.compatibility.decision.outcome,
        CompatibilityOutcome::Compatible
    );
    assert_eq!(backend.restore_calls, 1);
    assert_ne!(restored.phase, WorkspaceMovePhase::Recovered);
}

#[test]
fn missing_b06_or_a13_capability_blocks_before_restore_effect() {
    for missing in [B06_CAP, A13_CAP] {
        let mut target = exact_target();
        target.compatibility_refs.retain(|item| item != missing);
        let mut f = fixture(Vec::new());
        let result = WorkspaceMover::restore_target(
            f.reverified,
            "attempt:restore:missing-capability",
            target,
            vec!["evidence:compatibility".to_owned()],
            COMPAT_EVALUATED_MS,
            COMPAT_VALID_UNTIL_MS,
            RESTORE_NOW_MS,
            &f.reservations,
            &f.lease,
            &f.leases,
            NOW + 5,
            &mut f.backend,
        );
        assert!(matches!(
            result,
            Err(WorkspaceMoveError::Checkpoint(
                SessionVaultError::Checkpoint(CheckpointError::IncompatibleRestoreTarget)
            ))
        ));
        assert_eq!(f.backend.restore_calls, 0);
    }
}

#[test]
fn stale_provider_generation_and_foreign_workspace_revision_block() {
    let mut provider_stale = exact_target();
    provider_stale.provider_targets[0].target_provider_generation = 7;
    assert!(matches!(
        restore(
            fixture(Vec::new()),
            provider_stale,
            COMPAT_EVALUATED_MS,
            COMPAT_VALID_UNTIL_MS,
            RESTORE_NOW_MS,
            NOW + 5,
        ),
        Err(WorkspaceMoveError::Checkpoint(
            SessionVaultError::Checkpoint(CheckpointError::IncompatibleRestoreTarget)
        ))
    ));

    let mut foreign_revision = exact_target();
    foreign_revision.workspace_revision_ref = "workspace-revision:foreign".to_owned();
    assert!(matches!(
        restore(
            fixture(Vec::new()),
            foreign_revision,
            COMPAT_EVALUATED_MS,
            COMPAT_VALID_UNTIL_MS,
            RESTORE_NOW_MS,
            NOW + 5,
        ),
        Err(WorkspaceMoveError::Checkpoint(
            SessionVaultError::Checkpoint(CheckpointError::IncompatibleRestoreTarget)
        ))
    ));
}

#[test]
fn expired_compatibility_decision_blocks_restore() {
    assert!(matches!(
        restore(
            fixture(Vec::new()),
            exact_target(),
            COMPAT_EVALUATED_MS,
            COMPAT_VALID_UNTIL_MS,
            COMPAT_VALID_UNTIL_MS + 1,
            NOW + 5,
        ),
        Err(WorkspaceMoveError::Checkpoint(
            SessionVaultError::Checkpoint(CheckpointError::ExpiredCompatibilityDecision)
        ))
    ));
}

#[test]
fn retained_conflicts_fail_closed_before_restore() {
    let mut f = fixture(vec!["conflict:retained:e04-task5".to_owned()]);
    let result = WorkspaceMover::restore_target(
        f.reverified,
        "attempt:restore:conflicted",
        exact_target(),
        vec!["evidence:compatibility".to_owned()],
        COMPAT_EVALUATED_MS,
        COMPAT_VALID_UNTIL_MS,
        RESTORE_NOW_MS,
        &f.reservations,
        &f.lease,
        &f.leases,
        NOW + 5,
        &mut f.backend,
    );
    assert!(matches!(
        result,
        Err(WorkspaceMoveError::RetainedConflicts(conflicts))
            if conflicts == vec!["conflict:retained:e04-task5".to_owned()]
    ));
    assert_eq!(f.backend.restore_calls, 0);
}

#[test]
fn stale_revoked_and_expired_lease_block_restore() {
    let mut stale = fixture(Vec::new());
    let record = stale
        .reservations
        .reservation(&stale.reverified.target.reservation_ref)
        .expect("reservation record")
        .clone();
    stale
        .leases
        .issue(&record, entity("isolation.lease"), NOW + 3, NOW + 90)
        .expect("newer owner");
    let result = WorkspaceMover::restore_target(
        stale.reverified,
        "attempt:restore:stale-lease",
        exact_target(),
        vec!["evidence:compatibility".to_owned()],
        COMPAT_EVALUATED_MS,
        COMPAT_VALID_UNTIL_MS,
        RESTORE_NOW_MS,
        &stale.reservations,
        &stale.lease,
        &stale.leases,
        NOW + 5,
        &mut stale.backend,
    );
    assert!(matches!(
        result,
        Err(WorkspaceMoveError::Lease(LeaseError::StaleFence))
    ));
    assert_eq!(stale.backend.restore_calls, 0);

    let mut revoked = fixture(Vec::new());
    revoked
        .leases
        .revoke(revoked.lease.lease_ref())
        .expect("revoke lease");
    let result = WorkspaceMover::restore_target(
        revoked.reverified,
        "attempt:restore:revoked-lease",
        exact_target(),
        vec!["evidence:compatibility".to_owned()],
        COMPAT_EVALUATED_MS,
        COMPAT_VALID_UNTIL_MS,
        RESTORE_NOW_MS,
        &revoked.reservations,
        &revoked.lease,
        &revoked.leases,
        NOW + 5,
        &mut revoked.backend,
    );
    assert!(matches!(
        result,
        Err(WorkspaceMoveError::Lease(LeaseError::RevokedLease))
    ));
    assert_eq!(revoked.backend.restore_calls, 0);

    let mut expired = fixture(Vec::new());
    let result = WorkspaceMover::restore_target(
        expired.reverified,
        "attempt:restore:expired-lease",
        exact_target(),
        vec!["evidence:compatibility".to_owned()],
        COMPAT_EVALUATED_MS,
        COMPAT_VALID_UNTIL_MS,
        RESTORE_NOW_MS,
        &expired.reservations,
        &expired.lease,
        &expired.leases,
        LEASE_EXPIRES,
        &mut expired.backend,
    );
    assert!(matches!(
        result,
        Err(WorkspaceMoveError::Lease(LeaseError::ExpiredLease))
    ));
    assert_eq!(expired.backend.restore_calls, 0);
}

#[test]
fn revoked_reservation_blocks_even_if_lease_bytes_are_unchanged() {
    let mut f = fixture(Vec::new());
    f.reservations
        .revoke(&f.reverified.target.reservation_ref)
        .expect("revoke reservation");
    let result = WorkspaceMover::restore_target(
        f.reverified,
        "attempt:restore:revoked-reservation",
        exact_target(),
        vec!["evidence:compatibility".to_owned()],
        COMPAT_EVALUATED_MS,
        COMPAT_VALID_UNTIL_MS,
        RESTORE_NOW_MS,
        &f.reservations,
        &f.lease,
        &f.leases,
        NOW + 5,
        &mut f.backend,
    );
    assert!(matches!(
        result,
        Err(WorkspaceMoveError::Reservation(ReservationError::NotActive))
    ));
    assert_eq!(f.backend.restore_calls, 0);
}

#[test]
fn current_lease_must_match_the_exact_retained_target_session_and_fence() {
    let mut f = fixture(Vec::new());
    let wrong_binding = AuthorityBinding::new(
        f.lease.binding().attempt_ref().clone(),
        f.lease.binding().node_id(),
        NodeGeneration::new(f.lease.binding().node_generation().value() + 1),
        f.lease.binding().connection_epoch(),
    );
    let forged = Lease::new(
        f.lease.lease_ref().clone(),
        f.lease.reservation_ref().clone(),
        wrong_binding,
        f.lease.fence(),
        f.lease.expires_at_unix_seconds(),
    );
    let result = WorkspaceMover::restore_target(
        f.reverified,
        "attempt:restore:wrong-session",
        exact_target(),
        vec!["evidence:compatibility".to_owned()],
        COMPAT_EVALUATED_MS,
        COMPAT_VALID_UNTIL_MS,
        RESTORE_NOW_MS,
        &f.reservations,
        &forged,
        &f.leases,
        NOW + 5,
        &mut f.backend,
    );
    assert!(matches!(
        result,
        Err(WorkspaceMoveError::TargetAuthorityMismatch)
    ));
    assert_eq!(f.backend.restore_calls, 0);
}
