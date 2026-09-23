//! E04 Task 6 independent recovery verification is the only success boundary.

use ptah_checkpoint::{
    export_session_vault, import_session_vault, CaptureRequest, CapturedComponent,
    CheckpointBackend, CheckpointClass, CheckpointEngine, CheckpointError, CheckpointRequest,
    ComponentRestoreRequest, Consistency, Postcondition, ProviderRecoveryTarget,
    ReadbackVerification, RecoveryOutcome, RecoverySnapshot, RestoreTarget, RestoredComponent,
    SessionVaultExportSpec, VerificationState, WorkspaceVersionRecord,
};
use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::{
    NodeResourceSnapshot, ResourcePressure, ResourceQuantity, ResourceUnit, SnapshotOutcome,
};
use ptah_node_link::{CredentialFingerprint, ProtocolVersion, SessionBinding};
use ptah_placement_runtime::{
    AuthorityBinding, LeaseRegistry, PlacementMetadata, ReservationRegistry, ReservedResource,
};
use ptah_transfer::{
    TransferPeerBinding, TransferRouteCandidate, TransferRouteKind, TransferTicket,
    TransferVerificationReport,
};
use ptah_workspace_movement::{WorkspaceMovePhase, WorkspaceMover};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const NOW: u64 = 1_800_000_000;
const A13_CAP: &str = "capability:a13";
const B06_CAP: &str = "capability:b06";

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity")
}

#[derive(Default)]
struct Backend;

impl CheckpointBackend for Backend {
    fn capture(&mut self, request: &CaptureRequest) -> Result<CapturedComponent, CheckpointError> {
        Ok(CapturedComponent {
            subject_refs: vec![format!("subject:{:?}", request.class)],
            bytes: b"e04-task6-workspace".to_vec(),
            provider_revision_ref: "provider-revision:e04-task6".to_owned(),
            provider_instance_ref: "provider:e04-task6".to_owned(),
            provider_generation: 7,
            connection_epoch: 4,
            consistency: Consistency::CrashConsistent,
            compatibility_requirement_refs: vec![A13_CAP.to_owned()],
            evidence_refs: vec!["evidence:capture:e04-task6".to_owned()],
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
        Ok(RestoredComponent {
            output_refs: vec!["restored:e04-task6".to_owned()],
            evidence_refs: vec!["evidence:restore:e04-task6".to_owned()],
            limitations: Vec::new(),
            observed_provider_instance_ref: request.target_provider_instance_ref.clone(),
            observed_provider_generation: request.target_provider_generation,
            observed_connection_epoch: request.target_connection_epoch,
            observed_materialization_generation: request.target_materialization_generation,
        })
    }
}

fn source_bytes() -> Vec<u8> {
    let mut engine = CheckpointEngine::default();
    let mut backend = Backend;
    let request = CheckpointRequest {
        request_ref: "checkpoint-request:e04-task6".to_owned(),
        workspace_ref: "workspace:e04-task6".to_owned(),
        workspace_revision_ref: "workspace-revision:e04-task6".to_owned(),
        workspace_materialization_ref: "materialization:e04-task6".to_owned(),
        materialization_generation: 9,
        requested_classes: vec![CheckpointClass::Workspace],
        requested_consistency: Consistency::CrashConsistent,
        privacy_policy_ref: "policy:privacy:e04-task6".to_owned(),
        credential_policy_ref: "policy:credential:e04-task6".to_owned(),
        destination_or_retention_refs: vec!["retention:e04-task6".to_owned()],
        requested_proof_refs: vec!["proof:e04-task6".to_owned()],
    };
    let bundle = engine
        .create_checkpoint(
            request.clone(),
            RecoverySnapshot::default(),
            "activity:checkpoint:e04-task6",
            "attempt:checkpoint:e04-task6",
            vec!["receipt:capture:e04-task6".to_owned()],
            &mut backend,
        )
        .expect("checkpoint");
    let verification = engine
        .verify_checkpoint(&bundle.bundle_id, &request.requested_classes, &backend)
        .expect("verify checkpoint");
    assert_eq!(verification.state, VerificationState::Verified);

    export_session_vault(
        &engine,
        &bundle,
        SessionVaultExportSpec {
            workspace_versions: vec![WorkspaceVersionRecord {
                workspace_revision_ref: request.workspace_revision_ref,
                materialization_generation: request.materialization_generation,
                parent_revision_ref: None,
                evidence_refs: vec!["evidence:workspace-version:e04-task6".to_owned()],
            }],
            sessions: Vec::new(),
            objects: Vec::new(),
            artifacts: Vec::new(),
            conflicts: Vec::new(),
            additional_required_capability_refs: vec![B06_CAP.to_owned()],
            export_evidence_refs: vec!["evidence:vault-export:e04-task6".to_owned()],
        },
    )
    .expect("vault export")
}

fn session() -> SessionBinding {
    SessionBinding {
        node_id: NodeId::new(),
        node_generation: NodeGeneration::new(7),
        connection_epoch: ConnectionEpoch::new(11),
        enrollment_ref: entity("security.node-enrollment"),
        credential_fingerprint: CredentialFingerprint::from_der(b"e04-task6"),
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
    .expect("snapshot")
}

fn peer(seed: u8, node_id: NodeId, generation: u64, epoch: u64) -> TransferPeerBinding {
    TransferPeerBinding {
        node_id,
        node_generation: NodeGeneration::new(generation),
        connection_epoch: ConnectionEpoch::new(epoch),
        credential_fingerprint: [seed; 32],
    }
}

fn exact_target() -> RestoreTarget {
    RestoreTarget {
        workspace_ref: "workspace:e04-task6".to_owned(),
        workspace_revision_ref: "workspace-revision:e04-task6".to_owned(),
        target_materialization_generation: 10,
        provider_targets: vec![ProviderRecoveryTarget {
            source_provider_instance_ref: "provider:e04-task6".to_owned(),
            target_provider_instance_ref: "provider:e04-task6:target".to_owned(),
            target_provider_generation: 8,
            target_connection_epoch: 12,
        }],
        compatibility_refs: vec![A13_CAP.to_owned(), B06_CAP.to_owned()],
        restart_evidence_refs: vec!["evidence:restart:e04-task6".to_owned()],
        authorization_refs: vec!["authorization:e04-task6".to_owned()],
        executor_ref: "executor:e04-task6".to_owned(),
    }
}

fn route() -> TransferRouteCandidate {
    TransferRouteCandidate {
        kind: TransferRouteKind::Direct,
        endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44103),
        server_name: "target.e04-task6.test".to_owned(),
        expected_peer_fingerprint: [0x22; 32],
        relay_ref: None,
    }
}

fn restored() -> ptah_workspace_movement::RestoredWorkspaceMove {
    let bytes = source_bytes();
    let imported = import_session_vault(&bytes).expect("source import");
    let prepared = WorkspaceMover::prepare_source(imported.archive());

    let session = session();
    let snapshot = snapshot(&session);
    let mut reservations = ReservationRegistry::new(&session, &snapshot).expect("reservations");
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
            vec![ReservedResource::new("cpu", ResourceUnit::Cores, 1.0).expect("cpu")],
            NOW,
            NOW + 120,
        )
        .expect("reservation");
    let record = reservations
        .reservation(reservation.reservation_ref())
        .expect("record")
        .clone();
    let mut leases = LeaseRegistry::new();
    let lease = leases
        .issue(&record, entity("isolation.lease"), NOW, NOW + 60)
        .expect("lease");

    let authorized = WorkspaceMover::admit_target(
        prepared,
        &PlacementMetadata::new(binding.clone()),
        &reservation,
        Some(&lease),
        &binding,
        lease.fence(),
        NOW + 1,
    )
    .expect("target");

    let route = route();
    let size = u64::try_from(bytes.len()).expect("size");
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
        size,
        authorized.source.source_archive_sha256.clone(),
        1024,
        vec![route.clone()],
        NOW,
        NOW + 120,
        61,
    )
    .expect("ticket");
    let report = TransferVerificationReport {
        run_ref: ticket.run_ref().clone(),
        verification_ref: entity("transfer.verification"),
        verification_state: "verified".to_owned(),
        source_sha256: Some(ticket.canonical_sha256().to_owned()),
        destination_sha256: ticket.canonical_sha256().to_owned(),
        observed_size: size,
        materialized_path: None,
    };
    let transferred =
        WorkspaceMover::accept_transfer(authorized, &ticket, &route, &report, NOW + 2)
            .expect("transfer");

    let mut backend = Backend;
    let reverified =
        WorkspaceMover::reverify_target(transferred, &bytes, &backend).expect("reverify");

    WorkspaceMover::restore_target(
        reverified,
        "attempt:restore:e04-task6",
        exact_target(),
        vec!["evidence:compatibility:e04-task6".to_owned()],
        1_000,
        2_000,
        1_500,
        &reservations,
        &lease,
        &leases,
        NOW + 5,
        &mut backend,
    )
    .expect("restore")
}

fn passed_postcondition() -> Postcondition {
    Postcondition {
        key: "workspace.resume".to_owned(),
        passed: true,
        evidence_refs: vec!["evidence:workspace-resume".to_owned()],
    }
}

#[test]
fn recovered_is_the_only_outcome_that_advances_e04_to_recovered() {
    let verified = WorkspaceMover::verify_recovery(
        restored(),
        "verifier:independent",
        vec![passed_postcondition()],
        Vec::new(),
        vec!["evidence:independent-recovery".to_owned()],
    );

    assert_eq!(
        verified.recovery_verification.outcome,
        RecoveryOutcome::Recovered
    );
    assert_eq!(verified.phase, WorkspaceMovePhase::Recovered);
    assert_eq!(
        verified.recovery_verification.restore_run_ref,
        verified.restore_run.restore_run_id
    );
}

#[test]
fn failed_postcondition_remains_non_success() {
    let mut postcondition = passed_postcondition();
    postcondition.passed = false;
    let verified = WorkspaceMover::verify_recovery(
        restored(),
        "verifier:independent",
        vec![postcondition],
        Vec::new(),
        vec!["evidence:independent-recovery".to_owned()],
    );

    assert_eq!(
        verified.recovery_verification.outcome,
        RecoveryOutcome::Failed
    );
    assert_eq!(verified.phase, WorkspaceMovePhase::Failed);
}

#[test]
fn unresolved_operation_is_partial_and_remains_non_success() {
    let verified = WorkspaceMover::verify_recovery(
        restored(),
        "verifier:independent",
        vec![passed_postcondition()],
        vec!["operation:unresolved".to_owned()],
        vec!["evidence:independent-recovery".to_owned()],
    );

    assert_eq!(
        verified.recovery_verification.outcome,
        RecoveryOutcome::Partial
    );
    assert_eq!(verified.phase, WorkspaceMovePhase::Failed);
}

#[test]
fn non_independent_verifier_is_inconclusive_and_remains_non_success() {
    let verified = WorkspaceMover::verify_recovery(
        restored(),
        "executor:e04-task6",
        vec![passed_postcondition()],
        Vec::new(),
        vec!["evidence:independent-recovery".to_owned()],
    );

    assert_eq!(
        verified.recovery_verification.outcome,
        RecoveryOutcome::Inconclusive
    );
    assert!(!verified.recovery_verification.verifier_independent);
    assert_eq!(verified.phase, WorkspaceMovePhase::Failed);
}
