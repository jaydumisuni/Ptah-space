//! E04 Task 4 positive owner-composition proof.
//!
//! This test uses the real A13 checkpoint engine and B06 Session Vault export/import
//! boundaries, then proves E04 advances only after independent target re-verification.
//! It deliberately stops before compatibility/restore authority.

use ptah_checkpoint::{
    export_session_vault, import_session_vault, CaptureRequest, CapturedComponent,
    CheckpointBackend, CheckpointClass, CheckpointEngine, CheckpointError, CheckpointRequest,
    ComponentRestoreRequest, Consistency, ReadbackVerification, RecoverySnapshot,
    RestoredComponent, SessionVaultExportSpec, VerificationState, WorkspaceVersionRecord,
};
use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_placement_runtime::{AuthorityBinding, FenceToken};
use ptah_transfer::{
    TransferPeerBinding, TransferRouteCandidate, TransferRouteKind, TransferTicket,
    TransferVerificationReport,
};
use ptah_workspace_movement::{
    AuthorizedWorkspaceMove, TargetAuthorityEvidence, WorkspaceMoveEvidence, WorkspaceMovePhase,
    WorkspaceMover,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const NOW: u64 = 1_800_000_000;
const EXPIRES: u64 = NOW + 60;

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity kind")
}

struct TargetBackend;

impl CheckpointBackend for TargetBackend {
    fn capture(&mut self, request: &CaptureRequest) -> Result<CapturedComponent, CheckpointError> {
        Ok(CapturedComponent {
            subject_refs: vec![format!("subject:{:?}", request.class)],
            bytes: b"ptah-e04-positive-workspace".to_vec(),
            provider_revision_ref: "provider-revision:e04".to_owned(),
            provider_instance_ref: "provider:e04".to_owned(),
            provider_generation: 7,
            connection_epoch: 4,
            consistency: Consistency::CrashConsistent,
            compatibility_requirement_refs: vec!["capability:workspace".to_owned()],
            evidence_refs: vec!["evidence:capture:e04".to_owned()],
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
            evidence_refs: vec![format!("target-readback:{component_ref}")],
            limitations: Vec::new(),
        })
    }

    fn restore(
        &mut self,
        _request: &ComponentRestoreRequest,
    ) -> Result<RestoredComponent, CheckpointError> {
        panic!("Task 4 re-verification must not execute restore")
    }
}

fn verified_vault_bytes() -> (Vec<u8>, String, TargetBackend) {
    let mut engine = CheckpointEngine::default();
    let mut backend = TargetBackend;
    let request = CheckpointRequest {
        request_ref: "checkpoint-request:e04-positive".to_owned(),
        workspace_ref: "workspace:e04-positive".to_owned(),
        workspace_revision_ref: "workspace-revision:e04-positive".to_owned(),
        workspace_materialization_ref: "materialization:e04-positive".to_owned(),
        materialization_generation: 9,
        requested_classes: vec![CheckpointClass::Workspace],
        requested_consistency: Consistency::CrashConsistent,
        privacy_policy_ref: "policy:privacy:e04".to_owned(),
        credential_policy_ref: "policy:credential:e04".to_owned(),
        destination_or_retention_refs: vec!["retention:vault:e04".to_owned()],
        requested_proof_refs: vec!["proof:e04-positive".to_owned()],
    };

    let bundle = engine
        .create_checkpoint(
            request.clone(),
            RecoverySnapshot {
                activity_refs: vec!["activity:e04".to_owned()],
                attachment_refs: Vec::new(),
                lease_refs: Vec::new(),
                partial_artifact_refs: Vec::new(),
                result_handles: Vec::new(),
                schedules: Vec::new(),
                conflict_receipt_refs: Vec::new(),
                uncertain_external_effect_refs: Vec::new(),
            },
            "activity:checkpoint:e04",
            "attempt:checkpoint:e04",
            vec!["receipt:capture:e04".to_owned()],
            &mut backend,
        )
        .expect("A13 checkpoint creation");

    let verification = engine
        .verify_checkpoint(&bundle.bundle_id, &request.requested_classes, &backend)
        .expect("A13 source checkpoint verification");
    assert_eq!(verification.state, VerificationState::Verified);

    let bytes = export_session_vault(
        &engine,
        &bundle,
        SessionVaultExportSpec {
            workspace_versions: vec![WorkspaceVersionRecord {
                workspace_revision_ref: request.workspace_revision_ref,
                materialization_generation: request.materialization_generation,
                parent_revision_ref: None,
                evidence_refs: vec!["evidence:workspace-version:e04".to_owned()],
            }],
            sessions: Vec::new(),
            objects: Vec::new(),
            artifacts: Vec::new(),
            conflicts: Vec::new(),
            additional_required_capability_refs: Vec::new(),
            export_evidence_refs: vec!["evidence:vault-export:e04".to_owned()],
        },
    )
    .expect("B06 verified Session Vault export");

    let imported = import_session_vault(&bytes).expect("B06 integrity-bound import");
    assert!(
        !imported.is_checkpoint_verified(),
        "B06 import must drop prior A13 restore authorization"
    );
    let payload_sha256 = imported.archive().payload_sha256.clone();

    (bytes, payload_sha256, backend)
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
        fence: FenceToken::new(23).expect("positive E02 fence"),
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

#[test]
fn valid_target_vault_requires_and_earns_independent_a13_reverification() {
    let (vault_bytes, payload_sha256, backend) = verified_vault_bytes();
    let target = target_authority();
    let movement = AuthorizedWorkspaceMove {
        phase: WorkspaceMovePhase::Transferring,
        source: WorkspaceMoveEvidence {
            source_archive_sha256: payload_sha256.clone(),
            checkpoint_bundle_ref: "checkpoint:e04-positive".to_owned(),
            workspace_ref: "workspace:e04-positive".to_owned(),
            workspace_revision_ref: "workspace-revision:e04-positive".to_owned(),
        },
        target: target.clone(),
    };

    let route = TransferRouteCandidate {
        kind: TransferRouteKind::Direct,
        endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 44103),
        server_name: "target.e04-positive.test".to_owned(),
        expected_peer_fingerprint: [0x22; 32],
        relay_ref: None,
    };
    let binding = &target.binding;
    let expected_size = u64::try_from(vault_bytes.len()).expect("vault length fits u64");
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
        payload_sha256.clone(),
        1024,
        vec![route.clone()],
        NOW - 10,
        EXPIRES,
        41,
    )
    .expect("exact E03 ticket");

    let report = TransferVerificationReport {
        run_ref: ticket.run_ref().clone(),
        verification_ref: entity("transfer.verification"),
        verification_state: "verified".to_owned(),
        source_sha256: Some(payload_sha256.clone()),
        destination_sha256: payload_sha256.clone(),
        observed_size: expected_size,
        materialized_path: None,
    };

    let transferred = WorkspaceMover::accept_transfer(movement, &ticket, &route, &report, NOW)
        .expect("exact E03/A08 transfer authority");
    assert_eq!(transferred.phase, WorkspaceMovePhase::Reverifying);

    let reverified = WorkspaceMover::reverify_target(transferred, &vault_bytes, &backend)
        .expect("B06 target import plus independent A13 re-verification");

    assert_eq!(reverified.phase, WorkspaceMovePhase::CompatibilityChecked);
    assert_eq!(
        reverified.checkpoint_verification.state,
        VerificationState::Verified
    );
    assert!(reverified.imported_vault().is_checkpoint_verified());
    assert_eq!(reverified.transfer.destination_sha256, payload_sha256);
    assert_eq!(reverified.transfer.observed_size, expected_size);
    assert_ne!(reverified.phase, WorkspaceMovePhase::Restoring);
    assert_ne!(reverified.phase, WorkspaceMovePhase::Recovered);
}
