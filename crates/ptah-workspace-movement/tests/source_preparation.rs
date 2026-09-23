//! E04 source preparation authority boundary.

use ptah_checkpoint::{
    export_session_vault, import_session_vault, CaptureRequest, CapturedComponent,
    CheckpointBackend, CheckpointClass, CheckpointEngine, CheckpointError, CheckpointRequest,
    ComponentRestoreRequest, Consistency, ReadbackVerification, RecoverySnapshot,
    RestoredComponent, SessionVaultExportSpec, VerificationState, WorkspaceVersionRecord,
};
use ptah_workspace_movement::{WorkspaceMovePhase, WorkspaceMover};

struct Backend;

impl CheckpointBackend for Backend {
    fn capture(&mut self, request: &CaptureRequest) -> Result<CapturedComponent, CheckpointError> {
        Ok(CapturedComponent {
            subject_refs: vec![format!("subject:{:?}", request.class)],
            bytes: b"workspace-state".to_vec(),
            provider_revision_ref: "provider-revision:1".to_owned(),
            provider_instance_ref: "provider:1".to_owned(),
            provider_generation: 1,
            connection_epoch: 1,
            consistency: Consistency::CrashConsistent,
            compatibility_requirement_refs: vec!["capability:workspace".to_owned()],
            evidence_refs: vec!["evidence:capture".to_owned()],
            limitations: Vec::new(),
        })
    }

    fn verify_readback(
        &self,
        component_ref: &str,
        _expected_sha256: &str,
    ) -> Result<ReadbackVerification, CheckpointError> {
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
            output_refs: vec!["restored:workspace".to_owned()],
            evidence_refs: vec!["evidence:restore".to_owned()],
            limitations: Vec::new(),
            observed_provider_instance_ref: request.target_provider_instance_ref.clone(),
            observed_provider_generation: request.target_provider_generation,
            observed_connection_epoch: request.target_connection_epoch,
            observed_materialization_generation: request.target_materialization_generation,
        })
    }
}

fn verified_archive() -> ptah_checkpoint::ImportedSessionVault {
    let mut engine = CheckpointEngine::default();
    let mut backend = Backend;
    let request = CheckpointRequest {
        request_ref: "checkpoint-request:e04".to_owned(),
        workspace_ref: "workspace:e04".to_owned(),
        workspace_revision_ref: "workspace-revision:e04".to_owned(),
        workspace_materialization_ref: "materialization:e04".to_owned(),
        materialization_generation: 4,
        requested_classes: vec![CheckpointClass::Workspace],
        requested_consistency: Consistency::CrashConsistent,
        privacy_policy_ref: "policy:privacy".to_owned(),
        credential_policy_ref: "policy:credential".to_owned(),
        destination_or_retention_refs: vec!["retention:e04".to_owned()],
        requested_proof_refs: vec!["proof:e04".to_owned()],
    };
    let bundle = engine
        .create_checkpoint(
            request.clone(),
            RecoverySnapshot {
                activity_refs: Vec::new(),
                attachment_refs: Vec::new(),
                lease_refs: Vec::new(),
                partial_artifact_refs: Vec::new(),
                result_handles: Vec::new(),
                schedules: Vec::new(),
                conflict_receipt_refs: Vec::new(),
                uncertain_external_effect_refs: Vec::new(),
            },
            "activity:e04",
            "attempt:e04",
            vec!["receipt:e04".to_owned()],
            &mut backend,
        )
        .expect("checkpoint creation");
    let verification = engine
        .verify_checkpoint(&bundle.bundle_id, &request.requested_classes, &backend)
        .expect("checkpoint verification");
    assert_eq!(verification.state, VerificationState::Verified);

    let bytes = export_session_vault(
        &engine,
        &bundle,
        SessionVaultExportSpec {
            workspace_versions: vec![WorkspaceVersionRecord {
                workspace_revision_ref: request.workspace_revision_ref,
                materialization_generation: request.materialization_generation,
                parent_revision_ref: None,
                evidence_refs: vec!["evidence:workspace-version".to_owned()],
            }],
            sessions: Vec::new(),
            objects: Vec::new(),
            artifacts: Vec::new(),
            conflicts: Vec::new(),
            additional_required_capability_refs: Vec::new(),
            export_evidence_refs: vec!["evidence:vault-export".to_owned()],
        },
    )
    .expect("verified Session Vault export");

    import_session_vault(&bytes).expect("integrity-bound Session Vault import")
}

#[test]
fn verified_source_vault_enters_e04_without_manufacturing_success() {
    let imported = verified_archive();
    let archive = imported.archive();

    let prepared = WorkspaceMover::prepare_source(archive);

    assert_eq!(prepared.phase, WorkspaceMovePhase::AwaitingPlacement);
    assert_ne!(prepared.phase, WorkspaceMovePhase::Recovered);
    assert_eq!(
        prepared.evidence.source_archive_sha256,
        archive.payload_sha256
    );
    assert_eq!(
        prepared.evidence.checkpoint_bundle_ref,
        archive.manifest.checkpoint_bundle_ref
    );
    assert_eq!(
        prepared.evidence.workspace_ref,
        archive.manifest.workspace_ref
    );
    assert_eq!(
        prepared.evidence.workspace_revision_ref,
        archive.manifest.current_workspace_revision_ref
    );
}
