//! B06 Session Vault v1 portability, compatibility and recovery acceptance corpus.

use ptah_checkpoint::*;
use std::collections::BTreeMap;

const COMPAT: &str = "compat:alpha";
const VAULT_CAP: &str = "capability:session-vault-v1";
const NOW: u64 = 1_000;
const VALID_UNTIL: u64 = 2_000;

struct MemoryBackend {
    captured: BTreeMap<CheckpointClass, CapturedComponent>,
    restore_calls: usize,
}

impl MemoryBackend {
    fn fixture() -> Self {
        let mut captured = BTreeMap::new();
        for (class, bytes) in [
            (CheckpointClass::Workspace, b"workspace".as_slice()),
            (CheckpointClass::Process, b"process".as_slice()),
        ] {
            captured.insert(
                class,
                CapturedComponent {
                    subject_refs: vec![format!("subject:{class:?}")],
                    bytes: bytes.to_vec(),
                    provider_revision_ref: "provider-revision:a".to_owned(),
                    provider_instance_ref: "provider:a".to_owned(),
                    provider_generation: 7,
                    connection_epoch: 4,
                    consistency: Consistency::CrashConsistent,
                    compatibility_requirement_refs: vec![COMPAT.to_owned()],
                    evidence_refs: vec![format!("capture:{class:?}")],
                    limitations: Vec::new(),
                },
            );
        }
        Self {
            captured,
            restore_calls: 0,
        }
    }
}

impl CheckpointBackend for MemoryBackend {
    fn capture(&mut self, request: &CaptureRequest) -> Result<CapturedComponent, CheckpointError> {
        self.captured
            .get(&request.class)
            .cloned()
            .ok_or_else(|| CheckpointError::CaptureFailed("missing fixture".to_owned()))
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
        self.restore_calls += 1;
        Ok(RestoredComponent {
            output_refs: vec![format!("restored:{}", request.checkpoint_component_ref)],
            evidence_refs: vec![format!("restore:{}", request.checkpoint_component_ref)],
            limitations: Vec::new(),
            observed_provider_instance_ref: request.target_provider_instance_ref.clone(),
            observed_provider_generation: request.target_provider_generation,
            observed_connection_epoch: request.target_connection_epoch,
            observed_materialization_generation: request.target_materialization_generation,
        })
    }
}

fn request() -> CheckpointRequest {
    CheckpointRequest {
        request_ref: "checkpoint-request:b06".to_owned(),
        workspace_ref: "workspace:1".to_owned(),
        workspace_revision_ref: "workspace-revision:4".to_owned(),
        workspace_materialization_ref: "materialization:9".to_owned(),
        materialization_generation: 9,
        requested_classes: vec![CheckpointClass::Workspace, CheckpointClass::Process],
        requested_consistency: Consistency::CrashConsistent,
        privacy_policy_ref: "policy:privacy".to_owned(),
        credential_policy_ref: "policy:credential".to_owned(),
        destination_or_retention_refs: vec!["retention:vault".to_owned()],
        requested_proof_refs: vec!["proof:b06".to_owned()],
    }
}

fn snapshot() -> RecoverySnapshot {
    RecoverySnapshot {
        activity_refs: vec!["activity:running".to_owned()],
        attachment_refs: vec!["attachment:old".to_owned()],
        lease_refs: vec!["lease:old".to_owned()],
        partial_artifact_refs: vec!["artifact:partial".to_owned()],
        result_handles: Vec::new(),
        schedules: Vec::new(),
        conflict_receipt_refs: vec!["receipt:conflict".to_owned()],
        uncertain_external_effect_refs: Vec::new(),
    }
}

fn create_verified() -> (CheckpointEngine, MemoryBackend, CheckpointBundle) {
    let mut engine = CheckpointEngine::default();
    let mut backend = MemoryBackend::fixture();
    let bundle = engine
        .create_checkpoint(
            request(),
            snapshot(),
            "activity:checkpoint",
            "attempt:checkpoint",
            vec!["receipt:capture".to_owned()],
            &mut backend,
        )
        .expect("checkpoint creation");
    let verification = engine
        .verify_checkpoint(&bundle.bundle_id, &request().requested_classes, &backend)
        .expect("checkpoint verification");
    assert_eq!(verification.state, VerificationState::Verified);
    (engine, backend, bundle)
}

fn export_spec() -> SessionVaultExportSpec {
    SessionVaultExportSpec {
        workspace_versions: vec![
            WorkspaceVersionRecord {
                workspace_revision_ref: "workspace-revision:3".to_owned(),
                materialization_generation: 8,
                parent_revision_ref: None,
                evidence_refs: vec!["evidence:version:3".to_owned()],
            },
            WorkspaceVersionRecord {
                workspace_revision_ref: "workspace-revision:4".to_owned(),
                materialization_generation: 9,
                parent_revision_ref: Some("workspace-revision:3".to_owned()),
                evidence_refs: vec!["evidence:version:4".to_owned()],
            },
        ],
        sessions: vec![SessionVaultSession {
            session_ref: "session:1".to_owned(),
            workspace_ref: "workspace:1".to_owned(),
            workspace_revision_ref: "workspace-revision:4".to_owned(),
            provider_instance_ref: "provider:a".to_owned(),
            provider_generation: 7,
            connection_epoch: 4,
            node_ref: Some("node:a".to_owned()),
            node_generation: Some(3),
            attachment_refs: vec!["attachment:old".to_owned()],
            subject_refs: vec!["object:1".to_owned()],
        }],
        objects: vec![VaultObjectEntry {
            object_ref: "object:1".to_owned(),
            revision_ref: "object-revision:1".to_owned(),
            content_sha256: Some("a".repeat(64)),
            byte_len: Some(12),
            artifact_refs: vec!["artifact:1".to_owned()],
        }],
        artifacts: vec![VaultArtifactEntry {
            artifact_ref: "artifact:1".to_owned(),
            object_ref: "object:1".to_owned(),
            revision_ref: "object-revision:1".to_owned(),
            artifact_type: "document".to_owned(),
            purpose: "portable recovery fixture".to_owned(),
        }],
        conflicts: vec!["conflict:retained".to_owned()],
        additional_required_capability_refs: vec![VAULT_CAP.to_owned()],
        export_evidence_refs: vec!["evidence:vault-export".to_owned()],
    }
}

fn target(include_vault_capability: bool) -> RestoreTarget {
    let mut compatibility_refs = vec![COMPAT.to_owned()];
    if include_vault_capability {
        compatibility_refs.push(VAULT_CAP.to_owned());
    }
    RestoreTarget {
        workspace_ref: "workspace:1".to_owned(),
        workspace_revision_ref: "workspace-revision:4".to_owned(),
        target_materialization_generation: 10,
        provider_targets: vec![ProviderRecoveryTarget {
            source_provider_instance_ref: "provider:a".to_owned(),
            target_provider_instance_ref: "provider:a:node-b".to_owned(),
            target_provider_generation: 8,
            target_connection_epoch: 5,
        }],
        compatibility_refs,
        restart_evidence_refs: vec!["evidence:node-b-restart".to_owned()],
        authorization_refs: vec!["grant:restore".to_owned()],
        executor_ref: "executor:node-b".to_owned(),
    }
}

fn export_verified_bytes() -> (Vec<u8>, MemoryBackend) {
    let (engine, backend, bundle) = create_verified();
    let bytes =
        export_session_vault(&engine, &bundle, export_spec()).expect("verified vault export");
    (bytes, backend)
}

#[test]
fn export_requires_current_independent_checkpoint_verification() {
    let mut engine = CheckpointEngine::default();
    let mut backend = MemoryBackend::fixture();
    let bundle = engine
        .create_checkpoint(
            request(),
            snapshot(),
            "activity:checkpoint",
            "attempt:checkpoint",
            vec!["receipt:capture".to_owned()],
            &mut backend,
        )
        .expect("checkpoint creation");
    assert_eq!(
        export_session_vault(&engine, &bundle, export_spec()),
        Err(SessionVaultError::UnverifiedCheckpoint)
    );
}

#[test]
fn verified_archive_roundtrip_preserves_workspace_sessions_objects_and_artifacts() {
    let (bytes, _) = export_verified_bytes();
    let imported = import_session_vault(&bytes).expect("vault import");
    let manifest = &imported.archive().manifest;
    assert_eq!(manifest.workspace_ref, "workspace:1");
    assert_eq!(
        manifest.current_workspace_revision_ref,
        "workspace-revision:4"
    );
    assert_eq!(manifest.workspace_versions.len(), 2);
    assert_eq!(manifest.sessions[0].session_ref, "session:1");
    assert_eq!(manifest.objects[0].object_ref, "object:1");
    assert_eq!(manifest.artifacts[0].artifact_ref, "artifact:1");
    assert!(
        manifest
            .required_capability_refs
            .contains(&COMPAT.to_owned())
    );
    assert!(
        manifest
            .required_capability_refs
            .contains(&VAULT_CAP.to_owned())
    );
    assert_eq!(manifest.conflicts, vec!["conflict:retained"]);
}

#[test]
fn readable_recovery_export_omits_raw_checkpoint_bytes_but_retains_digests() {
    let (bytes, _) = export_verified_bytes();
    let imported = import_session_vault(&bytes).expect("vault import");
    let readable = imported
        .archive()
        .readable_recovery_export()
        .expect("readable recovery export");
    assert!(readable.contains("checkpoint_components"));
    assert!(readable.contains("content_sha256"));
    assert!(readable.contains("raw checkpoint component bytes intentionally omitted"));
    assert!(!readable.contains("119,111,114,107,115,112,97,99,101"));
}

#[test]
fn imported_vault_drops_restore_authorization_until_reverification() {
    let (bytes, backend) = export_verified_bytes();
    let mut imported = import_session_vault(&bytes).expect("vault import");
    assert!(!imported.is_checkpoint_verified());
    let verification = imported
        .reverify_checkpoint(&backend)
        .expect("destination re-verification");
    assert_eq!(verification.state, VerificationState::Verified);
    assert!(imported.is_checkpoint_verified());
}

#[test]
fn compatible_other_node_resume_and_independent_recovery_verification_pass() {
    let (bytes, mut backend) = export_verified_bytes();
    let mut imported = import_session_vault(&bytes).expect("vault import");
    imported
        .reverify_checkpoint(&backend)
        .expect("destination verification");
    let restore_target = target(true);
    let compatibility = imported
        .evaluate_compatibility(
            &restore_target,
            vec!["evidence:target-capabilities".to_owned()],
            NOW,
            VALID_UNTIL,
        )
        .expect("compatibility");
    assert_eq!(
        compatibility.decision.outcome,
        CompatibilityOutcome::Compatible
    );
    assert!(compatibility.missing_capability_refs.is_empty());
    let restore = imported
        .restore_on_target(
            "attempt:node-b-restore",
            restore_target,
            &compatibility,
            NOW,
            &mut backend,
        )
        .expect("cross-node restore");
    assert_eq!(backend.restore_calls, 2);
    let verification = imported.verify_recovery(
        &restore,
        "verifier:independent",
        vec![Postcondition {
            key: "workspace.resume".to_owned(),
            passed: true,
            evidence_refs: vec!["evidence:workspace-resume".to_owned()],
        }],
        Vec::new(),
        vec!["evidence:independent-recovery".to_owned()],
    );
    assert_eq!(verification.outcome, RecoveryOutcome::Recovered);
    assert!(verification.verifier_independent);
}

#[test]
fn missing_vault_capability_is_exact_and_cannot_restore() {
    let (bytes, mut backend) = export_verified_bytes();
    let mut imported = import_session_vault(&bytes).expect("vault import");
    imported
        .reverify_checkpoint(&backend)
        .expect("destination verification");
    let restore_target = target(false);
    let compatibility = imported
        .evaluate_compatibility(
            &restore_target,
            vec!["evidence:target-capabilities".to_owned()],
            NOW,
            VALID_UNTIL,
        )
        .expect("compatibility report");
    assert_eq!(compatibility.missing_capability_refs, vec![VAULT_CAP]);
    assert_eq!(
        compatibility.decision.outcome,
        CompatibilityOutcome::Incompatible
    );
    let mut forged = compatibility.clone();
    forged.decision.outcome = CompatibilityOutcome::Compatible;
    forged.decision.limitations.clear();
    forged.missing_capability_refs.clear();
    assert!(matches!(
        imported.restore_on_target(
            "attempt:must-not-run",
            restore_target,
            &forged,
            NOW,
            &mut backend,
        ),
        Err(SessionVaultError::Checkpoint(
            CheckpointError::IncompatibleRestoreTarget
        ))
    ));
    assert_eq!(backend.restore_calls, 0);
}

#[test]
fn incompatible_a13_capability_remains_explicit() {
    let (bytes, backend) = export_verified_bytes();
    let imported = import_session_vault(&bytes).expect("vault import");
    let mut restore_target = target(true);
    restore_target
        .compatibility_refs
        .retain(|item| item != COMPAT);
    let report = imported
        .evaluate_compatibility(
            &restore_target,
            vec!["evidence:target-capabilities".to_owned()],
            NOW,
            VALID_UNTIL,
        )
        .expect("incompatible report");
    assert_eq!(report.decision.outcome, CompatibilityOutcome::Incompatible);
    assert!(report.missing_capability_refs.contains(&COMPAT.to_owned()));
    drop(backend);
}

#[test]
fn archive_digest_tamper_fails_before_imported_engine_exists() {
    let (bytes, _) = export_verified_bytes();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("vault json");
    value["manifest"]["workspace_ref"] = serde_json::json!("workspace:tampered");
    let tampered = serde_json::to_vec(&value).expect("tampered json");
    assert_eq!(
        import_session_vault(&tampered).map(|_| ()),
        Err(SessionVaultError::PayloadDigestMismatch)
    );
}

#[test]
fn current_workspace_version_must_match_exact_checkpoint_revision_and_generation() {
    let (engine, _, bundle) = create_verified();
    let mut spec = export_spec();
    spec.workspace_versions
        .retain(|version| version.workspace_revision_ref != "workspace-revision:4");
    assert_eq!(
        export_session_vault(&engine, &bundle, spec),
        Err(SessionVaultError::InvalidMetadata(
            "checkpoint workspace version missing"
        ))
    );
}

#[test]
fn artifact_links_are_bidirectional_and_revision_exact() {
    let (engine, _, bundle) = create_verified();
    let mut wrong_revision = export_spec();
    wrong_revision.artifacts[0].revision_ref = "object-revision:other".to_owned();
    assert_eq!(
        export_session_vault(&engine, &bundle, wrong_revision),
        Err(SessionVaultError::InvalidMetadata(
            "artifact owner mismatch"
        ))
    );

    let mut cross_owner = export_spec();
    cross_owner.objects.push(VaultObjectEntry {
        object_ref: "object:2".to_owned(),
        revision_ref: "object-revision:2".to_owned(),
        content_sha256: None,
        byte_len: None,
        artifact_refs: Vec::new(),
    });
    cross_owner.artifacts[0].object_ref = "object:2".to_owned();
    cross_owner.artifacts[0].revision_ref = "object-revision:2".to_owned();
    assert_eq!(
        export_session_vault(&engine, &bundle, cross_owner),
        Err(SessionVaultError::InvalidMetadata(
            "artifact owner mismatch"
        ))
    );

    let mut dangling = export_spec();
    dangling.artifacts.clear();
    assert_eq!(
        export_session_vault(&engine, &bundle, dangling),
        Err(SessionVaultError::InvalidMetadata(
            "object artifact_ref missing artifact manifest entry"
        ))
    );
}

#[test]
fn retained_conflicts_survive_portability_without_becoming_hidden_success() {
    let (bytes, _) = export_verified_bytes();
    let imported = import_session_vault(&bytes).expect("vault import");
    let report = imported
        .evaluate_compatibility(
            &target(true),
            vec!["evidence:target-capabilities".to_owned()],
            NOW,
            VALID_UNTIL,
        )
        .expect("compatibility");
    assert_eq!(report.retained_conflicts, vec!["conflict:retained"]);
    assert_eq!(report.decision.outcome, CompatibilityOutcome::Compatible);
}

#[test]
fn used_restore_attempt_fence_survives_export_and_import() {
    let (mut engine, mut backend, bundle) = create_verified();
    let restore_target = target(false);
    let decision = engine
        .evaluate_restore_compatibility(
            &bundle.bundle_id,
            &restore_target,
            vec!["evidence:compatibility".to_owned()],
            NOW,
            VALID_UNTIL,
        )
        .expect("A13 compatibility");
    assert_eq!(decision.outcome, CompatibilityOutcome::Compatible);
    engine
        .restore(
            &bundle.bundle_id,
            "attempt:already-used",
            restore_target,
            &decision,
            NOW,
            &mut backend,
        )
        .expect("source restore");
    let bytes =
        export_session_vault(&engine, &bundle, export_spec()).expect("post-restore vault export");
    let mut imported = import_session_vault(&bytes).expect("vault import");
    imported
        .reverify_checkpoint(&backend)
        .expect("destination verification");
    let destination_target = target(true);
    let compatibility = imported
        .evaluate_compatibility(
            &destination_target,
            vec!["evidence:target-capabilities".to_owned()],
            NOW,
            VALID_UNTIL,
        )
        .expect("destination compatibility");
    assert!(matches!(
        imported.restore_on_target(
            "attempt:already-used",
            destination_target,
            &compatibility,
            NOW,
            &mut backend,
        ),
        Err(SessionVaultError::Checkpoint(
            CheckpointError::ReusedAttempt
        ))
    ));
}
