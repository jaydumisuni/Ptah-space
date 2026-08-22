//! A13 checkpoint/restart/recovery authoritative acceptance and adversarial corpus.

use ptah_checkpoint::*;
use std::collections::BTreeMap;

const COMPAT: &str = "compat:alpha";
const NOW: u64 = 1_000;
const VALID_UNTIL: u64 = 2_000;

#[derive(Clone, Copy)]
enum ReadbackMode {
    Pass,
    Fail,
    Error,
}

struct MemoryBackend {
    captured: BTreeMap<CheckpointClass, CapturedComponent>,
    readback: ReadbackMode,
    restore_calls: usize,
    fail_restore_call: Option<usize>,
    mismatch_generation: bool,
}

impl MemoryBackend {
    fn fixture() -> Self {
        let mut captured = BTreeMap::new();
        for (class, bytes, instance, generation) in [
            (
                CheckpointClass::Workspace,
                b"workspace".as_slice(),
                "provider:a",
                7,
            ),
            (
                CheckpointClass::Process,
                b"process".as_slice(),
                "provider:a",
                7,
            ),
            (
                CheckpointClass::Terminal,
                b"terminal".as_slice(),
                "provider:b",
                12,
            ),
            (
                CheckpointClass::Browser,
                b"browser".as_slice(),
                "provider:b",
                12,
            ),
        ] {
            captured.insert(
                class,
                CapturedComponent {
                    subject_refs: vec![format!("subject:{class:?}")],
                    bytes: bytes.to_vec(),
                    provider_revision_ref: format!("revision:{instance}"),
                    provider_instance_ref: instance.to_owned(),
                    provider_generation: generation,
                    connection_epoch: 4,
                    consistency: Consistency::CrashConsistent,
                    compatibility_requirement_refs: vec![COMPAT.to_owned()],
                    evidence_refs: vec![format!("capture-evidence:{class:?}")],
                    limitations: Vec::new(),
                },
            );
        }
        Self {
            captured,
            readback: ReadbackMode::Pass,
            restore_calls: 0,
            fail_restore_call: None,
            mismatch_generation: false,
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
        match self.readback {
            ReadbackMode::Pass => Ok(ReadbackVerification {
                verified: true,
                evidence_refs: vec![format!("readback:{component_ref}")],
                limitations: Vec::new(),
            }),
            ReadbackMode::Fail => Ok(ReadbackVerification {
                verified: false,
                evidence_refs: vec![format!("readback-failed:{component_ref}")],
                limitations: vec!["digest_mismatch".to_owned()],
            }),
            ReadbackMode::Error => Err(CheckpointError::VerificationFailed),
        }
    }

    fn restore(
        &mut self,
        request: &ComponentRestoreRequest,
    ) -> Result<RestoredComponent, CheckpointError> {
        self.restore_calls += 1;
        if self.fail_restore_call == Some(self.restore_calls) {
            return Err(CheckpointError::CaptureFailed(
                "injected restore failure".to_owned(),
            ));
        }
        Ok(RestoredComponent {
            output_refs: vec![format!("restored:{}", request.checkpoint_component_ref)],
            evidence_refs: vec![format!(
                "restore-evidence:{}",
                request.checkpoint_component_ref
            )],
            limitations: Vec::new(),
            observed_provider_instance_ref: request.target_provider_instance_ref.clone(),
            observed_provider_generation: if self.mismatch_generation {
                request.target_provider_generation + 1
            } else {
                request.target_provider_generation
            },
            observed_connection_epoch: request.target_connection_epoch,
            observed_materialization_generation: request.target_materialization_generation,
        })
    }
}

fn request() -> CheckpointRequest {
    CheckpointRequest {
        request_ref: "checkpoint-request:1".to_owned(),
        workspace_ref: "workspace:1".to_owned(),
        workspace_revision_ref: "workspace-revision:4".to_owned(),
        workspace_materialization_ref: "materialization:9".to_owned(),
        materialization_generation: 9,
        requested_classes: vec![
            CheckpointClass::Workspace,
            CheckpointClass::Process,
            CheckpointClass::Terminal,
            CheckpointClass::Browser,
        ],
        requested_consistency: Consistency::CrashConsistent,
        privacy_policy_ref: "policy:privacy".to_owned(),
        credential_policy_ref: "policy:credential".to_owned(),
        destination_or_retention_refs: vec!["retention:alpha".to_owned()],
        requested_proof_refs: vec!["proof:a13".to_owned()],
    }
}

fn snapshot(with_uncertain_effect: bool) -> RecoverySnapshot {
    RecoverySnapshot {
        activity_refs: vec!["activity:running".to_owned()],
        attachment_refs: vec!["attachment:old".to_owned()],
        lease_refs: vec!["lease:old".to_owned()],
        partial_artifact_refs: vec!["artifact:partial".to_owned()],
        result_handles: vec![StableResultHandle {
            handle_ref: "result:stable".to_owned(),
            state: "partial".to_owned(),
            artifact_refs: vec!["artifact:partial".to_owned()],
        }],
        schedules: vec![DurableSchedule {
            schedule_ref: "schedule:exact".to_owned(),
            kind: ScheduleKind::Exact,
            expression: "2026-08-22T08:00:00+02:00".to_owned(),
        }],
        conflict_receipt_refs: vec!["receipt:conflict".to_owned()],
        uncertain_external_effect_refs: if with_uncertain_effect {
            vec!["operation:external-unknown".to_owned()]
        } else {
            Vec::new()
        },
    }
}

fn target() -> RestoreTarget {
    RestoreTarget {
        workspace_ref: "workspace:1".to_owned(),
        workspace_revision_ref: "workspace-revision:4".to_owned(),
        target_materialization_generation: 10,
        provider_targets: vec![
            ProviderRecoveryTarget {
                source_provider_instance_ref: "provider:a".to_owned(),
                target_provider_instance_ref: "provider:a:restart".to_owned(),
                target_provider_generation: 8,
                target_connection_epoch: 5,
            },
            ProviderRecoveryTarget {
                source_provider_instance_ref: "provider:b".to_owned(),
                target_provider_instance_ref: "provider:b:restart".to_owned(),
                target_provider_generation: 13,
                target_connection_epoch: 5,
            },
        ],
        compatibility_refs: vec![COMPAT.to_owned()],
        restart_evidence_refs: vec!["evidence:node-restart".to_owned()],
        authorization_refs: vec!["grant:restore-runtime".to_owned()],
        executor_ref: "executor:restore".to_owned(),
    }
}

fn create_bundle(
    with_uncertain_effect: bool,
) -> (CheckpointEngine, MemoryBackend, CheckpointBundle) {
    let mut engine = CheckpointEngine::default();
    let mut backend = MemoryBackend::fixture();
    let bundle = engine
        .create_checkpoint(
            request(),
            snapshot(with_uncertain_effect),
            "activity:checkpoint",
            "attempt:checkpoint",
            vec!["receipt:capture".to_owned()],
            &mut backend,
        )
        .expect("checkpoint creation");
    (engine, backend, bundle)
}

fn verify(engine: &mut CheckpointEngine, backend: &MemoryBackend, bundle: &CheckpointBundle) {
    let verification = engine
        .verify_checkpoint(&bundle.bundle_id, &request().requested_classes, backend)
        .expect("checkpoint verification");
    assert_eq!(verification.state, VerificationState::Verified);
}

fn decision(
    engine: &CheckpointEngine,
    bundle: &CheckpointBundle,
    restore_target: &RestoreTarget,
) -> RestoreCompatibilityDecision {
    let decision = engine
        .evaluate_restore_compatibility(
            &bundle.bundle_id,
            restore_target,
            vec!["evidence:compatibility".to_owned()],
            NOW,
            VALID_UNTIL,
        )
        .expect("compatibility decision");
    assert_eq!(decision.outcome, CompatibilityOutcome::Compatible);
    decision
}

fn passing_postconditions() -> Vec<Postcondition> {
    vec![
        Postcondition {
            key: "workspace.identity".to_owned(),
            passed: true,
            evidence_refs: vec!["evidence:workspace".to_owned()],
        },
        Postcondition {
            key: "provider.readiness".to_owned(),
            passed: true,
            evidence_refs: vec!["evidence:readiness".to_owned()],
        },
    ]
}

#[test]
fn checkpoint_existence_never_authorizes_restore() {
    let (mut engine, mut backend, bundle) = create_bundle(false);
    let restore_target = target();
    let compatibility = decision(&engine, &bundle, &restore_target);
    assert!(matches!(
        engine.restore(
            &bundle.bundle_id,
            "attempt:restore",
            restore_target,
            &compatibility,
            NOW,
            &mut backend,
        ),
        Err(CheckpointError::UnverifiedBundle)
    ));
    assert_eq!(backend.restore_calls, 0);
}

#[test]
fn request_scope_and_consistency_fail_closed_before_registration() {
    let mut engine = CheckpointEngine::default();
    let mut backend = MemoryBackend::fixture();
    let mut duplicate = request();
    duplicate.requested_classes.push(CheckpointClass::Workspace);
    assert!(matches!(
        engine.create_checkpoint(
            duplicate,
            snapshot(false),
            "activity:x",
            "attempt:x",
            vec!["receipt:x".to_owned()],
            &mut backend,
        ),
        Err(CheckpointError::DuplicateClass)
    ));
    let mut strict = request();
    strict.requested_consistency = Consistency::Consistent;
    assert!(matches!(
        engine.create_checkpoint(
            strict,
            snapshot(false),
            "activity:y",
            "attempt:y",
            vec!["receipt:y".to_owned()],
            &mut backend,
        ),
        Err(CheckpointError::ConsistencyRequirementNotMet)
    ));
}

#[test]
fn readback_failure_is_failed_and_readback_error_is_inconclusive() {
    let (mut engine, mut backend, bundle) = create_bundle(false);
    backend.readback = ReadbackMode::Fail;
    let failed = engine
        .verify_checkpoint(&bundle.bundle_id, &request().requested_classes, &backend)
        .expect("failed verification record");
    assert_eq!(failed.state, VerificationState::Failed);
    assert!(!engine.is_verified(&bundle.bundle_id));
    backend.readback = ReadbackMode::Error;
    let inconclusive = engine
        .verify_checkpoint(&bundle.bundle_id, &request().requested_classes, &backend)
        .expect("inconclusive verification record");
    assert_eq!(inconclusive.state, VerificationState::Inconclusive);
    assert!(
        inconclusive
            .limitations
            .iter()
            .any(|item| item.starts_with("readback_error:"))
    );
}

#[test]
fn checkpoint_integrity_and_restore_compatibility_are_separate_facts() {
    let (mut engine, backend, bundle) = create_bundle(false);
    verify(&mut engine, &backend, &bundle);
    let mut incompatible_target = target();
    incompatible_target.compatibility_refs.clear();
    let compatibility = engine
        .evaluate_restore_compatibility(
            &bundle.bundle_id,
            &incompatible_target,
            vec!["evidence:compatibility".to_owned()],
            NOW,
            VALID_UNTIL,
        )
        .expect("compatibility decision");
    assert!(engine.is_verified(&bundle.bundle_id));
    assert_eq!(compatibility.outcome, CompatibilityOutcome::Incompatible);
    assert!(
        compatibility
            .limitations
            .iter()
            .any(|item| item == "missing_compatibility:compat:alpha")
    );
}

#[test]
fn incompatible_unknown_expired_and_rebound_decisions_cannot_mutate() {
    let (mut engine, mut backend, bundle) = create_bundle(false);
    verify(&mut engine, &backend, &bundle);
    let restore_target = target();
    let unknown = engine
        .evaluate_restore_compatibility(
            &bundle.bundle_id,
            &restore_target,
            Vec::new(),
            NOW,
            VALID_UNTIL,
        )
        .expect("unknown decision");
    assert_eq!(unknown.outcome, CompatibilityOutcome::Unknown);
    assert!(matches!(
        engine.restore(
            &bundle.bundle_id,
            "attempt:unknown",
            restore_target.clone(),
            &unknown,
            NOW,
            &mut backend,
        ),
        Err(CheckpointError::IncompatibleRestoreTarget)
    ));
    let valid = decision(&engine, &bundle, &restore_target);
    assert!(matches!(
        engine.restore(
            &bundle.bundle_id,
            "attempt:expired",
            restore_target.clone(),
            &valid,
            VALID_UNTIL + 1,
            &mut backend,
        ),
        Err(CheckpointError::ExpiredCompatibilityDecision)
    ));
    let mut changed_target = restore_target;
    changed_target.target_materialization_generation += 1;
    assert!(matches!(
        engine.restore(
            &bundle.bundle_id,
            "attempt:rebound",
            changed_target,
            &valid,
            NOW,
            &mut backend,
        ),
        Err(CheckpointError::CompatibilityDecisionMismatch)
    ));
    assert_eq!(backend.restore_calls, 0);
}

#[test]
fn stale_generations_are_incompatible_before_side_effects() {
    let (mut engine, backend, bundle) = create_bundle(false);
    verify(&mut engine, &backend, &bundle);
    let mut stale_materialization = target();
    stale_materialization.target_materialization_generation = 9;
    assert!(matches!(
        engine.evaluate_restore_compatibility(
            &bundle.bundle_id,
            &stale_materialization,
            vec!["evidence:compatibility".to_owned()],
            NOW,
            VALID_UNTIL,
        ),
        Err(CheckpointError::StaleMaterializationGeneration)
    ));
    let mut stale_provider = target();
    stale_provider.provider_targets[1].target_provider_generation = 12;
    let decision = engine
        .evaluate_restore_compatibility(
            &bundle.bundle_id,
            &stale_provider,
            vec!["evidence:compatibility".to_owned()],
            NOW,
            VALID_UNTIL,
        )
        .expect("incompatible stale provider decision");
    assert_eq!(decision.outcome, CompatibilityOutcome::Incompatible);
}

#[test]
fn missing_provider_restart_or_authorization_is_rejected_before_mutation() {
    let (mut engine, backend, bundle) = create_bundle(false);
    verify(&mut engine, &backend, &bundle);
    let mut missing_provider = target();
    missing_provider.provider_targets.pop();
    let missing = engine
        .evaluate_restore_compatibility(
            &bundle.bundle_id,
            &missing_provider,
            vec!["evidence:compatibility".to_owned()],
            NOW,
            VALID_UNTIL,
        )
        .expect("missing provider decision");
    assert_eq!(missing.outcome, CompatibilityOutcome::Incompatible);
    let mut no_restart = target();
    no_restart.restart_evidence_refs.clear();
    assert!(matches!(
        engine.evaluate_restore_compatibility(
            &bundle.bundle_id,
            &no_restart,
            vec!["evidence:compatibility".to_owned()],
            NOW,
            VALID_UNTIL,
        ),
        Err(CheckpointError::MissingRestartEvidence)
    ));
    let mut no_authorization = target();
    no_authorization.authorization_refs.clear();
    assert!(matches!(
        engine.evaluate_restore_compatibility(
            &bundle.bundle_id,
            &no_authorization,
            vec!["evidence:compatibility".to_owned()],
            NOW,
            VALID_UNTIL,
        ),
        Err(CheckpointError::InvalidRestoreTarget("authorization_refs"))
    ));
}

#[test]
fn successful_restore_reconciles_durable_state_and_retains_new_evidence() {
    let (mut engine, mut backend, bundle) = create_bundle(false);
    verify(&mut engine, &backend, &bundle);
    let restore_target = target();
    let compatibility = decision(&engine, &bundle, &restore_target);
    let restore = engine
        .restore(
            &bundle.bundle_id,
            "attempt:restore:1",
            restore_target,
            &compatibility,
            NOW,
            &mut backend,
        )
        .expect("restore");
    assert_eq!(restore.activities[0].state, ReconciliationState::Recovered);
    assert_eq!(restore.attachments[0].state, ReconciliationState::Detached);
    assert_eq!(restore.leases[0].state, ReconciliationState::Fenced);
    assert_eq!(
        restore.partial_artifacts[0].state,
        ReconciliationState::Partial
    );
    assert_eq!(
        restore.result_handles[0].state,
        ReconciliationState::Retained
    );
    assert_eq!(restore.schedules[0].state, ReconciliationState::Retained);
    assert_eq!(
        restore.conflict_receipts[0].state,
        ReconciliationState::Conflict
    );
    assert_eq!(restore.restored_output_refs.len(), 4);
    assert!(restore.evidence_refs.len() >= 5);
}

#[test]
fn uncertain_external_effect_cannot_be_omitted_from_recovery_verification() {
    let (mut engine, mut backend, bundle) = create_bundle(true);
    verify(&mut engine, &backend, &bundle);
    let restore_target = target();
    let compatibility = decision(&engine, &bundle, &restore_target);
    let restore = engine
        .restore(
            &bundle.bundle_id,
            "attempt:restore:1",
            restore_target,
            &compatibility,
            NOW,
            &mut backend,
        )
        .expect("restore");
    let proof = engine.verify_recovery(
        &restore,
        "verifier:independent",
        passing_postconditions(),
        Vec::new(),
        vec!["evidence:independent".to_owned()],
    );
    assert_eq!(proof.outcome, RecoveryOutcome::Partial);
    assert_eq!(
        proof.unresolved_operation_refs,
        vec!["operation:external-unknown".to_owned()]
    );
}

#[test]
fn recovery_verifier_must_be_independent_and_evidenced() {
    let (mut engine, mut backend, bundle) = create_bundle(false);
    verify(&mut engine, &backend, &bundle);
    let restore_target = target();
    let compatibility = decision(&engine, &bundle, &restore_target);
    let restore = engine
        .restore(
            &bundle.bundle_id,
            "attempt:restore:1",
            restore_target,
            &compatibility,
            NOW,
            &mut backend,
        )
        .expect("restore");
    let same_executor = engine.verify_recovery(
        &restore,
        "executor:restore",
        passing_postconditions(),
        Vec::new(),
        vec!["evidence:review".to_owned()],
    );
    assert_eq!(same_executor.outcome, RecoveryOutcome::Inconclusive);
    let independent = engine.verify_recovery(
        &restore,
        "verifier:independent",
        passing_postconditions(),
        Vec::new(),
        vec!["evidence:review".to_owned()],
    );
    assert_eq!(independent.outcome, RecoveryOutcome::Recovered);
}

#[test]
fn partial_restore_failure_retains_progress_evidence_and_uncertain_effects() {
    let (mut engine, mut backend, bundle) = create_bundle(true);
    verify(&mut engine, &backend, &bundle);
    let restore_target = target();
    let compatibility = decision(&engine, &bundle, &restore_target);
    backend.fail_restore_call = Some(2);
    let error = engine
        .restore(
            &bundle.bundle_id,
            "attempt:partial",
            restore_target,
            &compatibility,
            NOW,
            &mut backend,
        )
        .expect_err("second component must fail");
    let CheckpointError::RestoreFailed(failure) = error else {
        panic!("expected retained partial failure evidence");
    };
    assert_eq!(failure.restored_output_refs.len(), 1);
    assert!(failure.evidence_refs.len() >= 2);
    assert!(
        failure
            .uncertain_external_effect_refs
            .iter()
            .any(|item| item == "operation:external-unknown")
    );
    assert!(
        failure
            .uncertain_external_effect_refs
            .iter()
            .any(|item| item == &failure.failed_component_ref)
    );
}

#[test]
fn backend_observation_mismatch_is_retained_as_partial_failure() {
    let (mut engine, mut backend, bundle) = create_bundle(false);
    verify(&mut engine, &backend, &bundle);
    let restore_target = target();
    let compatibility = decision(&engine, &bundle, &restore_target);
    backend.mismatch_generation = true;
    let error = engine
        .restore(
            &bundle.bundle_id,
            "attempt:mismatch",
            restore_target,
            &compatibility,
            NOW,
            &mut backend,
        )
        .expect_err("mismatched backend evidence must fail");
    let CheckpointError::RestoreFailed(failure) = error else {
        panic!("expected retained mismatch failure");
    };
    assert!(failure.message.contains("provider generation"));
}

#[test]
fn durable_restart_reearns_verification_preserves_attempt_fencing_and_rejects_corruption() {
    let (mut engine, backend, bundle) = create_bundle(false);
    verify(&mut engine, &backend, &bundle);
    let bytes = engine.export_state().expect("export");
    let mut corrupted = bytes.clone();
    let needle = b"workspace:1";
    let replacement = b"workspace:X";
    let offset = corrupted
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("workspace marker");
    corrupted[offset..offset + replacement.len()].copy_from_slice(replacement);
    assert!(matches!(
        CheckpointEngine::import_state(&corrupted),
        Err(CheckpointError::ManifestMismatch)
    ));

    let mut restarted = CheckpointEngine::import_state(&bytes).expect("import");
    assert!(!restarted.is_verified(&bundle.bundle_id));
    restarted
        .verify_checkpoint(&bundle.bundle_id, &request().requested_classes, &backend)
        .expect("reverify");
    let restore_target = target();
    let compatibility = decision(&restarted, &bundle, &restore_target);
    let mut restore_backend = MemoryBackend::fixture();
    restarted
        .restore(
            &bundle.bundle_id,
            "attempt:restart",
            restore_target.clone(),
            &compatibility,
            NOW,
            &mut restore_backend,
        )
        .expect("restore after restart");

    let bytes_after = restarted.export_state().expect("export after restore");
    let mut restarted_again = CheckpointEngine::import_state(&bytes_after).expect("reimport");
    restarted_again
        .verify_checkpoint(&bundle.bundle_id, &request().requested_classes, &backend)
        .expect("reverify again");
    let compatibility_again = decision(&restarted_again, &bundle, &restore_target);
    assert!(matches!(
        restarted_again.restore(
            &bundle.bundle_id,
            "attempt:restart",
            restore_target,
            &compatibility_again,
            NOW,
            &mut MemoryBackend::fixture(),
        ),
        Err(CheckpointError::ReusedAttempt)
    ));
}
