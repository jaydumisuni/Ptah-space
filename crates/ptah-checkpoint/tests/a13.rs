//! A13 checkpoint/restart/recovery acceptance and adversarial corpus.

use ptah_checkpoint::*;
use std::collections::BTreeMap;

const COMPAT: &str = "compat:alpha";

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
            (CheckpointClass::Workspace, b"workspace".as_slice(), "provider:a", 7),
            (CheckpointClass::Process, b"process".as_slice(), "provider:a", 7),
            (CheckpointClass::Terminal, b"terminal".as_slice(), "provider:b", 12),
            (CheckpointClass::Browser, b"browser".as_slice(), "provider:b", 12),
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
            return Err(CheckpointError::CaptureFailed("injected restore failure".to_owned()));
        }
        Ok(RestoredComponent {
            output_refs: vec![format!("restored:{}", request.checkpoint_component_ref)],
            evidence_refs: vec![format!("restore-evidence:{}", request.checkpoint_component_ref)],
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
        executor_ref: "executor:restore".to_owned(),
    }
}

fn create_verified(
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
        .expect("create");
    let verification = engine
        .verify_checkpoint(
            &bundle.bundle_id,
            &request().requested_classes,
            &[COMPAT.to_owned()],
            &backend,
        )
        .expect("verify");
    assert_eq!(verification.state, VerificationState::Verified);
    (engine, backend, bundle)
}

fn passing_postconditions() -> Vec<Postcondition> {
    vec![
        Postcondition {
            key: "workspace.identity".to_owned(),
            passed: true,
            evidence_refs: vec!["evidence:workspace".to_owned()],
        },
        Postcondition {
            key: "provider.generation".to_owned(),
            passed: true,
            evidence_refs: vec!["evidence:generation".to_owned()],
        },
    ]
}

#[test]
fn checkpoint_existence_never_authorizes_restore() {
    let mut engine = CheckpointEngine::default();
    let mut backend = MemoryBackend::fixture();
    let bundle = engine
        .create_checkpoint(
            request(),
            snapshot(false),
            "activity:checkpoint",
            "attempt:checkpoint",
            vec!["receipt:capture".to_owned()],
            &mut backend,
        )
        .expect("create");
    assert!(matches!(
        engine.restore(&bundle.bundle_id, "attempt:restore", target(), &mut backend),
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
    let mut engine = CheckpointEngine::default();
    let mut backend = MemoryBackend::fixture();
    let bundle = engine
        .create_checkpoint(
            request(),
            snapshot(false),
            "activity:checkpoint",
            "attempt:checkpoint",
            vec!["receipt:capture".to_owned()],
            &mut backend,
        )
        .expect("create");

    backend.readback = ReadbackMode::Fail;
    let failed = engine
        .verify_checkpoint(
            &bundle.bundle_id,
            &request().requested_classes,
            &[COMPAT.to_owned()],
            &backend,
        )
        .expect("failed verification record");
    assert_eq!(failed.state, VerificationState::Failed);
    assert!(!engine.is_verified(&bundle.bundle_id));

    backend.readback = ReadbackMode::Error;
    let inconclusive = engine
        .verify_checkpoint(
            &bundle.bundle_id,
            &request().requested_classes,
            &[COMPAT.to_owned()],
            &backend,
        )
        .expect("inconclusive verification record");
    assert_eq!(inconclusive.state, VerificationState::Inconclusive);
    assert!(inconclusive
        .limitations
        .iter()
        .any(|item| item.starts_with("readback_error:")));
}

#[test]
fn compatibility_is_bound_at_verification_and_rechecked_before_restore() {
    let mut engine = CheckpointEngine::default();
    let mut backend = MemoryBackend::fixture();
    let bundle = engine
        .create_checkpoint(
            request(),
            snapshot(false),
            "activity:checkpoint",
            "attempt:checkpoint",
            vec!["receipt:capture".to_owned()],
            &mut backend,
        )
        .expect("create");
    let incompatible = engine
        .verify_checkpoint(
            &bundle.bundle_id,
            &request().requested_classes,
            &[],
            &backend,
        )
        .expect("verification");
    assert_eq!(incompatible.state, VerificationState::Failed);

    let compatible = engine
        .verify_checkpoint(
            &bundle.bundle_id,
            &request().requested_classes,
            &[COMPAT.to_owned()],
            &backend,
        )
        .expect("verification");
    assert_eq!(compatible.state, VerificationState::Verified);
    let mut changed_target = target();
    changed_target.compatibility_refs.clear();
    assert!(matches!(
        engine.restore(
            &bundle.bundle_id,
            "attempt:restore",
            changed_target,
            &mut backend,
        ),
        Err(CheckpointError::CompatibilityUnsatisfied(_))
    ));
    assert_eq!(backend.restore_calls, 0);
}

#[test]
fn provider_and_materialization_generations_must_advance_before_side_effects() {
    let (mut engine, mut backend, bundle) = create_verified(false);
    let mut stale_materialization = target();
    stale_materialization.target_materialization_generation = 9;
    assert!(matches!(
        engine.restore(
            &bundle.bundle_id,
            "attempt:materialization-stale",
            stale_materialization,
            &mut backend,
        ),
        Err(CheckpointError::StaleMaterializationGeneration)
    ));

    let mut stale_provider = target();
    stale_provider.provider_targets[1].target_provider_generation = 12;
    assert!(matches!(
        engine.restore(
            &bundle.bundle_id,
            "attempt:provider-stale",
            stale_provider,
            &mut backend,
        ),
        Err(CheckpointError::StaleProviderGeneration(_))
    ));
    assert_eq!(backend.restore_calls, 0);
}

#[test]
fn missing_provider_target_and_restart_evidence_fail_before_side_effects() {
    let (mut engine, mut backend, bundle) = create_verified(false);
    let mut missing_provider = target();
    missing_provider.provider_targets.pop();
    assert!(matches!(
        engine.restore(
            &bundle.bundle_id,
            "attempt:no-provider",
            missing_provider,
            &mut backend,
        ),
        Err(CheckpointError::MissingProviderTarget(_))
    ));

    let mut no_restart = target();
    no_restart.restart_evidence_refs.clear();
    assert!(matches!(
        engine.restore(
            &bundle.bundle_id,
            "attempt:no-restart",
            no_restart,
            &mut backend,
        ),
        Err(CheckpointError::MissingRestartEvidence)
    ));
    assert_eq!(backend.restore_calls, 0);
}

#[test]
fn successful_restore_reconciles_state_and_retains_evidence() {
    let (mut engine, mut backend, bundle) = create_verified(false);
    let restore = engine
        .restore(
            &bundle.bundle_id,
            "attempt:restore:1",
            target(),
            &mut backend,
        )
        .expect("restore");
    assert_eq!(restore.activities[0].state, ReconciliationState::Recovered);
    assert_eq!(restore.attachments[0].state, ReconciliationState::Detached);
    assert_eq!(restore.leases[0].state, ReconciliationState::Fenced);
    assert_eq!(restore.partial_artifacts[0].state, ReconciliationState::Partial);
    assert_eq!(restore.result_handles[0].state, ReconciliationState::Retained);
    assert_eq!(restore.schedules[0].state, ReconciliationState::Retained);
    assert_eq!(restore.conflict_receipts[0].state, ReconciliationState::Conflict);
    assert!(restore.activities[0].evidence_refs.len() >= 2);
    assert_eq!(restore.restored_output_refs.len(), 4);
}

#[test]
fn uncertain_external_effect_cannot_be_omitted_from_recovery_verification() {
    let (mut engine, mut backend, bundle) = create_verified(true);
    let restore = engine
        .restore(
            &bundle.bundle_id,
            "attempt:restore:1",
            target(),
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
    let (mut engine, mut backend, bundle) = create_verified(false);
    let restore = engine
        .restore(
            &bundle.bundle_id,
            "attempt:restore:1",
            target(),
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
fn partial_restore_failure_retains_prior_outputs_and_uncertain_effects() {
    let (mut engine, mut backend, bundle) = create_verified(true);
    backend.fail_restore_call = Some(2);
    let error = engine
        .restore(
            &bundle.bundle_id,
            "attempt:partial",
            target(),
            &mut backend,
        )
        .expect_err("second component must fail");
    let CheckpointError::RestoreFailed(failure) = error else {
        panic!("expected partial restore failure evidence");
    };
    assert_eq!(failure.restored_output_refs.len(), 1);
    assert!(!failure.evidence_refs.is_empty());
    assert!(failure
        .uncertain_external_effect_refs
        .iter()
        .any(|item| item == "operation:external-unknown"));
    assert!(failure
        .uncertain_external_effect_refs
        .iter()
        .any(|item| item == &failure.failed_component_ref));
}

#[test]
fn restore_observation_mismatch_is_retained_as_partial_failure() {
    let (mut engine, mut backend, bundle) = create_verified(false);
    backend.mismatch_generation = true;
    let error = engine
        .restore(
            &bundle.bundle_id,
            "attempt:mismatch",
            target(),
            &mut backend,
        )
        .expect_err("mismatched backend evidence must fail");
    let CheckpointError::RestoreFailed(failure) = error else {
        panic!("expected retained failure");
    };
    assert!(failure.message.contains("provider generation"));
}

#[test]
fn durable_restart_revokes_verification_but_preserves_attempt_fencing() {
    let (engine, backend, bundle) = create_verified(false);
    let bytes = engine.export_state().expect("export");
    let mut restarted = CheckpointEngine::import_state(&bytes).expect("import");
    assert!(!restarted.is_verified(&bundle.bundle_id));
    assert!(matches!(
        restarted.restore(
            &bundle.bundle_id,
            "attempt:restart",
            target(),
            &mut MemoryBackend::fixture(),
        ),
        Err(CheckpointError::UnverifiedBundle)
    ));
    restarted
        .verify_checkpoint(
            &bundle.bundle_id,
            &request().requested_classes,
            &[COMPAT.to_owned()],
            &backend,
        )
        .expect("reverify");
    let mut restore_backend = MemoryBackend::fixture();
    restarted
        .restore(
            &bundle.bundle_id,
            "attempt:restart",
            target(),
            &mut restore_backend,
        )
        .expect("restore");
    let bytes_after_restore = restarted.export_state().expect("export after restore");
    let mut restarted_again = CheckpointEngine::import_state(&bytes_after_restore).expect("reimport");
    restarted_again
        .verify_checkpoint(
            &bundle.bundle_id,
            &request().requested_classes,
            &[COMPAT.to_owned()],
            &backend,
        )
        .expect("reverify again");
    assert!(matches!(
        restarted_again.restore(
            &bundle.bundle_id,
            "attempt:restart",
            target(),
            &mut MemoryBackend::fixture(),
        ),
        Err(CheckpointError::ReusedAttempt)
    ));
}

#[test]
fn corrupted_durable_state_cannot_be_imported() {
    let (engine, _backend, _bundle) = create_verified(false);
    let mut bytes = engine.export_state().expect("export");
    let needle = b"workspace:1";
    let replacement = b"workspace:X";
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("workspace marker");
    bytes[offset..offset + replacement.len()].copy_from_slice(replacement);
    assert!(matches!(
        CheckpointEngine::import_state(&bytes),
        Err(CheckpointError::ManifestMismatch)
    ));
}
