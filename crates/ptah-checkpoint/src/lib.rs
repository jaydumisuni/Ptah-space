#![forbid(unsafe_code)]
//! A13 checkpoint, restart and verified-recovery substrate.
//!
//! Recovery is deliberately evidence-gated: a checkpoint bundle is not a successful
//! restore, provider acknowledgements are not recovery proof, stale generations are
//! fenced, and unresolved external effects remain visible.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use uuid::Uuid;

/// Runtime package implemented by A13. This is capability presence, not an authorization grant.
pub const PTAH_CHECKPOINT_RUNTIME_IMPLEMENTED: bool = true;

/// Checkpoint component classes used by the Online Alpha slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointClass {
    Workspace,
    Process,
    Terminal,
    Browser,
    Activity,
    Attachment,
    Lease,
    PartialArtifact,
    ResultHandle,
    Schedule,
    ConflictReceipt,
}

/// Declared consistency of captured state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Consistency {
    Consistent,
    CrashConsistent,
    Partial,
    Unknown,
}

/// Verification result; existence alone never implies success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Verified,
    Failed,
    Partial,
    Inconclusive,
}

/// Independent recovery-verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOutcome {
    Recovered,
    Failed,
    Partial,
    Inconclusive,
}

/// Recovery treatment of one durable item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationState {
    Recovered,
    Retained,
    Fenced,
    Detached,
    Partial,
    Conflict,
    Unknown,
}

/// Scheduling semantics preserved across restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleKind {
    Exact,
    Flexible,
    ConditionWatch,
}

/// Caller request for one checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointRequest {
    pub request_id: String,
    pub workspace_ref: String,
    pub workspace_revision_ref: String,
    pub workspace_materialization_ref: String,
    pub materialization_generation: u64,
    pub requested_classes: Vec<CheckpointClass>,
    pub requested_consistency: Consistency,
    pub privacy_policy_ref: String,
    pub credential_policy_ref: String,
    pub destination_or_retention_refs: Vec<String>,
    pub requested_proof_refs: Vec<String>,
}

/// Provider capture request for one component class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRequest {
    pub checkpoint_request_ref: String,
    pub workspace_ref: String,
    pub class: CheckpointClass,
}

/// Bytes plus exact producer evidence returned by a checkpoint backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedComponent {
    pub subject_refs: Vec<String>,
    pub bytes: Vec<u8>,
    pub provider_revision_ref: String,
    pub provider_instance_ref: String,
    pub provider_generation: u64,
    pub connection_epoch: u64,
    pub consistency: Consistency,
    pub compatibility_requirement_refs: Vec<String>,
    pub limitations: Vec<String>,
}

/// Immutable component record included in a checkpoint bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointComponent {
    pub component_id: String,
    pub class: CheckpointClass,
    pub source_subject_refs: Vec<String>,
    pub source_materialization_generation: u64,
    pub producer_provider_revision_ref: String,
    pub producer_provider_instance_ref: String,
    pub provider_generation: u64,
    pub connection_epoch: u64,
    pub content_sha256: String,
    pub byte_len: usize,
    pub consistency: Consistency,
    pub compatibility_requirement_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub limitations: Vec<String>,
}

/// Stable result handle retained through restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StableResultHandle {
    pub handle_ref: String,
    pub state: String,
    pub artifact_refs: Vec<String>,
}

/// Schedule input retained through restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableSchedule {
    pub schedule_ref: String,
    pub kind: ScheduleKind,
    pub expression: String,
}

/// Runtime state that A13 must reconcile rather than silently discard.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverySnapshot {
    pub activity_refs: Vec<String>,
    pub attachment_refs: Vec<String>,
    pub lease_refs: Vec<String>,
    pub partial_artifact_refs: Vec<String>,
    pub result_handles: Vec<StableResultHandle>,
    pub schedules: Vec<DurableSchedule>,
    pub conflict_receipt_refs: Vec<String>,
    pub uncertain_external_effect_refs: Vec<String>,
}

/// Immutable manifest whose digest binds a checkpoint bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    pub checkpoint_request_ref: String,
    pub workspace_ref: String,
    pub workspace_revision_ref: String,
    pub source_materialization_generation: u64,
    pub components: Vec<CheckpointComponent>,
    pub snapshot: RecoverySnapshot,
}

/// A created bundle. It is not recoverable until independent verification passes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointBundle {
    pub bundle_id: String,
    pub manifest: BundleManifest,
    pub manifest_sha256: String,
    pub created_activity_ref: String,
    pub created_attempt_ref: String,
    pub receipt_refs: Vec<String>,
}

/// Per-component integrity and readback result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentVerification {
    pub component_ref: String,
    pub integrity_verified: bool,
    pub readback_verified: bool,
    pub evidence_refs: Vec<String>,
}

/// Independent checkpoint verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointVerification {
    pub verification_id: String,
    pub checkpoint_bundle_ref: String,
    pub state: VerificationState,
    pub manifest_valid: bool,
    pub required_components_present: bool,
    pub component_results: Vec<ComponentVerification>,
    pub evidence_refs: Vec<String>,
    pub limitations: Vec<String>,
}

/// Restore request passed to a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentRestoreRequest {
    pub checkpoint_component_ref: String,
    pub bytes: Vec<u8>,
    pub target_provider_generation: u64,
    pub target_materialization_generation: u64,
}

/// Provider restore result. This is still not independent recovery proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredComponent {
    pub output_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub limitations: Vec<String>,
}

/// Reconciliation record for retained runtime state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reconciliation {
    pub subject_ref: String,
    pub state: ReconciliationState,
    pub evidence_refs: Vec<String>,
}

/// Restore run created after a verified checkpoint and generation transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreRun {
    pub restore_run_id: String,
    pub checkpoint_bundle_ref: String,
    pub attempt_ref: String,
    pub target_provider_generation: u64,
    pub target_materialization_generation: u64,
    pub restored_component_refs: Vec<String>,
    pub activities: Vec<Reconciliation>,
    pub attachments: Vec<Reconciliation>,
    pub leases: Vec<Reconciliation>,
    pub partial_artifacts: Vec<Reconciliation>,
    pub result_handles: Vec<Reconciliation>,
    pub schedules: Vec<Reconciliation>,
    pub conflict_receipts: Vec<Reconciliation>,
    pub uncertain_external_effects: Vec<Reconciliation>,
    pub evidence_refs: Vec<String>,
    pub limitations: Vec<String>,
}

/// One independently checked postcondition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Postcondition {
    pub key: String,
    pub passed: bool,
    pub evidence_refs: Vec<String>,
}

/// Final recovery verification record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryVerification {
    pub verification_id: String,
    pub restore_run_ref: String,
    pub target_materialization_generation: u64,
    pub outcome: RecoveryOutcome,
    pub postconditions: Vec<Postcondition>,
    pub unresolved_operation_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub limitations: Vec<String>,
}

/// Backend boundary. Provider acknowledgement never substitutes for readback or recovery verification.
pub trait CheckpointBackend {
    fn capture(&mut self, request: &CaptureRequest) -> Result<CapturedComponent, CheckpointError>;
    fn verify_readback(&self, component_ref: &str, expected_sha256: &str)
        -> Result<bool, CheckpointError>;
    fn restore(&mut self, request: &ComponentRestoreRequest)
        -> Result<RestoredComponent, CheckpointError>;
}

/// A13 failures are fail-closed and evidence-preserving.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    #[error("checkpoint request has no component classes")]
    EmptyScope,
    #[error("checkpoint component capture failed: {0}")]
    CaptureFailed(String),
    #[error("checkpoint bundle not found")]
    BundleNotFound,
    #[error("checkpoint bundle has not been independently verified")]
    UnverifiedBundle,
    #[error("checkpoint manifest digest mismatch")]
    ManifestMismatch,
    #[error("required checkpoint component is missing")]
    MissingComponent,
    #[error("component integrity/readback verification failed")]
    VerificationFailed,
    #[error("target provider generation must advance")]
    StaleProviderGeneration,
    #[error("target materialization generation must advance")]
    StaleMaterializationGeneration,
    #[error("restore attempt identity was already used")]
    ReusedAttempt,
    #[error("restore backend failed: {0}")]
    RestoreFailed(String),
}

/// In-memory orchestration core. Durable callers persist returned records in the Ptah ledger/object store.
#[derive(Default)]
pub struct CheckpointEngine {
    bundles: HashMap<String, StoredBundle>,
    verified_bundles: HashSet<String>,
    used_attempts: HashSet<String>,
}

#[derive(Clone)]
struct StoredBundle {
    bundle: CheckpointBundle,
    bytes_by_component: HashMap<String, Vec<u8>>,
}

impl CheckpointEngine {
    /// Create a checkpoint. This captures exact bytes and producer evidence but does not mark recovery proven.
    pub fn create_checkpoint<B: CheckpointBackend>(
        &mut self,
        request: CheckpointRequest,
        snapshot: RecoverySnapshot,
        activity_ref: impl Into<String>,
        attempt_ref: impl Into<String>,
        receipt_refs: Vec<String>,
        backend: &mut B,
    ) -> Result<CheckpointBundle, CheckpointError> {
        if request.requested_classes.is_empty() {
            return Err(CheckpointError::EmptyScope);
        }
        let mut components = Vec::with_capacity(request.requested_classes.len());
        let mut bytes_by_component = HashMap::new();
        for class in &request.requested_classes {
            let captured = backend
                .capture(&CaptureRequest {
                    checkpoint_request_ref: request.request_id.clone(),
                    workspace_ref: request.workspace_ref.clone(),
                    class: *class,
                })
                .map_err(|error| CheckpointError::CaptureFailed(error.to_string()))?;
            let component_id = new_id();
            let digest = sha256_hex(&captured.bytes);
            bytes_by_component.insert(component_id.clone(), captured.bytes);
            components.push(CheckpointComponent {
                component_id,
                class: *class,
                source_subject_refs: captured.subject_refs,
                source_materialization_generation: request.materialization_generation,
                producer_provider_revision_ref: captured.provider_revision_ref,
                producer_provider_instance_ref: captured.provider_instance_ref,
                provider_generation: captured.provider_generation,
                connection_epoch: captured.connection_epoch,
                content_sha256: digest,
                byte_len: bytes_by_component.values().last().map_or(0, Vec::len),
                consistency: captured.consistency,
                compatibility_requirement_refs: captured.compatibility_requirement_refs,
                evidence_refs: receipt_refs.clone(),
                limitations: captured.limitations,
            });
        }
        // Repair byte_len deterministically by looking up each component after insertion.
        for component in &mut components {
            component.byte_len = bytes_by_component[&component.component_id].len();
        }
        let manifest = BundleManifest {
            checkpoint_request_ref: request.request_id,
            workspace_ref: request.workspace_ref,
            workspace_revision_ref: request.workspace_revision_ref,
            source_materialization_generation: request.materialization_generation,
            components,
            snapshot,
        };
        let manifest_sha256 = sha256_json(&manifest)?;
        let bundle = CheckpointBundle {
            bundle_id: new_id(),
            manifest,
            manifest_sha256,
            created_activity_ref: activity_ref.into(),
            created_attempt_ref: attempt_ref.into(),
            receipt_refs,
        };
        self.bundles.insert(
            bundle.bundle_id.clone(),
            StoredBundle { bundle: bundle.clone(), bytes_by_component },
        );
        Ok(bundle)
    }

    /// Independently verify manifest integrity, required scope, retained bytes and backend readback.
    pub fn verify_checkpoint<B: CheckpointBackend>(
        &mut self,
        bundle_id: &str,
        required_classes: &[CheckpointClass],
        backend: &B,
    ) -> Result<CheckpointVerification, CheckpointError> {
        let stored = self.bundles.get(bundle_id).ok_or(CheckpointError::BundleNotFound)?;
        let manifest_valid = sha256_json(&stored.bundle.manifest)? == stored.bundle.manifest_sha256;
        let present: HashSet<_> = stored.bundle.manifest.components.iter().map(|c| c.class).collect();
        let required_components_present = required_classes.iter().all(|class| present.contains(class));
        let mut component_results = Vec::new();
        let mut all_verified = manifest_valid && required_components_present;
        for component in &stored.bundle.manifest.components {
            let retained = stored.bytes_by_component.get(&component.component_id);
            let integrity_verified = retained.is_some_and(|bytes| {
                bytes.len() == component.byte_len && sha256_hex(bytes) == component.content_sha256
            });
            let readback_verified = backend
                .verify_readback(&component.component_id, &component.content_sha256)
                .unwrap_or(false);
            all_verified &= integrity_verified && readback_verified;
            component_results.push(ComponentVerification {
                component_ref: component.component_id.clone(),
                integrity_verified,
                readback_verified,
                evidence_refs: component.evidence_refs.clone(),
            });
        }
        let state = if all_verified {
            self.verified_bundles.insert(bundle_id.to_owned());
            VerificationState::Verified
        } else if !manifest_valid || !required_components_present {
            VerificationState::Failed
        } else {
            VerificationState::Inconclusive
        };
        Ok(CheckpointVerification {
            verification_id: new_id(),
            checkpoint_bundle_ref: bundle_id.to_owned(),
            state,
            manifest_valid,
            required_components_present,
            component_results,
            evidence_refs: stored.bundle.receipt_refs.clone(),
            limitations: Vec::new(),
        })
    }

    /// Restore only a verified bundle into strictly newer generations.
    pub fn restore<B: CheckpointBackend>(
        &mut self,
        bundle_id: &str,
        attempt_ref: impl Into<String>,
        target_provider_generation: u64,
        target_materialization_generation: u64,
        backend: &mut B,
    ) -> Result<RestoreRun, CheckpointError> {
        if !self.verified_bundles.contains(bundle_id) {
            return Err(CheckpointError::UnverifiedBundle);
        }
        let stored = self.bundles.get(bundle_id).ok_or(CheckpointError::BundleNotFound)?.clone();
        if sha256_json(&stored.bundle.manifest)? != stored.bundle.manifest_sha256 {
            return Err(CheckpointError::ManifestMismatch);
        }
        let max_provider_generation = stored.bundle.manifest.components.iter().map(|c| c.provider_generation).max().unwrap_or(0);
        if target_provider_generation <= max_provider_generation {
            return Err(CheckpointError::StaleProviderGeneration);
        }
        if target_materialization_generation <= stored.bundle.manifest.source_materialization_generation {
            return Err(CheckpointError::StaleMaterializationGeneration);
        }
        let attempt_ref = attempt_ref.into();
        if !self.used_attempts.insert(attempt_ref.clone()) {
            return Err(CheckpointError::ReusedAttempt);
        }
        let mut restored_component_refs = Vec::new();
        let mut evidence_refs = Vec::new();
        let mut limitations = Vec::new();
        for component in &stored.bundle.manifest.components {
            let bytes = stored.bytes_by_component.get(&component.component_id).ok_or(CheckpointError::VerificationFailed)?;
            if sha256_hex(bytes) != component.content_sha256 {
                return Err(CheckpointError::VerificationFailed);
            }
            let restored = backend
                .restore(&ComponentRestoreRequest {
                    checkpoint_component_ref: component.component_id.clone(),
                    bytes: bytes.clone(),
                    target_provider_generation,
                    target_materialization_generation,
                })
                .map_err(|error| CheckpointError::RestoreFailed(error.to_string()))?;
            restored_component_refs.push(component.component_id.clone());
            evidence_refs.extend(restored.evidence_refs);
            limitations.extend(restored.limitations);
        }
        let snap = &stored.bundle.manifest.snapshot;
        Ok(RestoreRun {
            restore_run_id: new_id(),
            checkpoint_bundle_ref: bundle_id.to_owned(),
            attempt_ref,
            target_provider_generation,
            target_materialization_generation,
            restored_component_refs,
            activities: reconcile(&snap.activity_refs, ReconciliationState::Recovered),
            attachments: reconcile(&snap.attachment_refs, ReconciliationState::Detached),
            // A restart invalidates old control authority. Callers must issue fresh leases/fences.
            leases: reconcile(&snap.lease_refs, ReconciliationState::Fenced),
            partial_artifacts: reconcile(&snap.partial_artifact_refs, ReconciliationState::Partial),
            result_handles: reconcile(&snap.result_handles.iter().map(|h| h.handle_ref.clone()).collect::<Vec<_>>(), ReconciliationState::Retained),
            schedules: reconcile(&snap.schedules.iter().map(|s| s.schedule_ref.clone()).collect::<Vec<_>>(), ReconciliationState::Retained),
            conflict_receipts: reconcile(&snap.conflict_receipt_refs, ReconciliationState::Conflict),
            uncertain_external_effects: reconcile(&snap.uncertain_external_effect_refs, ReconciliationState::Unknown),
            evidence_refs,
            limitations,
        })
    }

    /// Produce independent recovery proof from explicit postconditions and unresolved effects.
    #[must_use]
    pub fn verify_recovery(
        &self,
        restore: &RestoreRun,
        postconditions: Vec<Postcondition>,
        unresolved_operation_refs: Vec<String>,
        evidence_refs: Vec<String>,
    ) -> RecoveryVerification {
        let missing_evidence = evidence_refs.is_empty()
            || postconditions.is_empty()
            || postconditions.iter().any(|p| p.evidence_refs.is_empty());
        let failed_postcondition = postconditions.iter().any(|p| !p.passed);
        let outcome = if failed_postcondition {
            RecoveryOutcome::Failed
        } else if missing_evidence {
            RecoveryOutcome::Inconclusive
        } else if !unresolved_operation_refs.is_empty() {
            RecoveryOutcome::Partial
        } else {
            RecoveryOutcome::Recovered
        };
        RecoveryVerification {
            verification_id: new_id(),
            restore_run_ref: restore.restore_run_id.clone(),
            target_materialization_generation: restore.target_materialization_generation,
            outcome,
            postconditions,
            unresolved_operation_refs,
            evidence_refs,
            limitations: restore.limitations.clone(),
        }
    }
}

fn reconcile(refs: &[String], state: ReconciliationState) -> Vec<Reconciliation> {
    refs.iter().map(|subject_ref| Reconciliation {
        subject_ref: subject_ref.clone(),
        state,
        evidence_refs: Vec::new(),
    }).collect()
}

fn new_id() -> String {
    Uuid::now_v7().to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_json<T: Serialize>(value: &T) -> Result<String, CheckpointError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| CheckpointError::CaptureFailed(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryBackend {
        captured: HashMap<CheckpointClass, Vec<u8>>,
        readback_ok: bool,
        restored: Vec<String>,
        fail_restore: bool,
    }

    impl CheckpointBackend for MemoryBackend {
        fn capture(&mut self, request: &CaptureRequest) -> Result<CapturedComponent, CheckpointError> {
            let bytes = self.captured.get(&request.class).cloned().ok_or_else(|| CheckpointError::CaptureFailed("missing fixture".into()))?;
            Ok(CapturedComponent {
                subject_refs: vec![format!("subject:{:?}", request.class)],
                bytes,
                provider_revision_ref: "provider-revision:1".into(),
                provider_instance_ref: "provider-instance:1".into(),
                provider_generation: 7,
                connection_epoch: 3,
                consistency: Consistency::CrashConsistent,
                compatibility_requirement_refs: vec!["compat:alpha".into()],
                limitations: Vec::new(),
            })
        }

        fn verify_readback(&self, _: &str, _: &str) -> Result<bool, CheckpointError> {
            Ok(self.readback_ok)
        }

        fn restore(&mut self, request: &ComponentRestoreRequest) -> Result<RestoredComponent, CheckpointError> {
            if self.fail_restore { return Err(CheckpointError::RestoreFailed("injected".into())); }
            self.restored.push(request.checkpoint_component_ref.clone());
            Ok(RestoredComponent {
                output_refs: vec![format!("restored:{}", request.checkpoint_component_ref)],
                evidence_refs: vec![format!("evidence:{}", request.checkpoint_component_ref)],
                limitations: Vec::new(),
            })
        }
    }

    fn fixture() -> (CheckpointEngine, MemoryBackend, CheckpointRequest, RecoverySnapshot) {
        let mut backend = MemoryBackend::default();
        backend.readback_ok = true;
        backend.captured.insert(CheckpointClass::Workspace, b"workspace-state".to_vec());
        backend.captured.insert(CheckpointClass::Process, b"process-state".to_vec());
        backend.captured.insert(CheckpointClass::Terminal, b"terminal-state".to_vec());
        backend.captured.insert(CheckpointClass::Browser, b"browser-state".to_vec());
        let request = CheckpointRequest {
            request_id: "checkpoint-request:1".into(),
            workspace_ref: "workspace:1".into(),
            workspace_revision_ref: "workspace-revision:4".into(),
            workspace_materialization_ref: "materialization:1".into(),
            materialization_generation: 9,
            requested_classes: vec![CheckpointClass::Workspace, CheckpointClass::Process, CheckpointClass::Terminal, CheckpointClass::Browser],
            requested_consistency: Consistency::CrashConsistent,
            privacy_policy_ref: "policy:privacy".into(),
            credential_policy_ref: "policy:credential".into(),
            destination_or_retention_refs: vec!["retention:alpha".into()],
            requested_proof_refs: vec!["proof:a13".into()],
        };
        let snapshot = RecoverySnapshot {
            activity_refs: vec!["activity:running".into()],
            attachment_refs: vec!["terminal-attachment:old".into()],
            lease_refs: vec!["control-lease:old".into()],
            partial_artifact_refs: vec!["artifact:partial".into()],
            result_handles: vec![StableResultHandle { handle_ref: "result:stable".into(), state: "partial".into(), artifact_refs: vec!["artifact:partial".into()] }],
            schedules: vec![DurableSchedule { schedule_ref: "schedule:exact".into(), kind: ScheduleKind::Exact, expression: "2026-08-22T01:00:00+02:00".into() }],
            conflict_receipt_refs: vec!["receipt:moved-target-conflict".into()],
            uncertain_external_effect_refs: vec!["operation:external-unknown".into()],
        };
        (CheckpointEngine::default(), backend, request, snapshot)
    }

    #[test]
    fn checkpoint_existence_does_not_authorize_restore() {
        let (mut engine, mut backend, request, snapshot) = fixture();
        let bundle = engine.create_checkpoint(request, snapshot, "activity:checkpoint", "attempt:checkpoint", vec!["receipt:capture".into()], &mut backend).unwrap();
        assert_eq!(engine.restore(&bundle.bundle_id, "attempt:restore", 8, 10, &mut backend), Err(CheckpointError::UnverifiedBundle));
    }

    #[test]
    fn verified_recovery_advances_generation_and_reconciles_durable_state() {
        let (mut engine, mut backend, request, snapshot) = fixture();
        let bundle = engine.create_checkpoint(request, snapshot, "activity:checkpoint", "attempt:checkpoint", vec!["receipt:capture".into()], &mut backend).unwrap();
        let verification = engine.verify_checkpoint(&bundle.bundle_id, &[CheckpointClass::Workspace, CheckpointClass::Process, CheckpointClass::Terminal, CheckpointClass::Browser], &backend).unwrap();
        assert_eq!(verification.state, VerificationState::Verified);
        let restore = engine.restore(&bundle.bundle_id, "attempt:restore:1", 8, 10, &mut backend).unwrap();
        assert_eq!(restore.leases[0].state, ReconciliationState::Fenced);
        assert_eq!(restore.attachments[0].state, ReconciliationState::Detached);
        assert_eq!(restore.activities[0].state, ReconciliationState::Recovered);
        assert_eq!(restore.partial_artifacts[0].state, ReconciliationState::Partial);
        assert_eq!(restore.result_handles[0].state, ReconciliationState::Retained);
        assert_eq!(restore.schedules[0].state, ReconciliationState::Retained);
        assert_eq!(restore.conflict_receipts[0].state, ReconciliationState::Conflict);
        assert_eq!(restore.uncertain_external_effects[0].state, ReconciliationState::Unknown);
        let proof = engine.verify_recovery(&restore, vec![Postcondition { key: "workspace.identity".into(), passed: true, evidence_refs: vec!["evidence:workspace".into()] }, Postcondition { key: "provider.generation".into(), passed: true, evidence_refs: vec!["evidence:generation".into()] }], vec![], vec!["evidence:independent-review".into()]);
        assert_eq!(proof.outcome, RecoveryOutcome::Recovered);
    }

    #[test]
    fn stale_generations_and_reused_attempts_fail_closed() {
        let (mut engine, mut backend, request, snapshot) = fixture();
        let bundle = engine.create_checkpoint(request, snapshot, "activity:checkpoint", "attempt:checkpoint", vec!["receipt:capture".into()], &mut backend).unwrap();
        engine.verify_checkpoint(&bundle.bundle_id, &[], &backend).unwrap();
        assert_eq!(engine.restore(&bundle.bundle_id, "attempt:old-provider", 7, 10, &mut backend), Err(CheckpointError::StaleProviderGeneration));
        assert_eq!(engine.restore(&bundle.bundle_id, "attempt:old-materialization", 8, 9, &mut backend), Err(CheckpointError::StaleMaterializationGeneration));
        engine.restore(&bundle.bundle_id, "attempt:unique", 8, 10, &mut backend).unwrap();
        assert_eq!(engine.restore(&bundle.bundle_id, "attempt:unique", 8, 10, &mut backend), Err(CheckpointError::ReusedAttempt));
    }

    #[test]
    fn missing_readback_evidence_blocks_verified_restore() {
        let (mut engine, mut backend, request, snapshot) = fixture();
        backend.readback_ok = false;
        let bundle = engine.create_checkpoint(request, snapshot, "activity:checkpoint", "attempt:checkpoint", vec!["receipt:capture".into()], &mut backend).unwrap();
        let verification = engine.verify_checkpoint(&bundle.bundle_id, &[], &backend).unwrap();
        assert_eq!(verification.state, VerificationState::Inconclusive);
        assert_eq!(engine.restore(&bundle.bundle_id, "attempt:restore", 8, 10, &mut backend), Err(CheckpointError::UnverifiedBundle));
    }

    #[test]
    fn recovery_without_independent_evidence_is_inconclusive_and_external_unknown_is_partial() {
        let (mut engine, mut backend, request, snapshot) = fixture();
        let bundle = engine.create_checkpoint(request, snapshot, "activity:checkpoint", "attempt:checkpoint", vec!["receipt:capture".into()], &mut backend).unwrap();
        engine.verify_checkpoint(&bundle.bundle_id, &[], &backend).unwrap();
        let restore = engine.restore(&bundle.bundle_id, "attempt:restore", 8, 10, &mut backend).unwrap();
        let inconclusive = engine.verify_recovery(&restore, vec![Postcondition { key: "workspace.identity".into(), passed: true, evidence_refs: vec![] }], vec![], vec![]);
        assert_eq!(inconclusive.outcome, RecoveryOutcome::Inconclusive);
        let partial = engine.verify_recovery(&restore, vec![Postcondition { key: "workspace.identity".into(), passed: true, evidence_refs: vec!["evidence:workspace".into()] }], vec!["operation:external-unknown".into()], vec!["evidence:review".into()]);
        assert_eq!(partial.outcome, RecoveryOutcome::Partial);
    }
}
