#![forbid(unsafe_code)]
//! A13 checkpoint, restart and independently verified recovery.
//!
//! Checkpoint existence is never recovery proof. Captured bytes, manifest identity,
//! compatibility, backend readback, restart evidence, Provider generations, restore
//! evidence, reconciliation, and independent postconditions remain distinct facts.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

/// A13 runtime capability is implemented. This constant is not an authorization grant.
pub const PTAH_CHECKPOINT_RUNTIME_IMPLEMENTED: bool = true;

const DURABLE_STATE_SCHEMA: &str = "ptah.checkpoint.engine.v1";

/// Component classes captured by the Online Alpha recovery slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointClass {
    /// Workspace identity and revision projection.
    Workspace,
    /// Native or container process recovery metadata.
    Process,
    /// PTY/terminal recovery metadata.
    Terminal,
    /// Browser profile/process/context/page recovery metadata.
    Browser,
    /// Durable Activity state.
    Activity,
    /// Session or terminal attachment state.
    Attachment,
    /// Lease/fence state that must be invalidated on restart.
    Lease,
    /// Partial Artifact state.
    PartialArtifact,
    /// Stable result handle state.
    ResultHandle,
    /// Durable schedule state.
    Schedule,
    /// Conflict Receipt state.
    ConflictReceipt,
}

/// Declared consistency of captured bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Consistency {
    /// Provider states the capture is application-consistent.
    Consistent,
    /// Provider states the capture is crash-consistent.
    CrashConsistent,
    /// Provider states only a bounded subset is consistent.
    Partial,
    /// Provider cannot establish consistency.
    Unknown,
}

/// Independent checkpoint-verification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    /// Manifest, bytes, compatibility and readback all passed.
    Verified,
    /// A required structural, integrity or compatibility condition failed.
    Failed,
    /// Required evidence could not be obtained conclusively.
    Inconclusive,
}

/// Independent recovery-verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOutcome {
    /// All required postconditions passed with independent evidence.
    Recovered,
    /// At least one required postcondition failed.
    Failed,
    /// Recovery succeeded only partially or unresolved external effects remain.
    Partial,
    /// Independent recovery proof is incomplete.
    Inconclusive,
}

/// Recovery treatment of one retained runtime fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationState {
    /// The subject was recovered into the new runtime generation.
    Recovered,
    /// The subject remains durable without being recreated.
    Retained,
    /// Old control authority is deliberately invalidated.
    Fenced,
    /// The old attachment is retained as history but not reattached.
    Detached,
    /// A partial result remains partial after restart.
    Partial,
    /// A pre-existing conflict remains explicit.
    Conflict,
    /// Outcome is not yet known and must not be collapsed to success.
    Unknown,
}

/// Scheduling semantics preserved across restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleKind {
    /// Exact-clock schedule.
    Exact,
    /// Flexible daypart/window schedule.
    Flexible,
    /// Recurring condition watch.
    ConditionWatch,
}

/// Caller request for one checkpoint operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointRequest {
    /// Canonical request reference supplied by the caller.
    pub request_ref: String,
    /// Canonical Workspace reference.
    pub workspace_ref: String,
    /// Exact Workspace Revision reference.
    pub workspace_revision_ref: String,
    /// Exact current Workspace materialization reference.
    pub workspace_materialization_ref: String,
    /// Current materialization generation.
    pub materialization_generation: u64,
    /// Component classes that must be captured exactly once.
    pub requested_classes: Vec<CheckpointClass>,
    /// Minimum acceptable consistency.
    pub requested_consistency: Consistency,
    /// Exact privacy Policy reference applied to capture.
    pub privacy_policy_ref: String,
    /// Exact credential Policy reference applied to capture.
    pub credential_policy_ref: String,
    /// Destination or retention authority references.
    pub destination_or_retention_refs: Vec<String>,
    /// Proof requirements attached by the caller.
    pub requested_proof_refs: Vec<String>,
}

/// Provider capture request for one component class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRequest {
    /// Parent checkpoint request reference.
    pub checkpoint_request_ref: String,
    /// Canonical Workspace reference.
    pub workspace_ref: String,
    /// Requested component class.
    pub class: CheckpointClass,
    /// Minimum consistency required by the caller.
    pub requested_consistency: Consistency,
}

/// Captured bytes and exact producer evidence returned by a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedComponent {
    /// Canonical subjects represented by the bytes.
    pub subject_refs: Vec<String>,
    /// Captured component bytes.
    pub bytes: Vec<u8>,
    /// Exact producer Provider Revision reference.
    pub provider_revision_ref: String,
    /// Exact producer Provider Instance reference.
    pub provider_instance_ref: String,
    /// Exact producer Provider Generation.
    pub provider_generation: u64,
    /// Exact producer connection epoch.
    pub connection_epoch: u64,
    /// Consistency actually obtained.
    pub consistency: Consistency,
    /// Requirements a recovery target must satisfy.
    pub compatibility_requirement_refs: Vec<String>,
    /// Evidence supporting this capture.
    pub evidence_refs: Vec<String>,
    /// Explicit capture limitations.
    pub limitations: Vec<String>,
}

/// Immutable component record bound into a checkpoint manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointComponent {
    /// Stable component identifier within the bundle.
    pub component_id: String,
    /// Component class.
    pub class: CheckpointClass,
    /// Canonical source subjects.
    pub source_subject_refs: Vec<String>,
    /// Source materialization generation.
    pub source_materialization_generation: u64,
    /// Producer Provider Revision reference.
    pub producer_provider_revision_ref: String,
    /// Producer Provider Instance reference.
    pub producer_provider_instance_ref: String,
    /// Producer Provider Generation.
    pub provider_generation: u64,
    /// Producer connection epoch.
    pub connection_epoch: u64,
    /// SHA-256 of retained component bytes.
    pub content_sha256: String,
    /// Exact retained byte length.
    pub byte_len: usize,
    /// Consistency actually obtained.
    pub consistency: Consistency,
    /// Compatibility requirements retained from capture.
    pub compatibility_requirement_refs: Vec<String>,
    /// Evidence supporting the component.
    pub evidence_refs: Vec<String>,
    /// Explicit component limitations.
    pub limitations: Vec<String>,
}

/// Stable result handle retained through restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StableResultHandle {
    /// Stable result reference.
    pub handle_ref: String,
    /// Caller-visible result state at checkpoint time.
    pub state: String,
    /// Artifact references already attached to the result.
    pub artifact_refs: Vec<String>,
}

/// Schedule input retained through restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableSchedule {
    /// Stable schedule reference.
    pub schedule_ref: String,
    /// Schedule semantics.
    pub kind: ScheduleKind,
    /// Exact retained schedule expression.
    pub expression: String,
}

/// Runtime state that recovery must reconcile explicitly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverySnapshot {
    /// Durable Activities present at checkpoint time.
    pub activity_refs: Vec<String>,
    /// Attachments present at checkpoint time.
    pub attachment_refs: Vec<String>,
    /// Leases/fences present at checkpoint time.
    pub lease_refs: Vec<String>,
    /// Partial Artifacts present at checkpoint time.
    pub partial_artifact_refs: Vec<String>,
    /// Stable result handles.
    pub result_handles: Vec<StableResultHandle>,
    /// Durable schedules.
    pub schedules: Vec<DurableSchedule>,
    /// Conflict Receipt references.
    pub conflict_receipt_refs: Vec<String>,
    /// Operations whose external effect was uncertain at checkpoint time.
    pub uncertain_external_effect_refs: Vec<String>,
}

/// Immutable manifest whose digest binds one checkpoint bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Parent checkpoint request reference.
    pub checkpoint_request_ref: String,
    /// Canonical Workspace reference.
    pub workspace_ref: String,
    /// Exact Workspace Revision reference.
    pub workspace_revision_ref: String,
    /// Exact source Workspace materialization reference.
    pub workspace_materialization_ref: String,
    /// Source materialization generation.
    pub source_materialization_generation: u64,
    /// Minimum consistency requested by the caller.
    pub requested_consistency: Consistency,
    /// Privacy Policy applied to capture.
    pub privacy_policy_ref: String,
    /// Credential Policy applied to capture.
    pub credential_policy_ref: String,
    /// Destination/retention authorities.
    pub destination_or_retention_refs: Vec<String>,
    /// Caller proof requirements.
    pub requested_proof_refs: Vec<String>,
    /// Captured components.
    pub components: Vec<CheckpointComponent>,
    /// Runtime reconciliation snapshot.
    pub snapshot: RecoverySnapshot,
}

/// A created checkpoint bundle. Creation alone does not authorize restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointBundle {
    /// Stable bundle identifier.
    pub bundle_id: String,
    /// Immutable manifest.
    pub manifest: BundleManifest,
    /// SHA-256 of canonical manifest serialization.
    pub manifest_sha256: String,
    /// Activity that created the checkpoint.
    pub created_activity_ref: String,
    /// Attempt that created the checkpoint.
    pub created_attempt_ref: String,
    /// Receipt references retained from capture.
    pub receipt_refs: Vec<String>,
}

/// Independent backend readback evidence for one retained component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadbackVerification {
    /// Whether backend readback matched the expected content.
    pub verified: bool,
    /// Independent evidence supporting the readback result.
    pub evidence_refs: Vec<String>,
    /// Explicit readback limitations.
    pub limitations: Vec<String>,
}

/// Per-component checkpoint verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentVerification {
    /// Component identifier.
    pub component_ref: String,
    /// Retained bytes matched length and digest.
    pub integrity_verified: bool,
    /// Independent backend readback passed.
    pub readback_verified: bool,
    /// Recovery-target compatibility requirements were satisfied.
    pub compatibility_verified: bool,
    /// Evidence supporting the verification result.
    pub evidence_refs: Vec<String>,
    /// Explicit verification limitations.
    pub limitations: Vec<String>,
}

/// Independent checkpoint verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointVerification {
    /// Stable verification identifier.
    pub verification_id: String,
    /// Verified checkpoint bundle reference.
    pub checkpoint_bundle_ref: String,
    /// Overall verification state.
    pub state: VerificationState,
    /// Manifest hash was valid.
    pub manifest_valid: bool,
    /// Every required component class was present.
    pub required_components_present: bool,
    /// Per-component results.
    pub component_results: Vec<ComponentVerification>,
    /// Independent verification evidence.
    pub evidence_refs: Vec<String>,
    /// Explicit verification limitations.
    pub limitations: Vec<String>,
}

/// Exact recovery target for one source Provider Instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRecoveryTarget {
    /// Source Provider Instance represented in the checkpoint.
    pub source_provider_instance_ref: String,
    /// New target Provider Instance after restart/replacement.
    pub target_provider_instance_ref: String,
    /// New Provider Generation, which must strictly advance.
    pub target_provider_generation: u64,
    /// Target connection epoch.
    pub target_connection_epoch: u64,
}

/// Recovery authority and target state supplied before any restore side effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreTarget {
    /// New Workspace materialization generation.
    pub target_materialization_generation: u64,
    /// Exact per-Provider recovery targets.
    pub provider_targets: Vec<ProviderRecoveryTarget>,
    /// Compatibility capabilities available on the target runtime.
    pub compatibility_refs: Vec<String>,
    /// Evidence that the Node/runtime restart or replacement actually occurred.
    pub restart_evidence_refs: Vec<String>,
    /// Exact executor identity for independence checks.
    pub executor_ref: String,
}

/// Restore request passed to a backend for one component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentRestoreRequest {
    /// Checkpoint component being restored.
    pub checkpoint_component_ref: String,
    /// Exact retained component bytes.
    pub bytes: Vec<u8>,
    /// New target Provider Instance reference.
    pub target_provider_instance_ref: String,
    /// New target Provider Generation.
    pub target_provider_generation: u64,
    /// New target connection epoch.
    pub target_connection_epoch: u64,
    /// New Workspace materialization generation.
    pub target_materialization_generation: u64,
}

/// Backend restore result. This is not independent recovery proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredComponent {
    /// Canonical/runtime output references produced by restoration.
    pub output_refs: Vec<String>,
    /// Evidence supporting backend restoration.
    pub evidence_refs: Vec<String>,
    /// Explicit restoration limitations.
    pub limitations: Vec<String>,
    /// Provider Instance that actually performed restoration.
    pub observed_provider_instance_ref: String,
    /// Provider Generation actually observed after restoration.
    pub observed_provider_generation: u64,
    /// Connection epoch actually observed after restoration.
    pub observed_connection_epoch: u64,
    /// Workspace materialization generation actually observed.
    pub observed_materialization_generation: u64,
}

/// Reconciliation record for one durable runtime subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reconciliation {
    /// Reconciled subject reference.
    pub subject_ref: String,
    /// Recovery treatment of the subject.
    pub state: ReconciliationState,
    /// Evidence supporting the reconciliation.
    pub evidence_refs: Vec<String>,
}

/// Evidence retained when restoration fails after work may already have occurred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialRestoreFailure {
    /// Checkpoint bundle being restored.
    pub checkpoint_bundle_ref: String,
    /// Attempt used by the failed restore.
    pub attempt_ref: String,
    /// Component at which failure was observed.
    pub failed_component_ref: String,
    /// Human-readable backend or evidence failure.
    pub message: String,
    /// Output references already produced before the failure.
    pub restored_output_refs: Vec<String>,
    /// Evidence retained before/at failure.
    pub evidence_refs: Vec<String>,
    /// Explicit limitations retained before/at failure.
    pub limitations: Vec<String>,
    /// External effects that remain uncertain after failure.
    pub uncertain_external_effect_refs: Vec<String>,
    /// Target materialization generation.
    pub target_materialization_generation: u64,
}

/// Restore run created only after checkpoint verification and generation advance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreRun {
    /// Stable restore-run identifier.
    pub restore_run_id: String,
    /// Source checkpoint bundle reference.
    pub checkpoint_bundle_ref: String,
    /// Unique restore Attempt reference.
    pub attempt_ref: String,
    /// Exact restore executor identity.
    pub executor_ref: String,
    /// Target Workspace materialization generation.
    pub target_materialization_generation: u64,
    /// Exact Provider targets used for recovery.
    pub provider_targets: Vec<ProviderRecoveryTarget>,
    /// Evidence of runtime restart/replacement.
    pub restart_evidence_refs: Vec<String>,
    /// Output references produced by restored components.
    pub restored_output_refs: Vec<String>,
    /// Activity reconciliation.
    pub activities: Vec<Reconciliation>,
    /// Attachment reconciliation.
    pub attachments: Vec<Reconciliation>,
    /// Lease/fence reconciliation.
    pub leases: Vec<Reconciliation>,
    /// Partial Artifact reconciliation.
    pub partial_artifacts: Vec<Reconciliation>,
    /// Stable result-handle reconciliation.
    pub result_handles: Vec<Reconciliation>,
    /// Schedule reconciliation.
    pub schedules: Vec<Reconciliation>,
    /// Conflict Receipt reconciliation.
    pub conflict_receipts: Vec<Reconciliation>,
    /// Uncertain external-effect reconciliation.
    pub uncertain_external_effects: Vec<Reconciliation>,
    /// Restore evidence.
    pub evidence_refs: Vec<String>,
    /// Explicit restore limitations.
    pub limitations: Vec<String>,
}

/// One independently checked recovery postcondition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Postcondition {
    /// Stable postcondition key.
    pub key: String,
    /// Whether the postcondition passed.
    pub passed: bool,
    /// Evidence supporting the result.
    pub evidence_refs: Vec<String>,
}

/// Final independent recovery-verification record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryVerification {
    /// Stable verification identifier.
    pub verification_id: String,
    /// Restore run being verified.
    pub restore_run_ref: String,
    /// Exact verifier identity.
    pub verifier_ref: String,
    /// Whether verifier and restore executor were independent.
    pub verifier_independent: bool,
    /// Target materialization generation observed by the verifier.
    pub target_materialization_generation: u64,
    /// Overall recovery outcome.
    pub outcome: RecoveryOutcome,
    /// Checked postconditions.
    pub postconditions: Vec<Postcondition>,
    /// Operations/effects still unresolved after reconciliation.
    pub unresolved_operation_refs: Vec<String>,
    /// Independent verification evidence.
    pub evidence_refs: Vec<String>,
    /// Explicit recovery limitations.
    pub limitations: Vec<String>,
}

/// Mechanical backend boundary used by the A13 orchestrator.
pub trait CheckpointBackend {
    /// Capture one requested component.
    ///
    /// # Errors
    /// Returns a mechanical capture failure without manufacturing checkpoint success.
    fn capture(&mut self, request: &CaptureRequest) -> Result<CapturedComponent, CheckpointError>;

    /// Independently read back one retained component.
    ///
    /// # Errors
    /// Returns an evidence-acquisition error, which produces an inconclusive verification.
    fn verify_readback(
        &self,
        component_ref: &str,
        expected_sha256: &str,
    ) -> Result<ReadbackVerification, CheckpointError>;

    /// Restore one already validated component into an exact newer target.
    ///
    /// # Errors
    /// Returns a mechanical restore failure; the engine retains any prior progress as uncertain.
    fn restore(
        &mut self,
        request: &ComponentRestoreRequest,
    ) -> Result<RestoredComponent, CheckpointError>;
}

/// A13 failures are fail-closed and preserve evidence where side effects may exist.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    /// Caller request is structurally invalid.
    #[error("invalid checkpoint request: {0}")]
    InvalidRequest(&'static str),
    /// A component class was requested more than once.
    #[error("checkpoint component class requested more than once")]
    DuplicateClass,
    /// Backend capture failed.
    #[error("checkpoint component capture failed: {0}")]
    CaptureFailed(String),
    /// Captured Provider/evidence facts are incomplete.
    #[error("captured component evidence is invalid: {0}")]
    InvalidCapturedEvidence(&'static str),
    /// Captured consistency is weaker than the caller requested.
    #[error("captured consistency does not satisfy the checkpoint request")]
    ConsistencyRequirementNotMet,
    /// Checkpoint bundle is unknown.
    #[error("checkpoint bundle not found")]
    BundleNotFound,
    /// Checkpoint manifest digest does not match retained bytes.
    #[error("checkpoint manifest digest mismatch")]
    ManifestMismatch,
    /// A required component class is missing.
    #[error("required checkpoint component is missing")]
    MissingComponent,
    /// Component bytes failed length/digest verification.
    #[error("component integrity verification failed")]
    VerificationFailed,
    /// Target compatibility requirement is not satisfied.
    #[error("target compatibility requirement is unsatisfied: {0}")]
    CompatibilityUnsatisfied(String),
    /// Checkpoint has not passed independent verification.
    #[error("checkpoint bundle has not been independently verified")]
    UnverifiedBundle,
    /// Restore target is structurally invalid.
    #[error("invalid restore target: {0}")]
    InvalidRestoreTarget(&'static str),
    /// No target Provider was supplied for a captured Provider Instance.
    #[error("missing recovery target for source Provider Instance: {0}")]
    MissingProviderTarget(String),
    /// Provider Generation did not strictly advance.
    #[error("target Provider Generation must advance for source Provider Instance: {0}")]
    StaleProviderGeneration(String),
    /// Workspace materialization Generation did not strictly advance.
    #[error("target materialization Generation must advance")]
    StaleMaterializationGeneration,
    /// Restart/replacement evidence is required before restore.
    #[error("runtime restart/replacement evidence is missing")]
    MissingRestartEvidence,
    /// Restore Attempt identity was already used, including across durable restart.
    #[error("restore Attempt identity was already used")]
    ReusedAttempt,
    /// Backend restore failed after side effects may have occurred.
    #[error("restore failed after partial progress: {0:?}")]
    RestoreFailed(Box<PartialRestoreFailure>),
    /// Backend reported restoration facts that do not match the validated target.
    #[error("restore evidence does not match the validated target: {0}")]
    RestoreEvidenceMismatch(&'static str),
    /// Durable-state serialization or decoding failed.
    #[error("checkpoint durable-state encoding failure: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredBundle {
    bundle: CheckpointBundle,
    bytes_by_component: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableStateEnvelope {
    schema_version: String,
    bundles: Vec<StoredBundle>,
    used_attempts: BTreeSet<String>,
}

/// Evidence-gated A13 orchestration core.
///
/// Durable callers persist [`Self::export_state`] bytes. Imported state deliberately
/// forgets previous verification authorization so readback and compatibility are
/// independently re-established after restart.
#[derive(Default)]
pub struct CheckpointEngine {
    bundles: BTreeMap<String, StoredBundle>,
    verified_bundles: BTreeSet<String>,
    used_attempts: BTreeSet<String>,
}

impl CheckpointEngine {
    /// Create a checkpoint from exact component captures.
    ///
    /// # Errors
    /// Fails before durable registration when request validation, capture evidence,
    /// or requested consistency cannot be satisfied.
    pub fn create_checkpoint<B: CheckpointBackend>(
        &mut self,
        request: CheckpointRequest,
        snapshot: RecoverySnapshot,
        activity_ref: impl Into<String>,
        attempt_ref: impl Into<String>,
        receipt_refs: Vec<String>,
        backend: &mut B,
    ) -> Result<CheckpointBundle, CheckpointError> {
        validate_request(&request)?;
        let activity_ref = activity_ref.into();
        let attempt_ref = attempt_ref.into();
        if activity_ref.trim().is_empty() {
            return Err(CheckpointError::InvalidRequest("activity_ref"));
        }
        if attempt_ref.trim().is_empty() {
            return Err(CheckpointError::InvalidRequest("attempt_ref"));
        }
        if receipt_refs.is_empty() || receipt_refs.iter().any(|item| item.trim().is_empty()) {
            return Err(CheckpointError::InvalidRequest("receipt_refs"));
        }

        let mut components = Vec::with_capacity(request.requested_classes.len());
        let mut bytes_by_component = BTreeMap::new();
        for class in &request.requested_classes {
            let captured = backend
                .capture(&CaptureRequest {
                    checkpoint_request_ref: request.request_ref.clone(),
                    workspace_ref: request.workspace_ref.clone(),
                    class: *class,
                    requested_consistency: request.requested_consistency,
                })
                .map_err(|error| CheckpointError::CaptureFailed(error.to_string()))?;
            validate_capture(&captured, request.requested_consistency)?;
            let component_id = new_id();
            let byte_len = captured.bytes.len();
            let content_sha256 = sha256_hex(&captured.bytes);
            let mut evidence_refs = captured.evidence_refs;
            append_unique(&mut evidence_refs, &receipt_refs);
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
                content_sha256,
                byte_len,
                consistency: captured.consistency,
                compatibility_requirement_refs: captured.compatibility_requirement_refs,
                evidence_refs,
                limitations: captured.limitations,
            });
        }

        let manifest = BundleManifest {
            checkpoint_request_ref: request.request_ref,
            workspace_ref: request.workspace_ref,
            workspace_revision_ref: request.workspace_revision_ref,
            workspace_materialization_ref: request.workspace_materialization_ref,
            source_materialization_generation: request.materialization_generation,
            requested_consistency: request.requested_consistency,
            privacy_policy_ref: request.privacy_policy_ref,
            credential_policy_ref: request.credential_policy_ref,
            destination_or_retention_refs: request.destination_or_retention_refs,
            requested_proof_refs: request.requested_proof_refs,
            components,
            snapshot,
        };
        let manifest_sha256 = sha256_json(&manifest)?;
        let bundle = CheckpointBundle {
            bundle_id: new_id(),
            manifest,
            manifest_sha256,
            created_activity_ref: activity_ref,
            created_attempt_ref: attempt_ref,
            receipt_refs,
        };
        self.bundles.insert(
            bundle.bundle_id.clone(),
            StoredBundle {
                bundle: bundle.clone(),
                bytes_by_component,
            },
        );
        Ok(bundle)
    }

    /// Independently verify manifest integrity, required scope, retained bytes,
    /// target compatibility and backend readback.
    ///
    /// A failed or inconclusive re-verification revokes any prior in-memory restore
    /// authorization for the bundle.
    ///
    /// # Errors
    /// Fails only when the bundle is unknown or verification serialization itself fails.
    pub fn verify_checkpoint<B: CheckpointBackend>(
        &mut self,
        bundle_id: &str,
        required_classes: &[CheckpointClass],
        available_compatibility_refs: &[String],
        backend: &B,
    ) -> Result<CheckpointVerification, CheckpointError> {
        let stored = self
            .bundles
            .get(bundle_id)
            .ok_or(CheckpointError::BundleNotFound)?;
        let manifest_valid = sha256_json(&stored.bundle.manifest)? == stored.bundle.manifest_sha256;
        let present: BTreeSet<_> = stored
            .bundle
            .manifest
            .components
            .iter()
            .map(|component| component.class)
            .collect();
        let required_components_present =
            required_classes.iter().all(|class| present.contains(class));
        let available: BTreeSet<_> = available_compatibility_refs.iter().cloned().collect();
        let mut component_results = Vec::with_capacity(stored.bundle.manifest.components.len());
        let mut explicit_failure = !manifest_valid || !required_components_present;
        let mut inconclusive = false;
        let mut verification_evidence = stored.bundle.receipt_refs.clone();
        let mut verification_limitations = Vec::new();

        for component in &stored.bundle.manifest.components {
            let retained = stored.bytes_by_component.get(&component.component_id);
            let integrity_verified = retained.is_some_and(|bytes| {
                bytes.len() == component.byte_len && sha256_hex(bytes) == component.content_sha256
            });
            explicit_failure |= !integrity_verified;
            let compatibility_verified = component
                .compatibility_requirement_refs
                .iter()
                .all(|requirement| available.contains(requirement));
            explicit_failure |= !compatibility_verified;

            let mut evidence_refs = component.evidence_refs.clone();
            let mut limitations = Vec::new();
            let readback_verified = match backend
                .verify_readback(&component.component_id, &component.content_sha256)
            {
                Ok(readback) => {
                    append_unique(&mut evidence_refs, &readback.evidence_refs);
                    append_unique(&mut verification_evidence, &readback.evidence_refs);
                    limitations.extend(readback.limitations);
                    if !readback.verified {
                        explicit_failure = true;
                    }
                    readback.verified
                }
                Err(error) => {
                    inconclusive = true;
                    limitations.push(format!("readback_error:{error}"));
                    false
                }
            };
            if !compatibility_verified {
                limitations.push("target_compatibility_unsatisfied".to_owned());
            }
            append_unique(&mut verification_limitations, &limitations);
            component_results.push(ComponentVerification {
                component_ref: component.component_id.clone(),
                integrity_verified,
                readback_verified,
                compatibility_verified,
                evidence_refs,
                limitations,
            });
        }

        let state = if explicit_failure {
            VerificationState::Failed
        } else if inconclusive || verification_evidence.is_empty() {
            VerificationState::Inconclusive
        } else {
            VerificationState::Verified
        };
        if state == VerificationState::Verified {
            self.verified_bundles.insert(bundle_id.to_owned());
        } else {
            self.verified_bundles.remove(bundle_id);
        }
        Ok(CheckpointVerification {
            verification_id: new_id(),
            checkpoint_bundle_ref: bundle_id.to_owned(),
            state,
            manifest_valid,
            required_components_present,
            component_results,
            evidence_refs: verification_evidence,
            limitations: verification_limitations,
        })
    }

    /// Restore a verified bundle into exact newer Provider/materialization generations.
    ///
    /// Every structural, compatibility, generation and retained-byte check runs before
    /// the first restore call. Any later backend/evidence failure returns
    /// [`CheckpointError::RestoreFailed`] with partial progress and uncertain effects.
    ///
    /// # Errors
    /// Fails closed for unverified bundles, stale/missing targets, missing restart
    /// evidence, reused Attempts, integrity drift, compatibility drift, or backend
    /// restore/evidence failure.
    pub fn restore<B: CheckpointBackend>(
        &mut self,
        bundle_id: &str,
        attempt_ref: impl Into<String>,
        target: RestoreTarget,
        backend: &mut B,
    ) -> Result<RestoreRun, CheckpointError> {
        if !self.verified_bundles.contains(bundle_id) {
            return Err(CheckpointError::UnverifiedBundle);
        }
        let stored = self
            .bundles
            .get(bundle_id)
            .ok_or(CheckpointError::BundleNotFound)?
            .clone();
        if sha256_json(&stored.bundle.manifest)? != stored.bundle.manifest_sha256 {
            self.verified_bundles.remove(bundle_id);
            return Err(CheckpointError::ManifestMismatch);
        }
        validate_restore_target(&stored, &target)?;
        let attempt_ref = attempt_ref.into();
        if attempt_ref.trim().is_empty() {
            return Err(CheckpointError::InvalidRestoreTarget("attempt_ref"));
        }
        if !self.used_attempts.insert(attempt_ref.clone()) {
            return Err(CheckpointError::ReusedAttempt);
        }

        let target_map: BTreeMap<_, _> = target
            .provider_targets
            .iter()
            .map(|item| (item.source_provider_instance_ref.clone(), item.clone()))
            .collect();
        let compatibility: BTreeSet<_> = target.compatibility_refs.iter().cloned().collect();
        for component in &stored.bundle.manifest.components {
            let bytes = stored
                .bytes_by_component
                .get(&component.component_id)
                .ok_or(CheckpointError::VerificationFailed)?;
            if bytes.len() != component.byte_len || sha256_hex(bytes) != component.content_sha256 {
                self.verified_bundles.remove(bundle_id);
                return Err(CheckpointError::VerificationFailed);
            }
            if let Some(requirement) = component
                .compatibility_requirement_refs
                .iter()
                .find(|requirement| !compatibility.contains(*requirement))
            {
                return Err(CheckpointError::CompatibilityUnsatisfied(requirement.clone()));
            }
            let provider_target = target_map
                .get(&component.producer_provider_instance_ref)
                .ok_or_else(|| {
                    CheckpointError::MissingProviderTarget(
                        component.producer_provider_instance_ref.clone(),
                    )
                })?;
            if provider_target.target_provider_generation <= component.provider_generation {
                return Err(CheckpointError::StaleProviderGeneration(
                    component.producer_provider_instance_ref.clone(),
                ));
            }
        }

        let mut restored_output_refs = Vec::new();
        let mut evidence_refs = target.restart_evidence_refs.clone();
        let mut limitations = Vec::new();
        for component in &stored.bundle.manifest.components {
            let provider_target = &target_map[&component.producer_provider_instance_ref];
            let request = ComponentRestoreRequest {
                checkpoint_component_ref: component.component_id.clone(),
                bytes: stored.bytes_by_component[&component.component_id].clone(),
                target_provider_instance_ref: provider_target.target_provider_instance_ref.clone(),
                target_provider_generation: provider_target.target_provider_generation,
                target_connection_epoch: provider_target.target_connection_epoch,
                target_materialization_generation: target.target_materialization_generation,
            };
            let restored = match backend.restore(&request) {
                Ok(restored) => restored,
                Err(error) => {
                    return Err(partial_restore_error(
                        &stored,
                        &attempt_ref,
                        &component.component_id,
                        error.to_string(),
                        &restored_output_refs,
                        &evidence_refs,
                        &limitations,
                        target.target_materialization_generation,
                    ));
                }
            };
            if let Some(reason) = restore_evidence_mismatch(&request, &restored) {
                return Err(partial_restore_error(
                    &stored,
                    &attempt_ref,
                    &component.component_id,
                    format!("restore_evidence_mismatch:{reason}"),
                    &restored_output_refs,
                    &evidence_refs,
                    &limitations,
                    target.target_materialization_generation,
                ));
            }
            append_unique(&mut restored_output_refs, &restored.output_refs);
            append_unique(&mut evidence_refs, &restored.evidence_refs);
            append_unique(&mut limitations, &restored.limitations);
        }

        let snap = &stored.bundle.manifest.snapshot;
        let reconciliation_evidence = evidence_refs.clone();
        Ok(RestoreRun {
            restore_run_id: new_id(),
            checkpoint_bundle_ref: bundle_id.to_owned(),
            attempt_ref,
            executor_ref: target.executor_ref,
            target_materialization_generation: target.target_materialization_generation,
            provider_targets: target.provider_targets,
            restart_evidence_refs: target.restart_evidence_refs,
            restored_output_refs,
            activities: reconcile(
                &snap.activity_refs,
                ReconciliationState::Recovered,
                &reconciliation_evidence,
            ),
            attachments: reconcile(
                &snap.attachment_refs,
                ReconciliationState::Detached,
                &reconciliation_evidence,
            ),
            leases: reconcile(
                &snap.lease_refs,
                ReconciliationState::Fenced,
                &reconciliation_evidence,
            ),
            partial_artifacts: reconcile(
                &snap.partial_artifact_refs,
                ReconciliationState::Partial,
                &reconciliation_evidence,
            ),
            result_handles: reconcile(
                &snap
                    .result_handles
                    .iter()
                    .map(|handle| handle.handle_ref.clone())
                    .collect::<Vec<_>>(),
                ReconciliationState::Retained,
                &reconciliation_evidence,
            ),
            schedules: reconcile(
                &snap
                    .schedules
                    .iter()
                    .map(|schedule| schedule.schedule_ref.clone())
                    .collect::<Vec<_>>(),
                ReconciliationState::Retained,
                &reconciliation_evidence,
            ),
            conflict_receipts: reconcile(
                &snap.conflict_receipt_refs,
                ReconciliationState::Conflict,
                &reconciliation_evidence,
            ),
            uncertain_external_effects: reconcile(
                &snap.uncertain_external_effect_refs,
                ReconciliationState::Unknown,
                &reconciliation_evidence,
            ),
            evidence_refs,
            limitations,
        })
    }

    /// Produce independent recovery proof from explicit postconditions.
    ///
    /// Uncertain external effects retained by the restore are automatically included;
    /// a caller cannot omit them to manufacture `Recovered`.
    #[must_use]
    pub fn verify_recovery(
        &self,
        restore: &RestoreRun,
        verifier_ref: impl Into<String>,
        postconditions: Vec<Postcondition>,
        unresolved_operation_refs: Vec<String>,
        evidence_refs: Vec<String>,
    ) -> RecoveryVerification {
        let verifier_ref = verifier_ref.into();
        let verifier_independent = !verifier_ref.trim().is_empty() && verifier_ref != restore.executor_ref;
        let mut unresolved: BTreeSet<String> = unresolved_operation_refs.into_iter().collect();
        unresolved.extend(
            restore
                .uncertain_external_effects
                .iter()
                .map(|item| item.subject_ref.clone()),
        );
        let unresolved_operation_refs: Vec<_> = unresolved.into_iter().collect();
        let missing_evidence = evidence_refs.is_empty()
            || restore.restart_evidence_refs.is_empty()
            || postconditions.is_empty()
            || postconditions.iter().any(|item| {
                item.key.trim().is_empty() || item.evidence_refs.is_empty()
            });
        let failed_postcondition = postconditions.iter().any(|item| !item.passed);
        let outcome = if failed_postcondition {
            RecoveryOutcome::Failed
        } else if !verifier_independent || missing_evidence {
            RecoveryOutcome::Inconclusive
        } else if !unresolved_operation_refs.is_empty() {
            RecoveryOutcome::Partial
        } else {
            RecoveryOutcome::Recovered
        };
        RecoveryVerification {
            verification_id: new_id(),
            restore_run_ref: restore.restore_run_id.clone(),
            verifier_ref,
            verifier_independent,
            target_materialization_generation: restore.target_materialization_generation,
            outcome,
            postconditions,
            unresolved_operation_refs,
            evidence_refs,
            limitations: restore.limitations.clone(),
        }
    }

    /// Export deterministic durable engine state for Node/runtime restart.
    ///
    /// Verification authorization is intentionally excluded and must be re-earned
    /// after import. Used restore Attempt identities are persisted so restart cannot
    /// bypass Attempt fencing.
    ///
    /// # Errors
    /// Returns serialization failure if durable state cannot be encoded.
    pub fn export_state(&self) -> Result<Vec<u8>, CheckpointError> {
        let envelope = DurableStateEnvelope {
            schema_version: DURABLE_STATE_SCHEMA.to_owned(),
            bundles: self.bundles.values().cloned().collect(),
            used_attempts: self.used_attempts.clone(),
        };
        serde_json::to_vec(&envelope).map_err(serialization_error)
    }

    /// Import and independently validate durable state after restart.
    ///
    /// Imported bundles start unverified even when they were verified before export.
    ///
    /// # Errors
    /// Fails closed for unknown schema, duplicate bundle IDs, manifest mismatch,
    /// missing component bytes, or component digest/length mismatch.
    pub fn import_state(bytes: &[u8]) -> Result<Self, CheckpointError> {
        let envelope: DurableStateEnvelope =
            serde_json::from_slice(bytes).map_err(serialization_error)?;
        if envelope.schema_version != DURABLE_STATE_SCHEMA {
            return Err(CheckpointError::Serialization(
                "unsupported durable state schema".to_owned(),
            ));
        }
        let mut bundles = BTreeMap::new();
        for stored in envelope.bundles {
            validate_stored_bundle(&stored)?;
            if bundles
                .insert(stored.bundle.bundle_id.clone(), stored)
                .is_some()
            {
                return Err(CheckpointError::Serialization(
                    "duplicate bundle identifier".to_owned(),
                ));
            }
        }
        Ok(Self {
            bundles,
            verified_bundles: BTreeSet::new(),
            used_attempts: envelope.used_attempts,
        })
    }

    /// Return whether a bundle currently holds in-memory restore authorization.
    #[must_use]
    pub fn is_verified(&self, bundle_id: &str) -> bool {
        self.verified_bundles.contains(bundle_id)
    }
}

fn validate_request(request: &CheckpointRequest) -> Result<(), CheckpointError> {
    for (name, value) in [
        ("request_ref", request.request_ref.as_str()),
        ("workspace_ref", request.workspace_ref.as_str()),
        ("workspace_revision_ref", request.workspace_revision_ref.as_str()),
        (
            "workspace_materialization_ref",
            request.workspace_materialization_ref.as_str(),
        ),
        ("privacy_policy_ref", request.privacy_policy_ref.as_str()),
        (
            "credential_policy_ref",
            request.credential_policy_ref.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(CheckpointError::InvalidRequest(name));
        }
    }
    if request.materialization_generation == 0 {
        return Err(CheckpointError::InvalidRequest(
            "materialization_generation",
        ));
    }
    if request.requested_classes.is_empty() {
        return Err(CheckpointError::InvalidRequest("requested_classes"));
    }
    let unique: BTreeSet<_> = request.requested_classes.iter().copied().collect();
    if unique.len() != request.requested_classes.len() {
        return Err(CheckpointError::DuplicateClass);
    }
    if request.destination_or_retention_refs.is_empty()
        || request
            .destination_or_retention_refs
            .iter()
            .any(|item| item.trim().is_empty())
    {
        return Err(CheckpointError::InvalidRequest(
            "destination_or_retention_refs",
        ));
    }
    if request.requested_proof_refs.is_empty()
        || request
            .requested_proof_refs
            .iter()
            .any(|item| item.trim().is_empty())
    {
        return Err(CheckpointError::InvalidRequest("requested_proof_refs"));
    }
    Ok(())
}

fn validate_capture(
    captured: &CapturedComponent,
    requested_consistency: Consistency,
) -> Result<(), CheckpointError> {
    if captured.subject_refs.is_empty()
        || captured
            .subject_refs
            .iter()
            .any(|item| item.trim().is_empty())
    {
        return Err(CheckpointError::InvalidCapturedEvidence("subject_refs"));
    }
    if captured.provider_revision_ref.trim().is_empty() {
        return Err(CheckpointError::InvalidCapturedEvidence(
            "provider_revision_ref",
        ));
    }
    if captured.provider_instance_ref.trim().is_empty() {
        return Err(CheckpointError::InvalidCapturedEvidence(
            "provider_instance_ref",
        ));
    }
    if captured.provider_generation == 0 {
        return Err(CheckpointError::InvalidCapturedEvidence(
            "provider_generation",
        ));
    }
    if captured.evidence_refs.is_empty()
        || captured
            .evidence_refs
            .iter()
            .any(|item| item.trim().is_empty())
    {
        return Err(CheckpointError::InvalidCapturedEvidence("evidence_refs"));
    }
    if !consistency_satisfies(captured.consistency, requested_consistency) {
        return Err(CheckpointError::ConsistencyRequirementNotMet);
    }
    Ok(())
}

fn consistency_satisfies(actual: Consistency, requested: Consistency) -> bool {
    match requested {
        Consistency::Consistent => actual == Consistency::Consistent,
        Consistency::CrashConsistent => {
            matches!(actual, Consistency::Consistent | Consistency::CrashConsistent)
        }
        Consistency::Partial => actual != Consistency::Unknown,
        Consistency::Unknown => true,
    }
}

fn validate_restore_target(
    stored: &StoredBundle,
    target: &RestoreTarget,
) -> Result<(), CheckpointError> {
    if target.target_materialization_generation
        <= stored.bundle.manifest.source_materialization_generation
    {
        return Err(CheckpointError::StaleMaterializationGeneration);
    }
    if target.executor_ref.trim().is_empty() {
        return Err(CheckpointError::InvalidRestoreTarget("executor_ref"));
    }
    if target.restart_evidence_refs.is_empty()
        || target
            .restart_evidence_refs
            .iter()
            .any(|item| item.trim().is_empty())
    {
        return Err(CheckpointError::MissingRestartEvidence);
    }
    let mut sources = BTreeSet::new();
    for provider_target in &target.provider_targets {
        if provider_target.source_provider_instance_ref.trim().is_empty()
            || provider_target.target_provider_instance_ref.trim().is_empty()
            || provider_target.target_provider_generation == 0
        {
            return Err(CheckpointError::InvalidRestoreTarget(
                "provider_targets",
            ));
        }
        if !sources.insert(provider_target.source_provider_instance_ref.clone()) {
            return Err(CheckpointError::InvalidRestoreTarget(
                "duplicate provider target",
            ));
        }
    }
    Ok(())
}

fn restore_evidence_mismatch(
    request: &ComponentRestoreRequest,
    restored: &RestoredComponent,
) -> Option<&'static str> {
    if restored.output_refs.is_empty() || restored.evidence_refs.is_empty() {
        return Some("missing output/evidence references");
    }
    if restored.observed_provider_instance_ref != request.target_provider_instance_ref {
        return Some("provider instance");
    }
    if restored.observed_provider_generation != request.target_provider_generation {
        return Some("provider generation");
    }
    if restored.observed_connection_epoch != request.target_connection_epoch {
        return Some("connection epoch");
    }
    if restored.observed_materialization_generation != request.target_materialization_generation {
        return Some("materialization generation");
    }
    None
}

fn partial_restore_error(
    stored: &StoredBundle,
    attempt_ref: &str,
    failed_component_ref: &str,
    message: String,
    restored_output_refs: &[String],
    evidence_refs: &[String],
    limitations: &[String],
    target_materialization_generation: u64,
) -> CheckpointError {
    let mut uncertain = stored
        .bundle
        .manifest
        .snapshot
        .uncertain_external_effect_refs
        .clone();
    if !uncertain.iter().any(|item| item == failed_component_ref) {
        uncertain.push(failed_component_ref.to_owned());
    }
    CheckpointError::RestoreFailed(Box::new(PartialRestoreFailure {
        checkpoint_bundle_ref: stored.bundle.bundle_id.clone(),
        attempt_ref: attempt_ref.to_owned(),
        failed_component_ref: failed_component_ref.to_owned(),
        message,
        restored_output_refs: restored_output_refs.to_vec(),
        evidence_refs: evidence_refs.to_vec(),
        limitations: limitations.to_vec(),
        uncertain_external_effect_refs: uncertain,
        target_materialization_generation,
    }))
}

fn reconcile(
    refs: &[String],
    state: ReconciliationState,
    evidence_refs: &[String],
) -> Vec<Reconciliation> {
    refs.iter()
        .map(|subject_ref| Reconciliation {
            subject_ref: subject_ref.clone(),
            state,
            evidence_refs: evidence_refs.to_vec(),
        })
        .collect()
}

fn validate_stored_bundle(stored: &StoredBundle) -> Result<(), CheckpointError> {
    if sha256_json(&stored.bundle.manifest)? != stored.bundle.manifest_sha256 {
        return Err(CheckpointError::ManifestMismatch);
    }
    if stored.bytes_by_component.len() != stored.bundle.manifest.components.len() {
        return Err(CheckpointError::VerificationFailed);
    }
    for component in &stored.bundle.manifest.components {
        let bytes = stored
            .bytes_by_component
            .get(&component.component_id)
            .ok_or(CheckpointError::VerificationFailed)?;
        if bytes.len() != component.byte_len || sha256_hex(bytes) != component.content_sha256 {
            return Err(CheckpointError::VerificationFailed);
        }
    }
    Ok(())
}

fn append_unique(target: &mut Vec<String>, additions: &[String]) {
    for addition in additions {
        if !target.iter().any(|item| item == addition) {
            target.push(addition.clone());
        }
    }
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
        .map_err(serialization_error)
}

fn serialization_error(error: serde_json::Error) -> CheckpointError {
    CheckpointError::Serialization(error.to_string())
}
