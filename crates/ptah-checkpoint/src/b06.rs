//! B06 Session Vault v1 portability over verified A13 checkpoint/recovery truth.

use crate::{
    CheckpointBackend, CheckpointBundle, CheckpointClass, CheckpointEngine, CheckpointError,
    CheckpointVerification, CompatibilityOutcome, Postcondition, RecoveryVerification,
    RestoreCompatibilityDecision, RestoreRun, RestoreTarget, VerificationState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

/// Frozen B06 portable archive schema.
pub const SESSION_VAULT_SCHEMA_VERSION: &str = "ptah.session-vault.v1";
/// B06 Session Vault v1 is implemented. This constant is not restore authorization.
pub const PTAH_SESSION_VAULT_V1_IMPLEMENTED: bool = true;

/// One durable Workspace version retained in the Session Vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceVersionRecord {
    /// Exact Workspace Revision reference.
    pub workspace_revision_ref: String,
    /// Materialization generation associated with this version.
    pub materialization_generation: u64,
    /// Optional exact parent Workspace Revision.
    pub parent_revision_ref: Option<String>,
    /// Evidence supporting this version record.
    pub evidence_refs: Vec<String>,
}

/// Portable Session descriptor. It is metadata, not live Session authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionVaultSession {
    /// Canonical Session reference.
    pub session_ref: String,
    /// Owning Workspace reference.
    pub workspace_ref: String,
    /// Exact Workspace Revision observed for the Session.
    pub workspace_revision_ref: String,
    /// Exact Provider Instance observed at export time.
    pub provider_instance_ref: String,
    /// Provider Generation observed at export time.
    pub provider_generation: u64,
    /// Provider connection epoch observed at export time.
    pub connection_epoch: u64,
    /// Optional source Node reference.
    pub node_ref: Option<String>,
    /// Optional source Node generation.
    pub node_generation: Option<u64>,
    /// Durable attachment references retained as history.
    pub attachment_refs: Vec<String>,
    /// Workspace-scoped subject references associated with the Session.
    pub subject_refs: Vec<String>,
}

/// One logical Object/Revision entry in the readable Session Vault manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultObjectEntry {
    /// Canonical Object reference.
    pub object_ref: String,
    /// Exact Object Revision reference.
    pub revision_ref: String,
    /// Exact content SHA-256 when materialized content is known.
    pub content_sha256: Option<String>,
    /// Exact byte length when materialized content is known.
    pub byte_len: Option<u64>,
    /// Artifact references currently associated with this Object/Revision.
    pub artifact_refs: Vec<String>,
}

/// One Artifact entry in the Session Vault manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultArtifactEntry {
    /// Canonical Artifact reference.
    pub artifact_ref: String,
    /// Canonical Object reference represented by the Artifact.
    pub object_ref: String,
    /// Exact Object Revision represented by the Artifact.
    pub revision_ref: String,
    /// Stable Artifact type key.
    pub artifact_type: String,
    /// Human-readable purpose retained for recovery inspection.
    pub purpose: String,
}

/// Caller-supplied B06 export metadata layered over one verified A13 checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionVaultExportSpec {
    /// Workspace version history to retain, including the exact checkpoint version.
    pub workspace_versions: Vec<WorkspaceVersionRecord>,
    /// Session descriptors to retain.
    pub sessions: Vec<SessionVaultSession>,
    /// Object/Revision manifest.
    pub objects: Vec<VaultObjectEntry>,
    /// Artifact manifest.
    pub artifacts: Vec<VaultArtifactEntry>,
    /// Conflicts known at export time.
    pub conflicts: Vec<String>,
    /// Additional target capability requirements beyond A13 component requirements.
    pub additional_required_capability_refs: Vec<String>,
    /// Evidence supporting the Session Vault export operation itself.
    pub export_evidence_refs: Vec<String>,
}

/// Integrity-bound, readable Session Vault manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionVaultManifest {
    /// Canonical Workspace reference.
    pub workspace_ref: String,
    /// Exact current Workspace Revision represented by the checkpoint.
    pub current_workspace_revision_ref: String,
    /// Current Workspace materialization generation represented by the checkpoint.
    pub current_materialization_generation: u64,
    /// Ordered Workspace version history.
    pub workspace_versions: Vec<WorkspaceVersionRecord>,
    /// Ordered Session descriptors.
    pub sessions: Vec<SessionVaultSession>,
    /// Ordered Object/Revision manifest.
    pub objects: Vec<VaultObjectEntry>,
    /// Ordered Artifact manifest.
    pub artifacts: Vec<VaultArtifactEntry>,
    /// Explicit retained conflicts.
    pub conflicts: Vec<String>,
    /// Exact compatibility capabilities required for full resume.
    pub required_capability_refs: Vec<String>,
    /// A13 checkpoint bundle bound into this archive.
    pub checkpoint_bundle_ref: String,
    /// A13 checkpoint manifest digest.
    pub checkpoint_manifest_sha256: String,
    /// Independent A13 verification retained as export evidence.
    pub checkpoint_verification_ref: String,
    /// Evidence from the independent A13 checkpoint verification.
    pub checkpoint_verification_evidence_refs: Vec<String>,
    /// Evidence supporting this B06 export operation.
    pub export_evidence_refs: Vec<String>,
}

/// Portable B06 archive carrying public checkpoint metadata plus opaque durable A13 state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionVaultArchive {
    /// Frozen archive schema identity.
    pub schema_version: String,
    /// Human-readable portability manifest.
    pub manifest: SessionVaultManifest,
    /// Exact public A13 checkpoint bundle represented by the archive.
    pub checkpoint_bundle: CheckpointBundle,
    /// Opaque A13 durable engine state. Import is delegated back to A13.
    checkpoint_engine_state: Vec<u8>,
    /// SHA-256 over schema, manifest, public bundle and exact opaque A13 durable state.
    pub payload_sha256: String,
}

/// One checkpoint component exposed in the readable recovery export without retained bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadableCheckpointComponent {
    /// Stable A13 checkpoint component reference.
    pub component_ref: String,
    /// Component class.
    pub class: CheckpointClass,
    /// Exact component content digest.
    pub content_sha256: String,
    /// Exact component byte length.
    pub byte_len: usize,
    /// Exact compatibility requirements for this component.
    pub compatibility_requirement_refs: Vec<String>,
    /// Explicit capture limitations.
    pub limitations: Vec<String>,
}

/// Human-readable recovery export that deliberately omits captured component bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadableRecoveryExport {
    /// Frozen Session Vault schema.
    pub schema_version: String,
    /// Session Vault manifest.
    pub manifest: SessionVaultManifest,
    /// Checkpoint component summaries without raw retained content.
    pub checkpoint_components: Vec<ReadableCheckpointComponent>,
    /// Vault payload digest.
    pub payload_sha256: String,
    /// Explicit readable-export limitations.
    pub limitations: Vec<String>,
}

/// Target-specific B06 compatibility projection over the A13 decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionVaultCompatibilityReport {
    /// Exact A13 target-bound compatibility decision, tightened by B06 requirements.
    pub decision: RestoreCompatibilityDecision,
    /// Exact capability references absent from the target.
    pub missing_capability_refs: Vec<String>,
    /// Restore-specific conflicts such as workspace mismatch or stale/missing Provider targets.
    pub restore_conflicts: Vec<String>,
    /// Pre-existing conflicts retained in the Session Vault manifest.
    pub retained_conflicts: Vec<String>,
}

/// Imported Session Vault whose A13 checkpoint must be independently re-verified before restore.
pub struct ImportedSessionVault {
    archive: SessionVaultArchive,
    engine: CheckpointEngine,
}

impl ImportedSessionVault {
    /// Return the integrity-validated Session Vault archive.
    #[must_use]
    pub const fn archive(&self) -> &SessionVaultArchive {
        &self.archive
    }

    /// Return the exact embedded A13 checkpoint bundle.
    #[must_use]
    pub const fn checkpoint_bundle(&self) -> &CheckpointBundle {
        &self.archive.checkpoint_bundle
    }

    /// Return whether restore authorization has been independently re-earned after import.
    #[must_use]
    pub fn is_checkpoint_verified(&self) -> bool {
        self.engine
            .is_verified(&self.archive.manifest.checkpoint_bundle_ref)
    }

    /// Independently re-verify every retained A13 component after import.
    ///
    /// # Errors
    /// Returns A13 verification or evidence-acquisition failure.
    pub fn reverify_checkpoint<B: CheckpointBackend>(
        &mut self,
        backend: &B,
    ) -> Result<CheckpointVerification, SessionVaultError> {
        let required: Vec<_> = self
            .archive
            .checkpoint_bundle
            .manifest
            .components
            .iter()
            .map(|component| component.class)
            .collect();
        self.engine
            .verify_checkpoint(
                &self.archive.manifest.checkpoint_bundle_ref,
                &required,
                backend,
            )
            .map_err(SessionVaultError::from)
    }

    /// Evaluate exact target compatibility and expose missing capabilities/conflicts structurally.
    ///
    /// B06-required capabilities tighten the A13 result: a capability missing from the target
    /// forces the returned decision to `Incompatible` even if A13's component-only requirements
    /// would otherwise be satisfied.
    ///
    /// # Errors
    /// Returns A13 target-validation/serialization failure.
    pub fn evaluate_compatibility(
        &self,
        target: &RestoreTarget,
        evidence_refs: Vec<String>,
        evaluated_at_unix_ms: u64,
        valid_until_unix_ms: u64,
    ) -> Result<SessionVaultCompatibilityReport, SessionVaultError> {
        let mut decision = self.engine.evaluate_restore_compatibility(
            &self.archive.manifest.checkpoint_bundle_ref,
            target,
            evidence_refs,
            evaluated_at_unix_ms,
            valid_until_unix_ms,
        )?;
        let available: BTreeSet<_> = target.compatibility_refs.iter().cloned().collect();
        let missing_capability_refs: Vec<_> = self
            .archive
            .manifest
            .required_capability_refs
            .iter()
            .filter(|capability| !available.contains(*capability))
            .cloned()
            .collect();
        if !missing_capability_refs.is_empty() {
            decision.outcome = CompatibilityOutcome::Incompatible;
            for capability in &missing_capability_refs {
                let limitation = format!("missing_compatibility:{capability}");
                if !decision.limitations.contains(&limitation) {
                    decision.limitations.push(limitation);
                }
            }
        }
        decision.limitations.sort();
        decision.limitations.dedup();
        let restore_conflicts = decision
            .limitations
            .iter()
            .filter(|item| !item.starts_with("missing_compatibility:"))
            .cloned()
            .collect();
        Ok(SessionVaultCompatibilityReport {
            decision,
            missing_capability_refs,
            restore_conflicts,
            retained_conflicts: self.archive.manifest.conflicts.clone(),
        })
    }

    /// Restore the imported Vault on an exact compatible target through A13.
    ///
    /// Import never grants restore authorization; [`Self::reverify_checkpoint`] must pass first.
    /// The target is checked again against B06-required capabilities so a caller-mutated report
    /// cannot weaken the Session Vault contract.
    ///
    /// # Errors
    /// Returns A13 fail-closed restore errors, including unverified or incompatible targets.
    pub fn restore_on_target<B: CheckpointBackend>(
        &mut self,
        attempt_ref: impl Into<String>,
        target: RestoreTarget,
        compatibility: &SessionVaultCompatibilityReport,
        now_unix_ms: u64,
        backend: &mut B,
    ) -> Result<RestoreRun, SessionVaultError> {
        if compatibility.decision.checkpoint_bundle_ref
            != self.archive.manifest.checkpoint_bundle_ref
        {
            return Err(SessionVaultError::ArchiveBindingMismatch(
                "compatibility checkpoint bundle",
            ));
        }
        let available: BTreeSet<_> = target.compatibility_refs.iter().cloned().collect();
        if self
            .archive
            .manifest
            .required_capability_refs
            .iter()
            .any(|capability| !available.contains(capability))
            || !compatibility_is_full(compatibility)
        {
            return Err(CheckpointError::IncompatibleRestoreTarget.into());
        }
        self.engine
            .restore(
                &self.archive.manifest.checkpoint_bundle_ref,
                attempt_ref,
                target,
                &compatibility.decision,
                now_unix_ms,
                backend,
            )
            .map_err(SessionVaultError::from)
    }

    /// Produce independent A13 recovery verification after a restore.
    #[must_use]
    pub fn verify_recovery(
        &self,
        restore: &RestoreRun,
        verifier_ref: impl Into<String>,
        postconditions: Vec<Postcondition>,
        unresolved_operation_refs: Vec<String>,
        evidence_refs: Vec<String>,
    ) -> RecoveryVerification {
        self.engine.verify_recovery(
            restore,
            verifier_ref,
            postconditions,
            unresolved_operation_refs,
            evidence_refs,
        )
    }
}

/// B06 validation failures. Archive existence never becomes restore success.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SessionVaultError {
    /// Underlying A13 checkpoint/recovery failure.
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
    /// Export or archive metadata is structurally invalid.
    #[error("invalid Session Vault metadata: {0}")]
    InvalidMetadata(&'static str),
    /// The supplied A13 checkpoint has not currently earned independent verification.
    #[error("Session Vault export requires a currently verified A13 checkpoint")]
    UnverifiedCheckpoint,
    /// The supplied verification does not bind the exact exported checkpoint.
    #[error("Session Vault verification does not bind the exact checkpoint")]
    VerificationMismatch,
    /// Session Vault JSON encoding/decoding failed.
    #[error("Session Vault serialization failure: {0}")]
    Serialization(String),
    /// Archive digest does not match the exact retained payload.
    #[error("Session Vault payload digest mismatch")]
    PayloadDigestMismatch,
    /// Archive metadata does not bind its embedded A13 checkpoint state.
    #[error("Session Vault archive binding mismatch: {0}")]
    ArchiveBindingMismatch(&'static str),
}

/// Export one Workspace-scoped Session Vault from an exact independently verified A13 checkpoint.
///
/// A13 durable engine state is consumed only through [`CheckpointEngine::export_state`]. B06
/// requires that export to contain exactly this checkpoint bundle, preventing an archive intended
/// for one Workspace from silently carrying unrelated checkpoint bundles.
///
/// # Errors
/// Fails closed for unverified/mismatched checkpoint evidence, malformed Workspace/Session/Object
/// metadata, impossible Artifact linkage, multi-bundle engine state, missing export evidence, or
/// serialization failure.
pub fn export_session_vault(
    engine: &CheckpointEngine,
    bundle: &CheckpointBundle,
    verification: &CheckpointVerification,
    mut spec: SessionVaultExportSpec,
) -> Result<Vec<u8>, SessionVaultError> {
    validate_export_verification(engine, bundle, verification)?;
    normalize_and_validate_spec(bundle, &mut spec)?;
    let checkpoint_engine_state = engine.export_state()?;
    validate_engine_state_binding(&checkpoint_engine_state, bundle)?;

    let mut required_capability_refs: BTreeSet<String> = bundle
        .manifest
        .components
        .iter()
        .flat_map(|component| component.compatibility_requirement_refs.iter().cloned())
        .collect();
    required_capability_refs.extend(spec.additional_required_capability_refs);
    let manifest = SessionVaultManifest {
        workspace_ref: bundle.manifest.workspace_ref.clone(),
        current_workspace_revision_ref: bundle.manifest.workspace_revision_ref.clone(),
        current_materialization_generation: bundle.manifest.source_materialization_generation,
        workspace_versions: spec.workspace_versions,
        sessions: spec.sessions,
        objects: spec.objects,
        artifacts: spec.artifacts,
        conflicts: spec.conflicts,
        required_capability_refs: required_capability_refs.into_iter().collect(),
        checkpoint_bundle_ref: bundle.bundle_id.clone(),
        checkpoint_manifest_sha256: bundle.manifest_sha256.clone(),
        checkpoint_verification_ref: verification.verification_id.clone(),
        checkpoint_verification_evidence_refs: sorted_unique(
            verification.evidence_refs.clone(),
            "checkpoint verification evidence",
        )?,
        export_evidence_refs: sorted_unique(spec.export_evidence_refs, "export evidence")?,
    };
    let mut archive = SessionVaultArchive {
        schema_version: SESSION_VAULT_SCHEMA_VERSION.to_owned(),
        manifest,
        checkpoint_bundle: bundle.clone(),
        checkpoint_engine_state,
        payload_sha256: String::new(),
    };
    archive.payload_sha256 = archive_digest(&archive)?;
    serde_json::to_vec(&archive).map_err(serialization_error)
}

/// Import an integrity-bound Session Vault into a new A13 engine.
///
/// Restore verification authorization is deliberately cleared by A13 import. Used restore Attempt
/// identities remain inside A13 durable state, so moving to another Node cannot bypass Attempt
/// fencing.
///
/// # Errors
/// Fails closed for unknown schema, archive digest drift, malformed metadata, checkpoint-state
/// binding failure, or A13 durable-state import failure.
pub fn import_session_vault(bytes: &[u8]) -> Result<ImportedSessionVault, SessionVaultError> {
    let archive: SessionVaultArchive =
        serde_json::from_slice(bytes).map_err(serialization_error)?;
    if archive.schema_version != SESSION_VAULT_SCHEMA_VERSION {
        return Err(SessionVaultError::InvalidMetadata("schema_version"));
    }
    if archive.payload_sha256 != archive_digest(&archive)? {
        return Err(SessionVaultError::PayloadDigestMismatch);
    }
    validate_archive_binding(&archive)?;
    validate_manifest_metadata(&archive.manifest)?;
    validate_engine_state_binding(&archive.checkpoint_engine_state, &archive.checkpoint_bundle)?;
    let engine = CheckpointEngine::import_state(&archive.checkpoint_engine_state)?;
    Ok(ImportedSessionVault { archive, engine })
}

impl SessionVaultArchive {
    /// Produce pretty JSON recovery metadata while deliberately omitting retained component bytes.
    ///
    /// # Errors
    /// Returns serialization failure when the readable projection cannot be encoded.
    pub fn readable_recovery_export(&self) -> Result<String, SessionVaultError> {
        let checkpoint_components = self
            .checkpoint_bundle
            .manifest
            .components
            .iter()
            .map(|component| ReadableCheckpointComponent {
                component_ref: component.component_id.clone(),
                class: component.class,
                content_sha256: component.content_sha256.clone(),
                byte_len: component.byte_len,
                compatibility_requirement_refs: component.compatibility_requirement_refs.clone(),
                limitations: component.limitations.clone(),
            })
            .collect();
        let readable = ReadableRecoveryExport {
            schema_version: self.schema_version.clone(),
            manifest: self.manifest.clone(),
            checkpoint_components,
            payload_sha256: self.payload_sha256.clone(),
            limitations: vec![
                "raw checkpoint component bytes intentionally omitted from readable recovery export"
                    .to_owned(),
                "imported checkpoint must be independently re-verified before restore".to_owned(),
            ],
        };
        serde_json::to_string_pretty(&readable).map_err(serialization_error)
    }
}

#[derive(Deserialize)]
struct DurableStateProjection {
    schema_version: String,
    bundles: Vec<StoredBundleProjection>,
}

#[derive(Deserialize)]
struct StoredBundleProjection {
    bundle: CheckpointBundle,
}

fn validate_engine_state_binding(
    bytes: &[u8],
    bundle: &CheckpointBundle,
) -> Result<(), SessionVaultError> {
    let projection: DurableStateProjection =
        serde_json::from_slice(bytes).map_err(serialization_error)?;
    require_text(
        &projection.schema_version,
        "checkpoint durable state schema",
    )?;
    if projection.bundles.len() != 1 {
        return Err(SessionVaultError::InvalidMetadata(
            "checkpoint engine must contain exactly one bundle",
        ));
    }
    if projection.bundles[0].bundle != *bundle {
        return Err(SessionVaultError::ArchiveBindingMismatch(
            "checkpoint durable state bundle",
        ));
    }
    Ok(())
}

fn validate_export_verification(
    engine: &CheckpointEngine,
    bundle: &CheckpointBundle,
    verification: &CheckpointVerification,
) -> Result<(), SessionVaultError> {
    if !engine.is_verified(&bundle.bundle_id) || verification.state != VerificationState::Verified {
        return Err(SessionVaultError::UnverifiedCheckpoint);
    }
    let expected_components: BTreeSet<_> = bundle
        .manifest
        .components
        .iter()
        .map(|component| component.component_id.as_str())
        .collect();
    let actual_components: BTreeSet<_> = verification
        .component_results
        .iter()
        .map(|component| component.component_ref.as_str())
        .collect();
    if verification.checkpoint_bundle_ref != bundle.bundle_id
        || !verification.manifest_valid
        || !verification.required_components_present
        || verification.evidence_refs.is_empty()
        || actual_components != expected_components
        || verification.component_results.len() != expected_components.len()
        || verification
            .component_results
            .iter()
            .any(|item| !item.integrity_verified || !item.readback_verified)
    {
        return Err(SessionVaultError::VerificationMismatch);
    }
    Ok(())
}

fn normalize_and_validate_spec(
    bundle: &CheckpointBundle,
    spec: &mut SessionVaultExportSpec,
) -> Result<(), SessionVaultError> {
    if spec.workspace_versions.is_empty() {
        return Err(SessionVaultError::InvalidMetadata("workspace_versions"));
    }
    validate_versions(bundle, &mut spec.workspace_versions)?;
    validate_sessions(bundle, &spec.workspace_versions, &mut spec.sessions)?;
    validate_objects(&mut spec.objects)?;
    validate_artifacts(&spec.objects, &mut spec.artifacts)?;
    spec.conflicts = sorted_unique(std::mem::take(&mut spec.conflicts), "conflicts")?;
    spec.additional_required_capability_refs = sorted_unique(
        std::mem::take(&mut spec.additional_required_capability_refs),
        "additional_required_capability_refs",
    )?;
    spec.export_evidence_refs = sorted_unique(
        std::mem::take(&mut spec.export_evidence_refs),
        "export_evidence_refs",
    )?;
    if spec.export_evidence_refs.is_empty() {
        return Err(SessionVaultError::InvalidMetadata("export_evidence_refs"));
    }
    Ok(())
}

fn validate_versions(
    bundle: &CheckpointBundle,
    versions: &mut [WorkspaceVersionRecord],
) -> Result<(), SessionVaultError> {
    let mut seen = BTreeSet::new();
    let mut current_found = false;
    for version in versions.iter_mut() {
        require_text(&version.workspace_revision_ref, "workspace_revision_ref")?;
        if version.materialization_generation == 0 {
            return Err(SessionVaultError::InvalidMetadata(
                "workspace version materialization_generation",
            ));
        }
        if version
            .parent_revision_ref
            .as_ref()
            .is_some_and(|value| value.trim().is_empty() || value != value.trim())
        {
            return Err(SessionVaultError::InvalidMetadata("parent_revision_ref"));
        }
        version.evidence_refs = sorted_unique(
            std::mem::take(&mut version.evidence_refs),
            "workspace version evidence",
        )?;
        if version.evidence_refs.is_empty() {
            return Err(SessionVaultError::InvalidMetadata(
                "workspace version evidence",
            ));
        }
        if !seen.insert(version.workspace_revision_ref.clone()) {
            return Err(SessionVaultError::InvalidMetadata(
                "duplicate workspace revision",
            ));
        }
        if version.workspace_revision_ref == bundle.manifest.workspace_revision_ref
            && version.materialization_generation
                == bundle.manifest.source_materialization_generation
        {
            current_found = true;
        }
    }
    if !current_found {
        return Err(SessionVaultError::InvalidMetadata(
            "checkpoint workspace version missing",
        ));
    }
    versions.sort_by(|left, right| {
        left.materialization_generation
            .cmp(&right.materialization_generation)
            .then_with(|| {
                left.workspace_revision_ref
                    .cmp(&right.workspace_revision_ref)
            })
    });
    Ok(())
}

fn validate_sessions(
    bundle: &CheckpointBundle,
    versions: &[WorkspaceVersionRecord],
    sessions: &mut [SessionVaultSession],
) -> Result<(), SessionVaultError> {
    let valid_versions: BTreeSet<_> = versions
        .iter()
        .map(|item| item.workspace_revision_ref.as_str())
        .collect();
    let mut seen = BTreeSet::new();
    for session in sessions.iter_mut() {
        for (name, value) in [
            ("session_ref", session.session_ref.as_str()),
            ("session workspace_ref", session.workspace_ref.as_str()),
            (
                "session workspace_revision_ref",
                session.workspace_revision_ref.as_str(),
            ),
            (
                "session provider_instance_ref",
                session.provider_instance_ref.as_str(),
            ),
        ] {
            require_text(value, name)?;
        }
        if session.workspace_ref != bundle.manifest.workspace_ref {
            return Err(SessionVaultError::InvalidMetadata(
                "session workspace mismatch",
            ));
        }
        if !valid_versions.contains(session.workspace_revision_ref.as_str()) {
            return Err(SessionVaultError::InvalidMetadata(
                "session workspace version missing",
            ));
        }
        if session.provider_generation == 0 || session.connection_epoch == 0 {
            return Err(SessionVaultError::InvalidMetadata(
                "session provider generation/epoch",
            ));
        }
        match (&session.node_ref, session.node_generation) {
            (Some(node_ref), Some(generation)) if !node_ref.trim().is_empty() && generation > 0 => {
            }
            (None, None) => {}
            _ => {
                return Err(SessionVaultError::InvalidMetadata(
                    "session node reference/generation",
                ));
            }
        }
        session.attachment_refs = sorted_unique(
            std::mem::take(&mut session.attachment_refs),
            "session attachment_refs",
        )?;
        session.subject_refs = sorted_unique(
            std::mem::take(&mut session.subject_refs),
            "session subject_refs",
        )?;
        if !seen.insert(session.session_ref.clone()) {
            return Err(SessionVaultError::InvalidMetadata("duplicate session_ref"));
        }
    }
    sessions.sort_by(|left, right| left.session_ref.cmp(&right.session_ref));
    Ok(())
}

fn validate_objects(objects: &mut [VaultObjectEntry]) -> Result<(), SessionVaultError> {
    let mut seen = BTreeSet::new();
    for object in objects.iter_mut() {
        require_text(&object.object_ref, "object_ref")?;
        require_text(&object.revision_ref, "object revision_ref")?;
        match (&object.content_sha256, object.byte_len) {
            (Some(digest), Some(_)) if valid_sha256(digest) => {}
            (None, None) => {}
            _ => {
                return Err(SessionVaultError::InvalidMetadata("object digest/byte_len"));
            }
        }
        object.artifact_refs = sorted_unique(
            std::mem::take(&mut object.artifact_refs),
            "object artifact_refs",
        )?;
        if !seen.insert((object.object_ref.clone(), object.revision_ref.clone())) {
            return Err(SessionVaultError::InvalidMetadata(
                "duplicate object revision",
            ));
        }
    }
    objects.sort_by(|left, right| {
        left.object_ref
            .cmp(&right.object_ref)
            .then_with(|| left.revision_ref.cmp(&right.revision_ref))
    });
    Ok(())
}

fn validate_artifacts(
    objects: &[VaultObjectEntry],
    artifacts: &mut [VaultArtifactEntry],
) -> Result<(), SessionVaultError> {
    let object_revisions: BTreeSet<_> = objects
        .iter()
        .map(|item| (item.object_ref.as_str(), item.revision_ref.as_str()))
        .collect();
    let declared_artifact_refs: BTreeSet<_> = objects
        .iter()
        .flat_map(|item| item.artifact_refs.iter().map(String::as_str))
        .collect();
    let mut seen = BTreeSet::new();
    for artifact in artifacts.iter() {
        for (name, value) in [
            ("artifact_ref", artifact.artifact_ref.as_str()),
            ("artifact object_ref", artifact.object_ref.as_str()),
            ("artifact revision_ref", artifact.revision_ref.as_str()),
            ("artifact_type", artifact.artifact_type.as_str()),
            ("artifact purpose", artifact.purpose.as_str()),
        ] {
            require_text(value, name)?;
        }
        if !object_revisions
            .contains(&(artifact.object_ref.as_str(), artifact.revision_ref.as_str()))
        {
            return Err(SessionVaultError::InvalidMetadata(
                "artifact object/revision missing from manifest",
            ));
        }
        if !declared_artifact_refs.contains(artifact.artifact_ref.as_str()) {
            return Err(SessionVaultError::InvalidMetadata(
                "artifact not linked from object manifest",
            ));
        }
        if !seen.insert(artifact.artifact_ref.clone()) {
            return Err(SessionVaultError::InvalidMetadata("duplicate artifact_ref"));
        }
    }
    artifacts.sort_by(|left, right| left.artifact_ref.cmp(&right.artifact_ref));
    Ok(())
}

fn validate_archive_binding(archive: &SessionVaultArchive) -> Result<(), SessionVaultError> {
    let bundle = &archive.checkpoint_bundle;
    let manifest = &archive.manifest;
    if manifest.checkpoint_bundle_ref != bundle.bundle_id {
        return Err(SessionVaultError::ArchiveBindingMismatch(
            "checkpoint_bundle_ref",
        ));
    }
    if manifest.checkpoint_manifest_sha256 != bundle.manifest_sha256 {
        return Err(SessionVaultError::ArchiveBindingMismatch(
            "checkpoint_manifest_sha256",
        ));
    }
    if manifest.workspace_ref != bundle.manifest.workspace_ref {
        return Err(SessionVaultError::ArchiveBindingMismatch("workspace_ref"));
    }
    if manifest.current_workspace_revision_ref != bundle.manifest.workspace_revision_ref {
        return Err(SessionVaultError::ArchiveBindingMismatch(
            "current_workspace_revision_ref",
        ));
    }
    if manifest.current_materialization_generation
        != bundle.manifest.source_materialization_generation
    {
        return Err(SessionVaultError::ArchiveBindingMismatch(
            "current_materialization_generation",
        ));
    }
    Ok(())
}

fn validate_manifest_metadata(manifest: &SessionVaultManifest) -> Result<(), SessionVaultError> {
    require_text(&manifest.workspace_ref, "workspace_ref")?;
    require_text(
        &manifest.current_workspace_revision_ref,
        "current_workspace_revision_ref",
    )?;
    require_text(&manifest.checkpoint_bundle_ref, "checkpoint_bundle_ref")?;
    if !valid_sha256(&manifest.checkpoint_manifest_sha256) {
        return Err(SessionVaultError::InvalidMetadata(
            "checkpoint_manifest_sha256",
        ));
    }
    require_text(
        &manifest.checkpoint_verification_ref,
        "checkpoint_verification_ref",
    )?;
    if manifest.current_materialization_generation == 0 {
        return Err(SessionVaultError::InvalidMetadata(
            "current_materialization_generation",
        ));
    }
    require_canonical_list(
        &manifest.checkpoint_verification_evidence_refs,
        "checkpoint verification evidence",
        true,
    )?;
    require_canonical_list(&manifest.export_evidence_refs, "export evidence", true)?;
    require_canonical_list(&manifest.conflicts, "conflicts", false)?;
    require_canonical_list(
        &manifest.required_capability_refs,
        "required_capability_refs",
        false,
    )?;

    let stub = manifest_bundle_stub(manifest);
    let mut versions = manifest.workspace_versions.clone();
    validate_versions(&stub, &mut versions)?;
    if versions != manifest.workspace_versions {
        return Err(SessionVaultError::InvalidMetadata(
            "workspace_versions canonical order",
        ));
    }
    let mut sessions = manifest.sessions.clone();
    validate_sessions(&stub, &versions, &mut sessions)?;
    if sessions != manifest.sessions {
        return Err(SessionVaultError::InvalidMetadata(
            "sessions canonical order",
        ));
    }
    let mut objects = manifest.objects.clone();
    validate_objects(&mut objects)?;
    if objects != manifest.objects {
        return Err(SessionVaultError::InvalidMetadata(
            "objects canonical order",
        ));
    }
    let mut artifacts = manifest.artifacts.clone();
    validate_artifacts(&objects, &mut artifacts)?;
    if artifacts != manifest.artifacts {
        return Err(SessionVaultError::InvalidMetadata(
            "artifacts canonical order",
        ));
    }
    Ok(())
}

fn manifest_bundle_stub(manifest: &SessionVaultManifest) -> CheckpointBundle {
    CheckpointBundle {
        bundle_id: manifest.checkpoint_bundle_ref.clone(),
        manifest: crate::BundleManifest {
            checkpoint_request_ref: "vault:validation".to_owned(),
            workspace_ref: manifest.workspace_ref.clone(),
            workspace_revision_ref: manifest.current_workspace_revision_ref.clone(),
            workspace_materialization_ref: "vault:materialization".to_owned(),
            source_materialization_generation: manifest.current_materialization_generation,
            requested_consistency: crate::Consistency::Unknown,
            privacy_policy_ref: "vault:privacy".to_owned(),
            credential_policy_ref: "vault:credential".to_owned(),
            destination_or_retention_refs: vec!["vault:retention".to_owned()],
            requested_proof_refs: vec!["vault:proof".to_owned()],
            components: Vec::new(),
            snapshot: crate::RecoverySnapshot::default(),
        },
        manifest_sha256: manifest.checkpoint_manifest_sha256.clone(),
        created_activity_ref: "vault:activity".to_owned(),
        created_attempt_ref: "vault:attempt".to_owned(),
        receipt_refs: vec!["vault:receipt".to_owned()],
    }
}

fn archive_digest(archive: &SessionVaultArchive) -> Result<String, SessionVaultError> {
    #[derive(Serialize)]
    struct Payload<'a> {
        schema_version: &'a str,
        manifest: &'a SessionVaultManifest,
        checkpoint_bundle: &'a CheckpointBundle,
        checkpoint_engine_state: &'a [u8],
    }
    let payload = Payload {
        schema_version: &archive.schema_version,
        manifest: &archive.manifest,
        checkpoint_bundle: &archive.checkpoint_bundle,
        checkpoint_engine_state: &archive.checkpoint_engine_state,
    };
    let bytes = serde_json::to_vec(&payload).map_err(serialization_error)?;
    Ok(sha256(&bytes))
}

fn require_canonical_list(
    values: &[String],
    name: &'static str,
    require_nonempty: bool,
) -> Result<(), SessionVaultError> {
    if require_nonempty && values.is_empty() {
        return Err(SessionVaultError::InvalidMetadata(name));
    }
    let canonical = sorted_unique(values.to_vec(), name)?;
    if canonical != values {
        return Err(SessionVaultError::InvalidMetadata(name));
    }
    Ok(())
}

fn sorted_unique(
    values: Vec<String>,
    name: &'static str,
) -> Result<Vec<String>, SessionVaultError> {
    if values
        .iter()
        .any(|item| item.trim().is_empty() || item != item.trim())
    {
        return Err(SessionVaultError::InvalidMetadata(name));
    }
    Ok(values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn require_text(value: &str, name: &'static str) -> Result<(), SessionVaultError> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(SessionVaultError::InvalidMetadata(name));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn serialization_error(error: serde_json::Error) -> SessionVaultError {
    SessionVaultError::Serialization(error.to_string())
}

fn compatibility_is_full(report: &SessionVaultCompatibilityReport) -> bool {
    matches!(
        report.decision.outcome,
        CompatibilityOutcome::Compatible | CompatibilityOutcome::CompatibleWithConversion
    ) && report.missing_capability_refs.is_empty()
}
