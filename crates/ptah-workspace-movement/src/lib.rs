//! E04 compatible Workspace movement orchestration.
//!
//! E04 owns sequencing only. Canonical checkpoint, placement, transfer and recovery truth remains
//! with the existing Ptah owners composed by this crate.

use ptah_checkpoint::SessionVaultArchive;

/// Mechanical E04 progress. No phase is success except [`Self::Recovered`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceMovePhase {
    /// Source evidence is being prepared.
    Preparing,
    /// Exact source Vault evidence exists; current E02 target authority is still required.
    AwaitingPlacement,
    /// Exact Vault bytes are moving under E03/A08 authority.
    Transferring,
    /// Destination bytes exist and target-side checkpoint verification is required.
    Reverifying,
    /// Target compatibility has been independently accepted.
    CompatibilityChecked,
    /// B06/A13 restore is executing under current E02 authority.
    Restoring,
    /// Restore completed but independent Recovery Verification is still required.
    VerifyingRecovery,
    /// Recovery Verification returned the authoritative recovered outcome.
    Recovered,
    /// The movement stopped at an owner authority boundary.
    Failed,
}

/// Exact owner evidence retained by E04 source preparation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceMoveEvidence {
    /// SHA-256 of the exact B06 Session Vault archive payload.
    pub source_archive_sha256: String,
    /// Exact A13 checkpoint bundle retained by the B06 manifest.
    pub checkpoint_bundle_ref: String,
    /// Canonical Workspace reference retained by B06.
    pub workspace_ref: String,
    /// Exact Workspace Revision represented by the source checkpoint.
    pub workspace_revision_ref: String,
}

/// Source-prepared E04 operation. This state carries no target or restore authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedWorkspaceMove {
    /// Current mechanical phase.
    pub phase: WorkspaceMovePhase,
    /// Exact immutable owner evidence copied from the B06 archive.
    pub evidence: WorkspaceMoveEvidence,
}

/// Stateless E04 coordinator.
pub struct WorkspaceMover;

impl WorkspaceMover {
    /// Prepare exact source Vault evidence without manufacturing target, transfer or recovery truth.
    #[must_use]
    pub fn prepare_source(archive: &SessionVaultArchive) -> PreparedWorkspaceMove {
        PreparedWorkspaceMove {
            phase: WorkspaceMovePhase::AwaitingPlacement,
            evidence: WorkspaceMoveEvidence {
                source_archive_sha256: archive.payload_sha256.clone(),
                checkpoint_bundle_ref: archive.manifest.checkpoint_bundle_ref.clone(),
                workspace_ref: archive.manifest.workspace_ref.clone(),
                workspace_revision_ref: archive.manifest.current_workspace_revision_ref.clone(),
            },
        }
    }
}
