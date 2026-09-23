//! E04 compatible Workspace movement orchestration.
//!
//! E04 owns sequencing only. Canonical checkpoint, placement, transfer and recovery truth remains
//! with the existing Ptah owners composed by this crate.

use ptah_checkpoint::{
    import_session_vault, CheckpointBackend, CheckpointVerification, ImportedSessionVault,
    RestoreRun, RestoreTarget, SessionVaultArchive, SessionVaultCompatibilityReport,
    SessionVaultError,
};
use ptah_identifiers::EntityRef;
use ptah_placement_runtime::{
    authorize_dispatch, AuthorityBinding, AuthorityError, FenceToken, Lease, LeaseError,
    LeaseRegistry, PlacementMetadata, Reservation, ReservationError, ReservationRegistry,
    ReservationState,
};
use ptah_transfer::{
    E03TransferError, TransferPeerRole, TransferRouteCandidate, TransferRouteKind, TransferTicket,
    TransferVerificationReport,
};

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

/// Exact E02 dispatch evidence retained for the target movement Attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetAuthorityEvidence {
    /// Exact Attempt/Node/session binding admitted by E02.
    pub binding: AuthorityBinding,
    /// Exact Reservation accepted by E02.
    pub reservation_ref: EntityRef,
    /// Exact Lease accepted by E02.
    pub lease_ref: EntityRef,
    /// Current Fence accepted by E02.
    pub fence: FenceToken,
}

/// Source plus target authority ready to enter the existing E03/A08 transfer plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedWorkspaceMove {
    /// Current mechanical phase.
    pub phase: WorkspaceMovePhase,
    /// Exact source owner evidence.
    pub source: WorkspaceMoveEvidence,
    /// Exact target dispatch authority.
    pub target: TargetAuthorityEvidence,
}

/// Exact E03/A08 evidence retained after target-side read-back verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultTransferEvidence {
    /// Exact control-issued E03 ticket.
    pub ticket_ref: EntityRef,
    /// Exact A08 run bound into the E03 ticket.
    pub run_ref: EntityRef,
    /// Exact A08 verification record proving destination read-back.
    pub verification_ref: EntityRef,
    /// Explicit E03 route class actually admitted for this movement.
    pub route_kind: TransferRouteKind,
    /// Destination digest independently read back by A08.
    pub destination_sha256: String,
    /// Exact destination byte count independently observed by A08.
    pub observed_size: u64,
}

/// E04 operation whose exact Vault bytes are proven at the target and await B06/A13 re-verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferredWorkspaceMove {
    /// Current mechanical phase.
    pub phase: WorkspaceMovePhase,
    /// Exact source owner evidence.
    pub source: WorkspaceMoveEvidence,
    /// Exact target dispatch authority.
    pub target: TargetAuthorityEvidence,
    /// Existing E03/A08 transfer proof; E04 owns no second transfer cursor or run.
    pub transfer: VaultTransferEvidence,
}

/// E04 orchestration failures preserve the owner boundary that rejected progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceMoveError {
    /// Target B06 import or A13 independent re-verification failed.
    Checkpoint(SessionVaultError),
    /// E02 rejected target dispatch authority.
    Placement(AuthorityError),
    /// E02 Reservation authority is absent or no longer current.
    Reservation(ReservationError),
    /// E02 Lease/Fence authority is absent or no longer current.
    Lease(LeaseError),
    /// Current E02 authority does not match the target session retained by E04.
    TargetAuthorityMismatch,
    /// Retained B06 conflicts require explicit resolution before restore.
    RetainedConflicts(Vec<String>),
    /// E03 rejected the ticket, current peer or selected route.
    Transfer(E03TransferError),
    /// The E03 ticket is not bound to the exact E02 target Attempt/session.
    TransferTargetAuthorityMismatch,
    /// The E03 ticket does not name the exact B06 Vault digest being moved.
    TransferSourceDigestMismatch,
    /// The A08 verification belongs to a different transfer run.
    TransferRunMismatch,
    /// Transport/finalization evidence exists without successful destination read-back verification.
    TransferNotVerified,
    /// A08 source or destination digest differs from the exact B06 Vault digest.
    TransferDigestMismatch,
    /// A08 destination byte count differs from the E03 ticket's exact expected size.
    TransferSizeMismatch,
}

/// Target-side Vault state after B06 import and independent A13 re-verification.
pub struct ReverifiedWorkspaceMove {
    /// Current mechanical phase.
    pub phase: WorkspaceMovePhase,
    /// Exact source owner evidence.
    pub source: WorkspaceMoveEvidence,
    /// Exact target dispatch authority retained from E02.
    pub target: TargetAuthorityEvidence,
    /// Exact E03/A08 transfer proof retained from the target read-back.
    pub transfer: VaultTransferEvidence,
    /// Independent A13 verification result earned after target import.
    pub checkpoint_verification: CheckpointVerification,
    imported_vault: ImportedSessionVault,
}

impl ReverifiedWorkspaceMove {
    /// Return the imported B06 Vault whose A13 state was independently re-verified.
    #[must_use]
    pub const fn imported_vault(&self) -> &ImportedSessionVault {
        &self.imported_vault
    }
}

/// E04 state after B06/A13 restore has executed under revalidated E02 authority.
///
/// This state is deliberately not movement success. Task 6 must obtain independent
/// A13 Recovery Verification before E04 may ever reach `WorkspaceMovePhase::Recovered`.
pub struct RestoredWorkspaceMove {
    /// Current mechanical phase.
    pub phase: WorkspaceMovePhase,
    /// Exact source owner evidence.
    pub source: WorkspaceMoveEvidence,
    /// Exact current target authority revalidated immediately before restore.
    pub target: TargetAuthorityEvidence,
    /// Exact E03/A08 transfer proof.
    pub transfer: VaultTransferEvidence,
    /// Independent A13 checkpoint verification retained from target import.
    pub checkpoint_verification: CheckpointVerification,
    /// Exact B06/A13 target compatibility report used for this restore.
    pub compatibility: SessionVaultCompatibilityReport,
    /// Exact A13 restore run; existence alone is not recovery success.
    pub restore_run: RestoreRun,
    imported_vault: ImportedSessionVault,
}

impl RestoredWorkspaceMove {
    /// Return the imported B06 Vault that owns subsequent A13 recovery verification.
    #[must_use]
    pub const fn imported_vault(&self) -> &ImportedSessionVault {
        &self.imported_vault
    }
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

    /// Admit an exact target only through the existing E02 dispatch-authority boundary.
    ///
    /// # Errors
    /// Returns [`WorkspaceMoveError::Placement`] with the exact E02 rejection reason.
    pub fn admit_target(
        prepared: PreparedWorkspaceMove,
        placement: &PlacementMetadata,
        reservation: &Reservation,
        lease: Option<&Lease>,
        expected_binding: &AuthorityBinding,
        current_fence: FenceToken,
        now_unix_seconds: u64,
    ) -> Result<AuthorizedWorkspaceMove, WorkspaceMoveError> {
        let authority = authorize_dispatch(
            placement,
            reservation,
            lease,
            expected_binding,
            current_fence,
            now_unix_seconds,
        )
        .map_err(WorkspaceMoveError::Placement)?;

        Ok(AuthorizedWorkspaceMove {
            phase: WorkspaceMovePhase::Transferring,
            source: prepared.evidence,
            target: TargetAuthorityEvidence {
                binding: authority.binding().clone(),
                reservation_ref: authority.reservation_ref().clone(),
                lease_ref: authority.lease_ref().clone(),
                fence: authority.fence(),
            },
        })
    }

    /// Consume existing E03 route authority plus final A08 destination read-back evidence.
    ///
    /// E04 does not transfer bytes, discover routes, or maintain a cursor. Direct/relay
    /// execution and verified-range resume remain E03/A08 responsibilities. This method
    /// only advances when those owners prove the exact Vault bytes at the exact target.
    ///
    /// # Errors
    /// Returns the first E02/E03/A08 authority or integrity mismatch observed.
    pub fn accept_transfer(
        authorized: AuthorizedWorkspaceMove,
        ticket: &TransferTicket,
        route: &TransferRouteCandidate,
        verification: &TransferVerificationReport,
        now_unix_seconds: u64,
    ) -> Result<TransferredWorkspaceMove, WorkspaceMoveError> {
        let target = ticket.target();
        let binding = &authorized.target.binding;
        if ticket.attempt_ref() != binding.attempt_ref()
            || target.node_id != binding.node_id()
            || target.node_generation != binding.node_generation()
            || target.connection_epoch != binding.connection_epoch()
        {
            return Err(WorkspaceMoveError::TransferTargetAuthorityMismatch);
        }

        ticket
            .authorize_peer(TransferPeerRole::Target, target, now_unix_seconds)
            .map_err(WorkspaceMoveError::Transfer)?;
        ticket
            .authorize_route(route)
            .map_err(WorkspaceMoveError::Transfer)?;

        if ticket.canonical_sha256() != authorized.source.source_archive_sha256 {
            return Err(WorkspaceMoveError::TransferSourceDigestMismatch);
        }
        if &verification.run_ref != ticket.run_ref() {
            return Err(WorkspaceMoveError::TransferRunMismatch);
        }
        if verification.verification_state != "verified" {
            return Err(WorkspaceMoveError::TransferNotVerified);
        }
        if verification.source_sha256.as_deref() != Some(ticket.canonical_sha256())
            || verification.destination_sha256 != ticket.canonical_sha256()
        {
            return Err(WorkspaceMoveError::TransferDigestMismatch);
        }
        if verification.observed_size != ticket.expected_size() {
            return Err(WorkspaceMoveError::TransferSizeMismatch);
        }

        Ok(TransferredWorkspaceMove {
            phase: WorkspaceMovePhase::Reverifying,
            source: authorized.source,
            target: authorized.target,
            transfer: VaultTransferEvidence {
                ticket_ref: ticket.ticket_ref().clone(),
                run_ref: ticket.run_ref().clone(),
                verification_ref: verification.verification_ref.clone(),
                route_kind: route.kind,
                destination_sha256: verification.destination_sha256.clone(),
                observed_size: verification.observed_size,
            },
        })
    }

    /// Import the transferred B06 Vault and independently re-verify its A13 checkpoint.
    ///
    /// Import integrity alone never advances the movement. E04 advances only after the existing
    /// B06 import boundary accepts the exact target bytes and A13 independently verifies every
    /// retained checkpoint component through the supplied owner backend.
    ///
    /// # Errors
    /// Returns the exact B06/A13 owner failure without manufacturing restore authority.
    pub fn reverify_target<B: CheckpointBackend>(
        transferred: TransferredWorkspaceMove,
        vault_bytes: &[u8],
        backend: &B,
    ) -> Result<ReverifiedWorkspaceMove, WorkspaceMoveError> {
        if u64::try_from(vault_bytes.len()).ok() != Some(transferred.transfer.observed_size) {
            return Err(WorkspaceMoveError::TransferSizeMismatch);
        }

        let mut imported_vault =
            import_session_vault(vault_bytes).map_err(WorkspaceMoveError::Checkpoint)?;

        if imported_vault.archive().payload_sha256 != transferred.source.source_archive_sha256
            || imported_vault.archive().payload_sha256 != transferred.transfer.destination_sha256
        {
            return Err(WorkspaceMoveError::TransferDigestMismatch);
        }

        let checkpoint_verification = imported_vault
            .reverify_checkpoint(backend)
            .map_err(WorkspaceMoveError::Checkpoint)?;

        Ok(ReverifiedWorkspaceMove {
            phase: WorkspaceMovePhase::CompatibilityChecked,
            source: transferred.source,
            target: transferred.target,
            transfer: transferred.transfer,
            checkpoint_verification,
            imported_vault,
        })
    }

    /// Re-evaluate B06/A13 compatibility, revalidate current E02 execution authority,
    /// then execute the owner-provided restore.
    ///
    /// Compatibility is evaluated first. Immediately before the restore side effect, E04
    /// requires the exact retained Reservation to remain active and unexpired, requires the
    /// supplied Lease projection to match the exact retained target binding/Reservation/Fence,
    /// and delegates current-owner truth to `LeaseRegistry::validate_current`. The restore
    /// itself remains B06/A13-owned and this transition stops at `VerifyingRecovery`.
    ///
    /// # Errors
    /// Returns the exact B06/A13 compatibility/restore failure, E02 Reservation/Lease failure,
    /// an exact-target mismatch, or explicit retained conflicts.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_target<B: CheckpointBackend>(
        mut reverified: ReverifiedWorkspaceMove,
        restore_attempt_ref: impl Into<String>,
        restore_target: RestoreTarget,
        compatibility_evidence_refs: Vec<String>,
        compatibility_evaluated_at_unix_ms: u64,
        compatibility_valid_until_unix_ms: u64,
        restore_now_unix_ms: u64,
        reservation_registry: &ReservationRegistry,
        current_lease: &Lease,
        lease_registry: &LeaseRegistry,
        authority_now_unix_seconds: u64,
        backend: &mut B,
    ) -> Result<RestoredWorkspaceMove, WorkspaceMoveError> {
        let compatibility = reverified
            .imported_vault
            .evaluate_compatibility(
                &restore_target,
                compatibility_evidence_refs,
                compatibility_evaluated_at_unix_ms,
                compatibility_valid_until_unix_ms,
            )
            .map_err(WorkspaceMoveError::Checkpoint)?;

        if !compatibility.retained_conflicts.is_empty() {
            return Err(WorkspaceMoveError::RetainedConflicts(
                compatibility.retained_conflicts.clone(),
            ));
        }

        let reservation = reservation_registry
            .reservation(&reverified.target.reservation_ref)
            .ok_or(WorkspaceMoveError::Reservation(
                ReservationError::UnknownReservation,
            ))?;
        if reservation.state() != ReservationState::Active
            || reservation.expires_at_unix_seconds() <= authority_now_unix_seconds
        {
            return Err(WorkspaceMoveError::Reservation(ReservationError::NotActive));
        }
        if reservation.binding() != &reverified.target.binding {
            return Err(WorkspaceMoveError::TargetAuthorityMismatch);
        }

        if current_lease.lease_ref() != &reverified.target.lease_ref
            || current_lease.reservation_ref() != &reverified.target.reservation_ref
            || current_lease.binding() != &reverified.target.binding
            || current_lease.fence() != reverified.target.fence
        {
            return Err(WorkspaceMoveError::TargetAuthorityMismatch);
        }

        lease_registry
            .validate_current(current_lease, authority_now_unix_seconds)
            .map_err(WorkspaceMoveError::Lease)?;

        let restore_run = reverified
            .imported_vault
            .restore_on_target(
                restore_attempt_ref,
                restore_target,
                &compatibility,
                restore_now_unix_ms,
                backend,
            )
            .map_err(WorkspaceMoveError::Checkpoint)?;

        Ok(RestoredWorkspaceMove {
            phase: WorkspaceMovePhase::VerifyingRecovery,
            source: reverified.source,
            target: reverified.target,
            transfer: reverified.transfer,
            checkpoint_verification: reverified.checkpoint_verification,
            compatibility,
            restore_run,
            imported_vault: reverified.imported_vault,
        })
    }
}
