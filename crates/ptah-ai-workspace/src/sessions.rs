//! D02 live Session-thread and B06 archived Session projections.

use crate::D02Error;
use ptah_checkpoint::{SessionVaultManifest, SessionVaultSession};
use ptah_identifiers::{EntityId, EntityRef};
use ptah_workspace::{SessionProjection, WorkspaceStore};

/// Non-authoritative projection of parallel durable Sessions in one Workspace.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionThreadProjection {
    /// Stable owning Workspace identity.
    pub workspace_ref: EntityRef,
    /// Durable A06 Session projections.
    pub sessions: Vec<SessionProjection>,
    /// Always false: this projection cannot choose a relevant or winning Session.
    pub authoritative: bool,
}

/// Project all currently durable A06 Sessions for one Workspace without semantic ranking.
///
/// # Errors
/// Returns A06 recovery/projection errors.
pub fn project_session_threads(
    workspace: &WorkspaceStore,
    workspace_id: EntityId,
) -> Result<SessionThreadProjection, D02Error> {
    let recovery = workspace.recovery_projection(workspace_id)?;
    let mut sessions = recovery.sessions;
    sessions.sort_by_key(|session| session.session_ref.entity_id.to_string());
    Ok(SessionThreadProjection {
        workspace_ref: recovery.workspace.workspace_ref,
        sessions,
        authoritative: false,
    })
}

/// Return exact archived Session metadata from a B06 Session Vault manifest.
///
/// Archive presence is recovery metadata, not live Session authority or relevance.
///
/// # Errors
/// Returns [`D02Error::ArchivedSessionNotFound`] when the exact identity is absent.
pub fn archived_session_by_identity<'a>(
    manifest: &'a SessionVaultManifest,
    session_ref: &EntityRef,
) -> Result<&'a SessionVaultSession, D02Error> {
    let expected = reference_key(session_ref);
    manifest
        .sessions
        .iter()
        .find(|session| session.session_ref == expected)
        .ok_or(D02Error::ArchivedSessionNotFound)
}

fn reference_key(reference: &EntityRef) -> String {
    format!("{}:{}", reference.entity_kind, reference.entity_id)
}
