#![forbid(unsafe_code)]
//! D02 neutral AI Project Workspace composition and caller-adapter substrate.
//!
//! This crate composes accepted Ptah primitives. It adds no canonical entity
//! family and owns no semantic context, review, approval, promotion, or next-action authority.

mod profile;

pub use profile::{
    AI_PROJECT_PROFILE_ID, ActivityResultState, AvailabilityState, OPERATIONS_PROFILE_ID,
    OperationEffectClass, OperationsCompatibilityDescriptor, RuntimeProfileDescriptor, TimingMode,
    ai_project_profile, operations_profile,
};

/// D02 composition failures. Every variant is mechanical; none expresses a semantic verdict.
#[derive(Debug, thiserror::Error)]
pub enum D02Error {
    /// Canonical identifier validation failed.
    #[error(transparent)]
    Identifier(#[from] ptah_identifiers::IdentifierError),
    /// Canonical ledger access failed.
    #[error(transparent)]
    Ledger(#[from] ptah_ledger::LedgerError),
    /// Workspace authority or projection access failed.
    #[error(transparent)]
    Workspace(#[from] ptah_workspace::WorkspaceError),
    /// Derived B07 search failed.
    #[error(transparent)]
    Search(#[from] ptah_archive_decomposition::SearchError),
    /// Caller-owned JSON container encoding or decoding failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Configured Workspace authority denied the request.
    #[error("D02 workspace access denied")]
    WorkspaceAccessDenied,
    /// Exact/latest canonical record is absent.
    #[error("D02 canonical record not found")]
    RecordNotFound,
    /// Canonical record does not match the requested D02 record class.
    #[error("D02 canonical record class mismatch")]
    RecordClassMismatch,
    /// Canonical record belongs to a different Workspace.
    #[error("D02 canonical record belongs to a different Workspace")]
    WorkspaceMismatch,
    /// Exact archived Session identity is absent from the supplied B06 archive.
    #[error("D02 archived Session not found")]
    ArchivedSessionNotFound,
    /// Caller record failed bounded structural validation.
    #[error("D02 caller record is invalid: {0}")]
    InvalidCallerRecord(&'static str),
    /// Requested input was not present in the exact admitted input set.
    #[error("D02 input reference was not declared by the caller")]
    InputNotDeclared,
    /// Requested Grant was not present in the exact admitted Grant set.
    #[error("D02 Grant reference was not declared by the caller")]
    GrantNotDeclared,
}
