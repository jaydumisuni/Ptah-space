#![forbid(unsafe_code)]
//! A12 deterministic archive decomposition plus B02 generic progressive decomposition.
//!
//! Parser backends and type detectors are untrusted mechanical facilities. This crate owns path
//! canonicalization, duplicate/link policy, recursive resource budgets, provenance, coverage truth,
//! detector disagreement, progressive decomposition truth and canonical registration through the
//! A07/A03 boundaries.

mod b02;
mod model;
mod persist;
mod policy;

pub use b02::{
    B02Error, ChildRelationship, DetectorEvidence, DetectorOutcome, ProgressiveLevel,
    ProgressiveReport, ProgressiveSpec, SearchMetadata, TypeAgreement, TypeAssessment, TypeDetector,
    TypeSignal, progressive_decompose,
};
pub use model::{
    ArchiveBackend, BackendIdentity, DecompositionBudget, DecompositionClock, DecompositionOutcome,
    DecompositionPlan, DecompositionSpec, InventoryEntry, MemberKind, ParseReport, ParseTerminal,
    ParsedMember, PersistedDecomposition, RecoveredMember,
};
pub use persist::{DECOMPOSITION_RUN_SCHEMA_ID, DecompositionStore};
pub use policy::{decompose, stable_decomposition_identity};

use ptah_identifiers::IdentifierError;
use ptah_ledger::LedgerError;
use ptah_object_store::ObjectStoreError;
use thiserror::Error;

/// A12 failures that prevent a truthful decomposition result from being retained.
#[derive(Debug, Error)]
pub enum DecompositionError {
    /// Backend invocation failed before it could return a bounded report.
    #[error("archive backend failed: {0}")]
    Backend(String),
    /// Archive member path violated deterministic A12 path policy.
    #[error("archive path rejected: {0}")]
    InvalidPath(String),
    /// Two archive members canonicalized to the same path.
    #[error("duplicate canonical archive path: {0}")]
    DuplicatePath(String),
    /// Link or special-file entry is outside the accepted A12 materialization policy.
    #[error("archive entry kind rejected at {path}: {kind}")]
    EntryKindRejected {
        /// Canonical member path.
        path: String,
        /// Rejected member kind.
        kind: &'static str,
    },
    /// A requested decomposition budget is invalid.
    #[error("invalid decomposition budget: {0}")]
    InvalidBudget(&'static str),
    /// Numeric accounting exceeded representable bounds.
    #[error("decomposition accounting overflow")]
    AccountingOverflow,
    /// Source Object Revision does not match the supplied bytes/workspace/evidence.
    #[error("source revision/evidence mismatch")]
    SourceMismatch,
    /// Canonical record did not have the expected shape.
    #[error("canonical A12 record type mismatch")]
    TypeMismatch,
    /// The injected clock cannot produce frozen UTC timestamps.
    #[error("invalid UTC timestamp")]
    InvalidTimestamp,
    /// A03 ledger failure.
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    /// A07 object/view/relationship registration failure.
    #[error(transparent)]
    ObjectStore(#[from] ObjectStoreError),
    /// Canonical identifier failure.
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
    /// Canonical JSON serialization failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
