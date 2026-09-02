use thiserror::Error;

/// D06 provenance/SBOM/signing composition errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum D06Error {
    /// A proof subject is mutable, missing, or lacks exact digest evidence.
    #[error("inexact provenance subject")]
    InexactSubject,
    /// A canonical record is outside the D06 WP07 boundary or malformed.
    #[error("invalid D06 canonical record")]
    InvalidCanonicalRecord,
    /// Canonical A03 ledger operation failed.
    #[error("ledger error: {0}")]
    Ledger(String),
}
