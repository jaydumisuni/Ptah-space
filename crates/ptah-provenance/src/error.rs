use thiserror::Error;

/// D06 provenance/SBOM/signing composition errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum D06Error {
    /// A proof subject is mutable, missing, or lacks exact digest evidence.
    #[error("inexact provenance subject")]
    InexactSubject,
    /// SBOM coverage binding or completeness is invalid.
    #[error("invalid SBOM coverage")]
    InvalidCoverage,
    /// A canonical record is outside the D06 WP07 boundary or malformed.
    #[error("invalid D06 canonical record")]
    InvalidCanonicalRecord,
    /// Public transparency would disclose identity without an explicit acknowledgement.
    #[error("identity disclosure acknowledgement required")]
    DisclosureRequired,
    /// Transparency evidence contradicts the selected no-log mode.
    #[error("fabricated transparency evidence")]
    FabricatedTransparency,
    /// Signature, subject, or policy binding is inconsistent.
    #[error("invalid verification binding")]
    InvalidVerificationBinding,
    /// OCI descriptor or referrer relationship is not exact.
    #[error("invalid OCI descriptor")]
    InvalidOciDescriptor,
    /// Deterministic evidence encoding failed.
    #[error("encoding error: {0}")]
    Encoding(String),
    /// Canonical A03 ledger operation failed.
    #[error("ledger error: {0}")]
    Ledger(String),
}
