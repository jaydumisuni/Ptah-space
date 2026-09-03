use thiserror::Error;

/// Mechanical D07 failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum D07Error {
    /// The submitted canonical record is not one of the frozen WP12 security records.
    #[error("unsupported or invalid WP12 security record")]
    UnsupportedSecuritySchema,
    /// Assessment target or plan digest is not canonical lowercase SHA-256.
    #[error("invalid canonical digest")]
    InvalidDigest,
    /// Timestamp is outside the supported canonical UTC form.
    #[error("invalid UTC timestamp")]
    InvalidTimestamp,
    /// Authorization has not reached its validity start.
    #[error("assessment authorization is not yet valid")]
    AuthorizationNotYetValid,
    /// Authorization has expired.
    #[error("assessment authorization expired")]
    AuthorizationExpired,
    /// Exact target is not present in the caller authorization.
    #[error("assessment target is outside authorization scope")]
    TargetOutOfScope,
    /// Requested security test class is not caller-authorized.
    #[error("security test class is outside authorization scope")]
    TestClassOutOfScope,
    /// Assessment Plan does not bind the exact Authorization/Target/Scanner inputs.
    #[error("assessment plan binding mismatch")]
    PlanBindingMismatch,
    /// Coverage projection overclaims completeness.
    #[error("assessment coverage overclaims completeness")]
    CoverageOverclaim,
    /// Underlying A06 authority check failed.
    #[error("A06 authority rejection: {0}")]
    A06(String),
    /// Underlying A04 orchestration operation failed.
    #[error("A04 security workload mapping failed: {0}")]
    A04(String),
    /// Identifier construction failed.
    #[error("D07 identifier error: {0}")]
    Identifier(String),
    /// Deterministic projection serialization failed.
    #[error("D07 serialization error: {0}")]
    Serialization(String),
    /// Underlying canonical ledger operation failed.
    #[error("security ledger failure: {0}")]
    Ledger(String),
}
