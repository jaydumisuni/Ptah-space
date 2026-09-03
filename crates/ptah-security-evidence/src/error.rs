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
    /// Finding confirmation requires explicit bounded review authority.
    #[error("finding confirmation requires explicit bounded review")]
    ReviewRequired,
    /// Finding candidate is structurally incomplete or mechanically invalid.
    #[error("invalid security finding draft")]
    InvalidFindingDraft,
    /// Claim lacks claimant, authority scope, subjects or evidence.
    #[error("invalid bounded security claim")]
    InvalidClaim,
    /// Evidence Item lacks an exact content/digest/collector/A04 binding.
    #[error("invalid security evidence binding")]
    InvalidEvidenceBinding,
    /// Evidence Bundle claims complete coverage beyond the retained assessment evidence.
    #[error("security evidence bundle overclaims coverage")]
    EvidenceCoverageOverclaim,
    /// Validation must allocate a fresh A04 Attempt.
    #[error("security validation requires a fresh A04 Attempt")]
    FreshAttemptRequired,
    /// Validation requires exact environment evidence.
    #[error("security validation requires environment evidence")]
    MissingEnvironmentEvidence,
    /// Review Decision is structurally incomplete.
    #[error("invalid security review decision")]
    InvalidReviewDecision,
    /// Dispute omits a competing Claim or Evidence position.
    #[error("invalid security dispute projection")]
    InvalidDispute,
    /// Disclosure lacks explicit audience/redaction/privacy authority.
    #[error("security disclosure denied")]
    DisclosureDenied,
    /// Patch lacks exact A07 object/base/digest binding.
    #[error("invalid security patch binding")]
    InvalidPatchBinding,
    /// Remediation execution request lacks exact targets/backups/authority binding.
    #[error("invalid security remediation request")]
    InvalidRemediationRequest,
    /// Post-fix verification lacks fresh attempt or exact evidence boundaries.
    #[error("invalid security post-fix verification")]
    InvalidPostFixVerification,
    /// Reproduction Protocol is structurally incomplete.
    #[error("invalid security reproduction protocol")]
    InvalidReproductionProtocol,
    /// Reproduction Request/Run binding is structurally incomplete.
    #[error("invalid security reproduction request")]
    InvalidReproductionRequest,
    /// Reproduction independence is asserted without the required mechanical evidence.
    #[error("independent reproduction is not proven")]
    IndependenceNotProven,
    /// Reproduction Comparison lacks original claim/run/outcome history.
    #[error("invalid security reproduction comparison")]
    InvalidReproductionComparison,
    /// Evidence Card projection is incomplete.
    #[error("invalid derived security Evidence Card")]
    InvalidEvidenceCard,
    /// Public Evidence Card input contains a restricted raw field family.
    #[error("restricted raw field is not allowed in a public Evidence Card")]
    RestrictedEvidenceCardField,
    /// Normalized private backend observation is incomplete.
    #[error("invalid provider-neutral security adapter observation")]
    InvalidAdapterObservation,
    /// Backend replacement changed canonical subjects or failed to create fresh machinery/evidence.
    #[error("invalid security backend replacement projection")]
    InvalidBackendReplacement,
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
