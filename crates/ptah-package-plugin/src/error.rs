use thiserror::Error;

/// D05 package/Plugin lifecycle failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum D05Error {
    /// Package coordinate is not exact enough to identify immutable bytes.
    #[error("package coordinate is not exact")]
    InexactPackageCoordinate,
    /// Registry source is stale, untrusted, or otherwise unavailable.
    #[error("registry source unavailable")]
    RegistrySourceUnavailable,
    /// Constraint does not admit the resolved package.
    #[error("package constraint mismatch")]
    ConstraintMismatch,
    /// Workspace authority does not permit the requested private package access.
    #[error("workspace access denied")]
    WorkspaceAccessDenied,
    /// Package licence policy explicitly denies admission.
    #[error("licence denied")]
    LicenceDenied,
    /// Package licence requires governed review before admission.
    #[error("licence review required")]
    LicenceReviewRequired,
    /// Required trust-policy evidence is absent.
    #[error("trust policy missing")]
    TrustPolicyMissing,
    /// A04 rejected lifecycle orchestration.
    #[error("activity runtime error: {0}")]
    ActivityRuntime(String),
    /// A03 rejected canonical package lifecycle persistence.
    #[error("ledger error: {0}")]
    Ledger(String),
    /// Verification input is incomplete or cannot establish the claimed state.
    #[error("verification incomplete")]
    VerificationIncomplete,
    /// Stored canonical lifecycle record is absent or malformed.
    #[error("package lifecycle record invalid")]
    InvalidLifecycleRecord,
    /// Plugin activation lacks current explicit policy/Grant authority.
    #[error("plugin activation authority missing")]
    ActivationAuthorityMissing,
}
