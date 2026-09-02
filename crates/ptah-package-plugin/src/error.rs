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
}
