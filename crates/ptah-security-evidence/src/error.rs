use thiserror::Error;

/// Mechanical D07 failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum D07Error {
    /// The submitted canonical record is not one of the frozen WP12 security records.
    #[error("unsupported or invalid WP12 security record")]
    UnsupportedSecuritySchema,
    /// Underlying canonical ledger operation failed.
    #[error("security ledger failure: {0}")]
    Ledger(String),
}
