//! D08 Application-platform validation failures.

use thiserror::Error;

/// Failures produced by the D08 application-platform composition boundary.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum D08Error {
    /// Compatibility evidence required by the frozen contract is absent.
    #[error("D08 compatibility evidence is missing")]
    MissingCompatibilityEvidence,
    /// Compatibility is expired, stale, or was not current at the requested observation time.
    #[error("D08 compatibility is stale or expired")]
    StaleCompatibility,
    /// Conditional compatibility omitted the conditions that bound the compatible scope.
    #[error("D08 compatibility conditions are missing")]
    MissingCompatibilityConditions,
    /// A mandatory requirement contradicts a compatible top-level decision.
    #[error("D08 mandatory compatibility requirement is unsatisfied")]
    MandatoryRequirementUnsatisfied,
    /// The requested platform requires Programme E remote-Node authority.
    #[error("D08 platform requires Programme E remote Node authority")]
    RemoteNodeRequired,
    /// No current node-local compatibility record can authorize the requested local operation.
    #[error("D08 node-local compatibility is missing")]
    MissingNodeLocalCompatibility,
    /// The supplied compatibility record covers a different operation.
    #[error("D08 compatibility operation mismatch")]
    CompatibilityOperationMismatch,
    /// A timestamp is not a strict UTC `Z` timestamp understood by this frozen boundary.
    #[error("D08 timestamp is not canonical UTC-Z")]
    InvalidTimestamp,
}
