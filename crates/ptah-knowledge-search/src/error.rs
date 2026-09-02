use thiserror::Error;

/// Mechanical D03 failures. These errors never express semantic trust or business judgment.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum D03Error {
    /// One D03 resource limit is zero or internally inconsistent.
    #[error("D03 resource limits are invalid")]
    InvalidLimits,
    /// A source identity/revision/hash binding is malformed.
    #[error("invalid D03 source binding: {0}")]
    InvalidSourceBinding(&'static str),
    /// A requested frozen knowledge schema is not present in the generated contract catalog.
    #[error("frozen knowledge schema is unavailable: {0}")]
    UnknownKnowledgeSchema(String),
    /// The caller presented a different canonical source revision than the cited source.
    #[error("D03 source revision is stale")]
    StaleSourceRevision,
    /// The caller presented different source bytes/digest for the cited revision.
    #[error("D03 source digest mismatch")]
    SourceDigestMismatch,
    /// Citation locator or evidence metadata is malformed.
    #[error("invalid D03 citation binding: {0}")]
    InvalidCitationBinding(&'static str),
}
