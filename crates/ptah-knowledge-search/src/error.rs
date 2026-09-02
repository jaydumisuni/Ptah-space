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
    /// A derived index document/field is malformed or exceeds D03 policy.
    #[error("invalid D03 index input: {0}")]
    InvalidIndexInput(&'static str),
    /// Textual/typed query shape is mechanically invalid.
    #[error("invalid D03 query: {0}")]
    InvalidQuery(&'static str),
    /// Private B07 adapter failed mechanically.
    #[error("D03 B07 adapter failure: {0}")]
    SearchAdapter(String),
    /// Structured dataset ingestion/query failed mechanically.
    #[error("D03 structured data failure: {0}")]
    StructuredData(String),
    /// Relational connection or query plan is invalid.
    #[error("D03 invalid relational plan: {0}")]
    InvalidRelationalPlan(String),
    /// Database operation violates the required read-only mode.
    #[error("D03 read-only policy violation: {0}")]
    ReadOnlyPolicyViolation(String),
    /// Requested database provider is unavailable.
    #[error("D03 database provider unavailable: {0}")]
    DatabaseProviderUnavailable(String),
    /// Exact database bytes differ from the bound snapshot.
    #[error("D03 database snapshot mismatch")]
    DatabaseSnapshotMismatch,
    /// Database provider failed mechanically.
    #[error("D03 database provider failure: {0}")]
    DatabaseProvider(String),
    /// Canonical serialization used for deterministic derived identity failed.
    #[error("D03 serialization failure: {0}")]
    Serialization(String),
}
