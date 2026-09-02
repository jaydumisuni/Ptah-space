use thiserror::Error;

/// Mechanical failures emitted by the D04 composition layer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum D04Error {
    /// An operation descriptor violates the D04 structural contract.
    #[error("invalid operation descriptor: {0}")]
    InvalidOperationDescriptor(&'static str),
    /// The D04 effect metadata conflicts with the frozen A04 execution class.
    #[error("operation effect {effect} is incompatible with A04 side effect {side_effect}")]
    EffectCompatibility {
        /// D04 effect class rendered in its canonical snake-case form.
        effect: String,
        /// A04 side-effect class rendered in its canonical debug form.
        side_effect: String,
    },
    /// A03 rejected or failed a D04 canonical record operation.
    #[error("recipe ledger failure: {0}")]
    Ledger(String),
    /// A caller supplied an invalid frozen Recipe shape.
    #[error("invalid recipe input: {0}")]
    InvalidRecipe(String),
    /// The requested Recipe does not exist in A03.
    #[error("recipe not found: {recipe_id}")]
    RecipeNotFound {
        /// Stable missing Recipe identifier.
        recipe_id: String,
    },
    /// Recipe Revision numbering would stop being strictly monotonic.
    #[error("recipe revision conflict: expected {expected}, got {actual}")]
    RecipeRevisionConflict {
        /// Exact next accepted revision number.
        expected: u64,
        /// Caller-supplied conflicting revision number.
        actual: u64,
    },
    /// A canonical record was present under the wrong frozen entity kind.
    #[error("record kind mismatch: expected {expected}, got {actual}")]
    RecordKindMismatch {
        /// Frozen entity kind required by D04.
        expected: String,
        /// Entity kind actually retained by A03.
        actual: String,
    },
    /// No separate Acceptance exists for the exact Recipe Revision.
    #[error("acceptance missing for recipe revision {recipe_revision_id}")]
    AcceptanceMissing {
        /// Exact Recipe Revision lacking Acceptance.
        recipe_revision_id: String,
    },
    /// Proposal and Acceptance do not bind the same exact Recipe Revision.
    #[error("acceptance proposal/revision binding mismatch")]
    AcceptanceBindingMismatch,
    /// Latest exact Acceptance is not an execution-accepting decision.
    #[error("acceptance decision blocks execution: {decision}")]
    AcceptanceRejected {
        /// Frozen WP07 decision blocking execution.
        decision: String,
    },
    /// Acceptance validity expired before the caller-supplied observation time.
    #[error("acceptance expired at {valid_until}")]
    AcceptanceExpired {
        /// Exact retained expiry timestamp.
        valid_until: String,
    },
    /// Compiled Plan references do not bind one exact accepted Recipe Revision.
    #[error("compiled plan binding mismatch")]
    PlanBindingMismatch,
    /// A retained canonical document does not contain the D04-required field.
    #[error("canonical record field missing or invalid: {0}")]
    InvalidStoredRecord(String),
    /// Canonical descriptor serialization failed before a digest could be produced.
    #[error("descriptor serialization failed: {0}")]
    DescriptorSerialization(String),
    /// The exact descriptor revision is already present in the derived catalog.
    #[error("operation descriptor already registered: {0}")]
    DescriptorDuplicate(String),
    /// No descriptor matches the exact caller-supplied lookup constraints.
    #[error("operation descriptor unavailable: {0}")]
    OperationUnavailable(String),
}
