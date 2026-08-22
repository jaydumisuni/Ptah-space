use ptah_identifiers::EntityRef;
use ptah_object_store::ProductionEvidence;
use std::sync::Arc;

/// Immutable identity evidence for one parser backend generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendIdentity {
    /// Canonical Provider identity.
    pub provider_ref: EntityRef,
    /// Canonical Provider generation.
    pub provider_generation: u64,
    /// Backend implementation family, for example `libarchive`.
    pub implementation: String,
    /// Exact backend implementation version.
    pub implementation_version: String,
    /// Locked source/archive SHA-256, when applicable.
    pub source_sha256: String,
    /// Exact executable/helper SHA-256.
    pub executable_sha256: String,
}

/// Archive member kind reported mechanically by a parser backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    /// Byte-backed regular file.
    Regular,
    /// Directory structure entry. Inventory-only; no child Object bytes.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Hard link.
    Hardlink,
    /// Device/FIFO/socket or another non-regular special entry.
    Special,
}

impl MemberKind {
    /// Stable lowercase A12 token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Regular => "regular",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::Hardlink => "hardlink",
            Self::Special => "special",
        }
    }
}

/// One parser-reported member. Bytes are never authoritative until A12 policy
/// accepts the path/kind/budget and A07 registers them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMember {
    /// Backend-reported logical member path.
    pub path: String,
    /// Entry kind.
    pub kind: MemberKind,
    /// Exact stored/decoded member bytes for regular entries.
    pub bytes: Vec<u8>,
}

/// Terminal parser condition returned together with any valid prefix members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseTerminal {
    /// Parser reached the end of the archive without a known gap.
    Complete,
    /// Archive is encrypted and no authorized credential was available.
    LockedEncrypted,
    /// Authorized credential is required.
    CredentialRequired,
    /// Supplied credential was rejected.
    WrongCredential,
    /// Encryption scheme is unsupported.
    UnsupportedEncryption,
    /// Parser identified malformed archive structure.
    Malformed,
    /// Source ended before the parser could complete.
    Truncated,
    /// Parser returned a bounded error.
    ParserError,
    /// Parser crashed or was independently observed to terminate unexpectedly.
    ParserCrash,
    /// Parser exceeded the admitted time budget.
    Timeout,
    /// Parser exceeded a decomposition resource budget.
    BudgetExhausted,
    /// Source is not a supported archive format.
    UnsupportedFormat,
    /// Source is recognized as opaque/non-decomposable.
    Opaque,
    /// Decomposition was cancelled.
    Cancelled,
    /// Other bounded failure.
    Failed,
}

/// Mechanical parser report. A non-complete terminal may still carry verified
/// prefix members; A12 preserves those instead of deleting useful evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseReport {
    /// Identified format name, when known.
    pub format: Option<String>,
    /// Valid prefix members reported before the terminal condition.
    pub members: Vec<ParsedMember>,
    /// Terminal parser condition.
    pub terminal: ParseTerminal,
    /// Bounded parser warnings.
    pub warnings: Vec<String>,
    /// Bounded parser limitations.
    pub limitations: Vec<String>,
}

/// Replaceable parser boundary. Implementations must not create canonical Ptah
/// records or extract archive paths directly to the host filesystem.
pub trait ArchiveBackend {
    /// Return exact backend identity/generation evidence.
    fn identity(&self) -> BackendIdentity;

    /// Parse one archive byte sequence into a bounded mechanical report.
    ///
    /// # Errors
    /// Returns an error only when the backend cannot produce a bounded report at
    /// all. Malformed/truncated/unsupported archives should normally be returned
    /// as `ParseReport` terminal conditions so valid prefix outputs are retained.
    fn parse(&self, bytes: &[u8]) -> Result<ParseReport, crate::DecompositionError>;
}

/// Admitted recursive archive budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecompositionBudget {
    /// Maximum nested archive depth, with the source archive at depth zero.
    pub max_depth: u32,
    /// Maximum inventory members across the complete recursive run.
    pub max_members: u64,
    /// Maximum cumulative decoded regular-member bytes across all levels.
    pub max_expanded_bytes: u64,
    /// Maximum decoded bytes for one regular member.
    pub max_member_bytes: u64,
    /// Maximum Unicode scalar count for one canonical logical path.
    pub max_path_chars: usize,
}

impl Default for DecompositionBudget {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_members: 100_000,
            max_expanded_bytes: 2 * 1024 * 1024 * 1024,
            max_member_bytes: 512 * 1024 * 1024,
            max_path_chars: 8192,
        }
    }
}

/// A12 request over one exact source Object Revision.
#[derive(Debug, Clone)]
pub struct DecompositionSpec {
    /// Workspace scope.
    pub workspace_ref: EntityRef,
    /// Authority authorizing decomposition.
    pub authority_ref: EntityRef,
    /// Exact immutable source Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact A04 producing evidence; its Operation must target the source Revision.
    pub production: ProductionEvidence,
    /// Recursive resource budget.
    pub budget: DecompositionBudget,
    /// Requested frozen decomposition level token.
    pub requested_level: String,
}

/// One deterministic inventory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryEntry {
    /// Canonical slash-separated path inside the root source archive.
    pub logical_path: String,
    /// Entry kind.
    pub kind: MemberKind,
    /// Nesting depth of the immediate containing archive.
    pub depth: u32,
    /// SHA-256 of the immediate container bytes.
    pub container_sha256: String,
    /// SHA-256 of regular entry bytes, when byte-backed.
    pub member_sha256: Option<String>,
    /// Exact byte size for regular entries; zero for inventory-only entries.
    pub byte_size: u64,
}

/// Byte-backed member accepted by A12 policy and eligible for A07 registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredMember {
    /// Inventory index that identifies this member inside the plan.
    pub inventory_index: usize,
    /// Inventory index of the immediate containing member for nested archives.
    pub parent_inventory_index: Option<usize>,
    /// Canonical logical path.
    pub logical_path: String,
    /// Exact recovered bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of the immediate container bytes.
    pub container_sha256: String,
    /// SHA-256 of the recovered member bytes.
    pub member_sha256: String,
    /// Nesting depth.
    pub depth: u32,
}

/// Frozen decomposition outcome vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompositionOutcome {
    /// Complete requested decomposition with no unknown gap.
    Complete,
    /// Useful verified outputs exist but coverage is incomplete.
    Partial,
    /// Encrypted archive requires credential.
    LockedEncrypted,
    /// Credential is required.
    CredentialRequired,
    /// Credential was rejected.
    WrongCredential,
    /// Encryption is unsupported.
    UnsupportedEncryption,
    /// Archive is malformed.
    Malformed,
    /// Archive is truncated.
    Truncated,
    /// Parser error.
    ParserError,
    /// Parser crash.
    ParserCrash,
    /// Timeout.
    Timeout,
    /// Budget exhausted.
    BudgetExhausted,
    /// Unsupported archive format.
    UnsupportedFormat,
    /// Opaque source.
    Opaque,
    /// Cancelled.
    Cancelled,
    /// Other failure.
    Failed,
}

impl DecompositionOutcome {
    /// Frozen schema token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::LockedEncrypted => "locked_encrypted",
            Self::CredentialRequired => "credential_required",
            Self::WrongCredential => "wrong_credential",
            Self::UnsupportedEncryption => "unsupported_encryption",
            Self::Malformed => "malformed",
            Self::Truncated => "truncated",
            Self::ParserError => "parser_error",
            Self::ParserCrash => "parser_crash",
            Self::Timeout => "timeout",
            Self::BudgetExhausted => "budget_exhausted",
            Self::UnsupportedFormat => "unsupported_format",
            Self::Opaque => "opaque",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    /// Whether the frozen schema permits a complete coverage claim.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Backend-neutral deterministic A12 plan.
#[derive(Debug, Clone)]
pub struct DecompositionPlan {
    /// Stable digest identity derived from source Revision + admitted request/policy,
    /// explicitly excluding the replaceable backend implementation.
    pub decomposition_identity: String,
    /// Exact source Revision.
    pub source_revision_ref: EntityRef,
    /// Backend evidence used for this observation.
    pub backend: BackendIdentity,
    /// Deterministic inventory order.
    pub inventory: Vec<InventoryEntry>,
    /// Byte-backed members eligible for A07 registration.
    pub recovered_members: Vec<RecoveredMember>,
    /// Final truthful outcome.
    pub outcome: DecompositionOutcome,
    /// Requested level.
    pub requested_level: String,
    /// Achieved level.
    pub achieved_level: String,
    /// Budget admitted for this run.
    pub budget_request: DecompositionBudget,
    /// Number of inventory members processed.
    pub processed_members: u64,
    /// Cumulative decoded regular-member bytes processed.
    pub processed_bytes: u64,
    /// Explicit unknown-gap descriptions.
    pub unknown_gaps: Vec<String>,
    /// Bounded warnings.
    pub warnings: Vec<String>,
    /// Bounded limitations.
    pub limitations: Vec<String>,
}

/// Canonical result retained after A07/A03 persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedDecomposition {
    /// Canonical Decomposition Run identity.
    pub run_ref: EntityRef,
    /// Source-bound archive inventory View.
    pub inventory_view_ref: EntityRef,
    /// Registered child logical Objects.
    pub child_object_refs: Vec<EntityRef>,
    /// Immediate-container relationship identities.
    pub relationship_refs: Vec<EntityRef>,
}

/// A12 UTC clock authority.
pub type DecompositionClock = Arc<dyn Fn() -> String + Send + Sync>;
