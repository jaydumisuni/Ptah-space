use ptah_activity_runtime::AttemptContext;
use ptah_identifiers::EntityRef;
use ptah_provider_api::ProviderContext;
use serde::{Deserialize, Serialize};
use std::{io, path::PathBuf};
use thiserror::Error;

/// Git transport protocol admitted by one Provider revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitProtocol {
    /// Git over HTTPS.
    Https,
    /// Git over SSH.
    Ssh,
    /// Native unauthenticated Git protocol.
    Git,
    /// Local filesystem Git transport.
    File,
}

impl GitProtocol {
    /// Return the token accepted by Git's `GIT_ALLOW_PROTOCOL` fence.
    #[must_use]
    pub const fn git_allow_protocol_token(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Ssh => "ssh",
            Self::Git => "git",
            Self::File => "file",
        }
    }
}

/// Requested repository materialization shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloneMode {
    /// Materialize a detached worktree at one exact commit.
    Checkout,
    /// Materialize a bare mirror containing Git object/history data only.
    Mirror,
}

/// Submodule execution policy. A09 never recurses silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmodulePolicy {
    /// Reject materialization when `.gitmodules` exists at the exact commit.
    DenyIfPresent,
    /// Retain submodule metadata but never recursively materialize it.
    PreserveMetadataNoRecurse,
}

/// Git LFS execution policy. A09 never runs the LFS smudge/process filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LfsPolicy {
    /// Reject repositories whose exact commit references Git LFS filters.
    DenyIfReferenced,
    /// Preserve Git LFS pointer files without executing LFS transport filters.
    PreservePointers,
}

/// A04 execution identity consumed by A09 without manufacturing Receipts.
#[derive(Debug, Clone)]
pub struct GitExecutionContext {
    /// Parent A04 Activity.
    pub activity_ref: EntityRef,
    /// Logical A04 Operation.
    pub operation_ref: EntityRef,
    /// Exact physical A04 Attempt.
    pub attempt_ref: EntityRef,
    /// Attempt execution context used to bind Provider generation and connection truth.
    pub attempt: AttemptContext,
}

/// Bounded Git materialization request.
#[derive(Debug, Clone)]
pub struct GitCloneSpec {
    /// Remote transport descriptor. This is an alias, never canonical repository identity.
    pub remote: String,
    /// Exact reference expression to resolve before materialization.
    pub reference: String,
    /// Provider-root-relative destination path.
    pub destination: PathBuf,
    /// Checkout or mirror materialization mode.
    pub mode: CloneMode,
    /// Opaque credential references. Raw credentials never enter this API.
    pub credential_refs: Vec<EntityRef>,
    /// Submodule policy.
    pub submodule_policy: SubmodulePolicy,
    /// Git LFS policy.
    pub lfs_policy: LfsPolicy,
}

/// Exact remote/ref resolution retained before clone/mirror execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedGitSource {
    /// Sanitized remote label suitable for retained evidence.
    pub remote_label: String,
    /// Requested Git reference expression.
    pub requested_reference: String,
    /// Exact resolved commit object id.
    pub resolved_commit: String,
    /// Admitted Git transport protocol.
    pub protocol: GitProtocol,
    /// UTC time at which exact resolution was observed.
    pub observed_at: String,
}

/// Mechanical command observation. `argv` never contains raw credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitCommandObservation {
    /// Bounded execution stage label.
    pub stage: String,
    /// Sanitized Git argument vector.
    pub argv: Vec<String>,
    /// Process exit code, or `-1` when the process has no numeric exit code.
    pub exit_code: i32,
    /// Bounded standard output observation.
    pub stdout: String,
    /// Bounded standard error observation.
    pub stderr: String,
}

/// Evidence returned for A07 projection/acceptance. No A07 identity is created here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitProjectionEvidence {
    /// Sanitized remote label.
    pub remote_label: String,
    /// Exact commit object id proven after materialization.
    pub resolved_commit: String,
    /// A09 materialization identity.
    pub materialization_ref: EntityRef,
    /// Exact Provider Revision/Instance/Generation context.
    pub provider_context: ProviderContext,
    /// Parent A04 Activity.
    pub activity_ref: EntityRef,
    /// Logical A04 Operation.
    pub operation_ref: EntityRef,
    /// Physical A04 Attempt.
    pub attempt_ref: EntityRef,
    /// Materialization shape used for the evidence.
    pub clone_mode: CloneMode,
    /// Whether `.gitmodules` metadata existed at the exact commit.
    pub submodules_present: bool,
    /// Whether Git LFS attributes existed at the exact commit.
    pub lfs_metadata_present: bool,
    /// Whether hooks/templates were mechanically suppressed for all Git commands.
    pub hooks_suppressed: bool,
    /// Opaque credential references associated with the request.
    pub credential_refs: Vec<EntityRef>,
    /// UTC evidence observation time.
    pub observed_at: String,
}

/// Successful exact Git materialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitMaterialization {
    /// A09 materialization identity.
    pub materialization_ref: EntityRef,
    /// Exact pre-materialization source resolution.
    pub source: ResolvedGitSource,
    /// Exact commit re-proven after materialization.
    pub exact_commit: String,
    /// Provider-root-relative path alias. This is not canonical object identity.
    pub relative_path_alias: PathBuf,
    /// Evidence packet intended for subsequent A07 acceptance/projection.
    pub projection_evidence: GitProjectionEvidence,
    /// Mechanical Git command observations retained for review/proof.
    pub commands: Vec<GitCommandObservation>,
}

/// Expected failure class retained when Git materialization begins but does not complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum GitMaterializationFailureKind {
    /// A mechanical Git subprocess failed.
    Command {
        /// Bounded command stage.
        stage: String,
        /// Process exit code.
        exit_code: i32,
        /// Sanitized and bounded standard-error observation.
        stderr: String,
    },
    /// Materialized repository did not prove the exact pre-resolved commit.
    CommitMismatch,
    /// Exact commit contained submodule metadata forbidden by request policy.
    SubmoduleDenied,
    /// Exact commit referenced Git LFS while request policy forbade it.
    LfsDenied,
}

/// Evidence retained for a failed or rejected Git materialization attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitMaterializationFailure {
    /// A09 failure identity.
    pub failure_ref: EntityRef,
    /// Exact source resolution that preceded the failed materialization.
    pub source: ResolvedGitSource,
    /// Provider-root-relative path alias attempted by the Provider.
    pub relative_path_alias: PathBuf,
    /// Exact Provider Revision/Instance/Generation context.
    pub provider_context: ProviderContext,
    /// Parent A04 Activity.
    pub activity_ref: EntityRef,
    /// Logical A04 Operation.
    pub operation_ref: EntityRef,
    /// Physical A04 Attempt.
    pub attempt_ref: EntityRef,
    /// Expected failure class.
    pub failure: GitMaterializationFailureKind,
    /// Whether any partial destination was absent after cleanup.
    pub partial_removed: bool,
    /// Sanitized mechanical Git observations collected before failure.
    pub commands: Vec<GitCommandObservation>,
    /// UTC failure observation time.
    pub observed_at: String,
}

/// A09 Git Provider failures.
#[derive(Debug, Error)]
pub enum GitProviderError {
    /// Provider identity/generation validation failed.
    #[error(transparent)]
    Provider(#[from] ptah_provider_api::ProviderError),
    /// Canonical identifier construction failed.
    #[error(transparent)]
    Identifier(#[from] ptah_identifiers::IdentifierError),
    /// Git/filesystem I/O failed.
    #[error("git I/O failure: {0}")]
    Io(#[from] io::Error),
    /// Caller request violated an A09 contract field.
    #[error("invalid Git request: {0}")]
    InvalidSpec(&'static str),
    /// Remote protocol is outside the Provider allowlist.
    #[error("Git protocol is not allowed")]
    ProtocolDenied,
    /// Remote descriptor embedded raw credentials.
    #[error("remote URL embeds credentials")]
    EmbeddedCredential,
    /// A04 execution context does not match the active Provider instance/generation.
    #[error("A04 execution context does not match this Provider instance")]
    ExecutionContextMismatch,
    /// Destination escaped the Provider root or traversed a symlink boundary.
    #[error("unsafe Git destination")]
    UnsafeDestination,
    /// Remote reference resolution was empty, ambiguous, or malformed.
    #[error("resolved Git reference is ambiguous or invalid")]
    InvalidResolution,
    /// One mechanical Git command failed.
    #[error("Git command failed at {stage} with exit code {exit_code}: {stderr}")]
    CommandFailed {
        /// Bounded command stage.
        stage: String,
        /// Process exit code.
        exit_code: i32,
        /// Bounded standard-error evidence.
        stderr: String,
    },
    /// Materialization began and failed with retained bounded evidence.
    #[error("Git materialization failed; inspect retained failure evidence")]
    MaterializationFailed(Box<GitMaterializationFailure>),
    /// Materialized repository did not prove the pre-resolved exact commit.
    #[error("resolved commit changed during materialization")]
    CommitMismatch,
    /// Exact commit contains submodule metadata forbidden by request policy.
    #[error("repository contains submodule metadata forbidden by policy")]
    SubmoduleDenied,
    /// Exact commit references Git LFS while request policy forbids it.
    #[error("repository references Git LFS but policy forbids it")]
    LfsDenied,
}
