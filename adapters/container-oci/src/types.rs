use ptah_activity_runtime::AttemptContext;
use ptah_identifiers::EntityRef;
use ptah_provider_api::{EndpointAlias, ProviderContext};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::{fmt, io};
use thiserror::Error;

/// Locked containerd version selected by the Phase 0C backend artifact authority.
pub const CONTAINERD_VERSION: &str = "2.3.1";
/// SHA-256 of the locked containerd Linux amd64 release archive.
pub const CONTAINERD_ARCHIVE_SHA256: &str =
    "628448bd973610c656c1cbea8e88b32fafd85b23cc1aa4a3372eb7198478c054";
/// Locked runc version selected by the Phase 0C backend artifact authority.
pub const RUNC_VERSION: &str = "1.4.2";
/// SHA-256 of the locked runc Linux amd64 executable.
pub const RUNC_BINARY_SHA256: &str =
    "ac8a90f9e225bb9322189937b230cdc5478d5753f0e31e1bda98a5cf06bd9539";

/// Exact immutable OCI image content digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ImageDigest(String);

impl ImageDigest {
    /// Parse one exact lowercase SHA-256 digest.
    ///
    /// # Errors
    /// Rejects mutable names/tags, uppercase/short hex and non-SHA-256 digests.
    pub fn parse(value: impl Into<String>) -> Result<Self, OciProviderError> {
        let value = value.into();
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(OciProviderError::MutableImageReference);
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(OciProviderError::InvalidImageDigest);
        }
        Ok(Self(value))
    }

    /// Borrow the canonical `sha256:<hex>` value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ImageDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl<'de> Deserialize<'de> for ImageDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// Image locator plus exact immutable content identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciImage {
    /// Human/backend image locator. It is an alias and may include a tag.
    pub reference_alias: String,
    /// Exact immutable image digest required for execution proof.
    pub digest: ImageDigest,
}

impl OciImage {
    /// Return a digest-bound image reference suitable for the mechanical backend.
    ///
    /// Validation requires any pre-existing digest suffix in `reference_alias` to
    /// agree with this exact digest; the mechanical form is then normalized to one
    /// authoritative digest suffix.
    #[must_use]
    pub fn digest_bound_reference(&self) -> String {
        let base = self
            .reference_alias
            .split_once('@')
            .map_or(self.reference_alias.as_str(), |(base, _)| base);
        format!("{base}@{}", self.digest)
    }
}

/// Resource bounds encoded into the OCI execution plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum resident memory in bytes.
    pub memory_bytes: u64,
    /// Linux CFS period in microseconds.
    pub cpu_period_micros: u64,
    /// Linux CFS quota in microseconds per period.
    pub cpu_quota_micros: u64,
}

impl ResourceLimits {
    /// Validate that every resource dimension is positively bounded.
    ///
    /// # Errors
    /// Returns [`OciProviderError::InvalidSpec`] for an unbounded/zero dimension.
    pub fn validate(self) -> Result<(), OciProviderError> {
        if self.memory_bytes == 0 {
            return Err(OciProviderError::InvalidSpec("memory_bytes"));
        }
        if self.cpu_period_micros == 0 {
            return Err(OciProviderError::InvalidSpec("cpu_period_micros"));
        }
        if self.cpu_quota_micros == 0 {
            return Err(OciProviderError::InvalidSpec("cpu_quota_micros"));
        }
        Ok(())
    }
}

/// Explicit network exposure requested by one workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// No host-network exposure is requested.
    Isolated,
    /// Join the host network under one exact WP11 network-exposure grant.
    Host {
        /// Exact grant authorizing host-network exposure.
        grant_ref: EntityRef,
    },
}

/// Filesystem bind-mount access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountAccess {
    /// Read-only bind mount.
    ReadOnly,
    /// Read/write bind mount.
    ReadWrite,
}

/// Explicit bind mount under one exact WP11 filesystem grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountRequest {
    /// Host source path alias. It is not canonical Object identity.
    pub source_alias: String,
    /// Absolute container destination path.
    pub destination: String,
    /// Requested access.
    pub access: MountAccess,
    /// Exact filesystem-access grant authorizing the exposure.
    pub grant_ref: EntityRef,
}

/// Exact host-network scope of one current WP11 network-exposure grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkGrantAuthority {
    /// Canonical `isolation.network_exposure_grant` reference.
    pub grant_ref: EntityRef,
    /// Whether this exact grant authorizes host-network namespace exposure.
    pub allow_host_network: bool,
}

/// Exact bind-mount scope of one current WP11 filesystem-access grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemGrantAuthority {
    /// Canonical `isolation.filesystem_access_grant` reference.
    pub grant_ref: EntityRef,
    /// Exact authorized host source path alias.
    pub source_alias: String,
    /// Exact authorized container destination.
    pub destination: String,
    /// Maximum access authorized by the grant.
    pub access: MountAccess,
}

/// Provider-local projection of current WP11 grant authority.
#[derive(Debug, Clone, Default)]
pub struct IsolationPolicy {
    /// Current network-exposure grant scopes accepted by this Provider generation.
    pub network_grants: Vec<NetworkGrantAuthority>,
    /// Current filesystem-access grant scopes accepted by this Provider generation.
    pub filesystem_grants: Vec<FilesystemGrantAuthority>,
}

/// Exact observed backend versions/digests required to instantiate A10.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendPinEvidence {
    /// Observed containerd version.
    pub containerd_version: String,
    /// Observed/verified containerd release archive SHA-256 (without `sha256:` prefix).
    pub containerd_archive_sha256: String,
    /// Observed runc version.
    pub runc_version: String,
    /// Observed/verified runc executable SHA-256 (without `sha256:` prefix).
    pub runc_binary_sha256: String,
}

impl BackendPinEvidence {
    /// Construct the exact expected Phase 0C lock values for comparison/tests.
    #[must_use]
    pub fn locked() -> Self {
        Self {
            containerd_version: CONTAINERD_VERSION.to_owned(),
            containerd_archive_sha256: CONTAINERD_ARCHIVE_SHA256.to_owned(),
            runc_version: RUNC_VERSION.to_owned(),
            runc_binary_sha256: RUNC_BINARY_SHA256.to_owned(),
        }
    }
}

/// A04 execution identity consumed by A10 without manufacturing Receipts.
#[derive(Debug, Clone)]
pub struct OciExecutionContext {
    /// Parent A04 Activity.
    pub activity_ref: EntityRef,
    /// Logical A04 Operation.
    pub operation_ref: EntityRef,
    /// Exact physical A04 Attempt.
    pub attempt_ref: EntityRef,
    /// Exact Node/Provider/workload generation and connection evidence.
    pub attempt: AttemptContext,
}

/// One digest-bound OCI workload request.
#[derive(Debug, Clone)]
pub struct OciRunSpec {
    /// Canonical caller-owned workload/logical target reference.
    pub workload_ref: EntityRef,
    /// Exact image identity plus non-authoritative locator alias.
    pub image: OciImage,
    /// Exact positive workload generation bound to the A04 Attempt.
    pub workload_generation: u64,
    /// Process argument vector. Empty means use the image configuration.
    pub args: Vec<String>,
    /// Explicit resource bounds.
    pub resources: ResourceLimits,
    /// Explicit network policy.
    pub network: NetworkPolicy,
    /// Explicit filesystem exposures.
    pub mounts: Vec<MountRequest>,
    /// Maximum retained bytes for each stdout/stderr observation.
    pub max_output_bytes: usize,
}

/// Backend-neutral launch plan emitted only after A10 policy/fencing validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendLaunchPlan {
    /// Exact digest-bound image reference.
    pub image_reference: String,
    /// Backend container identifier. It remains an alias only.
    pub container_alias: String,
    /// Process arguments.
    pub args: Vec<String>,
    /// Resource limits.
    pub resources: ResourceLimits,
    /// Whether host networking is explicitly authorized.
    pub host_network: bool,
    /// Validated bind mounts.
    pub mounts: Vec<MountRequest>,
    /// Maximum output retention per stream.
    pub max_output_bytes: usize,
}

/// Mechanical backend acknowledgement that a start request was accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendStartAck {
    /// Backend container identifier as non-authoritative alias evidence.
    pub container_alias: String,
    /// Backend observation time.
    pub observed_at: String,
    /// Backend-specific acknowledgement text, bounded by the backend.
    pub detail: String,
}

/// Independently observed terminal workload result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCompletion {
    /// Backend observation time.
    pub observed_at: String,
    /// Numeric process/container exit status when available.
    pub exit_code: Option<i32>,
    /// Backend-reported success. This is distinct from start acknowledgement.
    pub success: bool,
    /// Bounded stdout evidence.
    pub stdout: Vec<u8>,
    /// Bounded stderr evidence.
    pub stderr: Vec<u8>,
    /// Number of stdout bytes discarded by retention policy.
    pub stdout_truncated_bytes: u64,
    /// Number of stderr bytes discarded by retention policy.
    pub stderr_truncated_bytes: u64,
}

/// Mechanical backend boundary. A10 policy validation occurs before these calls.
pub trait OciBackend: Send + Sync {
    /// Accept/start one already validated launch plan.
    ///
    /// # Errors
    /// Returns backend mechanical failure without promoting it to workload truth.
    fn start(&self, plan: &BackendLaunchPlan) -> Result<BackendStartAck, OciProviderError>;

    /// Independently observe terminal workload completion.
    ///
    /// # Errors
    /// Returns backend mechanical failure when terminal evidence cannot be obtained.
    fn wait(
        &self,
        start: &BackendStartAck,
        max_output_bytes: usize,
    ) -> Result<BackendCompletion, OciProviderError>;
}

/// Successful A10 execution evidence. This is not an A04 Receipt or A07 Object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciExecutionEvidence {
    /// Canonical workload/logical target supplied by the caller.
    pub workload_ref: EntityRef,
    /// Exact immutable image digest.
    pub image_digest: ImageDigest,
    /// Image locator retained only as an alias.
    pub image_reference_alias: String,
    /// Exact Provider execution context.
    pub provider_context: ProviderContext,
    /// Parent A04 Activity.
    pub activity_ref: EntityRef,
    /// Logical A04 Operation.
    pub operation_ref: EntityRef,
    /// Physical A04 Attempt.
    pub attempt_ref: EntityRef,
    /// Start acknowledgement, retained separately from completion.
    pub start: BackendStartAck,
    /// Independently observed workload completion.
    pub completion: BackendCompletion,
    /// Backend identifier explicitly typed as a non-authoritative container alias.
    pub backend_alias: EndpointAlias,
    /// Exact workload generation retained from the A04 Attempt.
    pub workload_generation: u64,
    /// Exact resource bounds applied to the launch plan.
    pub resources: ResourceLimits,
    /// Explicit network policy used for the workload.
    pub network: NetworkPolicy,
    /// Explicit mount policy used for the workload.
    pub mounts: Vec<MountRequest>,
}

/// Projection describing backend replacement without changing logical workload identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendReplacementProjection {
    /// Canonical logical workload preserved across replacement.
    pub workload_ref: EntityRef,
    /// Previous exact Provider context.
    pub previous_provider: ProviderContext,
    /// Replacement exact Provider context.
    pub replacement_provider: ProviderContext,
    /// Previous backend alias/evidence.
    pub previous_backend_alias: EndpointAlias,
    /// Replacement backend alias/evidence.
    pub replacement_backend_alias: EndpointAlias,
    /// Observation time.
    pub observed_at: String,
}

/// A10 OCI Provider failures.
#[derive(Debug, Error)]
pub enum OciProviderError {
    /// Provider contract validation failed.
    #[error(transparent)]
    Provider(#[from] ptah_provider_api::ProviderError),
    /// Canonical identity construction failed.
    #[error(transparent)]
    Identifier(#[from] ptah_identifiers::IdentifierError),
    /// Backend I/O failed.
    #[error("OCI backend I/O failure: {0}")]
    Io(#[from] io::Error),
    /// Provider revision is not an OCI runtime Provider.
    #[error("provider revision is not an OCI runtime provider")]
    ProviderKindMismatch,
    /// Pinned backend evidence does not match the locked Phase 0C authority.
    #[error("pinned OCI backend evidence mismatch: {0}")]
    BackendPinMismatch(&'static str),
    /// Caller supplied a mutable image locator without exact digest authority.
    #[error("mutable image reference cannot satisfy exact OCI execution proof")]
    MutableImageReference,
    /// Image digest is not canonical lowercase SHA-256.
    #[error("invalid OCI image digest")]
    InvalidImageDigest,
    /// Caller request violates a bounded A10 field.
    #[error("invalid OCI request: {0}")]
    InvalidSpec(&'static str),
    /// A04 execution context does not match the active Provider generation/Node/epoch.
    #[error("A04 execution context does not match this OCI Provider instance")]
    ExecutionContextMismatch,
    /// Provider is not currently dispatch-ready.
    #[error("OCI Provider is not ready for dispatch")]
    ProviderNotReady,
    /// Host-network exposure lacks an exact current WP11 grant.
    #[error("host network capability is not authorized")]
    NetworkDenied,
    /// Filesystem exposure lacks an exact current WP11 grant.
    #[error("filesystem mount capability is not authorized")]
    MountDenied,
    /// Backend returned an invalid/non-current acknowledgement.
    #[error("invalid OCI backend acknowledgement")]
    InvalidBackendAck,
    /// Replacement did not advance/change exact Provider execution authority.
    #[error("backend replacement did not create new provider authority")]
    InvalidReplacement,
    /// Mechanical backend operation failed.
    #[error("OCI backend failure: {0}")]
    Backend(String),
}
