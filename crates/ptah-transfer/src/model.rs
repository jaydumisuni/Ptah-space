use ptah_identifiers::{EntityId, EntityRef};
use serde::{Deserialize, Serialize};
use std::{io, path::PathBuf};
use thiserror::Error;

/// Transfer mode vocabulary frozen by WP06.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferMode {
    /// Upload local/source bytes into a provider destination.
    Upload,
    /// Download provider/source bytes into a local or staged destination.
    Download,
    /// Copy bytes directly between provider-backed endpoints.
    ProviderToProvider,
    /// Copy bytes between Ptah Nodes.
    NodeToNode,
    /// Copy bytes between registered Storage Locations.
    LocationToLocation,
    /// Ingest an open-ended stream.
    StreamingIngest,
    /// Export an open-ended stream.
    StreamingExport,
    /// Copy bytes between local materializations.
    LocalCopy,
    /// Create or repair a replica copy.
    ReplicaCopy,
}

/// Transfer destination intent frozen by WP06.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationIntent {
    /// Materialize bytes for a new Storage Location.
    CreateNewLocation,
    /// Replace one Location generation under explicit policy.
    ReplaceLocationGeneration,
    /// Repair an existing Location.
    RepairLocation,
    /// Create another replica of existing Content.
    CreateReplica,
    /// Stage bytes for later A07 Object/Location acceptance.
    StageForObjectAcceptance,
    /// Deliver bytes externally without creating Ptah storage truth.
    ExportOnly,
}

/// Resumability policy frozen by WP06.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumabilityPolicy {
    /// The transfer is invalid unless safe resume state can be retained.
    Required,
    /// Resume should be used when the provider/runtime supports it.
    Preferred,
    /// Resume is permitted but not required.
    Allowed,
    /// Retained partial state must not be resumed.
    Disabled,
}

/// Source kind frozen by WP06.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Exact canonical Content.
    Content,
    /// Exact Object Revision.
    ObjectRevision,
    /// Registered Storage Location.
    StorageLocation,
    /// Remote/provider descriptor whose alias is not canonical identity.
    RemoteDescriptor,
    /// Open-ended stream source.
    Stream,
}

/// Digest domain frozen by WP06.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestDomain {
    /// Digest of canonical Content bytes.
    CanonicalContent,
    /// Digest of one transport chunk/range.
    TransportChunk,
    /// Digest of the whole transport byte sequence.
    TransportWhole,
    /// Provider-specific object digest domain.
    ProviderObject,
    /// Digest over encrypted payload bytes.
    EncryptedPayload,
    /// Digest over compressed payload bytes.
    CompressedPayload,
    /// Digest over a transfer manifest representation.
    Manifest,
    /// Explicit other digest domain.
    Other,
}

/// One qualified digest value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestValue {
    /// Algorithm token.
    pub algorithm: String,
    /// Encoded digest value.
    pub value: String,
    /// Byte domain named by the digest.
    pub digest_domain: DigestDomain,
}

impl DigestValue {
    /// Construct a canonical-content SHA-256 digest.
    #[must_use]
    pub fn canonical_sha256(value: impl Into<String>) -> Self {
        Self {
            algorithm: "sha256".to_owned(),
            value: value.into(),
            digest_domain: DigestDomain::CanonicalContent,
        }
    }

    /// Construct a transport-chunk SHA-256 digest.
    #[must_use]
    pub fn chunk_sha256(value: impl Into<String>) -> Self {
        Self {
            algorithm: "sha256".to_owned(),
            value: value.into(),
            digest_domain: DigestDomain::TransportChunk,
        }
    }
}

/// One mutable-source validator observation retained as evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorObservation {
    /// Validator type, e.g. `etag` or `provider_version`.
    pub validator_type: String,
    /// Provider-observed value.
    pub value: String,
    /// UTC observation time.
    pub observed_at: String,
}

/// Source descriptor used by Request, Run and Manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDescriptor {
    /// Source kind.
    pub source_kind: SourceKind,
    /// Canonical Content reference when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_ref: Option<EntityRef>,
    /// Exact Object Revision reference when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_revision_ref: Option<EntityRef>,
    /// Storage Location reference when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_ref: Option<EntityRef>,
    /// Provider instance when source is provider-backed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_instance_ref: Option<EntityRef>,
    /// Remote/provider alias reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_alias_ref: Option<EntityRef>,
    /// Stream reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_ref: Option<EntityRef>,
    /// Expected byte size when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_size: Option<u64>,
    /// Expected source digests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_digests: Vec<DigestValue>,
    /// Source validators used to fence resume.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validator_observations: Vec<ValidatorObservation>,
}

/// Destination descriptor used by Request, Run and Manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DestinationDescriptor {
    /// Destination intent.
    pub destination_intent: DestinationIntent,
    /// Provider instance identity.
    pub provider_instance_ref: EntityRef,
    /// Existing Location when replacing/repairing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub existing_location_ref: Option<EntityRef>,
    /// Provider namespace/alias reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_or_alias_ref: Option<EntityRef>,
    /// Stable storage-class key.
    pub storage_class: String,
    /// Expected Location generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_location_generation: Option<u64>,
}

/// Immutable execution proof references from A04 consumed by A08.
#[derive(Debug, Clone)]
pub struct TransferEvidence {
    /// Parent Activity.
    pub activity_ref: EntityRef,
    /// Logical Operation; identity survives retries/resume.
    pub operation_ref: EntityRef,
    /// Exact physical Attempt for this transfer try.
    pub attempt_ref: EntityRef,
    /// Positive immutable Receipts attached to that Attempt.
    pub receipt_refs: Vec<EntityRef>,
}

/// Engine identity/configuration for one transfer provider binding.
#[derive(Debug, Clone)]
pub struct TransferConfig {
    /// Canonical transfer Provider identity.
    pub provider_ref: EntityRef,
    /// Transfer provider instance.
    pub provider_instance_ref: EntityRef,
    /// Provider revision identity.
    pub provider_revision_ref: EntityRef,
    /// Current Provider generation.
    pub provider_generation: u64,
    /// Current connection epoch.
    pub connection_epoch: u64,
    /// Protocol identity retained in verification records.
    pub protocol_ref: EntityRef,
    /// Protocol revision text fenced by resume.
    pub protocol_revision: String,
    /// Producer identity for A08 records/events.
    pub producer_ref: EntityRef,
    /// Producer version text.
    pub producer_version: String,
}

/// Caller intent for one durable Transfer Request.
#[derive(Debug, Clone)]
pub struct TransferRequestSpec {
    /// Requestor identity.
    pub requestor_ref: EntityRef,
    /// Workspace scope.
    pub workspace_ref: EntityRef,
    /// Authority owning the canonical request.
    pub authority_ref: EntityRef,
    /// Transfer mode.
    pub transfer_mode: TransferMode,
    /// Source descriptor.
    pub source: SourceDescriptor,
    /// Destination descriptor.
    pub destination: DestinationDescriptor,
    /// Resume policy.
    pub resumability_policy: ResumabilityPolicy,
    /// Network/secure-grant references.
    pub network_or_grant_refs: Vec<EntityRef>,
    /// Opaque credential references; never raw secrets.
    pub credential_refs: Vec<EntityRef>,
    /// Privacy policy.
    pub privacy_policy_ref: EntityRef,
    /// Retention policy.
    pub retention_policy_ref: EntityRef,
    /// Verification domains required before completion.
    pub requested_verification_domains: Vec<VerificationDomain>,
}

/// Immutable transfer verification domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationDomain {
    /// Transport/finalization completed for the bounded effect.
    TransportCompleted,
    /// Observed destination byte count matches the declared expectation.
    ByteCountMatched,
    /// Transport-level checksum evidence passed.
    TransportChecksumsMatched,
    /// Canonical Content digest comparison passed.
    ContentDigestMatched,
    /// Destination bytes were independently read back and matched.
    DestinationReadbackMatched,
    /// A07 registered a verified Storage Location.
    LocationRegistered,
    /// A07 accepted the intended Object/Revision relationship.
    ObjectAcceptanceCompleted,
    /// An external delivery boundary independently confirmed delivery.
    ExternalDeliveryConfirmed,
}

/// Per-domain result retained by Transfer Verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainResultState {
    /// The bounded verification domain passed.
    Passed,
    /// The bounded verification domain failed.
    Failed,
    /// Only part of the bounded domain was established.
    Partial,
    /// The domain was intentionally not executed.
    NotPerformed,
    /// Available evidence cannot determine the domain.
    Unknown,
}

/// A07 output references bound only after independent acceptance exists.
#[derive(Debug, Clone)]
pub struct AcceptedOutputRefs {
    /// Accepted Content.
    pub content_ref: EntityRef,
    /// Accepted exact Object Revision.
    pub object_revision_ref: EntityRef,
    /// Accepted verified Storage Location.
    pub location_ref: EntityRef,
}

/// Start/resume parameters that must remain stable across physical Attempts.
#[derive(Debug, Clone)]
pub struct StartTransferSpec {
    /// Operation idempotency key.
    pub idempotency_key: String,
    /// Compression mode frozen into the manifest.
    pub compression_mode: String,
    /// Encryption mode frozen into the manifest.
    pub encryption_mode: String,
    /// Nominal transfer chunk size.
    pub chunk_size: usize,
}

/// Resume caller observation. Every field must match retained Run/Manifest state.
#[derive(Debug, Clone)]
pub struct ResumeSpec {
    /// Source descriptor re-observed at resume time.
    pub source: SourceDescriptor,
    /// Destination descriptor re-observed at resume time.
    pub destination: DestinationDescriptor,
    /// Current execution evidence under the same logical Operation and a new Attempt.
    pub evidence: TransferEvidence,
}

/// Result returned when one download Run is created.
#[derive(Debug, Clone)]
pub struct TransferRunHandle {
    /// Transfer Run identity.
    pub run_ref: EntityRef,
    /// Immutable first Manifest identity.
    pub manifest_ref: EntityRef,
    /// Private partial materialization path. This is operational data, never canonical identity.
    pub partial_path: PathBuf,
}

/// One retained progress observation.
#[derive(Debug, Clone)]
pub struct ProgressReport {
    /// Progress Snapshot identity.
    pub snapshot_ref: EntityRef,
    /// Total bytes received into partial state.
    pub bytes_received_unverified: u64,
    /// Bytes whose chunk digests were re-read and verified.
    pub bytes_verified: u64,
}

/// Final transfer read-back result. This does not imply A07 acceptance.
#[derive(Debug, Clone)]
pub struct TransferVerificationReport {
    /// Transfer Run identity.
    pub run_ref: EntityRef,
    /// Verification identity.
    pub verification_ref: EntityRef,
    /// Overall verification state.
    pub verification_state: String,
    /// Expected source SHA-256 when declared.
    pub source_sha256: Option<String>,
    /// Destination read-back SHA-256.
    pub destination_sha256: String,
    /// Destination read-back byte count.
    pub observed_size: u64,
    /// Operational materialized path when a local download was atomically promoted. Never canonical identity.
    pub materialized_path: Option<PathBuf>,
}

/// Source-side result of streaming one upload into a Provider sink.
///
/// This report proves only what the transfer runtime observed while reading the
/// source. Provider finalization and destination read-back happen in later phases.
#[derive(Debug, Clone)]
pub struct UploadTransportReport {
    /// Transfer Run identity.
    pub run_ref: EntityRef,
    /// SHA-256 computed while reading the source stream.
    pub source_sha256: String,
    /// Exact source bytes streamed.
    pub source_size: u64,
}

/// Provider acknowledgement returned by an Upload sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAcknowledgement {
    /// Provider reported that it accepted/finalized the transport effect.
    Acknowledged,
    /// Provider outcome is unresolved; automatic finalize retry is unsafe.
    Uncertain,
}

/// A08 transfer failures.
#[derive(Debug, Error)]
pub enum TransferError {
    /// A03 ledger failure.
    #[error(transparent)]
    Ledger(#[from] ptah_ledger::LedgerError),
    /// Canonical identifier failure.
    #[error(transparent)]
    Identifier(#[from] ptah_identifiers::IdentifierError),
    /// JSON conversion failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Filesystem failure.
    #[error("transfer I/O failure: {0}")]
    Io(#[from] io::Error),
    /// Event stream failure.
    #[error(transparent)]
    Event(#[from] ptah_events::EventError),
    /// Referenced canonical record was absent.
    #[error("canonical entity not found: {0}")]
    NotFound(EntityId),
    /// Canonical record kind/schema mismatch.
    #[error("canonical entity type mismatch")]
    TypeMismatch,
    /// Workspace fence failed.
    #[error("transfer entity belongs to another Workspace")]
    WorkspaceMismatch,
    /// Authority does not match durable A04 truth.
    #[error("transfer authority mismatch")]
    AuthorityMismatch,
    /// A04 execution evidence is not exact or is incomplete.
    #[error("transfer execution evidence mismatch")]
    ExecutionEvidenceMismatch,
    /// Required positive Receipt kind is absent.
    #[error("required positive Receipt kind is absent: {0}")]
    MissingReceiptKind(&'static str),
    /// Request/run state disallows the requested transition.
    #[error("invalid transfer lifecycle transition")]
    InvalidTransition,
    /// Resume dimensions drifted since the retained Manifest.
    #[error("retained transfer state is not resumable under current dimensions")]
    ResumeMismatch,
    /// Retained partial bytes no longer match their verified-range digests.
    #[error("retained partial transfer state is corrupt")]
    PartialStateCorrupt,
    /// Chunk offset is not the next contiguous byte.
    #[error("transfer chunk offset is not contiguous")]
    NonContiguousChunk,
    /// Digest/size/read-back verification failed.
    #[error("transfer verification failed")]
    VerificationFailed,
    /// Provider acknowledgement cannot satisfy completion proof.
    #[error("provider acknowledgement is insufficient for transfer completion")]
    AckNotCompletion,
    /// Destination path is absolute, traverses upward, or escapes the declared root.
    #[error("unsafe transfer destination")]
    UnsafeDestination,
    /// Caller field violates the frozen transfer schema constraints.
    #[error("invalid transfer field: {0}")]
    InvalidField(&'static str),
    /// Integer/range accounting overflow.
    #[error("transfer accounting overflow")]
    AccountingOverflow,
}
