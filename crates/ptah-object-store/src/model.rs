use ptah_identifiers::{EntityId, EntityRef, IdentifierError};
use ptah_ledger::{Ledger, LedgerError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{io, path::PathBuf, sync::Arc};
use thiserror::Error;

/// Frozen Content schema identity.
pub const CONTENT_SCHEMA_ID: &str = "urn:ptah:schema:object:content:0.1.0";
/// Frozen Hash Observation schema identity.
pub const HASH_OBSERVATION_SCHEMA_ID: &str =
    "urn:ptah:schema:object:hash-observation:0.1.0";
/// Frozen logical Object schema identity.
pub const OBJECT_SCHEMA_ID: &str = "urn:ptah:schema:object:object:0.1.0";
/// Frozen Object Revision schema identity.
pub const REVISION_SCHEMA_ID: &str = "urn:ptah:schema:object:revision:0.1.0";
/// Frozen Relationship identity schema.
pub const RELATIONSHIP_SCHEMA_ID: &str = "urn:ptah:schema:object:relationship:0.1.0";
/// Frozen Relationship Revision schema.
pub const RELATIONSHIP_REVISION_SCHEMA_ID: &str =
    "urn:ptah:schema:object:relationship-revision:0.1.0";
/// Frozen Artifact schema identity.
pub const ARTIFACT_SCHEMA_ID: &str = "urn:ptah:schema:object:artifact:0.1.0";
/// Frozen Storage Location schema identity.
pub const LOCATION_SCHEMA_ID: &str = "urn:ptah:schema:storage:location:0.1.0";
/// Frozen Storage Location Observation schema identity.
pub const LOCATION_OBSERVATION_SCHEMA_ID: &str =
    "urn:ptah:schema:storage:location-observation:0.1.0";
/// Frozen Storage Verification schema identity.
pub const STORAGE_VERIFICATION_SCHEMA_ID: &str =
    "urn:ptah:schema:storage:verification:0.1.0";
/// Frozen Receipt schema consumed as evidence by A07.
pub const RECEIPT_SCHEMA_ID: &str = "urn:ptah:schema:activity:receipt:0.1.0";
pub(super) const ACTIVITY_SCHEMA_ID: &str = "urn:ptah:schema:activity:activity:0.1.0";
pub(super) const OPERATION_SCHEMA_ID: &str = "urn:ptah:schema:activity:operation:0.1.0";
pub(super) const ATTEMPT_SCHEMA_ID: &str = "urn:ptah:schema:activity:attempt:0.1.0";

const SCHEMA_VERSION: &str = "0.1.0";
const OBJECT_KIND: &str = "object.object";
const REVISION_KIND: &str = "object.revision";
const CONTENT_KIND: &str = "object.content";
const HASH_OBSERVATION_KIND: &str = "object.hash_observation";
const RELATIONSHIP_KIND: &str = "core.relationship";
const RELATIONSHIP_REVISION_KIND: &str = "core.relationship_revision";
const ARTIFACT_KIND: &str = "object.artifact";
const LOCATION_KIND: &str = "storage.location";
const LOCATION_OBSERVATION_KIND: &str = "storage.location_observation";
const STORAGE_VERIFICATION_KIND: &str = "storage.verification";
const CAS_BACKEND_ALIAS_KIND: &str = "path";

/// A07 failures.
#[derive(Debug, Error)]
pub enum ObjectStoreError {
    /// Durable ledger failure.
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    /// Canonical identifier failure.
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
    /// JSON serialization/deserialization failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Direct read-only ledger projection query failed.
    #[error("read-only ledger projection failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Local CAS filesystem operation failed.
    #[error("local CAS I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Referenced canonical entity does not exist.
    #[error("entity not found: {0}")]
    NotFound(EntityId),
    /// Referenced entity exists but has the wrong frozen schema/kind.
    #[error("entity type mismatch")]
    TypeMismatch,
    /// Required input was empty or otherwise invalid.
    #[error("invalid A07 input: {0}")]
    InvalidInput(&'static str),
    /// Required positive Receipt evidence was absent.
    #[error("missing positive Receipt evidence kind: {0}")]
    MissingReceiptKind(&'static str),
    /// A Receipt did not bind to the exact submitted Activity/Operation/Attempt.
    #[error("Receipt execution correlation mismatch")]
    ReceiptCorrelationMismatch,
    /// A Receipt was not positive proof evidence.
    #[error("Receipt outcome is not positive")]
    ReceiptNotPositive,
    /// A local CAS path already existed with bytes that do not match its digest.
    #[error("local CAS collision or corruption detected for {0}")]
    CasCollision(String),
    /// The requested operation requires a local-CAS location.
    #[error("location is not backed by the A07 local CAS")]
    UnsupportedLocation,
    /// Canonical record revision arithmetic overflowed.
    #[error("record revision overflow")]
    RevisionOverflow,
}

/// Frozen Content deduplication scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeduplicationScope {
    /// Reuse only inside one logical Object.
    ObjectOnly,
    /// Reuse inside one Workspace.
    Workspace,
    /// Reuse inside an organization trust domain.
    OrganizationTrustDomain,
    /// Reuse inside a deployment trust domain.
    DeploymentTrustDomain,
    /// Reuse content explicitly eligible for public-content deduplication.
    PublicContent,
}

impl DeduplicationScope {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ObjectOnly => "object_only",
            Self::Workspace => "workspace",
            Self::OrganizationTrustDomain => "organization_trust_domain",
            Self::DeploymentTrustDomain => "deployment_trust_domain",
            Self::PublicContent => "public_content",
        }
    }
}

/// Frozen Object Revision role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionRole {
    /// Original source bytes.
    Original,
    /// Imported bytes.
    Imported,
    /// Captured bytes.
    Captured,
    /// Human or tool edited bytes.
    Edited,
    /// Generated bytes.
    Generated,
    /// Normalized bytes.
    Normalized,
    /// Converted bytes.
    Converted,
    /// Rebuilt bytes.
    Rebuilt,
    /// Restored bytes.
    Restored,
    /// Merged bytes.
    Merged,
    /// Recovered bytes.
    Recovered,
    /// Tombstone Revision with no Content payload.
    Tombstone,
}

/// Frozen Object Revision origin class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginClass {
    /// Original source.
    OriginalSource,
    /// Uploaded original.
    UploadedOriginal,
    /// Captured original.
    CapturedOriginal,
    /// Recovered embedded source.
    RecoveredEmbeddedSource,
    /// Decoded resource.
    DecodedResource,
    /// Generated content.
    Generated,
    /// Decompiled view.
    DecompiledView,
    /// Disassembly view.
    DisassemblyView,
    /// Human-edited derivative.
    HumanEditedDerivative,
    /// Restored copy.
    RestoredCopy,
    /// Origin cannot be established.
    Unknown,
}

/// Frozen declared-name role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameRole {
    /// Original name.
    Original,
    /// Display name.
    Display,
    /// Leaf from the source path.
    SourcePathLeaf,
    /// User label.
    UserLabel,
    /// Generated name.
    Generated,
    /// Legacy name.
    Legacy,
}

/// Frozen declared-name source class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameSource {
    /// Caller supplied.
    Caller,
    /// Provider supplied.
    Provider,
    /// Filesystem supplied.
    Filesystem,
    /// Remote source supplied.
    RemoteSource,
    /// Generated by Ptah/tooling.
    Generated,
    /// Migrated from a legacy source.
    Migration,
}

/// One frozen logical Object name claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredName {
    /// Name text.
    pub name: String,
    /// Role of the name.
    pub name_role: NameRole,
    /// Source class of the name.
    pub source_class: NameSource,
}

/// Exact A04 execution correlation accepted by A07.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionCorrelation {
    /// Activity that owns the work.
    pub activity_ref: EntityRef,
    /// Logical Operation that produced/verified the result.
    pub operation_ref: EntityRef,
    /// Exact physical Attempt.
    pub attempt_ref: EntityRef,
    /// Positive immutable Receipt references for this exact Attempt.
    pub receipt_refs: Vec<EntityRef>,
}

/// Input for registering a new logical Object and first immutable Revision.
#[derive(Debug, Clone)]
pub struct RegisterObject {
    /// Workspace owning the canonical records.
    pub workspace_ref: EntityRef,
    /// Authority/provenance retained in entity envelopes.
    pub authority_ref: EntityRef,
    /// Object class key.
    pub object_class: String,
    /// Human/provider/source names retained for the Object.
    pub declared_names: Vec<DeclaredName>,
    /// Source entities from which the bytes were obtained.
    pub source_refs: Vec<EntityRef>,
    /// Role of the first immutable Revision.
    pub revision_role: RevisionRole,
    /// Origin class of the first immutable Revision.
    pub origin_class: OriginClass,
    /// Why this Revision was created.
    pub created_reason: String,
    /// Content deduplication scope.
    pub deduplication_scope: DeduplicationScope,
    /// Required only for organization/deployment trust-domain scopes.
    pub deduplication_scope_ref: Option<EntityRef>,
    /// Optional media-type claim; omitted from canonical JSON when absent.
    pub media_type_claim: Option<String>,
    /// Producer/observer identity.
    pub producer_ref: EntityRef,
    /// Producer version.
    pub producer_version: String,
    /// Local CAS backend identity.
    pub backend_ref: EntityRef,
    /// Connection/configuration identity used to reach the backend.
    pub connection_ref: EntityRef,
    /// Exact A04 production evidence.
    pub production_correlation: ProductionCorrelation,
}

/// Input for appending one immutable Revision to an existing logical Object.
#[derive(Debug, Clone)]
pub struct AppendRevision {
    /// Authority/provenance retained in entity envelopes.
    pub authority_ref: EntityRef,
    /// Source entities from which the bytes were obtained.
    pub source_refs: Vec<EntityRef>,
    /// New Revision role.
    pub revision_role: RevisionRole,
    /// New Revision origin class.
    pub origin_class: OriginClass,
    /// Why the Revision was created.
    pub created_reason: String,
    /// Content deduplication scope.
    pub deduplication_scope: DeduplicationScope,
    /// Required only for organization/deployment trust-domain scopes.
    pub deduplication_scope_ref: Option<EntityRef>,
    /// Optional media-type claim.
    pub media_type_claim: Option<String>,
    /// Producer/observer identity.
    pub producer_ref: EntityRef,
    /// Producer version.
    pub producer_version: String,
    /// Local CAS backend identity.
    pub backend_ref: EntityRef,
    /// Connection/configuration identity used to reach the backend.
    pub connection_ref: EntityRef,
    /// Exact A04 production evidence.
    pub production_correlation: ProductionCorrelation,
}

/// Result of new-Object or append-Revision registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    /// Logical Object identity.
    pub object_ref: EntityRef,
    /// Immutable Object Revision identity.
    pub revision_ref: EntityRef,
    /// Exact Content identity.
    pub content_ref: EntityRef,
    /// Local CAS Storage Location identity.
    pub location_ref: EntityRef,
    /// Whether an existing Content record was reused under the requested scope.
    pub reused_content: bool,
    /// Whether an existing local CAS Location record was reused.
    pub reused_location: bool,
}

/// Input for explicit local-CAS verification.
#[derive(Debug, Clone)]
pub struct VerifyLocation {
    /// Authority/provenance retained in new/updated records.
    pub authority_ref: EntityRef,
    /// Independent verifier identity.
    pub verifier_ref: EntityRef,
    /// Verifier version.
    pub verifier_version: String,
    /// Exact A04 verification evidence.
    pub production_correlation: ProductionCorrelation,
}

/// Result of one immutable Storage Verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    /// New immutable verification record.
    pub verification_ref: EntityRef,
    /// Frozen verification outcome.
    pub outcome: String,
    /// Updated location projection state.
    pub location_verification_state: String,
}

/// Input for one first-class Relationship and immutable first revision.
#[derive(Debug, Clone)]
pub struct CreateRelationship {
    /// Workspace owning the relationship.
    pub workspace_ref: EntityRef,
    /// Envelope authority/provenance.
    pub authority_ref: EntityRef,
    /// Relationship subjects.
    pub subject_refs: Vec<EntityRef>,
    /// Related Objects.
    pub object_refs: Vec<EntityRef>,
    /// Frozen lower-case relationship type key.
    pub relationship_type: String,
    /// Optional direction class.
    pub direction_class: Option<String>,
    /// Frozen locator documents.
    pub locators: Vec<Value>,
    /// Frozen coverage document.
    pub coverage: Value,
    /// Confidence class.
    pub confidence_class: String,
    /// Exact A04 production evidence.
    pub production_correlation: ProductionCorrelation,
}

/// Input for a promoted Artifact over exact Object Revisions.
#[derive(Debug, Clone)]
pub struct PromoteArtifact {
    /// Workspace owning the Artifact.
    pub workspace_ref: EntityRef,
    /// Envelope authority/provenance.
    pub authority_ref: EntityRef,
    /// Stable artifact type key.
    pub artifact_type: String,
    /// Artifact version label.
    pub artifact_version: String,
    /// Purpose of the Artifact.
    pub purpose: String,
    /// Subjects represented by the Artifact.
    pub subject_refs: Vec<EntityRef>,
    /// Exact immutable Object Revisions promoted into the Artifact.
    pub promoted_revision_refs: Vec<EntityRef>,
    /// Additional provenance references.
    pub provenance_refs: Vec<EntityRef>,
    /// Exact A04 promotion evidence.
    pub production_correlation: ProductionCorrelation,
}

/// Persistent A07 Object/CAS repository.
pub struct ObjectStore {
    pub(super) ledger: Ledger,
    pub(super) ledger_path: PathBuf,
    pub(super) cas_root: PathBuf,
    pub(super) clock: Arc<dyn Fn() -> String + Send + Sync>,
}
