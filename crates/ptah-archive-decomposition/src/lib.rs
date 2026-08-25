#![forbid(unsafe_code)]
//! A12 deterministic archive decomposition plus B02–B07 Object World and C01–C05 firmware foundations.
//!
//! Parser backends, type detectors, document, media, executable/package and filesystem Providers are
//! untrusted mechanical facilities. This crate owns path canonicalization, recursive resource budgets,
//! provenance, coverage truth, detector disagreement, progressive decomposition truth, passive
//! interpretation, derived source-bound search, C01 immutable disk normalization/partition
//! interpretation, C02 filesystem Provider validation/materialization, C03 Android image/OTA static
//! inspection, C04 Apple firmware archive/IMG4 static inspection, C05 `MediaTek` scatter/bundle static
//! inspection plus bounded read-only MTK/META evidence correlation and explicit proof levels, plus
//! canonical registration plans through the A07/A03 boundaries. Derived projections never replace
//! canonical source truth.

mod b02;
mod b03;
mod b04;
mod b04_review;
mod b05;
mod b07;
mod c01;
mod c02;
mod c03;
mod c04;
mod c05;
mod model;
mod persist;
mod policy;

pub use b02::{
    B02Error, ChildRelationship, DetectorEvidence, DetectorOutcome, ProgressiveLevel,
    ProgressiveReport, ProgressiveSpec, SearchMetadata, TypeAgreement, TypeAssessment,
    TypeDetector, TypeSignal, progressive_decompose,
};
pub use b03::{
    AdapterConversion, AdapterDocument, AdapterPage, AdapterTextSpan, AnchoredText, B03Error,
    ConvertedDocument, DocumentAdapter, DocumentContext, DocumentCoverage, DocumentIsolation,
    DocumentLimits, DocumentMetadata, DocumentPageView, DocumentReport, IsolationPolicy,
    SafeHtmlAdapter, SafePreview, SafeTextAdapter, SourceAnchor, inspect_document,
};
pub use b04::{
    AdapterDerivedMedia, AdapterMedia, AdapterMediaFrame, AdapterMediaView, B04Error, DerivedMedia,
    DerivedMediaKind, ImageTransformOperation, ImageTransformRequest, MediaAdapter, MediaClass,
    MediaContext, MediaCoverage, MediaDuration, MediaFrameView, MediaIsolation,
    MediaIsolationPolicy, MediaLimits, MediaMetadata, MediaRequest, MediaView, PixelDimensions,
    TranscodeRequest,
};
pub use b04_review::{MediaReport, inspect_media};
pub use b05::{
    AdapterEmbeddedChild, AdapterExecutable, B05Error, EmbeddedExecutableChild, ExecutableAdapter,
    ExecutableClass, ExecutableContext, ExecutableCoverage, ExecutableLimits, ExecutableMetadata,
    ExecutableReport, ExecutableSection, ExecutionAssessment, SignatureObservation,
    SignatureStatus, StaticIsolation, StaticIsolationPolicy, inspect_executable,
};
pub use b07::{
    SearchDocument, SearchDocumentKind, SearchDomain, SearchError, SearchField, SearchHit,
    SearchIndex, SearchIndexRevision, SearchLimits, SearchMatch, SearchQuery, SearchResponse,
    SearchSourceBinding, activity_search_document, artifact_search_document,
    document_text_search_document, filename_metadata_document, log_search_document,
    source_symbol_search_document,
};
pub use c01::{
    C01Error, DiskImageComparison, DiskImageContext, DiskImageFormat, DiskImageLimits,
    DiskImageReport, NormalizedDiskImage, PartitionEntry, PartitionLayoutKind,
    PartitionLayoutRange, PartitionMapAssessment, PartitionMaterialization, PartitionTableKind,
    PartitionTableRange, SourceCoverageKind, SourceCoverageRange, compare_disk_images,
    encode_android_sparse, inspect_partition_map, materialize_partition, normalize_disk_image,
};
pub use c02::{
    C02Error, FilesystemAssessment, FilesystemContentState, FilesystemContext,
    FilesystemCoverageKind, FilesystemCoverageRange, FilesystemDetection, FilesystemEntry,
    FilesystemEntryKind, FilesystemExtent, FilesystemFileMaterialization, FilesystemKind,
    FilesystemLimits, FilesystemProvider, FilesystemProviderAlias, FilesystemReport,
    ProviderFilesystemObservation, detect_filesystem, inspect_filesystem,
    materialize_filesystem_file,
};
pub use c03::{
    AndroidArtifactKind, AndroidAssessment, AndroidBlockDevice, AndroidComparison,
    AndroidComparisonLevel, AndroidComponent, AndroidComponentKind, AndroidContext,
    AndroidDynamicExtent, AndroidDynamicGroup, AndroidDynamicPartition, AndroidInspectRequest,
    AndroidIntegrityAssessment, AndroidLimits, AndroidMaterialization, AndroidOtaManifest,
    AndroidRebuildProofLevel, AndroidReport, AndroidTrustAssessment, C03Error, DynamicExtentTarget,
    OtaDynamicGroup, OtaManifestObservation, OtaManifestProvider, OtaOperationRange,
    OtaPartitionUpdate, assess_android_rebuild, compare_android_artifacts,
    inspect_android_artifact, materialize_android_component, materialize_dynamic_partition,
};
pub use c04::{
    AppleArchiveEntry, AppleArchiveEntryObservation, AppleArchiveObservation, AppleArchiveProvider,
    AppleArchiveRole, AppleAssessment, AppleComparison, AppleComparisonLevel, AppleDerComponent,
    AppleDerComponentKind, AppleFirmwareArtifactKind, AppleFirmwareContext, AppleFirmwareLimits,
    AppleFirmwareReport, AppleInspectRequest, AppleManifest, AppleManifestComponent,
    AppleManifestComponentObservation, AppleManifestObservation, AppleManifestProvider,
    AppleMaterialization, AppleStaticProofLevel, AppleTrustAssessment, C04Error,
    assess_apple_rebuild, compare_apple_firmware, inspect_apple_firmware,
    materialize_apple_archive_entry, materialize_apple_der_component,
};
pub use c05::{
    C05Error, MediatekAssessment, MediatekBundleEntry, MediatekBundleEntryObservation,
    MediatekBundleObservation, MediatekBundleProvider, MediatekComparison, MediatekComparisonLevel,
    MediatekContext, MediatekEvidence, MediatekEvidenceCorrelation, MediatekEvidenceLevel,
    MediatekEvidenceObservation, MediatekEvidenceProvider, MediatekLimits, MediatekMaterialization,
    MediatekMode, MediatekPartition, MediatekPartitionRange, MediatekReport,
    MediatekStaticProofLevel, MediatekTrustAssessment, assess_mediatek_rebuild,
    compare_mediatek_packages, inspect_mediatek_package, materialize_mediatek_component,
};
pub use model::{
    ArchiveBackend, BackendIdentity, DecompositionBudget, DecompositionClock, DecompositionOutcome,
    DecompositionPlan, DecompositionSpec, InventoryEntry, MemberKind, ParseReport, ParseTerminal,
    ParsedMember, PersistedDecomposition, RecoveredMember,
};
pub use persist::{DECOMPOSITION_RUN_SCHEMA_ID, DecompositionStore};
pub use policy::{decompose, stable_decomposition_identity};

use ptah_identifiers::IdentifierError;
use ptah_ledger::LedgerError;
use ptah_object_store::ObjectStoreError;
use thiserror::Error;

/// A12 failures that prevent a truthful decomposition result from being retained.
#[derive(Debug, Error)]
pub enum DecompositionError {
    /// Backend invocation failed before it could return a bounded report.
    #[error("archive backend failed: {0}")]
    Backend(String),
    /// Archive member path violated deterministic A12 path policy.
    #[error("archive path rejected: {0}")]
    InvalidPath(String),
    /// Two archive members canonicalized to the same path.
    #[error("duplicate canonical archive path: {0}")]
    DuplicatePath(String),
    /// Link or special-file entry is outside the accepted A12 materialization policy.
    #[error("archive entry kind rejected at {path}: {kind}")]
    EntryKindRejected {
        /// Canonical member path.
        path: String,
        /// Rejected member kind.
        kind: &'static str,
    },
    /// A requested decomposition budget is invalid.
    #[error("invalid decomposition budget: {0}")]
    InvalidBudget(&'static str),
    /// Numeric accounting exceeded representable bounds.
    #[error("decomposition accounting overflow")]
    AccountingOverflow,
    /// Source Object Revision does not match the supplied bytes/workspace/evidence.
    #[error("source revision/evidence mismatch")]
    SourceMismatch,
    /// Canonical record did not have the expected shape.
    #[error("canonical A12 record type mismatch")]
    TypeMismatch,
    /// The injected clock cannot produce frozen UTC timestamps.
    #[error("invalid UTC timestamp")]
    InvalidTimestamp,
    /// A03 ledger failure.
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    /// A07 object/view/relationship registration failure.
    #[error(transparent)]
    ObjectStore(#[from] ObjectStoreError),
    /// Canonical identifier failure.
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
    /// Canonical JSON serialization failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
