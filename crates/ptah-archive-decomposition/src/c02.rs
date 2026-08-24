use ptah_identifiers::EntityRef;
use ptah_object_store::{
    OriginClass, ProductionEvidence, RegisterObjectSpec, Registration, RelationshipSpec,
    RevisionRole, ViewSpec,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAX_DECLARED_NAME_BYTES: usize = 8_192;

/// Filesystem families in the C02 public provider contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FilesystemKind {
    /// Linux ext2/3/4 family, delivered as ext4 provider capability.
    Ext4,
    /// Enhanced Read-Only File System.
    Erofs,
    /// Flash-Friendly File System.
    F2fs,
    /// `SquashFS`.
    SquashFs,
    /// UBI container layer.
    Ubi,
    /// UBIFS filesystem layer.
    Ubifs,
    /// FAT12/16/32 family.
    Fat,
    /// NTFS.
    Ntfs,
    /// ISO-9660 optical filesystem.
    Iso9660,
    /// No supported C02 signature was mechanically recognized.
    Unknown,
}

impl FilesystemKind {
    /// Stable human-readable provider family name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ext4 => "ext4",
            Self::Erofs => "erofs",
            Self::F2fs => "f2fs",
            Self::SquashFs => "squashfs",
            Self::Ubi => "ubi",
            Self::Ubifs => "ubifs",
            Self::Fat => "fat",
            Self::Ntfs => "ntfs",
            Self::Iso9660 => "iso9660",
            Self::Unknown => "unknown",
        }
    }
}

/// Truth status of one C02 filesystem interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemAssessment {
    /// Provider evidence covers the declared filesystem without unsupported or unknown regions.
    Complete,
    /// Useful filesystem evidence exists but coverage or feature support is incomplete.
    Partial,
    /// C02 cannot establish a trustworthy filesystem inventory.
    Inconclusive,
}

/// Mechanically detected source filesystem evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemDetection {
    /// Detected filesystem family.
    pub kind: FilesystemKind,
    /// Exact signature observation used for the classification.
    pub evidence: Vec<String>,
}

/// C02 read-coverage classification over exact source bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemCoverageKind {
    /// Bytes were mechanically interpreted by the provider and may back exact file extents.
    Read,
    /// Bytes are mechanically classified as filesystem free/unallocated space.
    Unallocated,
    /// Provider did not establish ownership or meaning for this range.
    Unknown,
    /// Provider identified a range whose feature/encoding it cannot safely interpret.
    Unsupported,
}

/// One exact non-overlapping source byte range in a C02 coverage projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemCoverageRange {
    /// Inclusive source byte start.
    pub byte_start: u64,
    /// Exclusive source byte end.
    pub byte_end_exclusive: u64,
    /// Provider/C02 coverage classification.
    pub kind: FilesystemCoverageKind,
}

/// Filesystem entry kind retained by C02.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemEntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic-link-like entry. C02 never follows it while materializing.
    Symlink,
    /// Device, socket, FIFO or other special entry.
    Special,
}

/// How much file content a provider has established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemContentState {
    /// Exact regular-file bytes are mechanically reconstructable from the retained extents.
    Exact,
    /// Metadata is retained but exact file bytes are not established.
    MetadataOnly,
    /// Provider explicitly encountered an unsupported content feature.
    Unsupported,
}

/// One logical file extent in reconstruction order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesystemExtent {
    /// Exact source bytes.
    Data {
        /// Inclusive source byte start.
        source_start: u64,
        /// Exclusive source byte end.
        source_end_exclusive: u64,
    },
    /// Filesystem-defined zero/hole bytes requiring no invented source allocation.
    Zero {
        /// Logical zero-byte length.
        length: u64,
    },
}

impl FilesystemExtent {
    fn logical_len(&self) -> Result<u64, C02Error> {
        match self {
            Self::Data {
                source_start,
                source_end_exclusive,
            } => source_end_exclusive
                .checked_sub(*source_start)
                .filter(|length| *length > 0)
                .ok_or(C02Error::InvalidExtent),
            Self::Zero { length } if *length > 0 => Ok(*length),
            Self::Zero { .. } => Err(C02Error::InvalidExtent),
        }
    }
}

/// One provider-reported filesystem entry after C02 validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemEntry {
    /// Canonical relative path. Absolute paths and traversal components are forbidden.
    pub path: String,
    /// Entry kind.
    pub kind: FilesystemEntryKind,
    /// Logical file size. Non-file entries use zero.
    pub size: u64,
    /// Exact-content availability state.
    pub content_state: FilesystemContentState,
    /// Logical reconstruction extents. Only exact regular files may retain extents.
    pub extents: Vec<FilesystemExtent>,
    /// Exact content digest for an exact regular file.
    pub content_sha256: Option<String>,
    /// Bounded passive metadata.
    pub metadata: BTreeMap<String, String>,
    /// Entry-specific unsupported/partial limitations.
    pub limitations: Vec<String>,
}

/// Provider/mount identifiers retained strictly as scoped aliases/evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemProviderAlias {
    /// Provider-local identifier. Never canonical Ptah identity.
    pub provider_id: String,
    /// Exact provider revision/version evidence.
    pub provider_revision: String,
    /// Provider Generation used for the observation.
    pub generation: u64,
    /// Optional provider-local read-only mount/session handle.
    pub mount_id: Option<String>,
}

/// Untrusted provider output consumed by C02.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFilesystemObservation {
    /// Filesystem family the Provider believes it inspected.
    pub filesystem_kind: FilesystemKind,
    /// Provider claim that the requested filesystem coverage is complete.
    pub complete_claim: bool,
    /// Provider inventory entries.
    pub entries: Vec<FilesystemEntry>,
    /// Provider byte-coverage evidence. Gaps are converted to `Unknown` by C02.
    pub coverage: Vec<FilesystemCoverageRange>,
    /// Bounded filesystem-level metadata.
    pub metadata: BTreeMap<String, String>,
    /// Provider limitations and unsupported features.
    pub limitations: Vec<String>,
}

/// Replaceable filesystem engine contract.
pub trait FilesystemProvider {
    /// Alias/evidence describing the concrete Provider instance.
    fn alias(&self) -> FilesystemProviderAlias;

    /// Whether this Provider implements the requested filesystem family.
    fn supports(&self, kind: FilesystemKind) -> bool;

    /// Inspect exact immutable source bytes without mutating them.
    ///
    /// # Errors
    /// Provider invocation failure is returned as evidence and cannot become a complete report.
    fn inspect(
        &self,
        source: &[u8],
        kind: FilesystemKind,
        limits: FilesystemLimits,
    ) -> Result<ProviderFilesystemObservation, String>;
}

/// Exact A07 context for one immutable filesystem source Revision.
#[derive(Debug, Clone)]
pub struct FilesystemContext {
    /// Workspace owning the source Object Revision.
    pub workspace_ref: EntityRef,
    /// Authority used for A07 plans.
    pub authority_ref: EntityRef,
    /// Exact filesystem source Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact production evidence attached to derived plans.
    pub production: ProductionEvidence,
}

/// C02 bounded resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilesystemLimits {
    /// Maximum accepted filesystem source bytes.
    pub max_source_bytes: u64,
    /// Maximum retained entries.
    pub max_entries: usize,
    /// Maximum retained coverage ranges before gap canonicalization.
    pub max_coverage_ranges: usize,
    /// Maximum extents retained for one file.
    pub max_extents_per_file: usize,
    /// Maximum exact file bytes materialized in one call.
    pub max_materialize_bytes: u64,
    /// Maximum canonical path length in bytes.
    pub max_path_bytes: usize,
    /// Maximum metadata/limitation string length in bytes.
    pub max_string_bytes: usize,
    /// Maximum metadata pairs on a report or entry.
    pub max_metadata_pairs: usize,
}

impl Default for FilesystemLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 16 * 1024 * 1024 * 1024,
            max_entries: 1_000_000,
            max_coverage_ranges: 1_000_000,
            max_extents_per_file: 262_144,
            max_materialize_bytes: 4 * 1024 * 1024 * 1024,
            max_path_bytes: MAX_DECLARED_NAME_BYTES,
            max_string_bytes: 16 * 1024,
            max_metadata_pairs: 4_096,
        }
    }
}

/// Source-bound C02 filesystem report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemReport {
    /// Exact immutable source Object Revision.
    pub source_revision_ref: EntityRef,
    /// SHA-256 of exact source bytes.
    pub source_sha256: String,
    /// Exact source byte size.
    pub source_size: u64,
    /// Mechanically detected filesystem evidence.
    pub detection: FilesystemDetection,
    /// Concrete provider evidence retained only as Aliases.
    pub provider_alias: Option<FilesystemProviderAlias>,
    /// Truth assessment after C02 validation.
    pub assessment: FilesystemAssessment,
    /// Validated filesystem inventory.
    pub entries: Vec<FilesystemEntry>,
    /// Exact read/unallocated/unknown/unsupported source coverage.
    pub coverage: Vec<FilesystemCoverageRange>,
    /// Bounded provider metadata.
    pub metadata: BTreeMap<String, String>,
    /// Explicit partial/unsupported limitations.
    pub limitations: Vec<String>,
    projection_sha256: String,
}

impl FilesystemReport {
    /// Build source-bound A07 inventory and read-coverage Views.
    ///
    /// # Errors
    /// Rejects post-inspection report mutation or a mismatched source Revision.
    pub fn view_specs(&self, context: &FilesystemContext) -> Result<Vec<ViewSpec>, C02Error> {
        validate_context(context)?;
        validate_report_integrity(self)?;
        if self.source_revision_ref != context.source_revision_ref {
            return Err(C02Error::SourceBindingMismatch);
        }
        Ok(vec![
            view_spec(context, "filesystem.inventory", "inventory"),
            view_spec(context, "filesystem.read_coverage", "read-coverage"),
        ])
    }
}

/// Exact immutable regular-file materialization from a C02 report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemFileMaterialization {
    /// Validated inventory entry.
    pub entry: FilesystemEntry,
    /// Exact source Object Revision.
    pub source_revision_ref: EntityRef,
    /// SHA-256 of exact materialized file bytes.
    pub sha256: String,
    bytes: Vec<u8>,
}

impl FilesystemFileMaterialization {
    /// Read-only exact file bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Build an A07 recovered-file registration plan.
    ///
    /// # Errors
    /// Rejects malformed or mismatched canonical source context.
    pub fn registration_spec(
        &self,
        context: &FilesystemContext,
    ) -> Result<RegisterObjectSpec, C02Error> {
        validate_context(context)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C02Error::SourceBindingMismatch);
        }
        if self.entry.path.len() > MAX_DECLARED_NAME_BYTES {
            return Err(C02Error::UnsafePath);
        }
        Ok(RegisterObjectSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            object_class: "filesystem.file".to_owned(),
            declared_name: Some(self.entry.path.clone()),
            source_refs: vec![self.source_revision_ref.clone()],
            revision_role: RevisionRole::Recovered,
            origin_class: OriginClass::RecoveredEmbeddedSource,
            created_reason: "C02 exact read-only filesystem file materialization".to_owned(),
            production: context.production.clone(),
            expected_sha256: Some(self.sha256.clone()),
        })
    }

    /// Build an exact source-to-file A07 Relationship plan.
    ///
    /// # Errors
    /// Rejects registration evidence that does not describe these exact bytes.
    pub fn relationship_spec(
        &self,
        context: &FilesystemContext,
        registration: &Registration,
    ) -> Result<RelationshipSpec, C02Error> {
        validate_context(context)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C02Error::SourceBindingMismatch);
        }
        if registration.object_ref.entity_kind.as_str() != "object.object"
            || registration.revision_ref.entity_kind.as_str() != "object.revision"
        {
            return Err(C02Error::InvalidFileRegistration);
        }
        let byte_size =
            u64::try_from(self.bytes.len()).map_err(|_| C02Error::AccountingOverflow)?;
        if registration.sha256 != self.sha256 || registration.byte_size != byte_size {
            return Err(C02Error::FileRegistrationMismatch);
        }
        Ok(RelationshipSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            subject_refs: vec![self.source_revision_ref.clone()],
            relationship_type: "contains.filesystem_file".to_owned(),
            object_refs: vec![
                registration.object_ref.clone(),
                registration.revision_ref.clone(),
            ],
            production: context.production.clone(),
        })
    }
}

/// C02 validation and safety failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum C02Error {
    /// Workspace context is not canonical.
    #[error("C02 workspace must be core.workspace")]
    InvalidWorkspaceRef,
    /// Source must be an exact Object Revision.
    #[error("C02 source must be object.revision")]
    InvalidSourceRevision,
    /// One or more configured bounds are zero or inconsistent.
    #[error("C02 filesystem limits are invalid")]
    InvalidLimits,
    /// Source bytes exceed configured bounds.
    #[error("C02 filesystem source exceeds max_source_bytes")]
    SourceTooLarge,
    /// Concrete Provider alias evidence is malformed.
    #[error("C02 provider alias evidence is invalid")]
    InvalidProviderAlias,
    /// Provider does not support the mechanically detected filesystem.
    #[error("C02 provider does not support detected filesystem")]
    ProviderUnsupported,
    /// Provider invocation failed.
    #[error("C02 provider failed: {0}")]
    Provider(String),
    /// Provider filesystem family disagrees with C02 mechanical detection.
    #[error("C02 provider filesystem kind disagrees with mechanical detection")]
    ProviderKindMismatch,
    /// Provider attempted a complete claim while unknown/unsupported evidence remains.
    #[error("C02 provider complete claim is not supported by retained evidence")]
    FalseCompletenessClaim,
    /// Provider coverage is malformed, overlapping or out of source bounds.
    #[error("C02 filesystem coverage is invalid")]
    InvalidCoverage,
    /// Provider inventory exceeded configured bounds.
    #[error("C02 filesystem inventory exceeds configured bounds")]
    TooManyEntries,
    /// Provider coverage exceeded configured bounds.
    #[error("C02 filesystem coverage exceeds configured bounds")]
    TooManyCoverageRanges,
    /// Entry path violates traversal/canonicalization policy.
    #[error("C02 filesystem entry path is unsafe")]
    UnsafePath,
    /// Two entries use the same canonical path.
    #[error("C02 duplicate filesystem entry path")]
    DuplicatePath,
    /// Entry metadata or limitation strings exceed configured bounds.
    #[error("C02 filesystem metadata exceeds configured bounds")]
    MetadataTooLarge,
    /// File extent declaration is malformed or out of bounds.
    #[error("C02 filesystem file extent is invalid")]
    InvalidExtent,
    /// Exact file extent is not fully backed by provider `Read` coverage.
    #[error("C02 exact file extent is not backed by read coverage")]
    ExtentNotReadable,
    /// Exact file size/extents/digest contract is inconsistent.
    #[error("C02 exact filesystem file contract is inconsistent")]
    ExactFileMismatch,
    /// Requested entry is absent.
    #[error("C02 filesystem entry was not found")]
    EntryNotFound,
    /// Requested entry is not an exact materializable regular file.
    #[error("C02 filesystem entry is not exactly materializable")]
    EntryNotMaterializable,
    /// Materialization exceeds configured output bound.
    #[error("C02 file materialization exceeds configured bound")]
    MaterializationTooLarge,
    /// Materialized digest disagrees with provider-retained exact evidence.
    #[error("C02 materialized file digest mismatch")]
    MaterializedDigestMismatch,
    /// Source/report/context do not describe the same exact Revision/bytes.
    #[error("C02 source/report binding mismatch")]
    SourceBindingMismatch,
    /// Report fields were mutated after C02 sealed the projection.
    #[error("C02 filesystem report integrity seal mismatch")]
    ReportIntegrityMismatch,
    /// Registration endpoints are not canonical Object/Object-Revision refs.
    #[error("C02 file registration endpoint kinds are invalid")]
    InvalidFileRegistration,
    /// Registration digest/size does not match exact materialized bytes.
    #[error("C02 file registration does not match exact bytes")]
    FileRegistrationMismatch,
    /// Numeric accounting overflowed.
    #[error("C02 filesystem accounting overflow")]
    AccountingOverflow,
}

/// Detect a required C02 filesystem family from exact source signature evidence.
#[must_use]
pub fn detect_filesystem(source: &[u8]) -> FilesystemDetection {
    if has_bytes_at(source, 3, b"NTFS    ") && has_boot_signature(source) {
        return detection(FilesystemKind::Ntfs, "NTFS OEM ID at bytes 3..11");
    }
    if has_bytes_at(source, 32_769, b"CD001") && source.get(32_768) == Some(&1) {
        return detection(
            FilesystemKind::Iso9660,
            "ISO-9660 primary volume descriptor at sector 16",
        );
    }
    if has_bytes_at(source, 0, b"hsqs") {
        return detection(FilesystemKind::SquashFs, "SquashFS magic at byte 0");
    }
    if has_bytes_at(source, 0, b"UBI#") {
        return detection(
            FilesystemKind::Ubi,
            "UBI erase-counter header magic at byte 0",
        );
    }
    if has_bytes_at(source, 0, &[0x31, 0x18, 0x10, 0x06]) {
        return detection(FilesystemKind::Ubifs, "UBIFS node magic at byte 0");
    }
    if has_bytes_at(source, 1_024, &0xe0f5_e1e2_u32.to_le_bytes()) {
        return detection(FilesystemKind::Erofs, "EROFS superblock magic at byte 1024");
    }
    if has_bytes_at(source, 1_024, &0xf2f5_2010_u32.to_le_bytes()) {
        return detection(FilesystemKind::F2fs, "F2FS superblock magic at byte 1024");
    }
    if has_bytes_at(source, 1_080, &0xef53_u16.to_le_bytes()) {
        return detection(
            FilesystemKind::Ext4,
            "ext filesystem magic at superblock+0x38",
        );
    }
    if let Some(fat) = detect_fat(source) {
        return fat;
    }
    FilesystemDetection {
        kind: FilesystemKind::Unknown,
        evidence: vec!["no required C02 filesystem signature recognized".to_owned()],
    }
}

/// Validate one replaceable Provider observation and produce a sealed source-bound C02 report.
///
/// Passing `None` retains detection-only evidence as an inconclusive report rather than inventing
/// provider coverage.
///
/// # Errors
/// Rejects malformed context/limits, Provider disagreement, unsafe retained state, or unsupported
/// complete claims.
pub fn inspect_filesystem(
    source: &[u8],
    context: &FilesystemContext,
    limits: FilesystemLimits,
    provider: Option<&dyn FilesystemProvider>,
) -> Result<FilesystemReport, C02Error> {
    validate_context(context)?;
    validate_limits(limits)?;
    let source_size = u64::try_from(source.len()).map_err(|_| C02Error::AccountingOverflow)?;
    if source_size > limits.max_source_bytes {
        return Err(C02Error::SourceTooLarge);
    }
    let detection = detect_filesystem(source);
    let source_sha256 = sha256_bytes(source);

    let Some(provider) = provider else {
        return Ok(seal_report(FilesystemReport {
            source_revision_ref: context.source_revision_ref.clone(),
            source_sha256,
            source_size,
            detection,
            provider_alias: None,
            assessment: FilesystemAssessment::Inconclusive,
            entries: Vec::new(),
            coverage: unknown_coverage(source_size),
            metadata: BTreeMap::new(),
            limitations: vec!["no C02 filesystem Provider was supplied".to_owned()],
            projection_sha256: String::new(),
        }));
    };

    if detection.kind == FilesystemKind::Unknown {
        return Ok(seal_report(FilesystemReport {
            source_revision_ref: context.source_revision_ref.clone(),
            source_sha256,
            source_size,
            detection,
            provider_alias: None,
            assessment: FilesystemAssessment::Inconclusive,
            entries: Vec::new(),
            coverage: unknown_coverage(source_size),
            metadata: BTreeMap::new(),
            limitations: vec![
                "filesystem signature is outside the current C02 required family set".to_owned(),
            ],
            projection_sha256: String::new(),
        }));
    }

    let alias = provider.alias();
    validate_provider_alias(&alias, limits)?;
    if !provider.supports(detection.kind) {
        return Err(C02Error::ProviderUnsupported);
    }
    let observation = provider
        .inspect(source, detection.kind, limits)
        .map_err(C02Error::Provider)?;
    if observation.filesystem_kind != detection.kind {
        return Err(C02Error::ProviderKindMismatch);
    }
    validate_metadata(&observation.metadata, limits)?;
    validate_limitations(&observation.limitations, limits)?;
    let coverage = canonicalize_coverage(observation.coverage, source_size, limits)?;
    validate_entries(&observation.entries, &coverage, source_size, limits)?;

    let can_be_complete = complete_evidence_supported(
        &observation.entries,
        &coverage,
        &observation.limitations,
        source_size,
    );
    if observation.complete_claim && !can_be_complete {
        return Err(C02Error::FalseCompletenessClaim);
    }
    let assessment = if observation.complete_claim {
        FilesystemAssessment::Complete
    } else if observation.entries.is_empty()
        && !coverage
            .iter()
            .any(|range| range.kind == FilesystemCoverageKind::Read)
    {
        FilesystemAssessment::Inconclusive
    } else {
        FilesystemAssessment::Partial
    };
    let mut limitations = observation.limitations;
    if assessment != FilesystemAssessment::Complete && limitations.is_empty() {
        limitations.push("Provider did not establish complete filesystem coverage".to_owned());
    }

    Ok(seal_report(FilesystemReport {
        source_revision_ref: context.source_revision_ref.clone(),
        source_sha256,
        source_size,
        detection,
        provider_alias: Some(alias),
        assessment,
        entries: observation.entries,
        coverage,
        metadata: observation.metadata,
        limitations,
        projection_sha256: String::new(),
    }))
}

/// Materialize one exact regular file without following links or provider mount paths.
///
/// # Errors
/// Rejects report/source mutation, unsafe or non-exact entries, unsupported byte coverage, digest
/// mismatch, and configured output overflow.
pub fn materialize_filesystem_file(
    source: &[u8],
    report: &FilesystemReport,
    path: &str,
    context: &FilesystemContext,
    limits: FilesystemLimits,
) -> Result<FilesystemFileMaterialization, C02Error> {
    validate_context(context)?;
    validate_limits(limits)?;
    validate_report_integrity(report)?;
    if report.source_revision_ref != context.source_revision_ref
        || report.source_sha256 != sha256_bytes(source)
        || report.source_size
            != u64::try_from(source.len()).map_err(|_| C02Error::AccountingOverflow)?
    {
        return Err(C02Error::SourceBindingMismatch);
    }
    validate_path(path, limits)?;
    let entry = report
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .cloned()
        .ok_or(C02Error::EntryNotFound)?;
    if entry.kind != FilesystemEntryKind::File
        || entry.content_state != FilesystemContentState::Exact
    {
        return Err(C02Error::EntryNotMaterializable);
    }
    if entry.size > limits.max_materialize_bytes {
        return Err(C02Error::MaterializationTooLarge);
    }
    let mut output = Vec::new();
    let reserve = usize::try_from(entry.size).map_err(|_| C02Error::MaterializationTooLarge)?;
    output
        .try_reserve_exact(reserve)
        .map_err(|_| C02Error::MaterializationTooLarge)?;
    for extent in &entry.extents {
        match extent {
            FilesystemExtent::Data {
                source_start,
                source_end_exclusive,
            } => {
                if !range_is_exact_read(&report.coverage, *source_start, *source_end_exclusive) {
                    return Err(C02Error::ExtentNotReadable);
                }
                let start = usize::try_from(*source_start).map_err(|_| C02Error::InvalidExtent)?;
                let end =
                    usize::try_from(*source_end_exclusive).map_err(|_| C02Error::InvalidExtent)?;
                output.extend_from_slice(source.get(start..end).ok_or(C02Error::InvalidExtent)?);
            }
            FilesystemExtent::Zero { length } => {
                let next = u64::try_from(output.len())
                    .map_err(|_| C02Error::AccountingOverflow)?
                    .checked_add(*length)
                    .ok_or(C02Error::AccountingOverflow)?;
                if next > entry.size || next > limits.max_materialize_bytes {
                    return Err(C02Error::MaterializationTooLarge);
                }
                output.resize(
                    usize::try_from(next).map_err(|_| C02Error::MaterializationTooLarge)?,
                    0,
                );
            }
        }
    }
    if u64::try_from(output.len()).map_err(|_| C02Error::AccountingOverflow)? != entry.size {
        return Err(C02Error::ExactFileMismatch);
    }
    let digest = sha256_bytes(&output);
    if entry.content_sha256.as_deref() != Some(digest.as_str()) {
        return Err(C02Error::MaterializedDigestMismatch);
    }
    Ok(FilesystemFileMaterialization {
        entry,
        source_revision_ref: context.source_revision_ref.clone(),
        sha256: digest,
        bytes: output,
    })
}

fn validate_context(context: &FilesystemContext) -> Result<(), C02Error> {
    if context.workspace_ref.entity_kind.as_str() != "core.workspace" {
        return Err(C02Error::InvalidWorkspaceRef);
    }
    if context.source_revision_ref.entity_kind.as_str() != "object.revision" {
        return Err(C02Error::InvalidSourceRevision);
    }
    Ok(())
}

fn validate_limits(limits: FilesystemLimits) -> Result<(), C02Error> {
    if limits.max_source_bytes == 0
        || limits.max_entries == 0
        || limits.max_coverage_ranges == 0
        || limits.max_extents_per_file == 0
        || limits.max_materialize_bytes == 0
        || limits.max_path_bytes == 0
        || limits.max_path_bytes > MAX_DECLARED_NAME_BYTES
        || limits.max_string_bytes == 0
        || limits.max_metadata_pairs == 0
    {
        return Err(C02Error::InvalidLimits);
    }
    Ok(())
}

fn validate_provider_alias(
    alias: &FilesystemProviderAlias,
    limits: FilesystemLimits,
) -> Result<(), C02Error> {
    if alias.generation == 0
        || !bounded_nonempty(&alias.provider_id, limits.max_string_bytes)
        || !bounded_nonempty(&alias.provider_revision, limits.max_string_bytes)
        || alias
            .mount_id
            .as_deref()
            .is_some_and(|mount_id| !bounded_nonempty(mount_id, limits.max_string_bytes))
    {
        return Err(C02Error::InvalidProviderAlias);
    }
    Ok(())
}

fn validate_metadata(
    metadata: &BTreeMap<String, String>,
    limits: FilesystemLimits,
) -> Result<(), C02Error> {
    if metadata.len() > limits.max_metadata_pairs
        || metadata.iter().any(|(key, value)| {
            !bounded_nonempty(key, limits.max_string_bytes) || value.len() > limits.max_string_bytes
        })
    {
        return Err(C02Error::MetadataTooLarge);
    }
    Ok(())
}

fn validate_limitations(limitations: &[String], limits: FilesystemLimits) -> Result<(), C02Error> {
    if limitations.len() > limits.max_metadata_pairs
        || limitations
            .iter()
            .any(|value| !bounded_nonempty(value, limits.max_string_bytes))
    {
        return Err(C02Error::MetadataTooLarge);
    }
    Ok(())
}

fn canonicalize_coverage(
    mut coverage: Vec<FilesystemCoverageRange>,
    source_size: u64,
    limits: FilesystemLimits,
) -> Result<Vec<FilesystemCoverageRange>, C02Error> {
    if coverage.len() > limits.max_coverage_ranges {
        return Err(C02Error::TooManyCoverageRanges);
    }
    coverage.sort_by_key(|range| (range.byte_start, range.byte_end_exclusive));
    let mut cursor = 0_u64;
    let mut canonical = Vec::with_capacity(coverage.len().saturating_mul(2).saturating_add(1));
    for range in coverage {
        if range.byte_start >= range.byte_end_exclusive
            || range.byte_end_exclusive > source_size
            || range.byte_start < cursor
        {
            return Err(C02Error::InvalidCoverage);
        }
        if cursor < range.byte_start {
            push_coverage(
                &mut canonical,
                cursor,
                range.byte_start,
                FilesystemCoverageKind::Unknown,
            );
        }
        push_coverage(
            &mut canonical,
            range.byte_start,
            range.byte_end_exclusive,
            range.kind,
        );
        cursor = range.byte_end_exclusive;
    }
    if cursor < source_size {
        push_coverage(
            &mut canonical,
            cursor,
            source_size,
            FilesystemCoverageKind::Unknown,
        );
    }
    if canonical.len()
        > limits
            .max_coverage_ranges
            .saturating_mul(2)
            .saturating_add(1)
    {
        return Err(C02Error::TooManyCoverageRanges);
    }
    Ok(canonical)
}

fn validate_entries(
    entries: &[FilesystemEntry],
    coverage: &[FilesystemCoverageRange],
    source_size: u64,
    limits: FilesystemLimits,
) -> Result<(), C02Error> {
    if entries.len() > limits.max_entries {
        return Err(C02Error::TooManyEntries);
    }
    let mut paths = BTreeSet::new();
    for entry in entries {
        validate_path(&entry.path, limits)?;
        if !paths.insert(entry.path.as_str()) {
            return Err(C02Error::DuplicatePath);
        }
        validate_metadata(&entry.metadata, limits)?;
        validate_limitations(&entry.limitations, limits)?;
        validate_entry_contract(entry, coverage, source_size, limits)?;
    }
    Ok(())
}

fn validate_entry_contract(
    entry: &FilesystemEntry,
    coverage: &[FilesystemCoverageRange],
    source_size: u64,
    limits: FilesystemLimits,
) -> Result<(), C02Error> {
    if entry.extents.len() > limits.max_extents_per_file {
        return Err(C02Error::InvalidExtent);
    }
    if entry.kind != FilesystemEntryKind::File {
        if entry.size != 0 || !entry.extents.is_empty() || entry.content_sha256.is_some() {
            return Err(C02Error::ExactFileMismatch);
        }
        return Ok(());
    }
    match entry.content_state {
        FilesystemContentState::Exact => validate_exact_file(entry, coverage, source_size),
        FilesystemContentState::MetadataOnly | FilesystemContentState::Unsupported => {
            if !entry.extents.is_empty() || entry.content_sha256.is_some() {
                return Err(C02Error::ExactFileMismatch);
            }
            if entry.limitations.is_empty() {
                return Err(C02Error::ExactFileMismatch);
            }
            Ok(())
        }
    }
}

fn validate_exact_file(
    entry: &FilesystemEntry,
    coverage: &[FilesystemCoverageRange],
    source_size: u64,
) -> Result<(), C02Error> {
    if entry
        .content_sha256
        .as_deref()
        .is_none_or(|digest| digest.len() != 64)
    {
        return Err(C02Error::ExactFileMismatch);
    }
    if entry.size > 0 && entry.extents.is_empty() {
        return Err(C02Error::ExactFileMismatch);
    }
    let mut logical_size = 0_u64;
    for extent in &entry.extents {
        let length = extent.logical_len()?;
        logical_size = logical_size
            .checked_add(length)
            .ok_or(C02Error::AccountingOverflow)?;
        if let FilesystemExtent::Data {
            source_start,
            source_end_exclusive,
        } = extent
        {
            if *source_end_exclusive > source_size {
                return Err(C02Error::InvalidExtent);
            }
            if !range_is_exact_read(coverage, *source_start, *source_end_exclusive) {
                return Err(C02Error::ExtentNotReadable);
            }
        }
    }
    if logical_size != entry.size {
        return Err(C02Error::ExactFileMismatch);
    }
    Ok(())
}

fn complete_evidence_supported(
    entries: &[FilesystemEntry],
    coverage: &[FilesystemCoverageRange],
    limitations: &[String],
    source_size: u64,
) -> bool {
    if !limitations.is_empty() {
        return false;
    }
    if entries.iter().any(|entry| {
        !entry.limitations.is_empty()
            || entry.content_state == FilesystemContentState::Unsupported
            || (entry.kind == FilesystemEntryKind::File
                && entry.content_state != FilesystemContentState::Exact)
    }) {
        return false;
    }
    let full_coverage = if source_size == 0 {
        coverage.is_empty()
    } else {
        coverage.first().is_some_and(|range| range.byte_start == 0)
            && coverage
                .last()
                .is_some_and(|range| range.byte_end_exclusive == source_size)
    };
    full_coverage
        && coverage.iter().all(|range| {
            matches!(
                range.kind,
                FilesystemCoverageKind::Read | FilesystemCoverageKind::Unallocated
            )
        })
}

fn validate_path(path: &str, limits: FilesystemLimits) -> Result<(), C02Error> {
    if path.is_empty()
        || path.len() > limits.max_path_bytes
        || path.len() > MAX_DECLARED_NAME_BYTES
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains('\0')
    {
        return Err(C02Error::UnsafePath);
    }
    let first = path.split('/').next().unwrap_or_default();
    if first.len() >= 2 && first.as_bytes()[1] == b':' && first.as_bytes()[0].is_ascii_alphabetic()
    {
        return Err(C02Error::UnsafePath);
    }
    if path
        .split('/')
        .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(C02Error::UnsafePath);
    }
    Ok(())
}

fn range_is_exact_read(coverage: &[FilesystemCoverageRange], start: u64, end: u64) -> bool {
    if start >= end {
        return false;
    }
    let mut cursor = start;
    for range in coverage {
        if range.byte_end_exclusive <= cursor {
            continue;
        }
        if range.byte_start > cursor || range.kind != FilesystemCoverageKind::Read {
            return false;
        }
        cursor = cursor.max(range.byte_end_exclusive.min(end));
        if cursor == end {
            return true;
        }
    }
    false
}

fn report_projection_digest(report: &FilesystemReport) -> String {
    let mut hasher = Sha256::new();
    hash_guard_text(
        &mut hasher,
        &serde_json::to_string(&report.source_revision_ref).unwrap_or_default(),
    );
    hash_guard_text(&mut hasher, &report.source_sha256);
    hasher.update(report.source_size.to_le_bytes());
    hash_guard_text(&mut hasher, &format!("{:?}", report.detection));
    hash_guard_text(&mut hasher, &format!("{:?}", report.provider_alias));
    hash_guard_text(&mut hasher, &format!("{:?}", report.assessment));
    hash_guard_text(&mut hasher, &format!("{:?}", report.entries));
    hash_guard_text(&mut hasher, &format!("{:?}", report.coverage));
    hash_guard_text(&mut hasher, &format!("{:?}", report.metadata));
    hash_guard_text(&mut hasher, &format!("{:?}", report.limitations));
    format!("{:x}", hasher.finalize())
}

fn seal_report(mut report: FilesystemReport) -> FilesystemReport {
    report.projection_sha256 = report_projection_digest(&report);
    report
}

fn validate_report_integrity(report: &FilesystemReport) -> Result<(), C02Error> {
    if report.projection_sha256.is_empty()
        || report.projection_sha256 != report_projection_digest(report)
    {
        return Err(C02Error::ReportIntegrityMismatch);
    }
    Ok(())
}

fn view_spec(context: &FilesystemContext, view_kind: &str, suffix: &str) -> ViewSpec {
    ViewSpec {
        workspace_ref: context.workspace_ref.clone(),
        authority_ref: context.authority_ref.clone(),
        view_kind: view_kind.to_owned(),
        view_schema_id: format!("urn:ptah:schema:c02:{suffix}:0.1.0"),
        view_schema_version: "0.1.0".to_owned(),
        source_revision_refs: vec![context.source_revision_ref.clone()],
        origin_class: OriginClass::DecodedResource,
        production: context.production.clone(),
    }
}

fn detection(kind: FilesystemKind, evidence: &str) -> FilesystemDetection {
    FilesystemDetection {
        kind,
        evidence: vec![evidence.to_owned()],
    }
}

fn unknown_coverage(source_size: u64) -> Vec<FilesystemCoverageRange> {
    if source_size == 0 {
        Vec::new()
    } else {
        vec![FilesystemCoverageRange {
            byte_start: 0,
            byte_end_exclusive: source_size,
            kind: FilesystemCoverageKind::Unknown,
        }]
    }
}

fn push_coverage(
    coverage: &mut Vec<FilesystemCoverageRange>,
    start: u64,
    end: u64,
    kind: FilesystemCoverageKind,
) {
    if start == end {
        return;
    }
    if let Some(last) = coverage.last_mut()
        && last.byte_end_exclusive == start
        && last.kind == kind
    {
        last.byte_end_exclusive = end;
        return;
    }
    coverage.push(FilesystemCoverageRange {
        byte_start: start,
        byte_end_exclusive: end,
        kind,
    });
}

fn detect_fat(source: &[u8]) -> Option<FilesystemDetection> {
    if !has_boot_signature(source) {
        return None;
    }
    let bytes_per_sector = u64::from(read_u16_le(source, 11)?);
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
        return None;
    }
    let sectors_per_cluster = u64::from(*source.get(13)?);
    if sectors_per_cluster == 0
        || sectors_per_cluster > 128
        || !sectors_per_cluster.is_power_of_two()
    {
        return None;
    }
    let reserved = u64::from(read_u16_le(source, 14)?);
    let fats = u64::from(*source.get(16)?);
    let root_entries = u64::from(read_u16_le(source, 17)?);
    let total16 = u64::from(read_u16_le(source, 19)?);
    let fatsz16 = u64::from(read_u16_le(source, 22)?);
    let total32 = u64::from(read_u32_le(source, 32)?);
    let fatsz32 = u64::from(read_u32_le(source, 36)?);
    if reserved == 0 || !(1..=2).contains(&fats) {
        return None;
    }
    let total = if total16 != 0 { total16 } else { total32 };
    let fatsz = if fatsz16 != 0 { fatsz16 } else { fatsz32 };
    if total == 0 || fatsz == 0 {
        return None;
    }
    let root_dir_sectors = root_entries
        .checked_mul(32)?
        .checked_add(bytes_per_sector.checked_sub(1)?)?
        / bytes_per_sector;
    let non_data = reserved
        .checked_add(fats.checked_mul(fatsz)?)?
        .checked_add(root_dir_sectors)?;
    let data_sectors = total.checked_sub(non_data)?;
    let source_sectors = u64::try_from(source.len()).ok()? / bytes_per_sector;
    if data_sectors == 0 || total > source_sectors {
        return None;
    }
    let clusters = data_sectors / sectors_per_cluster;
    if clusters == 0 {
        return None;
    }
    let variant = if clusters < 4_085 {
        "FAT12"
    } else if clusters < 65_525 {
        "FAT16"
    } else {
        "FAT32"
    };
    if variant == "FAT32" {
        if root_entries != 0 || fatsz16 != 0 || fatsz32 == 0 {
            return None;
        }
    } else if root_entries == 0 || fatsz16 == 0 {
        return None;
    }
    Some(FilesystemDetection {
        kind: FilesystemKind::Fat,
        evidence: vec![format!(
            "{variant} validated BPB geometry with {clusters} data clusters"
        )],
    })
}

fn read_u16_le(source: &[u8], offset: usize) -> Option<u16> {
    let bytes = source.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(source: &[u8], offset: usize) -> Option<u32> {
    let bytes = source.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn has_boot_signature(source: &[u8]) -> bool {
    source.get(510) == Some(&0x55) && source.get(511) == Some(&0xaa)
}

fn has_bytes_at(source: &[u8], offset: usize, expected: &[u8]) -> bool {
    source
        .get(offset..offset.saturating_add(expected.len()))
        .is_some_and(|actual| actual == expected)
}

fn bounded_nonempty(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max
}

fn hash_guard_text(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
