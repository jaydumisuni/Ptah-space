use ptah_identifiers::EntityRef;
use ptah_object_store::{
    OriginClass, ProductionEvidence, RegisterObjectSpec, Registration, RelationshipSpec,
    RevisionRole, ViewSpec,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

const SECTOR_SIZE: u64 = 512;
const ANDROID_SPARSE_MAGIC: u32 = 0xed26_ff3a;
const SPARSE_CHUNK_RAW: u16 = 0xcac1;
const SPARSE_CHUNK_FILL: u16 = 0xcac2;
const SPARSE_CHUNK_DONT_CARE: u16 = 0xcac3;
const SPARSE_CHUNK_CRC32: u16 = 0xcac4;

/// C01 bounded disk-image interpretation limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskImageLimits {
    /// Maximum expanded/normalized image bytes.
    pub max_output_bytes: u64,
    /// Maximum Android sparse chunks accepted.
    pub max_sparse_chunks: u32,
    /// Maximum partition-table entries inspected.
    pub max_partition_entries: u32,
}

impl Default for DiskImageLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: 16 * 1024 * 1024 * 1024,
            max_sparse_chunks: 1_000_000,
            max_partition_entries: 16_384,
        }
    }
}

/// Exact A07/A04 context for one immutable source disk-image Revision.
#[derive(Debug, Clone)]
pub struct DiskImageContext {
    /// Workspace owning the source image.
    pub workspace_ref: EntityRef,
    /// Authority for canonical registration/View plans.
    pub authority_ref: EntityRef,
    /// Exact immutable source Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact producing evidence for derived plans.
    pub production: ProductionEvidence,
}

/// Source image encoding detected by C01.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskImageFormat {
    /// Byte-for-byte raw image.
    Raw,
    /// Android sparse image container.
    AndroidSparse,
}

/// Whether normalized bytes are defined by source evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCoverageKind {
    /// Exact bytes are mechanically defined by the source encoding.
    Defined,
    /// Source encoding intentionally leaves this normalized range unspecified.
    Unspecified,
}

/// One exact non-overlapping normalized byte range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCoverageRange {
    /// Inclusive normalized byte start.
    pub byte_start: u64,
    /// Exclusive normalized byte end.
    pub byte_end_exclusive: u64,
    /// Evidence status for the normalized bytes.
    pub kind: SourceCoverageKind,
}

/// Immutable normalized disk-image bytes plus exact source-coverage truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedDiskImage {
    source_sha256: String,
    normalized_sha256: String,
    source_format: DiskImageFormat,
    bytes: Vec<u8>,
    source_coverage: Vec<SourceCoverageRange>,
}

impl NormalizedDiskImage {
    /// SHA-256 of the exact original source encoding.
    #[must_use]
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    /// SHA-256 of exact normalized bytes.
    #[must_use]
    pub fn normalized_sha256(&self) -> &str {
        &self.normalized_sha256
    }

    /// Detected source encoding.
    #[must_use]
    pub fn source_format(&self) -> DiskImageFormat {
        self.source_format
    }

    /// Read-only normalized bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Exact source-defined/unspecified normalized ranges.
    #[must_use]
    pub fn source_coverage(&self) -> &[SourceCoverageRange] {
        &self.source_coverage
    }
}

/// Recognized partition-map family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionTableKind {
    /// No mechanically recognized partition map.
    None,
    /// DOS/MBR partition map.
    Mbr,
    /// GUID Partition Table.
    Gpt,
}

/// Truth status of partition-map interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionMapAssessment {
    /// All recognized map structures needed by C01 validated.
    Complete,
    /// Some exact entries are retained but unsupported/corrupt structure leaves gaps.
    Partial,
    /// C01 cannot establish a trustworthy partition layout.
    Inconclusive,
}

/// One exact byte range occupied by partition-table metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionTableRange {
    /// Inclusive normalized byte start.
    pub byte_start: u64,
    /// Exclusive normalized byte end.
    pub byte_end_exclusive: u64,
}

/// One exact MBR/GPT partition entry accepted by C01.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionEntry {
    /// One-based source table slot.
    pub index: u32,
    /// Optional human-facing GPT name.
    pub name: Option<String>,
    /// Exact type identity, e.g. `mbr:0x83` or canonical GPT GUID text.
    pub type_id: String,
    /// Inclusive first logical block.
    pub first_lba: u64,
    /// Inclusive last logical block.
    pub last_lba_inclusive: u64,
    /// Inclusive normalized byte start.
    pub byte_start: u64,
    /// Exclusive normalized byte end.
    pub byte_end_exclusive: u64,
    /// MBR bootable flag.
    pub bootable: bool,
    /// True for an MBR extended-partition container not recursively decomposed by C01.
    pub container: bool,
}

/// Partition-layout range classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionLayoutKind {
    /// Exact accepted partition bytes.
    Partition,
    /// Exact bytes outside accepted partitions under a complete map.
    Unallocated,
    /// Bytes whose partition ownership cannot be established conclusively.
    Unknown,
}

/// One exact non-overlapping partition-layout range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionLayoutRange {
    /// Inclusive normalized byte start.
    pub byte_start: u64,
    /// Exclusive normalized byte end.
    pub byte_end_exclusive: u64,
    /// Layout classification.
    pub kind: PartitionLayoutKind,
    /// Partition index when `kind == Partition`.
    pub partition_index: Option<u32>,
}

/// Source-bound C01 partition-map report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskImageReport {
    /// Exact source Object Revision.
    pub source_revision_ref: EntityRef,
    /// Original source digest.
    pub source_sha256: String,
    /// Normalized digest.
    pub normalized_sha256: String,
    /// Normalized byte size.
    pub normalized_size: u64,
    /// Source encoding.
    pub source_format: DiskImageFormat,
    /// Logical block size used by C01 partition foundations.
    pub logical_block_size: u64,
    /// Detected map family.
    pub partition_table: PartitionTableKind,
    /// Truth status.
    pub assessment: PartitionMapAssessment,
    /// Exact accepted partitions.
    pub partitions: Vec<PartitionEntry>,
    /// Partition-table metadata byte ranges.
    pub partition_table_ranges: Vec<PartitionTableRange>,
    /// Exact source-defined/unspecified coverage copied from normalization.
    pub source_coverage: Vec<SourceCoverageRange>,
    /// Exact partition/unknown/unallocated layout ranges.
    pub layout_coverage: Vec<PartitionLayoutRange>,
    /// Non-fatal mechanical warnings.
    pub warnings: Vec<String>,
    /// Unsupported/inconclusive boundaries.
    pub limitations: Vec<String>,
    /// Private integrity seal over source identity, exact partitions and source coverage.
    projection_sha256: String,
}

impl DiskImageReport {
    /// Produce source-bound A07 Views for the partition map and byte coverage.
    ///
    /// # Errors
    /// Fails if `context` does not name this exact source Revision.
    pub fn view_specs(&self, context: &DiskImageContext) -> Result<Vec<ViewSpec>, C01Error> {
        validate_context(context)?;
        validate_report_integrity(self)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C01Error::SourceBindingMismatch);
        }
        Ok(vec![
            view_spec(context, "disk.partition_map", "partition-map"),
            view_spec(context, "disk.block_coverage", "block-coverage"),
        ])
    }
}

/// Read-only exact partition materialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionMaterialization {
    /// Exact accepted partition metadata.
    pub partition: PartitionEntry,
    /// Exact immutable source Revision.
    pub source_revision_ref: EntityRef,
    /// SHA-256 of exact materialized bytes.
    pub sha256: String,
    bytes: Vec<u8>,
}

impl PartitionMaterialization {
    /// Read-only materialized bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Build an A07 registration request for this recovered partition Object.
    ///
    /// # Errors
    /// Rejects a malformed context or one that does not name this exact source Revision.
    pub fn registration_spec(
        &self,
        context: &DiskImageContext,
    ) -> Result<RegisterObjectSpec, C01Error> {
        validate_context(context)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C01Error::SourceBindingMismatch);
        }
        Ok(RegisterObjectSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            object_class: "disk.partition".to_owned(),
            declared_name: self
                .partition
                .name
                .clone()
                .or_else(|| Some(format!("partition-{}", self.partition.index))),
            source_refs: vec![self.source_revision_ref.clone()],
            revision_role: RevisionRole::Recovered,
            origin_class: OriginClass::RecoveredEmbeddedSource,
            created_reason: "C01 recovered exact disk partition bytes".to_owned(),
            production: context.production.clone(),
            expected_sha256: Some(self.sha256.clone()),
        })
    }

    /// Build an exact source-to-partition A07 Relationship plan.
    ///
    /// # Errors
    /// Rejects registration records that do not describe these exact bytes.
    pub fn relationship_spec(
        &self,
        context: &DiskImageContext,
        registration: &Registration,
    ) -> Result<RelationshipSpec, C01Error> {
        validate_context(context)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C01Error::SourceBindingMismatch);
        }
        if registration.object_ref.entity_kind.as_str() != "object.object"
            || registration.revision_ref.entity_kind.as_str() != "object.revision"
        {
            return Err(C01Error::InvalidPartitionRegistration);
        }
        let byte_size =
            u64::try_from(self.bytes.len()).map_err(|_| C01Error::AccountingOverflow)?;
        if registration.sha256 != self.sha256 || registration.byte_size != byte_size {
            return Err(C01Error::PartitionRegistrationMismatch);
        }
        Ok(RelationshipSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            subject_refs: vec![self.source_revision_ref.clone()],
            relationship_type: "contains.partition".to_owned(),
            object_refs: vec![
                registration.object_ref.clone(),
                registration.revision_ref.clone(),
            ],
            production: context.production.clone(),
        })
    }
}

/// Structural source-bound disk-image comparison foundation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskImageComparison {
    /// Exact left source Revision.
    pub left_source_revision_ref: EntityRef,
    /// Exact right source Revision.
    pub right_source_revision_ref: EntityRef,
    /// True only when the C01 structural projection is identical.
    pub identical_layout: bool,
    /// Deterministically ordered structural differences.
    pub differences: Vec<String>,
}

/// C01 failures. Corrupt partition maps generally become partial/inconclusive reports;
/// malformed encodings, unsafe materialization and resource violations fail closed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum C01Error {
    /// Exact source must be an Object Revision.
    #[error("C01 source must be an exact object.revision reference")]
    InvalidSourceRevision,
    /// Workspace scope must be canonical.
    #[error("C01 workspace reference must be core.workspace")]
    InvalidWorkspaceRef,
    /// A configured bound is zero.
    #[error("C01 disk-image limits must all be greater than zero")]
    InvalidLimits,
    /// Expanded/normalized image exceeds configured bounds.
    #[error("C01 normalized image exceeds max_output_bytes")]
    OutputTooLarge,
    /// Sparse chunk count exceeds configured bounds.
    #[error("C01 sparse image exceeds max_sparse_chunks")]
    TooManySparseChunks,
    /// Partition table declares too many entries.
    #[error("C01 partition table exceeds max_partition_entries")]
    TooManyPartitionEntries,
    /// Sparse encoding is malformed or unsupported.
    #[error("C01 malformed Android sparse image: {0}")]
    MalformedSparse(&'static str),
    /// Sparse CRC evidence disagrees with normalized bytes.
    #[error("C01 Android sparse CRC mismatch")]
    SparseCrcMismatch,
    /// Raw-to-sparse conversion requires block alignment.
    #[error("C01 sparse conversion requires block-aligned coverage")]
    SparseAlignment,
    /// Numeric byte/LBA accounting overflowed.
    #[error("C01 byte accounting overflow")]
    AccountingOverflow,
    /// Requested partition does not exist in the exact report.
    #[error("C01 partition index was not found")]
    PartitionNotFound,
    /// Report and normalized source are not the same exact projection.
    #[error("C01 report/normalized source binding mismatch")]
    SourceBindingMismatch,
    /// Public report fields changed after C01 sealed the exact parser projection.
    #[error("C01 partition report integrity seal mismatch")]
    ReportIntegrityMismatch,
    /// Materialization range is outside normalized bytes.
    #[error("C01 partition extent lies outside normalized bytes")]
    PartitionOutOfBounds,
    /// Materialization would invent bytes from sparse `DONT_CARE` coverage.
    #[error("C01 partition includes source-unspecified bytes")]
    UnspecifiedPartitionBytes,
    /// A supplied A07 registration has invalid endpoint kinds.
    #[error("C01 partition registration has invalid canonical endpoint kinds")]
    InvalidPartitionRegistration,
    /// A supplied A07 registration does not describe exact partition bytes.
    #[error("C01 partition registration does not match exact materialized bytes")]
    PartitionRegistrationMismatch,
}

/// Normalize a raw or Android sparse image without mutating source bytes.
///
/// Android `DONT_CARE` ranges are expanded as zero bytes only for positional normalization and are
/// retained as [`SourceCoverageKind::Unspecified`]; callers may not materialize those bytes as
/// canonical partition truth.
///
/// # Errors
/// Fails closed for malformed sparse input, CRC disagreement, overflow or configured bounds.
pub fn normalize_disk_image(
    source_bytes: &[u8],
    limits: DiskImageLimits,
) -> Result<NormalizedDiskImage, C01Error> {
    validate_limits(limits)?;
    let source_sha256 = sha256_bytes(source_bytes);
    if source_bytes.len() >= 4 && read_u32(source_bytes, 0)? == ANDROID_SPARSE_MAGIC {
        normalize_android_sparse(source_bytes, source_sha256, limits)
    } else {
        let output_len =
            u64::try_from(source_bytes.len()).map_err(|_| C01Error::AccountingOverflow)?;
        if output_len > limits.max_output_bytes {
            return Err(C01Error::OutputTooLarge);
        }
        let coverage = if source_bytes.is_empty() {
            Vec::new()
        } else {
            vec![SourceCoverageRange {
                byte_start: 0,
                byte_end_exclusive: output_len,
                kind: SourceCoverageKind::Defined,
            }]
        };
        Ok(NormalizedDiskImage {
            source_sha256,
            normalized_sha256: sha256_bytes(source_bytes),
            source_format: DiskImageFormat::Raw,
            bytes: source_bytes.to_vec(),
            source_coverage: coverage,
        })
    }
}

/// Encode normalized bytes into Android sparse format while preserving source-coverage semantics.
///
/// Defined ranges become RAW chunks and unspecified ranges become `DONT_CARE` chunks.
///
/// # Errors
/// Requires block-aligned normalized size and coverage, plus configured chunk/output bounds.
pub fn encode_android_sparse(
    image: &NormalizedDiskImage,
    block_size: u32,
    limits: DiskImageLimits,
) -> Result<Vec<u8>, C01Error> {
    validate_limits(limits)?;
    if block_size == 0 {
        return Err(C01Error::SparseAlignment);
    }
    let block = u64::from(block_size);
    let total_len = u64::try_from(image.bytes.len()).map_err(|_| C01Error::AccountingOverflow)?;
    if total_len % block != 0 {
        return Err(C01Error::SparseAlignment);
    }
    let total_blocks = total_len / block;
    let total_blocks_u32 = u32::try_from(total_blocks).map_err(|_| C01Error::AccountingOverflow)?;
    let chunks =
        u32::try_from(image.source_coverage.len()).map_err(|_| C01Error::AccountingOverflow)?;
    if chunks > limits.max_sparse_chunks {
        return Err(C01Error::TooManySparseChunks);
    }
    for range in &image.source_coverage {
        if range.byte_start % block != 0 || range.byte_end_exclusive % block != 0 {
            return Err(C01Error::SparseAlignment);
        }
    }

    let mut output = Vec::new();
    push_u32(&mut output, ANDROID_SPARSE_MAGIC);
    push_u16(&mut output, 1);
    push_u16(&mut output, 0);
    push_u16(&mut output, 28);
    push_u16(&mut output, 12);
    push_u32(&mut output, block_size);
    push_u32(&mut output, total_blocks_u32);
    push_u32(&mut output, chunks);
    push_u32(&mut output, crc32(&image.bytes));

    for range in &image.source_coverage {
        let range_len = range
            .byte_end_exclusive
            .checked_sub(range.byte_start)
            .ok_or(C01Error::AccountingOverflow)?;
        let chunk_blocks =
            u32::try_from(range_len / block).map_err(|_| C01Error::AccountingOverflow)?;
        match range.kind {
            SourceCoverageKind::Defined => {
                let start =
                    usize::try_from(range.byte_start).map_err(|_| C01Error::AccountingOverflow)?;
                let end = usize::try_from(range.byte_end_exclusive)
                    .map_err(|_| C01Error::AccountingOverflow)?;
                let payload_len =
                    u32::try_from(range_len).map_err(|_| C01Error::AccountingOverflow)?;
                push_u16(&mut output, SPARSE_CHUNK_RAW);
                push_u16(&mut output, 0);
                push_u32(&mut output, chunk_blocks);
                push_u32(
                    &mut output,
                    12_u32
                        .checked_add(payload_len)
                        .ok_or(C01Error::AccountingOverflow)?,
                );
                output.extend_from_slice(&image.bytes[start..end]);
            }
            SourceCoverageKind::Unspecified => {
                push_u16(&mut output, SPARSE_CHUNK_DONT_CARE);
                push_u16(&mut output, 0);
                push_u32(&mut output, chunk_blocks);
                push_u32(&mut output, 12);
            }
        }
    }
    Ok(output)
}

/// Inspect MBR/GPT partition foundations over exact normalized bytes.
///
/// Corrupt maps remain explicit partial/inconclusive reports rather than false complete success.
///
/// # Errors
/// Fails only for invalid context/limits, resource overflow or declared table-entry bounds.
pub fn inspect_partition_map(
    image: &NormalizedDiskImage,
    context: &DiskImageContext,
    limits: DiskImageLimits,
) -> Result<DiskImageReport, C01Error> {
    validate_context(context)?;
    validate_limits(limits)?;

    let size = u64::try_from(image.bytes.len()).map_err(|_| C01Error::AccountingOverflow)?;
    let mut report = DiskImageReport {
        source_revision_ref: context.source_revision_ref.clone(),
        source_sha256: image.source_sha256.clone(),
        normalized_sha256: image.normalized_sha256.clone(),
        normalized_size: size,
        source_format: image.source_format,
        logical_block_size: SECTOR_SIZE,
        partition_table: PartitionTableKind::None,
        assessment: PartitionMapAssessment::Inconclusive,
        partitions: Vec::new(),
        partition_table_ranges: Vec::new(),
        source_coverage: image.source_coverage.clone(),
        layout_coverage: vec![PartitionLayoutRange {
            byte_start: 0,
            byte_end_exclusive: size,
            kind: PartitionLayoutKind::Unknown,
            partition_index: None,
        }],
        warnings: Vec::new(),
        limitations: Vec::new(),
        projection_sha256: String::new(),
    };

    if image.bytes.len() < 512 {
        report
            .limitations
            .push("image is smaller than one 512-byte logical block".to_owned());
        return Ok(seal_report(report));
    }
    if image.bytes[510] != 0x55 || image.bytes[511] != 0xaa {
        report
            .limitations
            .push("no valid MBR signature; partition map is inconclusive".to_owned());
        return Ok(seal_report(report));
    }

    let mbr_types: Vec<u8> = (0..4)
        .map(|slot| image.bytes[446 + slot * 16 + 4])
        .filter(|partition_type| *partition_type != 0)
        .collect();
    let protective = mbr_types.contains(&0xee);
    let hybrid_mbr = protective
        && mbr_types
            .iter()
            .any(|partition_type| *partition_type != 0xee);
    if protective {
        report.partition_table = PartitionTableKind::Gpt;
        if image.bytes.len() < 1024 || &image.bytes[512..520] != b"EFI PART" {
            report.partition_table_ranges.push(PartitionTableRange {
                byte_start: 0,
                byte_end_exclusive: 512,
            });
            report.limitations.push(
                "protective MBR exists but a valid primary GPT signature is unavailable".to_owned(),
            );
            return Ok(seal_report(report));
        }
        inspect_gpt(image, limits, &mut report)?;
        if hybrid_mbr {
            if report.assessment == PartitionMapAssessment::Complete {
                report.assessment = PartitionMapAssessment::Partial;
            }
            report
                .limitations
                .push("hybrid MBR entries are not projected alongside GPT in C01".to_owned());
        }
    } else {
        inspect_mbr(image, &mut report);
    }

    report.layout_coverage = build_layout_coverage(
        report.normalized_size,
        &report.partitions,
        report.assessment,
    );
    Ok(seal_report(report))
}

/// Materialize one exact partition as immutable read-only bytes.
///
/// # Errors
/// Rejects stale/forged report bindings, out-of-bounds extents and any overlap with source
/// `Unspecified` coverage.
pub fn materialize_partition(
    image: &NormalizedDiskImage,
    report: &DiskImageReport,
    partition_index: u32,
    context: &DiskImageContext,
) -> Result<PartitionMaterialization, C01Error> {
    validate_context(context)?;
    validate_report_integrity(report)?;
    if report.source_revision_ref != context.source_revision_ref
        || report.source_sha256 != image.source_sha256
        || report.normalized_sha256 != image.normalized_sha256
        || report.normalized_size
            != u64::try_from(image.bytes.len()).map_err(|_| C01Error::AccountingOverflow)?
    {
        return Err(C01Error::SourceBindingMismatch);
    }
    let partition = report
        .partitions
        .iter()
        .find(|partition| partition.index == partition_index)
        .cloned()
        .ok_or(C01Error::PartitionNotFound)?;
    if partition.byte_end_exclusive <= partition.byte_start
        || partition.byte_end_exclusive > report.normalized_size
    {
        return Err(C01Error::PartitionOutOfBounds);
    }
    if image.source_coverage.iter().any(|range| {
        ranges_overlap(
            partition.byte_start,
            partition.byte_end_exclusive,
            range.byte_start,
            range.byte_end_exclusive,
        ) && range.kind == SourceCoverageKind::Unspecified
    }) {
        return Err(C01Error::UnspecifiedPartitionBytes);
    }
    let start = usize::try_from(partition.byte_start).map_err(|_| C01Error::AccountingOverflow)?;
    let end =
        usize::try_from(partition.byte_end_exclusive).map_err(|_| C01Error::AccountingOverflow)?;
    let bytes = image
        .bytes
        .get(start..end)
        .ok_or(C01Error::PartitionOutOfBounds)?
        .to_vec();
    Ok(PartitionMaterialization {
        partition,
        source_revision_ref: context.source_revision_ref.clone(),
        sha256: sha256_bytes(&bytes),
        bytes,
    })
}

/// Compare two source-bound C01 reports structurally.
///
/// No filesystem or semantic content claim is made; those belong to later Programme C providers.
#[must_use]
pub fn compare_disk_images(left: &DiskImageReport, right: &DiskImageReport) -> DiskImageComparison {
    let mut differences = Vec::new();
    if left.partition_table != right.partition_table {
        differences.push(format!(
            "partition_table:{:?}->{:?}",
            left.partition_table, right.partition_table
        ));
    }
    if left.normalized_size != right.normalized_size {
        differences.push(format!(
            "normalized_size:{}->{}",
            left.normalized_size, right.normalized_size
        ));
    }
    if left.assessment != right.assessment {
        differences.push(format!(
            "assessment:{:?}->{:?}",
            left.assessment, right.assessment
        ));
    }
    if left.layout_coverage != right.layout_coverage {
        differences.push("layout_coverage_changed".to_owned());
    }
    if left.source_coverage != right.source_coverage {
        differences.push("source_coverage_changed".to_owned());
    }

    let left_by_index: BTreeMap<_, _> = left
        .partitions
        .iter()
        .map(|partition| (partition.index, partition))
        .collect();
    let right_by_index: BTreeMap<_, _> = right
        .partitions
        .iter()
        .map(|partition| (partition.index, partition))
        .collect();
    for index in left_by_index
        .keys()
        .chain(right_by_index.keys())
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
    {
        match (left_by_index.get(&index), right_by_index.get(&index)) {
            (Some(a), Some(b)) if *a != *b => {
                differences.push(format!("partition_slot_changed:{index}"));
            }
            (Some(_), None) => differences.push(format!("partition_removed:{index}")),
            (None, Some(_)) => differences.push(format!("partition_added:{index}")),
            _ => {}
        }
    }

    DiskImageComparison {
        left_source_revision_ref: left.source_revision_ref.clone(),
        right_source_revision_ref: right.source_revision_ref.clone(),
        identical_layout: differences.is_empty(),
        differences,
    }
}

#[derive(Debug, Clone, Copy)]
struct SparseHeader {
    file_header_size: usize,
    chunk_header_size: usize,
    block_size: u64,
    total_blocks: u64,
    total_chunks: u32,
    image_checksum: u32,
    expanded_len: u64,
}

struct SparseDecodeState {
    output: Vec<u8>,
    coverage: Vec<SourceCoverageRange>,
    cursor: usize,
    produced_blocks: u64,
}

#[derive(Debug, Clone, Copy)]
struct SparseChunk {
    chunk_type: u16,
    blocks: u64,
    header_end: usize,
    chunk_end: usize,
    chunk_bytes: u64,
    range_start: u64,
    range_end: u64,
    total_size: usize,
}

fn parse_sparse_header(
    source_bytes: &[u8],
    limits: DiskImageLimits,
) -> Result<SparseHeader, C01Error> {
    if source_bytes.len() < 28 {
        return Err(C01Error::MalformedSparse("header is truncated"));
    }
    if read_u16(source_bytes, 4)? != 1 {
        return Err(C01Error::MalformedSparse("unsupported major version"));
    }
    let file_header_size = usize::from(read_u16(source_bytes, 8)?);
    let chunk_header_size = usize::from(read_u16(source_bytes, 10)?);
    let block_size = u64::from(read_u32(source_bytes, 12)?);
    let total_blocks = u64::from(read_u32(source_bytes, 16)?);
    let total_chunks = read_u32(source_bytes, 20)?;
    if !(28..=source_bytes.len()).contains(&file_header_size) {
        return Err(C01Error::MalformedSparse("invalid file header size"));
    }
    if chunk_header_size < 12 {
        return Err(C01Error::MalformedSparse("invalid chunk header size"));
    }
    if block_size == 0 {
        return Err(C01Error::MalformedSparse("block size is zero"));
    }
    if total_chunks > limits.max_sparse_chunks {
        return Err(C01Error::TooManySparseChunks);
    }
    let expanded_len = total_blocks
        .checked_mul(block_size)
        .ok_or(C01Error::AccountingOverflow)?;
    if expanded_len > limits.max_output_bytes {
        return Err(C01Error::OutputTooLarge);
    }
    Ok(SparseHeader {
        file_header_size,
        chunk_header_size,
        block_size,
        total_blocks,
        total_chunks,
        image_checksum: read_u32(source_bytes, 24)?,
        expanded_len,
    })
}

fn parse_sparse_chunk(
    source_bytes: &[u8],
    header: SparseHeader,
    state: &SparseDecodeState,
) -> Result<SparseChunk, C01Error> {
    let header_end = state
        .cursor
        .checked_add(header.chunk_header_size)
        .ok_or(C01Error::AccountingOverflow)?;
    if header_end > source_bytes.len() {
        return Err(C01Error::MalformedSparse("chunk header is truncated"));
    }
    let total_size = usize::try_from(read_u32(source_bytes, state.cursor + 8)?)
        .map_err(|_| C01Error::AccountingOverflow)?;
    if total_size < header.chunk_header_size {
        return Err(C01Error::MalformedSparse("chunk total size is too small"));
    }
    let chunk_end = state
        .cursor
        .checked_add(total_size)
        .ok_or(C01Error::AccountingOverflow)?;
    if chunk_end > source_bytes.len() {
        return Err(C01Error::MalformedSparse("chunk payload is truncated"));
    }
    let blocks = u64::from(read_u32(source_bytes, state.cursor + 4)?);
    let chunk_bytes = blocks
        .checked_mul(header.block_size)
        .ok_or(C01Error::AccountingOverflow)?;
    let range_start =
        u64::try_from(state.output.len()).map_err(|_| C01Error::AccountingOverflow)?;
    let range_end = range_start
        .checked_add(chunk_bytes)
        .ok_or(C01Error::AccountingOverflow)?;
    if range_end > header.expanded_len {
        return Err(C01Error::MalformedSparse(
            "chunk expands beyond declared image",
        ));
    }
    Ok(SparseChunk {
        chunk_type: read_u16(source_bytes, state.cursor)?,
        blocks,
        header_end,
        chunk_end,
        chunk_bytes,
        range_start,
        range_end,
        total_size,
    })
}

fn apply_sparse_chunk(
    source_bytes: &[u8],
    header: SparseHeader,
    chunk: SparseChunk,
    state: &mut SparseDecodeState,
) -> Result<(), C01Error> {
    match chunk.chunk_type {
        SPARSE_CHUNK_RAW => {
            let payload_len =
                usize::try_from(chunk.chunk_bytes).map_err(|_| C01Error::OutputTooLarge)?;
            let expected = header
                .chunk_header_size
                .checked_add(payload_len)
                .ok_or(C01Error::AccountingOverflow)?;
            if chunk.total_size != expected || chunk.blocks == 0 {
                return Err(C01Error::MalformedSparse("RAW chunk size mismatch"));
            }
            state
                .output
                .extend_from_slice(&source_bytes[chunk.header_end..chunk.chunk_end]);
            push_coverage(
                &mut state.coverage,
                chunk.range_start,
                chunk.range_end,
                SourceCoverageKind::Defined,
            );
            state.produced_blocks = state
                .produced_blocks
                .checked_add(chunk.blocks)
                .ok_or(C01Error::AccountingOverflow)?;
        }
        SPARSE_CHUNK_FILL => apply_sparse_fill(source_bytes, header, chunk, state)?,
        SPARSE_CHUNK_DONT_CARE => {
            if chunk.total_size != header.chunk_header_size || chunk.blocks == 0 {
                return Err(C01Error::MalformedSparse("DONT_CARE chunk size mismatch"));
            }
            let new_len = usize::try_from(chunk.range_end).map_err(|_| C01Error::OutputTooLarge)?;
            state.output.resize(new_len, 0);
            push_coverage(
                &mut state.coverage,
                chunk.range_start,
                chunk.range_end,
                SourceCoverageKind::Unspecified,
            );
            state.produced_blocks = state
                .produced_blocks
                .checked_add(chunk.blocks)
                .ok_or(C01Error::AccountingOverflow)?;
        }
        SPARSE_CHUNK_CRC32 => {
            if chunk.total_size != header.chunk_header_size + 4 || chunk.blocks != 0 {
                return Err(C01Error::MalformedSparse("CRC32 chunk size mismatch"));
            }
            if crc32(&state.output) != read_u32(source_bytes, chunk.header_end)? {
                return Err(C01Error::SparseCrcMismatch);
            }
        }
        _ => return Err(C01Error::MalformedSparse("unknown chunk type")),
    }
    state.cursor = chunk.chunk_end;
    Ok(())
}

fn apply_sparse_fill(
    source_bytes: &[u8],
    header: SparseHeader,
    chunk: SparseChunk,
    state: &mut SparseDecodeState,
) -> Result<(), C01Error> {
    if chunk.total_size != header.chunk_header_size + 4 || chunk.blocks == 0 {
        return Err(C01Error::MalformedSparse("FILL chunk size mismatch"));
    }
    if !chunk.chunk_bytes.is_multiple_of(4) {
        return Err(C01Error::MalformedSparse(
            "FILL chunk is not four-byte aligned",
        ));
    }
    let fill = source_bytes
        .get(chunk.header_end..chunk.header_end + 4)
        .ok_or(C01Error::MalformedSparse("FILL value is truncated"))?;
    let count = usize::try_from(chunk.chunk_bytes / 4).map_err(|_| C01Error::OutputTooLarge)?;
    for _ in 0..count {
        state.output.extend_from_slice(fill);
    }
    push_coverage(
        &mut state.coverage,
        chunk.range_start,
        chunk.range_end,
        SourceCoverageKind::Defined,
    );
    state.produced_blocks = state
        .produced_blocks
        .checked_add(chunk.blocks)
        .ok_or(C01Error::AccountingOverflow)?;
    Ok(())
}

fn normalize_android_sparse(
    source_bytes: &[u8],
    source_sha256: String,
    limits: DiskImageLimits,
) -> Result<NormalizedDiskImage, C01Error> {
    let header = parse_sparse_header(source_bytes, limits)?;
    let capacity = usize::try_from(header.expanded_len).map_err(|_| C01Error::OutputTooLarge)?;
    let mut state = SparseDecodeState {
        output: Vec::with_capacity(capacity),
        coverage: Vec::new(),
        cursor: header.file_header_size,
        produced_blocks: 0,
    };
    for _ in 0..header.total_chunks {
        let chunk = parse_sparse_chunk(source_bytes, header, &state)?;
        apply_sparse_chunk(source_bytes, header, chunk, &mut state)?;
        if u64::try_from(state.output.len()).map_err(|_| C01Error::AccountingOverflow)?
            > limits.max_output_bytes
        {
            return Err(C01Error::OutputTooLarge);
        }
    }
    if state.cursor != source_bytes.len() {
        return Err(C01Error::MalformedSparse(
            "trailing bytes remain after declared chunks",
        ));
    }
    if state.produced_blocks != header.total_blocks
        || u64::try_from(state.output.len()).map_err(|_| C01Error::AccountingOverflow)?
            != header.expanded_len
    {
        return Err(C01Error::MalformedSparse(
            "expanded block count does not match header",
        ));
    }
    if header.image_checksum != 0 && crc32(&state.output) != header.image_checksum {
        return Err(C01Error::SparseCrcMismatch);
    }
    Ok(NormalizedDiskImage {
        source_sha256,
        normalized_sha256: sha256_bytes(&state.output),
        source_format: DiskImageFormat::AndroidSparse,
        bytes: state.output,
        source_coverage: state.coverage,
    })
}

fn inspect_mbr(image: &NormalizedDiskImage, report: &mut DiskImageReport) {
    report.partition_table = PartitionTableKind::Mbr;
    report.assessment = PartitionMapAssessment::Complete;
    report.partition_table_ranges.push(PartitionTableRange {
        byte_start: 0,
        byte_end_exclusive: 512,
    });
    let image_size = u64::try_from(image.bytes.len()).unwrap_or(u64::MAX);
    let mut saw_invalid = false;
    let mut saw_extended = false;

    for slot in 0..4 {
        let offset = 446 + slot * 16;
        let status = image.bytes[offset];
        let partition_type = image.bytes[offset + 4];
        let first_lba = u64::from(read_u32_unchecked(&image.bytes, offset + 8));
        let sectors = u64::from(read_u32_unchecked(&image.bytes, offset + 12));
        if partition_type == 0 || sectors == 0 {
            continue;
        }
        if status != 0 && status != 0x80 {
            saw_invalid = true;
            report.warnings.push(format!(
                "MBR slot {} has invalid status byte 0x{status:02x}",
                slot + 1
            ));
        }
        let Some(last_exclusive_lba) = first_lba.checked_add(sectors) else {
            saw_invalid = true;
            report
                .warnings
                .push(format!("MBR slot {} LBA accounting overflow", slot + 1));
            continue;
        };
        let Some(byte_start) = first_lba.checked_mul(SECTOR_SIZE) else {
            saw_invalid = true;
            continue;
        };
        let Some(byte_end_exclusive) = last_exclusive_lba.checked_mul(SECTOR_SIZE) else {
            saw_invalid = true;
            continue;
        };
        if byte_start >= byte_end_exclusive || byte_end_exclusive > image_size {
            saw_invalid = true;
            report.warnings.push(format!(
                "MBR slot {} extent lies outside normalized image",
                slot + 1
            ));
            continue;
        }
        let container = matches!(partition_type, 0x05 | 0x0f | 0x85);
        if container {
            saw_extended = true;
        }
        report.partitions.push(PartitionEntry {
            index: u32::try_from(slot + 1).unwrap_or(u32::MAX),
            name: None,
            type_id: format!("mbr:0x{partition_type:02x}"),
            first_lba,
            last_lba_inclusive: last_exclusive_lba - 1,
            byte_start,
            byte_end_exclusive,
            bootable: status == 0x80,
            container,
        });
    }

    report
        .partitions
        .sort_by_key(|partition| (partition.byte_start, partition.index));
    if has_partition_overlap(&report.partitions) {
        saw_invalid = true;
        report
            .warnings
            .push("MBR primary partition entries overlap".to_owned());
    }
    if saw_invalid {
        report.assessment = if report.partitions.is_empty() {
            PartitionMapAssessment::Inconclusive
        } else {
            PartitionMapAssessment::Partial
        };
        report.limitations.push(
            "one or more MBR entries were invalid and were not promoted as partitions".to_owned(),
        );
    }
    if saw_extended {
        report.assessment = PartitionMapAssessment::Partial;
        report.limitations.push(
            "MBR extended-partition container retained; EBR recursion is outside C01".to_owned(),
        );
    }
}

#[derive(Debug, Clone, Copy)]
struct GptHeader {
    header_size: usize,
    first_usable_lba: u64,
    last_usable_lba: u64,
    entries_lba: u64,
    entry_count: u32,
    entry_size: u32,
    expected_entries_crc: u32,
}

#[derive(Debug, Clone, Copy)]
struct GptEntryArray {
    byte_start: u64,
    byte_end_exclusive: u64,
    start: usize,
    end: usize,
}

fn parse_gpt_header(
    image: &NormalizedDiskImage,
    limits: DiskImageLimits,
    report: &mut DiskImageReport,
) -> Result<Option<GptHeader>, C01Error> {
    let header_size = usize::try_from(read_u32(&image.bytes, 512 + 12)?)
        .map_err(|_| C01Error::AccountingOverflow)?;
    if !(92..=512).contains(&header_size) || 512 + header_size > image.bytes.len() {
        report
            .limitations
            .push("GPT header size is invalid".to_owned());
        return Ok(None);
    }
    report.partition_table_ranges.push(PartitionTableRange {
        byte_start: 512,
        byte_end_exclusive: u64::try_from(512 + header_size)
            .map_err(|_| C01Error::AccountingOverflow)?,
    });
    let expected_crc = read_u32(&image.bytes, 512 + 16)?;
    let mut header_bytes = image.bytes[512..512 + header_size].to_vec();
    header_bytes[16..20].fill(0);
    if crc32(&header_bytes) != expected_crc {
        report
            .limitations
            .push("GPT primary header CRC32 verification failed".to_owned());
        return Ok(None);
    }
    let total_lbas =
        u64::try_from(image.bytes.len() / 512).map_err(|_| C01Error::AccountingOverflow)?;
    let current_lba = read_u64(&image.bytes, 512 + 24)?;
    let backup_lba = read_u64(&image.bytes, 512 + 32)?;
    let first_usable_lba = read_u64(&image.bytes, 512 + 40)?;
    let last_usable_lba = read_u64(&image.bytes, 512 + 48)?;
    if current_lba != 1
        || backup_lba == current_lba
        || backup_lba >= total_lbas
        || first_usable_lba > last_usable_lba
        || last_usable_lba >= total_lbas
    {
        report
            .limitations
            .push("GPT primary header LBA bounds are invalid".to_owned());
        return Ok(None);
    }
    let entry_count = read_u32(&image.bytes, 512 + 80)?;
    let entry_size = read_u32(&image.bytes, 512 + 84)?;
    if entry_count > limits.max_partition_entries {
        return Err(C01Error::TooManyPartitionEntries);
    }
    if !(128..=4096).contains(&entry_size) || entry_size % 8 != 0 {
        report
            .limitations
            .push("GPT partition-entry size is unsupported".to_owned());
        return Ok(None);
    }
    Ok(Some(GptHeader {
        header_size,
        first_usable_lba,
        last_usable_lba,
        entries_lba: read_u64(&image.bytes, 512 + 72)?,
        entry_count,
        entry_size,
        expected_entries_crc: read_u32(&image.bytes, 512 + 88)?,
    }))
}

fn validate_gpt_entry_array(
    image: &NormalizedDiskImage,
    header: GptHeader,
    report: &mut DiskImageReport,
) -> Result<Option<GptEntryArray>, C01Error> {
    let entries_bytes = u64::from(header.entry_count)
        .checked_mul(u64::from(header.entry_size))
        .ok_or(C01Error::AccountingOverflow)?;
    let byte_start = header
        .entries_lba
        .checked_mul(SECTOR_SIZE)
        .ok_or(C01Error::AccountingOverflow)?;
    let byte_end_exclusive = byte_start
        .checked_add(entries_bytes)
        .ok_or(C01Error::AccountingOverflow)?;
    let image_size = u64::try_from(image.bytes.len()).map_err(|_| C01Error::AccountingOverflow)?;
    let occupied_sectors = entries_bytes
        .checked_add(SECTOR_SIZE - 1)
        .ok_or(C01Error::AccountingOverflow)?
        / SECTOR_SIZE;
    let entries_end_lba = header
        .entries_lba
        .checked_add(occupied_sectors)
        .ok_or(C01Error::AccountingOverflow)?;
    if header.entries_lba < 2
        || entries_end_lba > header.first_usable_lba
        || byte_end_exclusive > image_size
    {
        report
            .limitations
            .push("GPT partition-entry array bounds are invalid".to_owned());
        return Ok(None);
    }
    report.partition_table_ranges.push(PartitionTableRange {
        byte_start,
        byte_end_exclusive,
    });
    let start = usize::try_from(byte_start).map_err(|_| C01Error::AccountingOverflow)?;
    let end = usize::try_from(byte_end_exclusive).map_err(|_| C01Error::AccountingOverflow)?;
    if crc32(&image.bytes[start..end]) != header.expected_entries_crc {
        report
            .limitations
            .push("GPT partition-entry array CRC32 verification failed".to_owned());
        return Ok(None);
    }
    Ok(Some(GptEntryArray {
        byte_start,
        byte_end_exclusive,
        start,
        end,
    }))
}

fn parse_gpt_partitions(
    image: &NormalizedDiskImage,
    header: GptHeader,
    array: GptEntryArray,
    report: &mut DiskImageReport,
) -> Result<bool, C01Error> {
    debug_assert!(array.start <= array.end && array.byte_start <= array.byte_end_exclusive);
    let image_size = u64::try_from(image.bytes.len()).map_err(|_| C01Error::AccountingOverflow)?;
    let mut saw_invalid = false;
    for slot in 0..header.entry_count {
        let offset = array
            .byte_start
            .checked_add(
                u64::from(slot)
                    .checked_mul(u64::from(header.entry_size))
                    .ok_or(C01Error::AccountingOverflow)?,
            )
            .ok_or(C01Error::AccountingOverflow)?;
        let start = usize::try_from(offset).map_err(|_| C01Error::AccountingOverflow)?;
        let end = start
            .checked_add(
                usize::try_from(header.entry_size).map_err(|_| C01Error::AccountingOverflow)?,
            )
            .ok_or(C01Error::AccountingOverflow)?;
        let entry = &image.bytes[start..end];
        if entry[0..16].iter().all(|byte| *byte == 0) {
            continue;
        }
        let first_lba = read_u64(entry, 32)?;
        let last_lba = read_u64(entry, 40)?;
        let unique_guid_missing = entry[16..32].iter().all(|byte| *byte == 0);
        let valid_lbas = first_lba <= last_lba
            && first_lba >= header.first_usable_lba
            && last_lba <= header.last_usable_lba;
        let byte_start = first_lba.checked_mul(SECTOR_SIZE);
        let byte_end = last_lba
            .checked_add(1)
            .and_then(|value| value.checked_mul(SECTOR_SIZE));
        if unique_guid_missing
            || !valid_lbas
            || byte_start.is_none()
            || byte_end.is_none()
            || byte_end.is_some_and(|end| end > image_size)
        {
            saw_invalid = true;
            report.warnings.push(format!(
                "GPT slot {} has invalid identity or usable-LBA extent",
                slot + 1
            ));
            continue;
        }
        report.partitions.push(PartitionEntry {
            index: slot + 1,
            name: decode_gpt_name(&entry[56..entry.len().min(128)]),
            type_id: format_gpt_guid(&entry[0..16]),
            first_lba,
            last_lba_inclusive: last_lba,
            byte_start: byte_start.expect("validated above"),
            byte_end_exclusive: byte_end.expect("validated above"),
            bootable: false,
            container: false,
        });
    }
    Ok(saw_invalid)
}

fn inspect_gpt(
    image: &NormalizedDiskImage,
    limits: DiskImageLimits,
    report: &mut DiskImageReport,
) -> Result<(), C01Error> {
    report.partition_table = PartitionTableKind::Gpt;
    report.partition_table_ranges.push(PartitionTableRange {
        byte_start: 0,
        byte_end_exclusive: 512,
    });
    let Some(header) = parse_gpt_header(image, limits, report)? else {
        return Ok(());
    };
    debug_assert!(header.header_size >= 92);
    let Some(array) = validate_gpt_entry_array(image, header, report)? else {
        return Ok(());
    };
    let mut saw_invalid = parse_gpt_partitions(image, header, array, report)?;
    report
        .partitions
        .sort_by_key(|partition| (partition.byte_start, partition.index));
    if has_partition_overlap(&report.partitions) {
        saw_invalid = true;
        report.warnings.push(
            "GPT accepted partition entries overlap; layout is not fully trustworthy".to_owned(),
        );
    }
    report.assessment = if saw_invalid {
        if report.partitions.is_empty() {
            PartitionMapAssessment::Inconclusive
        } else {
            PartitionMapAssessment::Partial
        }
    } else {
        PartitionMapAssessment::Complete
    };
    if saw_invalid {
        report.limitations.push(
            "invalid GPT entries were excluded from canonical partition projection".to_owned(),
        );
    }
    Ok(())
}

fn build_layout_coverage(
    image_size: u64,
    partitions: &[PartitionEntry],
    assessment: PartitionMapAssessment,
) -> Vec<PartitionLayoutRange> {
    if image_size == 0 {
        return Vec::new();
    }
    if has_partition_overlap(partitions) {
        return vec![PartitionLayoutRange {
            byte_start: 0,
            byte_end_exclusive: image_size,
            kind: PartitionLayoutKind::Unknown,
            partition_index: None,
        }];
    }
    let gap_kind = if assessment == PartitionMapAssessment::Complete {
        PartitionLayoutKind::Unallocated
    } else {
        PartitionLayoutKind::Unknown
    };
    let mut ranges = Vec::new();
    let mut cursor = 0_u64;
    let mut sorted = partitions.to_vec();
    sorted.sort_by_key(|partition| (partition.byte_start, partition.byte_end_exclusive));
    for partition in sorted {
        if partition.byte_start > cursor {
            ranges.push(PartitionLayoutRange {
                byte_start: cursor,
                byte_end_exclusive: partition.byte_start,
                kind: gap_kind,
                partition_index: None,
            });
        }
        if partition.byte_end_exclusive > partition.byte_start {
            ranges.push(PartitionLayoutRange {
                byte_start: partition.byte_start,
                byte_end_exclusive: partition.byte_end_exclusive,
                kind: PartitionLayoutKind::Partition,
                partition_index: Some(partition.index),
            });
            cursor = cursor.max(partition.byte_end_exclusive);
        }
    }
    if cursor < image_size {
        ranges.push(PartitionLayoutRange {
            byte_start: cursor,
            byte_end_exclusive: image_size,
            kind: gap_kind,
            partition_index: None,
        });
    }
    ranges
}

fn has_partition_overlap(partitions: &[PartitionEntry]) -> bool {
    partitions.windows(2).any(|pair| {
        pair[0].byte_end_exclusive > pair[1].byte_start && !pair[0].container && !pair[1].container
    })
}

fn report_projection_digest(report: &DiskImageReport) -> String {
    let mut hasher = Sha256::new();
    hash_guard_text(
        &mut hasher,
        &serde_json::to_string(&report.source_revision_ref).unwrap_or_default(),
    );
    hash_guard_text(&mut hasher, &report.source_sha256);
    hash_guard_text(&mut hasher, &report.normalized_sha256);
    hasher.update(report.normalized_size.to_le_bytes());
    hash_guard_text(&mut hasher, &format!("{:?}", report.partition_table));
    hash_guard_text(&mut hasher, &format!("{:?}", report.assessment));
    hash_guard_text(&mut hasher, &format!("{:?}", report.partitions));
    hash_guard_text(&mut hasher, &format!("{:?}", report.source_coverage));
    format!("{:x}", hasher.finalize())
}

fn hash_guard_text(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn seal_report(mut report: DiskImageReport) -> DiskImageReport {
    report.projection_sha256 = report_projection_digest(&report);
    report
}

fn validate_report_integrity(report: &DiskImageReport) -> Result<(), C01Error> {
    if report.projection_sha256.is_empty()
        || report.projection_sha256 != report_projection_digest(report)
    {
        return Err(C01Error::ReportIntegrityMismatch);
    }
    Ok(())
}

fn validate_context(context: &DiskImageContext) -> Result<(), C01Error> {
    if context.workspace_ref.entity_kind.as_str() != "core.workspace" {
        return Err(C01Error::InvalidWorkspaceRef);
    }
    if context.source_revision_ref.entity_kind.as_str() != "object.revision" {
        return Err(C01Error::InvalidSourceRevision);
    }
    Ok(())
}

fn validate_limits(limits: DiskImageLimits) -> Result<(), C01Error> {
    if limits.max_output_bytes == 0
        || limits.max_sparse_chunks == 0
        || limits.max_partition_entries == 0
    {
        return Err(C01Error::InvalidLimits);
    }
    Ok(())
}

fn view_spec(context: &DiskImageContext, view_kind: &str, schema_suffix: &str) -> ViewSpec {
    ViewSpec {
        workspace_ref: context.workspace_ref.clone(),
        authority_ref: context.authority_ref.clone(),
        view_kind: view_kind.to_owned(),
        view_schema_id: format!("urn:ptah:schema:c01:{schema_suffix}:0.1.0"),
        view_schema_version: "0.1.0".to_owned(),
        source_revision_refs: vec![context.source_revision_ref.clone()],
        origin_class: OriginClass::DecodedResource,
        production: context.production.clone(),
    }
}

fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

fn push_coverage(
    coverage: &mut Vec<SourceCoverageRange>,
    start: u64,
    end: u64,
    kind: SourceCoverageKind,
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
    coverage.push(SourceCoverageRange {
        byte_start: start,
        byte_end_exclusive: end,
        kind,
    });
}

fn decode_gpt_name(bytes: &[u8]) -> Option<String> {
    let mut words = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        if word == 0 {
            break;
        }
        words.push(word);
    }
    if words.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&words))
}

fn format_gpt_guid(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return "gpt:invalid-guid".to_owned();
    }
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, C01Error> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or(C01Error::MalformedSparse("integer field is truncated"))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, C01Error> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or(C01Error::MalformedSparse("integer field is truncated"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, C01Error> {
    let slice = bytes
        .get(offset..offset + 8)
        .ok_or(C01Error::MalformedSparse("integer field is truncated"))?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_u32_unchecked(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
