use ptah_identifiers::EntityRef;
use ptah_object_store::{
    OriginClass, ProductionEvidence, RegisterObjectSpec, Registration, RelationshipSpec,
    RevisionRole, ViewSpec,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const BOOT_MAGIC: &[u8; 8] = b"ANDROID!";
const VENDOR_BOOT_MAGIC: &[u8; 8] = b"VNDRBOOT";
const AVB_MAGIC: &[u8; 4] = b"AVB0";
const OTA_MAGIC: &[u8; 4] = b"CrAU";
const DTBO_MAGIC: u32 = 0xd7b7_ab1e;
const LP_GEOMETRY_MAGIC: u32 = 0x616c_4467;
const LP_HEADER_MAGIC: u32 = 0x414c_5030;
const LP_RESERVED_BYTES: u64 = 4096;
const LP_GEOMETRY_SIZE: u64 = 4096;
const LP_SECTOR_SIZE: u64 = 512;
const LP_GEOMETRY_STRUCT_SIZE: usize = 52;
const LP_HEADER_V1_0_SIZE: usize = 128;
const LP_HEADER_V1_2_SIZE: usize = 256;
const AVB_HEADER_SIZE: u64 = 256;
const BOOT_V0_SIZE: u64 = 1632;
const BOOT_V1_SIZE: u64 = 1648;
const BOOT_V2_SIZE: u64 = 1660;
const BOOT_V3_SIZE: u64 = 1580;
const BOOT_V4_SIZE: u64 = 1584;
const VENDOR_BOOT_V3_SIZE: u64 = 2112;
const VENDOR_BOOT_V4_SIZE: u64 = 2128;
const VENDOR_RAMDISK_TABLE_ENTRY_V4_SIZE: u64 = 108;

/// Bounded resource limits for one C03 inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AndroidLimits {
    /// Maximum source bytes accepted by one inspection.
    pub max_source_bytes: u64,
    /// Maximum retained source-backed components.
    pub max_components: usize,
    /// Maximum liblp metadata slots.
    pub max_metadata_slots: u32,
    /// Maximum retained dynamic partitions.
    pub max_dynamic_partitions: usize,
    /// Maximum retained extents across one report.
    pub max_extents: usize,
    /// Maximum retained dynamic groups.
    pub max_dynamic_groups: usize,
    /// Maximum OTA manifest bytes accepted before Provider work.
    pub max_manifest_bytes: u64,
    /// Maximum OTA partition updates.
    pub max_ota_partitions: usize,
    /// Maximum OTA install operations.
    pub max_ota_operations: usize,
    /// Maximum bytes retained for any one string.
    pub max_string_bytes: usize,
    /// Maximum bytes materialized for one child or logical partition.
    pub max_materialized_bytes: u64,
}

impl Default for AndroidLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 16 * 1024 * 1024 * 1024,
            max_components: 65_536,
            max_metadata_slots: 32,
            max_dynamic_partitions: 16_384,
            max_extents: 1_000_000,
            max_dynamic_groups: 4096,
            max_manifest_bytes: 64 * 1024 * 1024,
            max_ota_partitions: 16_384,
            max_ota_operations: 1_000_000,
            max_string_bytes: 4096,
            max_materialized_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// Exact immutable source and A04 production context.
#[derive(Debug, Clone)]
pub struct AndroidContext {
    /// Workspace owning source and derived plans.
    pub workspace_ref: EntityRef,
    /// Authority for canonical plans.
    pub authority_ref: EntityRef,
    /// Exact immutable source Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact producing evidence.
    pub production: ProductionEvidence,
}

/// Generic Android artifact family inspected by C03.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AndroidArtifactKind {
    /// Android boot partition image.
    Boot,
    /// Android 13+ init_boot image.
    InitBoot,
    /// Android vendor_boot image.
    VendorBoot,
    /// Device-tree overlay table image.
    Dtbo,
    /// AVB vbmeta image.
    Vbmeta,
    /// Dynamic-partition super image.
    Super,
    /// Android update_engine payload.bin.
    OtaPayload,
}

/// Optional caller declaration needed when bytes alone are ambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AndroidInspectRequest {
    /// Required for `ANDROID!` images to distinguish boot from init_boot.
    pub declared_kind: Option<AndroidArtifactKind>,
}

impl Default for AndroidInspectRequest {
    fn default() -> Self {
        Self { declared_kind: None }
    }
}

/// Truth status of one C03 structural inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidAssessment {
    /// All C03-supported structures for this artifact were validated.
    Complete,
    /// Exact supported structures exist but limitations remain.
    Partial,
    /// A trustworthy C03 structural projection could not be established.
    Inconclusive,
}

/// Mechanical integrity evidence established by C03.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidIntegrityAssessment {
    /// Structural framing and bounds only.
    StructureChecked,
    /// Format-defined SHA-256 checksums were also verified.
    ChecksumsVerified,
}

/// Trust state deliberately separate from structural parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidTrustAssessment {
    /// C03 has not established boot/signing/update trust.
    NotEstablished,
}

/// Exact source-backed component class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AndroidComponentKind {
    /// Format header bytes.
    Header,
    /// Boot kernel.
    Kernel,
    /// Generic or legacy ramdisk.
    Ramdisk,
    /// Legacy second-stage payload.
    SecondStage,
    /// Legacy recovery DTBO/ACPIO payload.
    RecoveryDtbo,
    /// Device-tree blob.
    Dtb,
    /// Boot v4 signature region.
    BootSignature,
    /// Whole vendor ramdisk section.
    VendorRamdisk,
    /// One vendor ramdisk fragment.
    VendorRamdiskFragment,
    /// Vendor ramdisk table.
    VendorRamdiskTable,
    /// Vendor bootconfig.
    Bootconfig,
    /// One DTBO table entry payload.
    DtboEntry,
    /// vbmeta authentication block.
    VbmetaAuthentication,
    /// vbmeta auxiliary block.
    VbmetaAuxiliary,
    /// vbmeta descriptor subrange.
    VbmetaDescriptors,
    /// liblp geometry copy.
    SuperGeometry,
    /// liblp metadata copy.
    SuperMetadata,
    /// OTA manifest protobuf bytes.
    OtaManifest,
    /// OTA metadata signature bytes.
    OtaMetadataSignature,
    /// OTA payload-data bytes.
    OtaPayloadData,
}

/// One exact immutable source byte range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidComponent {
    /// Stable component class.
    pub kind: AndroidComponentKind,
    /// Deterministic component name.
    pub name: String,
    /// Inclusive source byte start.
    pub byte_start: u64,
    /// Exclusive source byte end.
    pub byte_end_exclusive: u64,
    /// SHA-256 of exact component bytes.
    pub sha256: String,
}

/// Dynamic-partition extent target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicExtentTarget {
    /// dm-linear mapping into one liblp block device.
    Linear {
        /// Physical sector on target block device.
        physical_sector: u64,
        /// Block-device table index.
        block_device_index: u32,
    },
    /// dm-zero extent with mechanically defined zero bytes.
    Zero,
}

/// One exact logical-partition extent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidDynamicExtent {
    /// Extent length in 512-byte sectors.
    pub num_sectors: u64,
    /// Exact target mapping.
    pub target: DynamicExtentTarget,
}

/// One dynamic-partition group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidDynamicGroup {
    /// Metadata slot containing the group.
    pub metadata_slot: u32,
    /// Group name.
    pub name: String,
    /// Maximum group bytes, zero meaning unlimited in liblp.
    pub maximum_size: u64,
}

/// One liblp block-device record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidBlockDevice {
    /// Metadata slot containing the record.
    pub metadata_slot: u32,
    /// GPT partition name.
    pub name: String,
    /// First logical sector usable for extents.
    pub first_logical_sector: u64,
    /// Declared block-device size.
    pub size: u64,
}

/// One logical dynamic partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidDynamicPartition {
    /// Metadata slot containing this projection.
    pub metadata_slot: u32,
    /// Logical partition name.
    pub name: String,
    /// Raw liblp partition attributes.
    pub attributes: u32,
    /// Owning group name.
    pub group_name: String,
    /// Ordered logical extents.
    pub extents: Vec<AndroidDynamicExtent>,
    /// Exact logical byte size.
    pub logical_size: u64,
}

/// One OTA operation data-blob range, relative to payload data start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtaOperationRange {
    /// Relative data offset.
    pub data_offset: u64,
    /// Data length.
    pub data_length: u64,
}

/// One partition update declared by an OTA manifest Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtaPartitionUpdate {
    /// Partition name.
    pub name: String,
    /// Optional exact target partition size.
    pub new_size: Option<u64>,
    /// Operation blobs referenced by this partition update.
    pub operations: Vec<OtaOperationRange>,
}

/// One dynamic group declared by an OTA manifest Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtaDynamicGroup {
    /// Group name.
    pub name: String,
    /// Optional maximum size.
    pub maximum_size: Option<u64>,
    /// Partition names assigned to the group.
    pub partition_names: Vec<String>,
}

/// Bounded protobuf semantics returned by a replaceable OTA manifest Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtaManifestObservation {
    /// Manifest block size.
    pub block_size: u32,
    /// Partition updates.
    pub partitions: Vec<OtaPartitionUpdate>,
    /// Dynamic partition groups.
    pub dynamic_groups: Vec<OtaDynamicGroup>,
    /// Whether the OTA is partial.
    pub partial_update: bool,
    /// Provider claim that all supported manifest semantics were decoded.
    pub complete_claim: bool,
    /// Explicit unsupported/partial semantics.
    pub limitations: Vec<String>,
}

/// Replaceable protobuf OTA manifest decoder boundary.
pub trait OtaManifestProvider: Send + Sync {
    /// Stable backend-local Provider alias/evidence identifier.
    fn provider_id(&self) -> &str;

    /// Decode exact immutable manifest protobuf bytes.
    ///
    /// # Errors
    /// Returns a Provider-specific mechanical failure.
    fn decode_manifest(
        &self,
        manifest_bytes: &[u8],
        major_version: u64,
        limits: AndroidLimits,
    ) -> Result<OtaManifestObservation, String>;
}

/// Validated OTA manifest projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidOtaManifest {
    /// Payload major version.
    pub major_version: u64,
    /// Exact manifest SHA-256.
    pub manifest_sha256: String,
    /// Backend-local Provider alias/evidence.
    pub provider_alias: String,
    /// Manifest block size.
    pub block_size: u32,
    /// Partition updates.
    pub partitions: Vec<OtaPartitionUpdate>,
    /// Dynamic groups.
    pub dynamic_groups: Vec<OtaDynamicGroup>,
    /// Partial-update flag.
    pub partial_update: bool,
    /// Explicit limitations.
    pub limitations: Vec<String>,
}

/// Source-bound C03 report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidReport {
    /// Exact source Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact whole-source SHA-256.
    pub source_sha256: String,
    /// Exact source byte size.
    pub source_size: u64,
    /// Artifact family.
    pub kind: AndroidArtifactKind,
    /// Structural truth status.
    pub assessment: AndroidAssessment,
    /// Mechanical integrity evidence.
    pub integrity: AndroidIntegrityAssessment,
    /// Trust state kept separate from parsing.
    pub trust: AndroidTrustAssessment,
    /// Exact source-backed components.
    pub components: Vec<AndroidComponent>,
    /// Dynamic logical partitions for super images.
    pub dynamic_partitions: Vec<AndroidDynamicPartition>,
    /// Dynamic groups for super images.
    pub dynamic_groups: Vec<AndroidDynamicGroup>,
    /// Block-device records for super images.
    pub block_devices: Vec<AndroidBlockDevice>,
    /// Validated OTA manifest semantics when a Provider was supplied.
    pub ota_manifest: Option<AndroidOtaManifest>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
    /// Unsupported, ambiguous or incomplete boundaries.
    pub limitations: Vec<String>,
    projection_sha256: String,
}

impl AndroidReport {
    /// Produce exact source-bound A07 Views.
    ///
    /// # Errors
    /// Rejects mutated reports or mismatched source context.
    pub fn view_specs(&self, context: &AndroidContext) -> Result<Vec<ViewSpec>, C03Error> {
        validate_context(context)?;
        validate_report_integrity(self)?;
        if self.source_revision_ref != context.source_revision_ref {
            return Err(C03Error::SourceBindingMismatch);
        }
        Ok(vec![
            view_spec(context, "android.inventory", "inventory"),
            view_spec(context, "android.partition_manifest", "partition-manifest"),
            view_spec(context, "android.proof_levels", "proof-levels"),
        ])
    }
}

/// Exact recovered component or logical-partition bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidMaterialization {
    /// Deterministic child name.
    pub name: String,
    /// A07 object class used for registration.
    pub object_class: String,
    /// Exact parent source Revision.
    pub source_revision_ref: EntityRef,
    /// Exact recovered SHA-256.
    pub sha256: String,
    bytes: Vec<u8>,
}

impl AndroidMaterialization {
    /// Read-only recovered bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Build exact source-bound A07 registration.
    ///
    /// # Errors
    /// Rejects context that does not bind the exact source Revision.
    pub fn registration_spec(
        &self,
        context: &AndroidContext,
    ) -> Result<RegisterObjectSpec, C03Error> {
        validate_context(context)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C03Error::SourceBindingMismatch);
        }
        Ok(RegisterObjectSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            object_class: self.object_class.clone(),
            declared_name: Some(self.name.clone()),
            source_refs: vec![self.source_revision_ref.clone()],
            revision_role: RevisionRole::Recovered,
            origin_class: OriginClass::RecoveredEmbeddedSource,
            created_reason: "C03 recovered exact Android child bytes".to_owned(),
            production: context.production.clone(),
            expected_sha256: Some(self.sha256.clone()),
        })
    }

    /// Build source-to-child A07 Relationship after exact registration.
    ///
    /// # Errors
    /// Rejects mismatched registration bytes or canonical endpoint kinds.
    pub fn relationship_spec(
        &self,
        context: &AndroidContext,
        registration: &Registration,
    ) -> Result<RelationshipSpec, C03Error> {
        validate_context(context)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C03Error::SourceBindingMismatch);
        }
        if registration.object_ref.entity_kind.as_str() != "object.object"
            || registration.revision_ref.entity_kind.as_str() != "object.revision"
        {
            return Err(C03Error::InvalidRegistration);
        }
        let byte_size =
            u64::try_from(self.bytes.len()).map_err(|_| C03Error::AccountingOverflow)?;
        if registration.sha256 != self.sha256 || registration.byte_size != byte_size {
            return Err(C03Error::RegistrationMismatch);
        }
        Ok(RelationshipSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            subject_refs: vec![self.source_revision_ref.clone()],
            relationship_type: "contains.android_child".to_owned(),
            object_refs: vec![
                registration.object_ref.clone(),
                registration.revision_ref.clone(),
            ],
            production: context.production.clone(),
        })
    }
}

/// Structural comparison strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AndroidComparisonLevel {
    /// Structural projections differ.
    Different,
    /// Structure matches but retained component digests differ.
    Structural,
    /// Retained component identities match but whole source differs.
    ComponentExact,
    /// Whole immutable source digest matches.
    ByteExact,
}

/// Explicit rebuild evidence level. No level implies bootability or signature trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AndroidRebuildProofLevel {
    /// No equivalence was established.
    None,
    /// Structural projection matches.
    Structural,
    /// All retained component identities match.
    ComponentExact,
    /// Whole source bytes are digest-identical.
    ByteExact,
}

/// Source-bound comparison report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidComparison {
    /// Left source Revision.
    pub left_source_revision_ref: EntityRef,
    /// Right source Revision.
    pub right_source_revision_ref: EntityRef,
    /// Strongest mechanically established level.
    pub level: AndroidComparisonLevel,
    /// Deterministic structural differences.
    pub differences: Vec<String>,
}

/// C03 failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum C03Error {
    /// Workspace reference is not canonical.
    #[error("C03 workspace reference must be core.workspace")]
    InvalidWorkspaceRef,
    /// Source must bind an exact Object Revision.
    #[error("C03 source must be an exact object.revision reference")]
    InvalidSourceRevision,
    /// One configured resource limit is zero.
    #[error("C03 limits must all be greater than zero")]
    InvalidLimits,
    /// Source exceeds configured bytes.
    #[error("C03 source exceeds max_source_bytes")]
    SourceTooLarge,
    /// Source signature is not a C03 Android artifact family.
    #[error("C03 Android artifact signature is unsupported")]
    UnsupportedArtifact,
    /// ANDROID! framing requires explicit boot/init_boot declaration.
    #[error("C03 ANDROID! source requires explicit boot or init_boot role")]
    BootRoleRequired,
    /// Caller-declared family disagrees with source framing.
    #[error("C03 declared Android role disagrees with source framing")]
    DeclaredKindMismatch,
    /// Header/version is malformed or unsupported.
    #[error("C03 malformed or unsupported Android header: {0}")]
    Malformed(&'static str),
    /// Numeric accounting overflowed.
    #[error("C03 byte accounting overflow")]
    AccountingOverflow,
    /// Component count exceeds configured bound.
    #[error("C03 component count exceeds configured limit")]
    TooManyComponents,
    /// Dynamic partition count exceeds configured bound.
    #[error("C03 dynamic partition count exceeds configured limit")]
    TooManyPartitions,
    /// Extent count exceeds configured bound.
    #[error("C03 extent count exceeds configured limit")]
    TooManyExtents,
    /// Dynamic group count exceeds configured bound.
    #[error("C03 dynamic group count exceeds configured limit")]
    TooManyGroups,
    /// OTA operation count exceeds configured bound.
    #[error("C03 OTA operation count exceeds configured limit")]
    TooManyOperations,
    /// String exceeds configured bounds or violates format grammar.
    #[error("C03 invalid bounded Android name/string")]
    InvalidString,
    /// OTA manifest exceeds configured bytes.
    #[error("C03 OTA manifest exceeds configured limit")]
    ManifestTooLarge,
    /// OTA Provider failed.
    #[error("C03 OTA manifest Provider failed: {0}")]
    OtaProvider(String),
    /// OTA Provider output is structurally inconsistent.
    #[error("C03 invalid OTA manifest Provider observation")]
    InvalidOtaObservation,
    /// Report/source/context binding mismatch.
    #[error("C03 exact source binding mismatch")]
    SourceBindingMismatch,
    /// Report was mutated after inspection.
    #[error("C03 report integrity seal mismatch")]
    ReportIntegrityMismatch,
    /// Requested child does not exist.
    #[error("C03 requested Android child was not found")]
    ChildNotFound,
    /// Requested logical partition cannot be materialized from this source.
    #[error("C03 logical partition cannot be materialized from exact source bytes")]
    PartitionNotMaterializable,
    /// Materialization exceeds configured bound.
    #[error("C03 materialization exceeds configured limit")]
    MaterializationTooLarge,
    /// Registered A07 endpoints have invalid kinds.
    #[error("C03 child registration has invalid canonical endpoint kinds")]
    InvalidRegistration,
    /// Registration bytes do not match exact recovered child.
    #[error("C03 child registration does not match exact bytes")]
    RegistrationMismatch,
}

/// Inspect one immutable Generic Android image or OTA artifact.
///
/// # Errors
/// Fails closed for malformed framing, bounds, checksum, Provider or resource violations.
pub fn inspect_android_artifact(
    source: &[u8],
    context: &AndroidContext,
    request: AndroidInspectRequest,
    limits: AndroidLimits,
    ota_provider: Option<&dyn OtaManifestProvider>,
) -> Result<AndroidReport, C03Error> {
    validate_context(context)?;
    validate_limits(limits)?;
    let source_size = u64::try_from(source.len()).map_err(|_| C03Error::AccountingOverflow)?;
    if source_size > limits.max_source_bytes {
        return Err(C03Error::SourceTooLarge);
    }
    let source_sha256 = sha256_bytes(source);

    if source.starts_with(BOOT_MAGIC) {
        let kind = request.declared_kind.ok_or(C03Error::BootRoleRequired)?;
        if !matches!(kind, AndroidArtifactKind::Boot | AndroidArtifactKind::InitBoot) {
            return Err(C03Error::DeclaredKindMismatch);
        }
        return inspect_boot(source, context, kind, source_sha256, limits);
    }
    if source.starts_with(VENDOR_BOOT_MAGIC) {
        require_declared_compatible(request.declared_kind, AndroidArtifactKind::VendorBoot)?;
        return inspect_vendor_boot(source, context, source_sha256, limits);
    }
    if source.len() >= 4 && read_be_u32(source, 0)? == DTBO_MAGIC {
        require_declared_compatible(request.declared_kind, AndroidArtifactKind::Dtbo)?;
        return inspect_dtbo(source, context, source_sha256, limits);
    }
    if source.starts_with(AVB_MAGIC) {
        require_declared_compatible(request.declared_kind, AndroidArtifactKind::Vbmeta)?;
        return inspect_vbmeta(source, context, source_sha256, limits);
    }
    if looks_like_super(source) {
        require_declared_compatible(request.declared_kind, AndroidArtifactKind::Super)?;
        return inspect_super(source, context, source_sha256, limits);
    }
    if source.starts_with(OTA_MAGIC) {
        require_declared_compatible(request.declared_kind, AndroidArtifactKind::OtaPayload)?;
        return inspect_ota(source, context, source_sha256, limits, ota_provider);
    }
    Err(C03Error::UnsupportedArtifact)
}

/// Materialize one exact source-backed component.
///
/// # Errors
/// Rejects mutated/stale reports, missing components and configured bounds.
pub fn materialize_android_component(
    source: &[u8],
    report: &AndroidReport,
    component_name: &str,
    context: &AndroidContext,
    limits: AndroidLimits,
) -> Result<AndroidMaterialization, C03Error> {
    validate_materialization_source(source, report, context, limits)?;
    let component = report
        .components
        .iter()
        .find(|component| component.name == component_name)
        .ok_or(C03Error::ChildNotFound)?;
    let length = component
        .byte_end_exclusive
        .checked_sub(component.byte_start)
        .ok_or(C03Error::AccountingOverflow)?;
    if length > limits.max_materialized_bytes {
        return Err(C03Error::MaterializationTooLarge);
    }
    let start = usize::try_from(component.byte_start).map_err(|_| C03Error::AccountingOverflow)?;
    let end = usize::try_from(component.byte_end_exclusive)
        .map_err(|_| C03Error::AccountingOverflow)?;
    let bytes = source
        .get(start..end)
        .ok_or(C03Error::SourceBindingMismatch)?
        .to_vec();
    if sha256_bytes(&bytes) != component.sha256 {
        return Err(C03Error::SourceBindingMismatch);
    }
    Ok(AndroidMaterialization {
        name: component.name.clone(),
        object_class: "android.image.component".to_owned(),
        source_revision_ref: report.source_revision_ref.clone(),
        sha256: component.sha256.clone(),
        bytes,
    })
}

/// Materialize one liblp logical partition from LINEAR/ZERO extents when all LINEAR targets are
/// exact source block-device index 0 ranges.
///
/// # Errors
/// Rejects stale reports, external block-device extents, out-of-bounds ranges and resource limits.
pub fn materialize_dynamic_partition(
    source: &[u8],
    report: &AndroidReport,
    metadata_slot: u32,
    partition_name: &str,
    context: &AndroidContext,
    limits: AndroidLimits,
) -> Result<AndroidMaterialization, C03Error> {
    validate_materialization_source(source, report, context, limits)?;
    if report.kind != AndroidArtifactKind::Super {
        return Err(C03Error::PartitionNotMaterializable);
    }
    let partition = report
        .dynamic_partitions
        .iter()
        .find(|partition| partition.metadata_slot == metadata_slot && partition.name == partition_name)
        .ok_or(C03Error::ChildNotFound)?;
    if partition.logical_size > limits.max_materialized_bytes {
        return Err(C03Error::MaterializationTooLarge);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(partition.logical_size).map_err(|_| C03Error::MaterializationTooLarge)?,
    );
    for extent in &partition.extents {
        let length = extent
            .num_sectors
            .checked_mul(LP_SECTOR_SIZE)
            .ok_or(C03Error::AccountingOverflow)?;
        match extent.target {
            DynamicExtentTarget::Zero => {
                let new_len = u64::try_from(bytes.len())
                    .map_err(|_| C03Error::AccountingOverflow)?
                    .checked_add(length)
                    .ok_or(C03Error::AccountingOverflow)?;
                bytes.resize(
                    usize::try_from(new_len).map_err(|_| C03Error::MaterializationTooLarge)?,
                    0,
                );
            }
            DynamicExtentTarget::Linear {
                physical_sector,
                block_device_index,
            } => {
                if block_device_index != 0 {
                    return Err(C03Error::PartitionNotMaterializable);
                }
                let start = physical_sector
                    .checked_mul(LP_SECTOR_SIZE)
                    .ok_or(C03Error::AccountingOverflow)?;
                let end = start
                    .checked_add(length)
                    .ok_or(C03Error::AccountingOverflow)?;
                let start = usize::try_from(start).map_err(|_| C03Error::AccountingOverflow)?;
                let end = usize::try_from(end).map_err(|_| C03Error::AccountingOverflow)?;
                bytes.extend_from_slice(
                    source
                        .get(start..end)
                        .ok_or(C03Error::PartitionNotMaterializable)?,
                );
            }
        }
    }
    if u64::try_from(bytes.len()).map_err(|_| C03Error::AccountingOverflow)? != partition.logical_size
    {
        return Err(C03Error::PartitionNotMaterializable);
    }
    Ok(AndroidMaterialization {
        name: partition.name.clone(),
        object_class: "android.dynamic_partition".to_owned(),
        source_revision_ref: report.source_revision_ref.clone(),
        sha256: sha256_bytes(&bytes),
        bytes,
    })
}

/// Compare two sealed C03 reports without making boot/signature/device claims.
#[must_use]
pub fn compare_android_artifacts(left: &AndroidReport, right: &AndroidReport) -> AndroidComparison {
    let mut differences = Vec::new();
    if left.kind != right.kind {
        differences.push(format!("kind:{:?}->{:?}", left.kind, right.kind));
    }
    if left.assessment != right.assessment {
        differences.push(format!(
            "assessment:{:?}->{:?}",
            left.assessment, right.assessment
        ));
    }
    if left.integrity != right.integrity {
        differences.push(format!(
            "integrity:{:?}->{:?}",
            left.integrity, right.integrity
        ));
    }
    if left.dynamic_partitions != right.dynamic_partitions {
        differences.push("dynamic_partitions_changed".to_owned());
    }
    if left.dynamic_groups != right.dynamic_groups {
        differences.push("dynamic_groups_changed".to_owned());
    }
    if left.block_devices != right.block_devices {
        differences.push("block_devices_changed".to_owned());
    }
    if left.ota_manifest != right.ota_manifest {
        differences.push("ota_manifest_changed".to_owned());
    }

    let left_shape: Vec<_> = left
        .components
        .iter()
        .map(|component| {
            (
                component.kind,
                component.name.as_str(),
                component.byte_start,
                component.byte_end_exclusive,
            )
        })
        .collect();
    let right_shape: Vec<_> = right
        .components
        .iter()
        .map(|component| {
            (
                component.kind,
                component.name.as_str(),
                component.byte_start,
                component.byte_end_exclusive,
            )
        })
        .collect();
    if left_shape != right_shape {
        differences.push("component_structure_changed".to_owned());
    }
    let component_exact = left.components == right.components;
    let structural = differences.is_empty() || (differences.len() == 1 && !component_exact && left_shape == right_shape);
    let level = if left.source_sha256 == right.source_sha256 && left.source_size == right.source_size {
        AndroidComparisonLevel::ByteExact
    } else if component_exact && differences.is_empty() {
        AndroidComparisonLevel::ComponentExact
    } else if structural && left.kind == right.kind {
        AndroidComparisonLevel::Structural
    } else {
        AndroidComparisonLevel::Different
    };
    AndroidComparison {
        left_source_revision_ref: left.source_revision_ref.clone(),
        right_source_revision_ref: right.source_revision_ref.clone(),
        level,
        differences,
    }
}

/// Convert comparison evidence into an explicit rebuild proof level.
#[must_use]
pub fn assess_android_rebuild(
    original: &AndroidReport,
    rebuilt: &AndroidReport,
) -> AndroidRebuildProofLevel {
    match compare_android_artifacts(original, rebuilt).level {
        AndroidComparisonLevel::Different => AndroidRebuildProofLevel::None,
        AndroidComparisonLevel::Structural => AndroidRebuildProofLevel::Structural,
        AndroidComparisonLevel::ComponentExact => AndroidRebuildProofLevel::ComponentExact,
        AndroidComparisonLevel::ByteExact => AndroidRebuildProofLevel::ByteExact,
    }
}

fn inspect_boot(
    source: &[u8],
    context: &AndroidContext,
    kind: AndroidArtifactKind,
    source_sha256: String,
    limits: AndroidLimits,
) -> Result<AndroidReport, C03Error> {
    if source.len() < 48 {
        return Err(C03Error::Malformed("boot header is truncated"));
    }
    let version = read_le_u32(source, 40)?;
    if version > 4 {
        return Err(C03Error::Malformed("unsupported boot header version"));
    }
    if kind == AndroidArtifactKind::InitBoot && version != 4 {
        return Err(C03Error::DeclaredKindMismatch);
    }
    let mut components = Vec::new();
    let mut limitations = Vec::new();
    if version <= 2 {
        if kind != AndroidArtifactKind::Boot {
            return Err(C03Error::DeclaredKindMismatch);
        }
        let page = u64::from(read_le_u32(source, 36)?);
        if page < 512 || page > 65_536 || !page.is_power_of_two() {
            return Err(C03Error::Malformed("invalid legacy boot page size"));
        }
        let header_size = match version {
            0 => BOOT_V0_SIZE,
            1 => BOOT_V1_SIZE,
            2 => BOOT_V2_SIZE,
            _ => unreachable!(),
        };
        push_component(
            source,
            &mut components,
            AndroidComponentKind::Header,
            "boot.header",
            0,
            header_size,
            limits,
        )?;
        let kernel_size = u64::from(read_le_u32(source, 8)?);
        let ramdisk_size = u64::from(read_le_u32(source, 16)?);
        let second_size = u64::from(read_le_u32(source, 24)?);
        if kernel_size == 0 || ramdisk_size == 0 {
            return Err(C03Error::Malformed("legacy boot kernel/ramdisk is empty"));
        }
        let mut cursor = page;
        cursor = push_aligned_component(
            source,
            &mut components,
            AndroidComponentKind::Kernel,
            "boot.kernel",
            cursor,
            kernel_size,
            page,
            limits,
        )?;
        cursor = push_aligned_component(
            source,
            &mut components,
            AndroidComponentKind::Ramdisk,
            "boot.ramdisk",
            cursor,
            ramdisk_size,
            page,
            limits,
        )?;
        if second_size > 0 {
            cursor = push_aligned_component(
                source,
                &mut components,
                AndroidComponentKind::SecondStage,
                "boot.second",
                cursor,
                second_size,
                page,
                limits,
            )?;
        }
        if version >= 1 {
            let recovery_size = u64::from(read_le_u32(source, 1632)?);
            let recovery_offset = read_le_u64(source, 1636)?;
            if recovery_size > 0 {
                if recovery_offset % page != 0 || recovery_offset < cursor {
                    return Err(C03Error::Malformed("invalid recovery DTBO offset"));
                }
                push_component(
                    source,
                    &mut components,
                    AndroidComponentKind::RecoveryDtbo,
                    "boot.recovery_dtbo",
                    recovery_offset,
                    recovery_offset
                        .checked_add(recovery_size)
                        .ok_or(C03Error::AccountingOverflow)?,
                    limits,
                )?;
                cursor = align_up(
                    recovery_offset
                        .checked_add(recovery_size)
                        .ok_or(C03Error::AccountingOverflow)?,
                    page,
                )?;
            }
        }
        if version == 2 {
            let dtb_size = u64::from(read_le_u32(source, 1648)?);
            if dtb_size == 0 {
                return Err(C03Error::Malformed("boot v2 DTB is empty"));
            }
            let dtb_end = cursor
                .checked_add(dtb_size)
                .ok_or(C03Error::AccountingOverflow)?;
            push_component(
                source,
                &mut components,
                AndroidComponentKind::Dtb,
                "boot.dtb",
                cursor,
                dtb_end,
                limits,
            )?;
        }
    } else {
        let expected_header = if version == 3 { BOOT_V3_SIZE } else { BOOT_V4_SIZE };
        let declared_header = u64::from(read_le_u32(source, 20)?);
        if declared_header < expected_header || declared_header > 4096 {
            return Err(C03Error::Malformed("invalid boot v3/v4 header size"));
        }
        push_component(
            source,
            &mut components,
            AndroidComponentKind::Header,
            "boot.header",
            0,
            declared_header,
            limits,
        )?;
        let kernel_size = u64::from(read_le_u32(source, 8)?);
        let ramdisk_size = u64::from(read_le_u32(source, 12)?);
        if kind == AndroidArtifactKind::InitBoot {
            if version != 4 || kernel_size != 0 || ramdisk_size == 0 {
                return Err(C03Error::Malformed("init_boot must be v4 ramdisk-only framing"));
            }
        } else if kernel_size == 0 {
            return Err(C03Error::Malformed("boot v3/v4 kernel is empty"));
        }
        let page = 4096_u64;
        let mut cursor = page;
        if kernel_size > 0 {
            cursor = push_aligned_component(
                source,
                &mut components,
                AndroidComponentKind::Kernel,
                "boot.kernel",
                cursor,
                kernel_size,
                page,
                limits,
            )?;
        }
        if ramdisk_size > 0 {
            cursor = push_aligned_component(
                source,
                &mut components,
                AndroidComponentKind::Ramdisk,
                if kind == AndroidArtifactKind::InitBoot {
                    "init_boot.ramdisk"
                } else {
                    "boot.ramdisk"
                },
                cursor,
                ramdisk_size,
                page,
                limits,
            )?;
        }
        if version == 4 {
            let signature_size = u64::from(read_le_u32(source, 1580)?);
            if signature_size > 0 {
                let signature_end = cursor
                    .checked_add(signature_size)
                    .ok_or(C03Error::AccountingOverflow)?;
                push_component(
                    source,
                    &mut components,
                    AndroidComponentKind::BootSignature,
                    "boot.signature",
                    cursor,
                    signature_end,
                    limits,
                )?;
                limitations.push(
                    "boot_signature presence is structural evidence, not device AVB trust".to_owned(),
                );
            }
        }
    }
    Ok(seal_report(AndroidReport {
        source_revision_ref: context.source_revision_ref.clone(),
        source_sha256,
        source_size: u64::try_from(source.len()).map_err(|_| C03Error::AccountingOverflow)?,
        kind,
        assessment: if limitations.is_empty() {
            AndroidAssessment::Complete
        } else {
            AndroidAssessment::Partial
        },
        integrity: AndroidIntegrityAssessment::StructureChecked,
        trust: AndroidTrustAssessment::NotEstablished,
        components,
        dynamic_partitions: Vec::new(),
        dynamic_groups: Vec::new(),
        block_devices: Vec::new(),
        ota_manifest: None,
        warnings: Vec::new(),
        limitations,
        projection_sha256: String::new(),
    }))
}

fn inspect_vendor_boot(
    source: &[u8],
    context: &AndroidContext,
    source_sha256: String,
    limits: AndroidLimits,
) -> Result<AndroidReport, C03Error> {
    if source.len() < usize::try_from(VENDOR_BOOT_V3_SIZE).unwrap_or(usize::MAX) {
        return Err(C03Error::Malformed("vendor_boot header is truncated"));
    }
    let version = read_le_u32(source, 8)?;
    if !matches!(version, 3 | 4) {
        return Err(C03Error::Malformed("unsupported vendor_boot version"));
    }
    let page = u64::from(read_le_u32(source, 12)?);
    if page < 512 || page > 65_536 || !page.is_power_of_two() {
        return Err(C03Error::Malformed("invalid vendor_boot page size"));
    }
    let ramdisk_size = u64::from(read_le_u32(source, 24)?);
    let declared_header = u64::from(read_le_u32(source, 2096)?);
    let expected_header = if version == 3 {
        VENDOR_BOOT_V3_SIZE
    } else {
        VENDOR_BOOT_V4_SIZE
    };
    if declared_header < expected_header || declared_header > page.max(expected_header) {
        return Err(C03Error::Malformed("invalid vendor_boot header size"));
    }
    let dtb_size = u64::from(read_le_u32(source, 2100)?);
    if ramdisk_size == 0 || dtb_size == 0 {
        return Err(C03Error::Malformed("vendor_boot ramdisk/DTB is empty"));
    }
    let mut components = Vec::new();
    push_component(
        source,
        &mut components,
        AndroidComponentKind::Header,
        "vendor_boot.header",
        0,
        declared_header,
        limits,
    )?;
    let mut cursor = align_up(expected_header, page)?;
    let ramdisk_start = cursor;
    cursor = push_aligned_component(
        source,
        &mut components,
        AndroidComponentKind::VendorRamdisk,
        "vendor_boot.ramdisk_section",
        cursor,
        ramdisk_size,
        page,
        limits,
    )?;
    cursor = push_aligned_component(
        source,
        &mut components,
        AndroidComponentKind::Dtb,
        "vendor_boot.dtb",
        cursor,
        dtb_size,
        page,
        limits,
    )?;
    if version == 4 {
        let table_size = u64::from(read_le_u32(source, 2112)?);
        let table_count = u64::from(read_le_u32(source, 2116)?);
        let table_entry_size = u64::from(read_le_u32(source, 2120)?);
        let bootconfig_size = u64::from(read_le_u32(source, 2124)?);
        if table_count > 0 {
            if table_entry_size < VENDOR_RAMDISK_TABLE_ENTRY_V4_SIZE
                || table_count
                    .checked_mul(table_entry_size)
                    .ok_or(C03Error::AccountingOverflow)?
                    > table_size
            {
                return Err(C03Error::Malformed("invalid vendor ramdisk table sizing"));
            }
            let table_start = cursor;
            let table_end = table_start
                .checked_add(table_size)
                .ok_or(C03Error::AccountingOverflow)?;
            push_component(
                source,
                &mut components,
                AndroidComponentKind::VendorRamdiskTable,
                "vendor_boot.ramdisk_table",
                table_start,
                table_end,
                limits,
            )?;
            for index in 0..table_count {
                let entry = table_start
                    .checked_add(
                        index
                            .checked_mul(table_entry_size)
                            .ok_or(C03Error::AccountingOverflow)?,
                    )
                    .ok_or(C03Error::AccountingOverflow)?;
                let entry_usize = usize::try_from(entry).map_err(|_| C03Error::AccountingOverflow)?;
                let fragment_size = u64::from(read_le_u32(source, entry_usize)?);
                let fragment_offset = u64::from(read_le_u32(source, entry_usize + 4)?);
                let fragment_start = ramdisk_start
                    .checked_add(fragment_offset)
                    .ok_or(C03Error::AccountingOverflow)?;
                let fragment_end = fragment_start
                    .checked_add(fragment_size)
                    .ok_or(C03Error::AccountingOverflow)?;
                if fragment_end
                    > ramdisk_start
                        .checked_add(ramdisk_size)
                        .ok_or(C03Error::AccountingOverflow)?
                {
                    return Err(C03Error::Malformed("vendor ramdisk fragment is out of section"));
                }
                push_component(
                    source,
                    &mut components,
                    AndroidComponentKind::VendorRamdiskFragment,
                    &format!("vendor_boot.ramdisk_fragment.{index}"),
                    fragment_start,
                    fragment_end,
                    limits,
                )?;
            }
            cursor = align_up(table_end, page)?;
        } else if table_size != 0 {
            return Err(C03Error::Malformed("vendor ramdisk table count/size mismatch"));
        }
        if bootconfig_size > 0 {
            let end = cursor
                .checked_add(bootconfig_size)
                .ok_or(C03Error::AccountingOverflow)?;
            push_component(
                source,
                &mut components,
                AndroidComponentKind::Bootconfig,
                "vendor_boot.bootconfig",
                cursor,
                end,
                limits,
            )?;
        }
    }
    Ok(seal_report(base_report(
        source,
        context,
        source_sha256,
        AndroidArtifactKind::VendorBoot,
        AndroidAssessment::Complete,
        AndroidIntegrityAssessment::StructureChecked,
        components,
    )?))
}

fn inspect_dtbo(
    source: &[u8],
    context: &AndroidContext,
    source_sha256: String,
    limits: AndroidLimits,
) -> Result<AndroidReport, C03Error> {
    if source.len() < 32 {
        return Err(C03Error::Malformed("DTBO header is truncated"));
    }
    let total_size = u64::from(read_be_u32(source, 4)?);
    let header_size = u64::from(read_be_u32(source, 8)?);
    let entry_size = u64::from(read_be_u32(source, 12)?);
    let entry_count = u64::from(read_be_u32(source, 16)?);
    let entries_offset = u64::from(read_be_u32(source, 20)?);
    let version = read_be_u32(source, 28)?;
    let required_entry_size = match version {
        0 | 1 => 32_u64,
        2 => 64_u64,
        _ => return Err(C03Error::Malformed("unsupported DTBO table version")),
    };
    if total_size > u64::try_from(source.len()).map_err(|_| C03Error::AccountingOverflow)?
        || header_size < 32
        || header_size > total_size
        || entry_size < required_entry_size
        || entries_offset < header_size
        || entry_count > u64::try_from(limits.max_components).unwrap_or(u64::MAX)
    {
        return Err(C03Error::Malformed("invalid DTBO table bounds"));
    }
    let table_bytes = entry_count
        .checked_mul(entry_size)
        .ok_or(C03Error::AccountingOverflow)?;
    if entries_offset
        .checked_add(table_bytes)
        .ok_or(C03Error::AccountingOverflow)?
        > total_size
    {
        return Err(C03Error::Malformed("DTBO entry table is out of bounds"));
    }
    let mut components = Vec::new();
    push_component(
        source,
        &mut components,
        AndroidComponentKind::Header,
        "dtbo.header",
        0,
        header_size,
        limits,
    )?;
    for index in 0..entry_count {
        let entry_offset = entries_offset
            .checked_add(index.checked_mul(entry_size).ok_or(C03Error::AccountingOverflow)?)
            .ok_or(C03Error::AccountingOverflow)?;
        let entry_offset = usize::try_from(entry_offset).map_err(|_| C03Error::AccountingOverflow)?;
        let dt_size = u64::from(read_be_u32(source, entry_offset)?);
        let dt_offset = u64::from(read_be_u32(source, entry_offset + 4)?);
        let dt_end = dt_offset
            .checked_add(dt_size)
            .ok_or(C03Error::AccountingOverflow)?;
        if dt_size == 0 || dt_offset < header_size || dt_end > total_size {
            return Err(C03Error::Malformed("DTBO entry payload is out of bounds"));
        }
        push_component(
            source,
            &mut components,
            AndroidComponentKind::DtboEntry,
            &format!("dtbo.entry.{index}"),
            dt_offset,
            dt_end,
            limits,
        )?;
    }
    Ok(seal_report(base_report(
        source,
        context,
        source_sha256,
        AndroidArtifactKind::Dtbo,
        AndroidAssessment::Complete,
        AndroidIntegrityAssessment::StructureChecked,
        components,
    )?))
}

fn inspect_vbmeta(
    source: &[u8],
    context: &AndroidContext,
    source_sha256: String,
    limits: AndroidLimits,
) -> Result<AndroidReport, C03Error> {
    if u64::try_from(source.len()).map_err(|_| C03Error::AccountingOverflow)? < AVB_HEADER_SIZE {
        return Err(C03Error::Malformed("vbmeta header is truncated"));
    }
    let auth_size = read_be_u64(source, 12)?;
    let aux_size = read_be_u64(source, 20)?;
    let auth_start = AVB_HEADER_SIZE;
    let auth_end = auth_start
        .checked_add(auth_size)
        .ok_or(C03Error::AccountingOverflow)?;
    let aux_end = auth_end
        .checked_add(aux_size)
        .ok_or(C03Error::AccountingOverflow)?;
    if aux_end > u64::try_from(source.len()).map_err(|_| C03Error::AccountingOverflow)? {
        return Err(C03Error::Malformed("vbmeta blocks exceed source"));
    }
    let descriptors_offset = read_be_u64(source, 96)?;
    let descriptors_size = read_be_u64(source, 104)?;
    let descriptors_start = auth_end
        .checked_add(descriptors_offset)
        .ok_or(C03Error::AccountingOverflow)?;
    let descriptors_end = descriptors_start
        .checked_add(descriptors_size)
        .ok_or(C03Error::AccountingOverflow)?;
    if descriptors_offset > aux_size
        || descriptors_size > aux_size.saturating_sub(descriptors_offset)
        || descriptors_end > aux_end
    {
        return Err(C03Error::Malformed("vbmeta descriptor range exceeds auxiliary block"));
    }
    let mut components = Vec::new();
    push_component(
        source,
        &mut components,
        AndroidComponentKind::Header,
        "vbmeta.header",
        0,
        AVB_HEADER_SIZE,
        limits,
    )?;
    if auth_size > 0 {
        push_component(
            source,
            &mut components,
            AndroidComponentKind::VbmetaAuthentication,
            "vbmeta.authentication",
            auth_start,
            auth_end,
            limits,
        )?;
    }
    if aux_size > 0 {
        push_component(
            source,
            &mut components,
            AndroidComponentKind::VbmetaAuxiliary,
            "vbmeta.auxiliary",
            auth_end,
            aux_end,
            limits,
        )?;
    }
    if descriptors_size > 0 {
        push_component(
            source,
            &mut components,
            AndroidComponentKind::VbmetaDescriptors,
            "vbmeta.descriptors",
            descriptors_start,
            descriptors_end,
            limits,
        )?;
    }
    let mut report = base_report(
        source,
        context,
        source_sha256,
        AndroidArtifactKind::Vbmeta,
        AndroidAssessment::Partial,
        AndroidIntegrityAssessment::StructureChecked,
        components,
    )?;
    report.limitations.push(
        "vbmeta structure parsed; AVB trust requires independent verification with a known-good key"
            .to_owned(),
    );
    Ok(seal_report(report))
}

fn inspect_super(
    source: &[u8],
    context: &AndroidContext,
    source_sha256: String,
    limits: AndroidLimits,
) -> Result<AndroidReport, C03Error> {
    let primary_geometry = parse_geometry(source, LP_RESERVED_BYTES).ok();
    let backup_geometry = parse_geometry(source, LP_RESERVED_BYTES + LP_GEOMETRY_SIZE).ok();
    let geometry = primary_geometry
        .clone()
        .or_else(|| backup_geometry.clone())
        .ok_or(C03Error::Malformed("both liblp geometry copies are invalid"))?;
    if geometry.metadata_slot_count > limits.max_metadata_slots {
        return Err(C03Error::Malformed("liblp metadata slot count exceeds configured bound"));
    }
    let mut limitations = Vec::new();
    if let (Some(primary), Some(backup)) = (&primary_geometry, &backup_geometry) {
        if primary != backup {
            limitations.push("primary and backup liblp geometry copies disagree".to_owned());
        }
    } else {
        limitations.push("one liblp geometry copy is invalid".to_owned());
    }
    let mut components = Vec::new();
    if primary_geometry.is_some() {
        push_component(
            source,
            &mut components,
            AndroidComponentKind::SuperGeometry,
            "super.geometry.primary",
            LP_RESERVED_BYTES,
            LP_RESERVED_BYTES + LP_GEOMETRY_SIZE,
            limits,
        )?;
    }
    if backup_geometry.is_some() {
        push_component(
            source,
            &mut components,
            AndroidComponentKind::SuperGeometry,
            "super.geometry.backup",
            LP_RESERVED_BYTES + LP_GEOMETRY_SIZE,
            LP_RESERVED_BYTES + (LP_GEOMETRY_SIZE * 2),
            limits,
        )?;
    }

    let metadata_base = LP_RESERVED_BYTES + (LP_GEOMETRY_SIZE * 2);
    let backup_base = metadata_base
        .checked_add(
            u64::from(geometry.metadata_max_size)
                .checked_mul(u64::from(geometry.metadata_slot_count))
                .ok_or(C03Error::AccountingOverflow)?,
        )
        .ok_or(C03Error::AccountingOverflow)?;
    let mut dynamic_partitions = Vec::new();
    let mut dynamic_groups = Vec::new();
    let mut block_devices = Vec::new();
    let mut extent_total = 0_usize;
    let mut valid_slots = 0_u32;
    for slot in 0..geometry.metadata_slot_count {
        let delta = u64::from(geometry.metadata_max_size)
            .checked_mul(u64::from(slot))
            .ok_or(C03Error::AccountingOverflow)?;
        let primary_offset = metadata_base
            .checked_add(delta)
            .ok_or(C03Error::AccountingOverflow)?;
        let backup_offset = backup_base
            .checked_add(delta)
            .ok_or(C03Error::AccountingOverflow)?;
        let primary = parse_super_slot(source, primary_offset, slot, &geometry, limits).ok();
        let backup = parse_super_slot(source, backup_offset, slot, &geometry, limits).ok();
        let selected = match (&primary, &backup) {
            (Some(primary), Some(backup)) => {
                if primary != backup {
                    limitations.push(format!(
                        "liblp metadata slot {slot} primary/backup copies disagree"
                    ));
                }
                primary.clone()
            }
            (Some(primary), None) => {
                limitations.push(format!("liblp metadata slot {slot} backup copy is invalid"));
                primary.clone()
            }
            (None, Some(backup)) => {
                limitations.push(format!("liblp metadata slot {slot} primary copy is invalid"));
                backup.clone()
            }
            (None, None) => {
                limitations.push(format!("liblp metadata slot {slot} has no valid copy"));
                continue;
            }
        };
        valid_slots = valid_slots.saturating_add(1);
        let selected_offset = if primary.is_some() {
            primary_offset
        } else {
            backup_offset
        };
        push_component(
            source,
            &mut components,
            AndroidComponentKind::SuperMetadata,
            &format!("super.metadata.slot.{slot}"),
            selected_offset,
            selected_offset
                .checked_add(selected.serialized_size)
                .ok_or(C03Error::AccountingOverflow)?,
            limits,
        )?;
        extent_total = extent_total
            .checked_add(selected.extent_count)
            .ok_or(C03Error::AccountingOverflow)?;
        if extent_total > limits.max_extents {
            return Err(C03Error::TooManyExtents);
        }
        dynamic_partitions.extend(selected.partitions);
        dynamic_groups.extend(selected.groups);
        block_devices.extend(selected.block_devices);
        if dynamic_partitions.len() > limits.max_dynamic_partitions {
            return Err(C03Error::TooManyPartitions);
        }
        if dynamic_groups.len() > limits.max_dynamic_groups {
            return Err(C03Error::TooManyGroups);
        }
    }
    if valid_slots == 0 {
        return Err(C03Error::Malformed("no valid liblp metadata slot"));
    }
    let assessment = if limitations.is_empty() {
        AndroidAssessment::Complete
    } else {
        AndroidAssessment::Partial
    };
    Ok(seal_report(AndroidReport {
        source_revision_ref: context.source_revision_ref.clone(),
        source_sha256,
        source_size: u64::try_from(source.len()).map_err(|_| C03Error::AccountingOverflow)?,
        kind: AndroidArtifactKind::Super,
        assessment,
        integrity: AndroidIntegrityAssessment::ChecksumsVerified,
        trust: AndroidTrustAssessment::NotEstablished,
        components,
        dynamic_partitions,
        dynamic_groups,
        block_devices,
        ota_manifest: None,
        warnings: Vec::new(),
        limitations,
        projection_sha256: String::new(),
    }))
}

fn inspect_ota(
    source: &[u8],
    context: &AndroidContext,
    source_sha256: String,
    limits: AndroidLimits,
    provider: Option<&dyn OtaManifestProvider>,
) -> Result<AndroidReport, C03Error> {
    if source.len() < 20 {
        return Err(C03Error::Malformed("OTA payload header is truncated"));
    }
    let major_version = read_be_u64(source, 4)?;
    if !matches!(major_version, 1 | 2) {
        return Err(C03Error::Malformed("unsupported OTA payload major version"));
    }
    let manifest_size = read_be_u64(source, 12)?;
    if manifest_size > limits.max_manifest_bytes {
        return Err(C03Error::ManifestTooLarge);
    }
    let (manifest_offset, signature_size) = if major_version == 2 {
        if source.len() < 24 {
            return Err(C03Error::Malformed("OTA v2 header is truncated"));
        }
        (24_u64, u64::from(read_be_u32(source, 20)?))
    } else {
        (20_u64, 0_u64)
    };
    let manifest_end = manifest_offset
        .checked_add(manifest_size)
        .ok_or(C03Error::AccountingOverflow)?;
    let signature_end = manifest_end
        .checked_add(signature_size)
        .ok_or(C03Error::AccountingOverflow)?;
    let source_size = u64::try_from(source.len()).map_err(|_| C03Error::AccountingOverflow)?;
    if signature_end > source_size {
        return Err(C03Error::Malformed("OTA metadata exceeds source"));
    }
    let mut components = Vec::new();
    push_component(
        source,
        &mut components,
        AndroidComponentKind::Header,
        "ota.header",
        0,
        manifest_offset,
        limits,
    )?;
    push_component(
        source,
        &mut components,
        AndroidComponentKind::OtaManifest,
        "ota.manifest",
        manifest_offset,
        manifest_end,
        limits,
    )?;
    if signature_size > 0 {
        push_component(
            source,
            &mut components,
            AndroidComponentKind::OtaMetadataSignature,
            "ota.metadata_signature",
            manifest_end,
            signature_end,
            limits,
        )?;
    }
    if signature_end < source_size {
        push_component(
            source,
            &mut components,
            AndroidComponentKind::OtaPayloadData,
            "ota.payload_data",
            signature_end,
            source_size,
            limits,
        )?;
    }
    let manifest_start_usize =
        usize::try_from(manifest_offset).map_err(|_| C03Error::AccountingOverflow)?;
    let manifest_end_usize =
        usize::try_from(manifest_end).map_err(|_| C03Error::AccountingOverflow)?;
    let manifest_bytes = source
        .get(manifest_start_usize..manifest_end_usize)
        .ok_or(C03Error::Malformed("OTA manifest is out of bounds"))?;
    let mut limitations = vec![
        "OTA applicability/signature trust is not established by static payload parsing".to_owned(),
    ];
    let ota_manifest = if let Some(provider) = provider {
        validate_string(provider.provider_id(), limits)?;
        let observation = provider
            .decode_manifest(manifest_bytes, major_version, limits)
            .map_err(C03Error::OtaProvider)?;
        validate_ota_observation(&observation, source_size - signature_end, limits)?;
        if !observation.limitations.is_empty() || !observation.complete_claim {
            limitations.extend(observation.limitations.clone());
        }
        Some(AndroidOtaManifest {
            major_version,
            manifest_sha256: sha256_bytes(manifest_bytes),
            provider_alias: provider.provider_id().to_owned(),
            block_size: observation.block_size,
            partitions: observation.partitions,
            dynamic_groups: observation.dynamic_groups,
            partial_update: observation.partial_update,
            limitations: observation.limitations,
        })
    } else {
        limitations.push("no OTA manifest protobuf Provider was supplied".to_owned());
        None
    };
    let assessment = if ota_manifest.is_some() && limitations.len() == 1 {
        AndroidAssessment::Complete
    } else {
        AndroidAssessment::Partial
    };
    Ok(seal_report(AndroidReport {
        source_revision_ref: context.source_revision_ref.clone(),
        source_sha256,
        source_size,
        kind: AndroidArtifactKind::OtaPayload,
        assessment,
        integrity: AndroidIntegrityAssessment::StructureChecked,
        trust: AndroidTrustAssessment::NotEstablished,
        components,
        dynamic_partitions: Vec::new(),
        dynamic_groups: Vec::new(),
        block_devices: Vec::new(),
        ota_manifest,
        warnings: Vec::new(),
        limitations,
        projection_sha256: String::new(),
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LpGeometry {
    metadata_max_size: u32,
    metadata_slot_count: u32,
    logical_block_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSuperSlot {
    serialized_size: u64,
    extent_count: usize,
    partitions: Vec<AndroidDynamicPartition>,
    groups: Vec<AndroidDynamicGroup>,
    block_devices: Vec<AndroidBlockDevice>,
}

#[derive(Debug, Clone, Copy)]
struct TableDescriptor {
    offset: u32,
    num_entries: u32,
    entry_size: u32,
}

fn parse_geometry(source: &[u8], offset: u64) -> Result<LpGeometry, C03Error> {
    let offset = usize::try_from(offset).map_err(|_| C03Error::AccountingOverflow)?;
    let end = offset
        .checked_add(LP_GEOMETRY_STRUCT_SIZE)
        .ok_or(C03Error::AccountingOverflow)?;
    let bytes = source
        .get(offset..end)
        .ok_or(C03Error::Malformed("liblp geometry is truncated"))?;
    if read_le_u32(bytes, 0)? != LP_GEOMETRY_MAGIC
        || usize::try_from(read_le_u32(bytes, 4)?).ok() != Some(LP_GEOMETRY_STRUCT_SIZE)
    {
        return Err(C03Error::Malformed("invalid liblp geometry magic/size"));
    }
    let expected = &bytes[8..40];
    let mut checked = bytes.to_vec();
    checked[8..40].fill(0);
    if sha256_raw(&checked).as_slice() != expected {
        return Err(C03Error::Malformed("liblp geometry checksum mismatch"));
    }
    let metadata_max_size = read_le_u32(bytes, 40)?;
    let metadata_slot_count = read_le_u32(bytes, 44)?;
    let logical_block_size = read_le_u32(bytes, 48)?;
    if metadata_max_size == 0
        || u64::from(metadata_max_size) % LP_SECTOR_SIZE != 0
        || metadata_slot_count == 0
        || logical_block_size == 0
        || u64::from(logical_block_size) % LP_SECTOR_SIZE != 0
    {
        return Err(C03Error::Malformed("invalid liblp geometry fields"));
    }
    Ok(LpGeometry {
        metadata_max_size,
        metadata_slot_count,
        logical_block_size,
    })
}

fn parse_super_slot(
    source: &[u8],
    offset: u64,
    slot: u32,
    geometry: &LpGeometry,
    limits: AndroidLimits,
) -> Result<ParsedSuperSlot, C03Error> {
    let start = usize::try_from(offset).map_err(|_| C03Error::AccountingOverflow)?;
    let prefix = source
        .get(start..start.checked_add(LP_HEADER_V1_0_SIZE).ok_or(C03Error::AccountingOverflow)?)
        .ok_or(C03Error::Malformed("liblp metadata header is truncated"))?;
    if read_le_u32(prefix, 0)? != LP_HEADER_MAGIC {
        return Err(C03Error::Malformed("invalid liblp metadata header magic"));
    }
    let major = read_le_u16(prefix, 4)?;
    let minor = read_le_u16(prefix, 6)?;
    if major != 10 || minor > 2 {
        return Err(C03Error::Malformed("unsupported liblp metadata version"));
    }
    let header_size = usize::try_from(read_le_u32(prefix, 8)?)
        .map_err(|_| C03Error::AccountingOverflow)?;
    let minimum = if minor >= 2 {
        LP_HEADER_V1_2_SIZE
    } else {
        LP_HEADER_V1_0_SIZE
    };
    if header_size < minimum || header_size > usize::try_from(geometry.metadata_max_size).unwrap_or(0)
    {
        return Err(C03Error::Malformed("invalid liblp metadata header size"));
    }
    let header_end = start
        .checked_add(header_size)
        .ok_or(C03Error::AccountingOverflow)?;
    let header = source
        .get(start..header_end)
        .ok_or(C03Error::Malformed("liblp metadata header exceeds source"))?;
    let expected_header = &header[12..44];
    let mut checked_header = header.to_vec();
    checked_header[12..44].fill(0);
    if sha256_raw(&checked_header).as_slice() != expected_header {
        return Err(C03Error::Malformed("liblp metadata header checksum mismatch"));
    }
    let tables_size = usize::try_from(read_le_u32(header, 44)?)
        .map_err(|_| C03Error::AccountingOverflow)?;
    let serialized_size = header_size
        .checked_add(tables_size)
        .ok_or(C03Error::AccountingOverflow)?;
    if serialized_size > usize::try_from(geometry.metadata_max_size).unwrap_or(0) {
        return Err(C03Error::Malformed("liblp tables exceed metadata slot"));
    }
    let tables_end = header_end
        .checked_add(tables_size)
        .ok_or(C03Error::AccountingOverflow)?;
    let tables = source
        .get(header_end..tables_end)
        .ok_or(C03Error::Malformed("liblp metadata tables exceed source"))?;
    if sha256_raw(tables).as_slice() != &header[48..80] {
        return Err(C03Error::Malformed("liblp table checksum mismatch"));
    }
    let descriptors = [
        parse_descriptor(header, 80)?,
        parse_descriptor(header, 92)?,
        parse_descriptor(header, 104)?,
        parse_descriptor(header, 116)?,
    ];
    validate_table_layout(&descriptors, tables_size)?;
    if descriptors[0].entry_size < 52
        || descriptors[1].entry_size < 24
        || descriptors[2].entry_size < 48
        || descriptors[3].entry_size < 64
        || descriptors[3].num_entries == 0
    {
        return Err(C03Error::Malformed("unsupported liblp table entry size"));
    }
    let extent_count = usize::try_from(descriptors[1].num_entries)
        .map_err(|_| C03Error::AccountingOverflow)?;
    if extent_count > limits.max_extents {
        return Err(C03Error::TooManyExtents);
    }
    let group_count = usize::try_from(descriptors[2].num_entries)
        .map_err(|_| C03Error::AccountingOverflow)?;
    if group_count > limits.max_dynamic_groups {
        return Err(C03Error::TooManyGroups);
    }
    let partition_count = usize::try_from(descriptors[0].num_entries)
        .map_err(|_| C03Error::AccountingOverflow)?;
    if partition_count > limits.max_dynamic_partitions {
        return Err(C03Error::TooManyPartitions);
    }

    let mut groups = Vec::with_capacity(group_count);
    let mut group_names = Vec::with_capacity(group_count);
    for index in 0..group_count {
        let entry = table_entry(tables, descriptors[2], index)?;
        let name = parse_lp_name(&entry[..36], limits)?;
        let maximum_size = read_le_u64(entry, 40)?;
        group_names.push(name.clone());
        groups.push(AndroidDynamicGroup {
            metadata_slot: slot,
            name,
            maximum_size,
        });
    }

    let block_count = usize::try_from(descriptors[3].num_entries)
        .map_err(|_| C03Error::AccountingOverflow)?;
    let mut block_devices = Vec::with_capacity(block_count);
    for index in 0..block_count {
        let entry = table_entry(tables, descriptors[3], index)?;
        let name = parse_lp_name(&entry[24..60], limits)?;
        let first_logical_sector = read_le_u64(entry, 0)?;
        let size = read_le_u64(entry, 16)?;
        if size == 0 || size % LP_SECTOR_SIZE != 0 || first_logical_sector >= size / LP_SECTOR_SIZE {
            return Err(C03Error::Malformed("invalid liblp block device"));
        }
        block_devices.push(AndroidBlockDevice {
            metadata_slot: slot,
            name,
            first_logical_sector,
            size,
        });
    }

    let mut extents = Vec::with_capacity(extent_count);
    for index in 0..extent_count {
        let entry = table_entry(tables, descriptors[1], index)?;
        let num_sectors = read_le_u64(entry, 0)?;
        let target_type = read_le_u32(entry, 8)?;
        let target_data = read_le_u64(entry, 12)?;
        let target_source = read_le_u32(entry, 20)?;
        if num_sectors == 0 {
            return Err(C03Error::Malformed("zero-length liblp extent"));
        }
        let target = match target_type {
            0 => {
                let block = block_devices
                    .get(usize::try_from(target_source).map_err(|_| C03Error::AccountingOverflow)?)
                    .ok_or(C03Error::Malformed("liblp extent target source is invalid"))?;
                let end_sector = target_data
                    .checked_add(num_sectors)
                    .ok_or(C03Error::AccountingOverflow)?;
                if target_data < block.first_logical_sector || end_sector > block.size / LP_SECTOR_SIZE {
                    return Err(C03Error::Malformed("liblp linear extent is out of block device"));
                }
                if target_source == 0 {
                    let end = end_sector
                        .checked_mul(LP_SECTOR_SIZE)
                        .ok_or(C03Error::AccountingOverflow)?;
                    if end > u64::try_from(source.len()).map_err(|_| C03Error::AccountingOverflow)? {
                        return Err(C03Error::Malformed("liblp linear extent exceeds source image"));
                    }
                }
                DynamicExtentTarget::Linear {
                    physical_sector: target_data,
                    block_device_index: target_source,
                }
            }
            1 if target_data == 0 && target_source == 0 => DynamicExtentTarget::Zero,
            1 => return Err(C03Error::Malformed("invalid liblp zero extent fields")),
            _ => return Err(C03Error::Malformed("unsupported liblp extent target type")),
        };
        extents.push(AndroidDynamicExtent {
            num_sectors,
            target,
        });
    }

    let mut partitions = Vec::with_capacity(partition_count);
    let mut names = BTreeSet::new();
    let mut group_totals = vec![0_u64; group_count];
    for index in 0..partition_count {
        let entry = table_entry(tables, descriptors[0], index)?;
        let name = parse_lp_name(&entry[..36], limits)?;
        if !names.insert(name.clone()) {
            return Err(C03Error::Malformed("duplicate liblp partition name"));
        }
        let attributes = read_le_u32(entry, 36)?;
        let first_extent = usize::try_from(read_le_u32(entry, 40)?)
            .map_err(|_| C03Error::AccountingOverflow)?;
        let count = usize::try_from(read_le_u32(entry, 44)?)
            .map_err(|_| C03Error::AccountingOverflow)?;
        let group_index = usize::try_from(read_le_u32(entry, 48)?)
            .map_err(|_| C03Error::AccountingOverflow)?;
        if count == 0
            || first_extent
                .checked_add(count)
                .is_none_or(|end| end > extents.len())
            || group_index >= groups.len()
        {
            return Err(C03Error::Malformed("invalid liblp partition extent/group index"));
        }
        let owned = extents[first_extent..first_extent + count].to_vec();
        let logical_size = owned.iter().try_fold(0_u64, |total, extent| {
            total
                .checked_add(
                    extent
                        .num_sectors
                        .checked_mul(LP_SECTOR_SIZE)
                        .ok_or(C03Error::AccountingOverflow)?,
                )
                .ok_or(C03Error::AccountingOverflow)
        })?;
        group_totals[group_index] = group_totals[group_index]
            .checked_add(logical_size)
            .ok_or(C03Error::AccountingOverflow)?;
        partitions.push(AndroidDynamicPartition {
            metadata_slot: slot,
            name,
            attributes,
            group_name: group_names[group_index].clone(),
            extents: owned,
            logical_size,
        });
    }
    for (index, group) in groups.iter().enumerate() {
        if group.maximum_size != 0 && group_totals[index] > group.maximum_size {
            return Err(C03Error::Malformed("liblp group maximum size exceeded"));
        }
    }
    Ok(ParsedSuperSlot {
        serialized_size: u64::try_from(serialized_size).map_err(|_| C03Error::AccountingOverflow)?,
        extent_count,
        partitions,
        groups,
        block_devices,
    })
}

fn parse_descriptor(header: &[u8], offset: usize) -> Result<TableDescriptor, C03Error> {
    Ok(TableDescriptor {
        offset: read_le_u32(header, offset)?,
        num_entries: read_le_u32(header, offset + 4)?,
        entry_size: read_le_u32(header, offset + 8)?,
    })
}

fn validate_table_layout(
    descriptors: &[TableDescriptor; 4],
    tables_size: usize,
) -> Result<(), C03Error> {
    let mut ranges = Vec::new();
    for descriptor in descriptors {
        let start = usize::try_from(descriptor.offset).map_err(|_| C03Error::AccountingOverflow)?;
        let length = usize::try_from(descriptor.num_entries)
            .map_err(|_| C03Error::AccountingOverflow)?
            .checked_mul(
                usize::try_from(descriptor.entry_size).map_err(|_| C03Error::AccountingOverflow)?,
            )
            .ok_or(C03Error::AccountingOverflow)?;
        let end = start.checked_add(length).ok_or(C03Error::AccountingOverflow)?;
        if end > tables_size {
            return Err(C03Error::Malformed("liblp table descriptor exceeds tables block"));
        }
        if length > 0 {
            ranges.push((start, end));
        }
    }
    ranges.sort_unstable();
    let mut cursor = 0_usize;
    for (start, end) in ranges {
        if start != cursor {
            return Err(C03Error::Malformed("liblp tables contain gap/overlap"));
        }
        cursor = end;
    }
    if cursor != tables_size {
        return Err(C03Error::Malformed("liblp table descriptors do not cover tables block"));
    }
    Ok(())
}

fn table_entry(
    tables: &[u8],
    descriptor: TableDescriptor,
    index: usize,
) -> Result<&[u8], C03Error> {
    let start = usize::try_from(descriptor.offset)
        .map_err(|_| C03Error::AccountingOverflow)?
        .checked_add(
            index
                .checked_mul(
                    usize::try_from(descriptor.entry_size)
                        .map_err(|_| C03Error::AccountingOverflow)?,
                )
                .ok_or(C03Error::AccountingOverflow)?,
        )
        .ok_or(C03Error::AccountingOverflow)?;
    let end = start
        .checked_add(
            usize::try_from(descriptor.entry_size).map_err(|_| C03Error::AccountingOverflow)?,
        )
        .ok_or(C03Error::AccountingOverflow)?;
    tables
        .get(start..end)
        .ok_or(C03Error::Malformed("liblp table entry exceeds table block"))
}

fn validate_ota_observation(
    observation: &OtaManifestObservation,
    payload_data_size: u64,
    limits: AndroidLimits,
) -> Result<(), C03Error> {
    if observation.block_size == 0
        || observation.partitions.len() > limits.max_ota_partitions
        || observation.dynamic_groups.len() > limits.max_dynamic_groups
    {
        return Err(C03Error::InvalidOtaObservation);
    }
    validate_limitations(&observation.limitations, limits)?;
    let mut partition_names = BTreeSet::new();
    let mut operation_count = 0_usize;
    for partition in &observation.partitions {
        validate_android_name(&partition.name, limits)?;
        if !partition_names.insert(partition.name.as_str()) {
            return Err(C03Error::InvalidOtaObservation);
        }
        operation_count = operation_count
            .checked_add(partition.operations.len())
            .ok_or(C03Error::AccountingOverflow)?;
        if operation_count > limits.max_ota_operations {
            return Err(C03Error::TooManyOperations);
        }
        for operation in &partition.operations {
            let end = operation
                .data_offset
                .checked_add(operation.data_length)
                .ok_or(C03Error::AccountingOverflow)?;
            if end > payload_data_size {
                return Err(C03Error::InvalidOtaObservation);
            }
        }
    }
    let mut group_names = BTreeSet::new();
    for group in &observation.dynamic_groups {
        validate_android_name(&group.name, limits)?;
        if !group_names.insert(group.name.as_str()) {
            return Err(C03Error::InvalidOtaObservation);
        }
        for partition_name in &group.partition_names {
            validate_android_name(partition_name, limits)?;
            if !partition_names.contains(partition_name.as_str()) {
                return Err(C03Error::InvalidOtaObservation);
            }
        }
    }
    if observation.complete_claim && !observation.limitations.is_empty() {
        return Err(C03Error::InvalidOtaObservation);
    }
    Ok(())
}

fn base_report(
    source: &[u8],
    context: &AndroidContext,
    source_sha256: String,
    kind: AndroidArtifactKind,
    assessment: AndroidAssessment,
    integrity: AndroidIntegrityAssessment,
    components: Vec<AndroidComponent>,
) -> Result<AndroidReport, C03Error> {
    Ok(AndroidReport {
        source_revision_ref: context.source_revision_ref.clone(),
        source_sha256,
        source_size: u64::try_from(source.len()).map_err(|_| C03Error::AccountingOverflow)?,
        kind,
        assessment,
        integrity,
        trust: AndroidTrustAssessment::NotEstablished,
        components,
        dynamic_partitions: Vec::new(),
        dynamic_groups: Vec::new(),
        block_devices: Vec::new(),
        ota_manifest: None,
        warnings: Vec::new(),
        limitations: Vec::new(),
        projection_sha256: String::new(),
    })
}

fn push_aligned_component(
    source: &[u8],
    components: &mut Vec<AndroidComponent>,
    kind: AndroidComponentKind,
    name: &str,
    start: u64,
    size: u64,
    alignment: u64,
    limits: AndroidLimits,
) -> Result<u64, C03Error> {
    let end = start.checked_add(size).ok_or(C03Error::AccountingOverflow)?;
    push_component(source, components, kind, name, start, end, limits)?;
    align_up(end, alignment)
}

fn push_component(
    source: &[u8],
    components: &mut Vec<AndroidComponent>,
    kind: AndroidComponentKind,
    name: &str,
    start: u64,
    end: u64,
    limits: AndroidLimits,
) -> Result<(), C03Error> {
    if components.len() >= limits.max_components || name.len() > limits.max_string_bytes {
        return Err(C03Error::TooManyComponents);
    }
    if end < start || end > u64::try_from(source.len()).map_err(|_| C03Error::AccountingOverflow)? {
        return Err(C03Error::Malformed("Android component range exceeds source"));
    }
    let start_usize = usize::try_from(start).map_err(|_| C03Error::AccountingOverflow)?;
    let end_usize = usize::try_from(end).map_err(|_| C03Error::AccountingOverflow)?;
    let bytes = source
        .get(start_usize..end_usize)
        .ok_or(C03Error::Malformed("Android component range exceeds source"))?;
    components.push(AndroidComponent {
        kind,
        name: name.to_owned(),
        byte_start: start,
        byte_end_exclusive: end,
        sha256: sha256_bytes(bytes),
    });
    Ok(())
}

fn validate_materialization_source(
    source: &[u8],
    report: &AndroidReport,
    context: &AndroidContext,
    limits: AndroidLimits,
) -> Result<(), C03Error> {
    validate_context(context)?;
    validate_limits(limits)?;
    validate_report_integrity(report)?;
    if report.source_revision_ref != context.source_revision_ref
        || report.source_size
            != u64::try_from(source.len()).map_err(|_| C03Error::AccountingOverflow)?
        || report.source_sha256 != sha256_bytes(source)
    {
        return Err(C03Error::SourceBindingMismatch);
    }
    Ok(())
}

fn validate_context(context: &AndroidContext) -> Result<(), C03Error> {
    if context.workspace_ref.entity_kind.as_str() != "core.workspace" {
        return Err(C03Error::InvalidWorkspaceRef);
    }
    if context.source_revision_ref.entity_kind.as_str() != "object.revision" {
        return Err(C03Error::InvalidSourceRevision);
    }
    Ok(())
}

fn validate_limits(limits: AndroidLimits) -> Result<(), C03Error> {
    if limits.max_source_bytes == 0
        || limits.max_components == 0
        || limits.max_metadata_slots == 0
        || limits.max_dynamic_partitions == 0
        || limits.max_extents == 0
        || limits.max_dynamic_groups == 0
        || limits.max_manifest_bytes == 0
        || limits.max_ota_partitions == 0
        || limits.max_ota_operations == 0
        || limits.max_string_bytes == 0
        || limits.max_materialized_bytes == 0
    {
        return Err(C03Error::InvalidLimits);
    }
    Ok(())
}

fn require_declared_compatible(
    declared: Option<AndroidArtifactKind>,
    actual: AndroidArtifactKind,
) -> Result<(), C03Error> {
    if declared.is_some_and(|declared| declared != actual) {
        return Err(C03Error::DeclaredKindMismatch);
    }
    Ok(())
}

fn validate_android_name(value: &str, limits: AndroidLimits) -> Result<(), C03Error> {
    validate_string(value, limits)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(C03Error::InvalidString);
    }
    Ok(())
}

fn validate_string(value: &str, limits: AndroidLimits) -> Result<(), C03Error> {
    if value.is_empty() || value.len() > limits.max_string_bytes {
        return Err(C03Error::InvalidString);
    }
    Ok(())
}

fn validate_limitations(values: &[String], limits: AndroidLimits) -> Result<(), C03Error> {
    for value in values {
        validate_string(value, limits)?;
    }
    Ok(())
}

fn parse_lp_name(bytes: &[u8], limits: AndroidLimits) -> Result<String, C03Error> {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    if end == 0 || bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(C03Error::InvalidString);
    }
    let value = std::str::from_utf8(&bytes[..end]).map_err(|_| C03Error::InvalidString)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(C03Error::InvalidString);
    }
    validate_string(value, limits)?;
    Ok(value.to_owned())
}

fn looks_like_super(source: &[u8]) -> bool {
    [LP_RESERVED_BYTES, LP_RESERVED_BYTES + LP_GEOMETRY_SIZE]
        .into_iter()
        .any(|offset| {
            usize::try_from(offset)
                .ok()
                .and_then(|offset| source.get(offset..offset.saturating_add(4)))
                .is_some_and(|bytes| bytes == LP_GEOMETRY_MAGIC.to_le_bytes())
        })
}

fn align_up(value: u64, alignment: u64) -> Result<u64, C03Error> {
    if alignment == 0 {
        return Err(C03Error::AccountingOverflow);
    }
    value
        .checked_add(alignment - 1)
        .map(|value| value / alignment * alignment)
        .ok_or(C03Error::AccountingOverflow)
}

fn report_projection_digest(report: &AndroidReport) -> String {
    let mut hasher = Sha256::new();
    hash_guard_text(
        &mut hasher,
        &serde_json::to_string(&report.source_revision_ref).unwrap_or_default(),
    );
    hash_guard_text(&mut hasher, &report.source_sha256);
    hasher.update(report.source_size.to_le_bytes());
    hash_guard_text(&mut hasher, &format!("{:?}", report.kind));
    hash_guard_text(&mut hasher, &format!("{:?}", report.assessment));
    hash_guard_text(&mut hasher, &format!("{:?}", report.integrity));
    hash_guard_text(&mut hasher, &format!("{:?}", report.trust));
    hash_guard_text(&mut hasher, &format!("{:?}", report.components));
    hash_guard_text(&mut hasher, &format!("{:?}", report.dynamic_partitions));
    hash_guard_text(&mut hasher, &format!("{:?}", report.dynamic_groups));
    hash_guard_text(&mut hasher, &format!("{:?}", report.block_devices));
    hash_guard_text(&mut hasher, &format!("{:?}", report.ota_manifest));
    hash_guard_text(&mut hasher, &format!("{:?}", report.warnings));
    hash_guard_text(&mut hasher, &format!("{:?}", report.limitations));
    format!("{:x}", hasher.finalize())
}

fn seal_report(mut report: AndroidReport) -> AndroidReport {
    report.projection_sha256 = report_projection_digest(&report);
    report
}

fn validate_report_integrity(report: &AndroidReport) -> Result<(), C03Error> {
    if report.projection_sha256.is_empty()
        || report.projection_sha256 != report_projection_digest(report)
    {
        return Err(C03Error::ReportIntegrityMismatch);
    }
    Ok(())
}

fn hash_guard_text(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn view_spec(context: &AndroidContext, view_kind: &str, suffix: &str) -> ViewSpec {
    ViewSpec {
        workspace_ref: context.workspace_ref.clone(),
        authority_ref: context.authority_ref.clone(),
        view_kind: view_kind.to_owned(),
        view_schema_id: format!("urn:ptah:schema:c03:{suffix}:0.1.0"),
        view_schema_version: "0.1.0".to_owned(),
        source_revision_refs: vec![context.source_revision_ref.clone()],
        origin_class: OriginClass::DecodedResource,
        production: context.production.clone(),
    }
}

fn read_le_u16(bytes: &[u8], offset: usize) -> Result<u16, C03Error> {
    let slice = bytes
        .get(offset..offset.checked_add(2).ok_or(C03Error::AccountingOverflow)?)
        .ok_or(C03Error::Malformed("truncated little-endian u16"))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Result<u32, C03Error> {
    let slice = bytes
        .get(offset..offset.checked_add(4).ok_or(C03Error::AccountingOverflow)?)
        .ok_or(C03Error::Malformed("truncated little-endian u32"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Result<u64, C03Error> {
    let slice = bytes
        .get(offset..offset.checked_add(8).ok_or(C03Error::AccountingOverflow)?)
        .ok_or(C03Error::Malformed("truncated little-endian u64"))?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Result<u32, C03Error> {
    let slice = bytes
        .get(offset..offset.checked_add(4).ok_or(C03Error::AccountingOverflow)?)
        .ok_or(C03Error::Malformed("truncated big-endian u32"))?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_be_u64(bytes: &[u8], offset: usize) -> Result<u64, C03Error> {
    let slice = bytes
        .get(offset..offset.checked_add(8).ok_or(C03Error::AccountingOverflow)?)
        .ok_or(C03Error::Malformed("truncated big-endian u64"))?;
    Ok(u64::from_be_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn sha256_raw(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}
