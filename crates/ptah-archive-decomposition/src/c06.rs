use ptah_identifiers::EntityRef;
use ptah_object_store::{
    OriginClass, ProductionEvidence, RegisterObjectSpec, Registration, RelationshipSpec,
    RevisionRole, ViewSpec,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Bounded resource limits for one C06 static inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct C06Limits {
    /// Maximum immutable primary-source bytes.
    pub max_source_bytes: u64,
    /// Maximum package/bundle entries.
    pub max_entries: usize,
    /// Maximum aggregate recovered sibling bytes.
    pub max_recovered_bytes: u64,
    /// Maximum retained string or path bytes.
    pub max_string_bytes: usize,
    /// Maximum normalized Firehose plan operations.
    pub max_operations: usize,
    /// Maximum exact child bytes materialized in one request.
    pub max_materialized_bytes: u64,
}

impl Default for C06Limits {
    fn default() -> Self {
        Self {
            max_source_bytes: 16 * 1024 * 1024 * 1024,
            max_entries: 131_072,
            max_recovered_bytes: 32 * 1024 * 1024 * 1024,
            max_string_bytes: 8192,
            max_operations: 131_072,
            max_materialized_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}

/// Exact immutable source and A04 production context.
#[derive(Debug, Clone)]
pub struct C06Context {
    /// Workspace owning source and derived plans.
    pub workspace_ref: EntityRef,
    /// Authority for canonical plans.
    pub authority_ref: EntityRef,
    /// Exact immutable package/index Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact producing evidence.
    pub production: ProductionEvidence,
}

/// Structural truth status of one C06 report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C06Assessment {
    /// All supplied C06-supported semantics were validated.
    Complete,
    /// Exact supported semantics exist but explicit limitations remain.
    Partial,
    /// A trustworthy static projection could not be established.
    Inconclusive,
}

/// Static package evidence grants no device mutation or loader-execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C06TrustAssessment {
    /// Device-side execution/write compatibility is not established by C06.
    NotEstablished,
}

/// Mechanically earned static proof level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum C06StaticProofLevel {
    /// Exact source identity and a bounded inventory exist.
    InventoryOnly,
    /// Package/bundle structure and ranges were validated.
    StructureChecked,
    /// Referenced component bytes are exact and digest-bound.
    ComponentsLinked,
    /// Static XML/loader relationships resolve to exact components.
    PlanLinked,
    /// Compared retained component identities and digests are exact.
    ComponentExact,
    /// Primary source bytes and retained component identities are exact.
    ByteExact,
}

/// Static comparison strength shared by both C06 families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum C06ComparisonLevel {
    /// Supported structural projections differ.
    Different,
    /// Structure matches but exact retained component bytes differ.
    Structural,
    /// Retained component identities/digests match while primary source bytes differ.
    ComponentExact,
    /// Primary source bytes and retained component identities are exact.
    ByteExact,
}

/// One exact inclusive/exclusive byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct C06ByteRange {
    /// Inclusive byte start.
    pub start: u64,
    /// Exclusive byte end.
    pub end_exclusive: u64,
}

/* ----------------------------- Unisoc PAC ----------------------------- */

/// Static role declared by the mechanical PAC table Provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnisocComponentRole {
    /// First-stage FDL payload.
    Fdl1,
    /// Second-stage FDL payload.
    Fdl2,
    /// XML/package metadata.
    Xml,
    /// Partition/image payload.
    PartitionImage,
    /// Other bounded PAC entry.
    Other,
}

/// One normalized PAC table entry from an untrusted mechanical Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnisocPacEntryObservation {
    /// PAC file-table identifier.
    pub file_id: u32,
    /// Canonical relative component path/name.
    pub path: String,
    /// Optional file version.
    pub file_version: Option<String>,
    /// Exact byte offset within the immutable PAC source.
    pub data_offset: u64,
    /// Exact byte size within the immutable PAC source.
    pub byte_size: u64,
    /// PAC flags retained as metadata only.
    pub flags: u32,
    /// PAC check flag retained as metadata only.
    pub check_flag: u32,
    /// Up to five PAC address values retained as metadata.
    pub addresses: [Option<u64>; 5],
    /// Mechanical static component role.
    pub role: UnisocComponentRole,
    /// Provider-declared lowercase SHA-256 for the exact source slice.
    pub expected_sha256: String,
}

/// Mechanical PAC structural-validation evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnisocPacValidationObservation {
    /// Provider explicitly validated the PAC magic/header family.
    pub magic_validated: bool,
    /// Provider explicitly validated supported header CRC/check semantics.
    pub header_crc_validated: bool,
    /// Provider explicitly validated supported file-table CRC/check semantics.
    pub table_crc_validated: bool,
}

/// Bounded normalized PAC observation from an untrusted Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnisocPacObservation {
    /// Optional product name.
    pub product_name: Option<String>,
    /// Optional product version.
    pub product_version: Option<String>,
    /// Optional product alias.
    pub product_alias: Option<String>,
    /// Explicit structural-validation evidence.
    pub validation: UnisocPacValidationObservation,
    /// Normalized PAC table entries.
    pub entries: Vec<UnisocPacEntryObservation>,
    /// Provider claim that all C06-supported PAC semantics were enumerated.
    pub complete_claim: bool,
    /// Explicit unsupported or partial semantics.
    pub limitations: Vec<String>,
}

/// Replaceable mechanical PAC parser boundary.
///
/// Provider output is never trusted as canonical truth: Core independently validates paths,
/// source ranges, overlap, digests, bounds and completeness semantics.
pub trait UnisocPacProvider: Send + Sync {
    /// Stable backend-local Provider alias/evidence identifier.
    fn provider_id(&self) -> &str;

    /// Parse one immutable PAC source into a bounded normalized observation.
    ///
    /// # Errors
    /// Returns a Provider-specific mechanical failure.
    fn inspect_pac(&self, source: &[u8], limits: C06Limits)
    -> Result<UnisocPacObservation, String>;
}

/// Validated exact PAC entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnisocPacEntry {
    /// PAC file-table identifier.
    pub file_id: u32,
    /// Canonical relative path.
    pub path: String,
    /// Optional file version.
    pub file_version: Option<String>,
    /// Exact source byte range.
    pub range: C06ByteRange,
    /// PAC flags retained as metadata only.
    pub flags: u32,
    /// PAC check flag retained as metadata only.
    pub check_flag: u32,
    /// Up to five PAC address values.
    pub addresses: [Option<u64>; 5],
    /// Static role.
    pub role: UnisocComponentRole,
    /// Exact source-slice SHA-256.
    pub sha256: String,
}

/// Explicit static FDL evidence boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnisocLoaderEvidence {
    /// FDL stage.
    pub role: UnisocComponentRole,
    /// Exact component path.
    pub component_path: String,
    /// Exact component digest.
    pub sha256: String,
    /// First PAC address value when supplied.
    pub base_address: Option<u64>,
    /// Device/board compatibility remains unestablished.
    pub compatibility: C06TrustAssessment,
}

/// Source-bound Unisoc PAC report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnisocPacReport {
    /// Exact PAC Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact immutable PAC SHA-256.
    pub source_sha256: String,
    /// Exact immutable PAC byte size.
    pub source_size: u64,
    /// Mechanical Provider alias.
    pub provider_alias: String,
    /// Optional product name.
    pub product_name: Option<String>,
    /// Optional product version.
    pub product_version: Option<String>,
    /// Optional product alias.
    pub product_alias: Option<String>,
    /// Structural PAC validation evidence.
    pub validation: UnisocPacValidationObservation,
    /// Validated PAC entries.
    pub entries: Vec<UnisocPacEntry>,
    /// FDL1/FDL2 static evidence only.
    pub loaders: Vec<UnisocLoaderEvidence>,
    /// Structural/semantic truth.
    pub assessment: C06Assessment,
    /// Device mutation/execution trust.
    pub trust: C06TrustAssessment,
    /// Mechanically earned static proof level.
    pub proof_level: Option<C06StaticProofLevel>,
    /// Explicit unsupported or incomplete boundaries.
    pub limitations: Vec<String>,
    projection_sha256: String,
}

impl UnisocPacReport {
    /// Produce exact source-bound A07 Views.
    ///
    /// # Errors
    /// Rejects mutated reports or mismatched source context.
    pub fn view_specs(&self, context: &C06Context) -> Result<Vec<ViewSpec>, C06Error> {
        validate_context(context)?;
        validate_unisoc_report_integrity(self)?;
        if self.source_revision_ref != context.source_revision_ref {
            return Err(C06Error::SourceBindingMismatch);
        }
        Ok(vec![
            c06_view_spec(context, "unisoc.pac.inventory", "unisoc-pac-inventory"),
            c06_view_spec(context, "unisoc.loader.evidence", "unisoc-loader-evidence"),
            c06_view_spec(context, "c06.proof_levels", "proof-levels"),
        ])
    }
}

/// Exact embedded PAC child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnisocMaterialization {
    /// Canonical PAC entry path.
    pub name: String,
    /// Exact PAC source Revision.
    pub source_revision_ref: EntityRef,
    /// Exact child SHA-256.
    pub sha256: String,
    bytes: Vec<u8>,
}

impl UnisocMaterialization {
    /// Read-only exact embedded bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Build exact source-bound A07 registration.
    ///
    /// # Errors
    /// Rejects context that does not bind the exact PAC Revision.
    pub fn registration_spec(&self, context: &C06Context) -> Result<RegisterObjectSpec, C06Error> {
        validate_context(context)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C06Error::SourceBindingMismatch);
        }
        Ok(RegisterObjectSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            object_class: "unisoc.pac.component".to_owned(),
            declared_name: Some(self.name.clone()),
            source_refs: vec![self.source_revision_ref.clone()],
            revision_role: RevisionRole::Recovered,
            origin_class: OriginClass::RecoveredEmbeddedSource,
            created_reason: "C06 recovered exact embedded Unisoc PAC component".to_owned(),
            production: context.production.clone(),
            expected_sha256: Some(self.sha256.clone()),
        })
    }

    /// Build PAC-parent-to-component A07 Relationship.
    ///
    /// # Errors
    /// Rejects mismatched registration bytes or canonical endpoint kinds.
    pub fn relationship_spec(
        &self,
        context: &C06Context,
        registration: &Registration,
    ) -> Result<RelationshipSpec, C06Error> {
        validate_materialization_registration(
            self.sha256.as_str(),
            self.bytes.len(),
            registration,
        )?;
        validate_context(context)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C06Error::SourceBindingMismatch);
        }
        Ok(RelationshipSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            subject_refs: vec![self.source_revision_ref.clone()],
            relationship_type: "contains.unisoc_pac_component".to_owned(),
            object_refs: vec![
                registration.object_ref.clone(),
                registration.revision_ref.clone(),
            ],
            production: context.production.clone(),
        })
    }
}

/// Source-bound Unisoc comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnisocComparison {
    /// Left source Revision.
    pub left_source_revision_ref: EntityRef,
    /// Right source Revision.
    pub right_source_revision_ref: EntityRef,
    /// Strongest mechanically established level.
    pub level: C06ComparisonLevel,
    /// Deterministic differences.
    pub differences: Vec<String>,
}

/// Inspect one immutable Unisoc PAC source through a bounded mechanical parser Provider.
///
/// C06 does not upload or execute FDL payloads and does not expose partition mutation.
///
/// # Errors
/// Fails closed for malformed Provider output, ranges, overlap, paths, digests or bounds.
pub fn inspect_unisoc_pac(
    source: &[u8],
    context: &C06Context,
    limits: C06Limits,
    provider: &dyn UnisocPacProvider,
) -> Result<UnisocPacReport, C06Error> {
    validate_context(context)?;
    validate_limits(limits)?;
    let source_size = u64::try_from(source.len()).map_err(|_| C06Error::AccountingOverflow)?;
    if source_size > limits.max_source_bytes {
        return Err(C06Error::SourceTooLarge);
    }
    validate_string(provider.provider_id(), limits)?;
    let observation = provider
        .inspect_pac(source, limits)
        .map_err(C06Error::UnisocProvider)?;
    let resolved = resolve_unisoc_observation(source, observation, limits)?;

    Ok(seal_unisoc_report(UnisocPacReport {
        source_revision_ref: context.source_revision_ref.clone(),
        source_sha256: sha256_bytes(source),
        source_size,
        provider_alias: provider.provider_id().to_owned(),
        product_name: resolved.product_name,
        product_version: resolved.product_version,
        product_alias: resolved.product_alias,
        validation: resolved.validation,
        entries: resolved.entries,
        loaders: resolved.loaders,
        assessment: resolved.assessment,
        trust: C06TrustAssessment::NotEstablished,
        proof_level: resolved.proof_level,
        limitations: resolved.limitations,
        projection_sha256: String::new(),
    }))
}

struct UnisocResolution {
    product_name: Option<String>,
    product_version: Option<String>,
    product_alias: Option<String>,
    validation: UnisocPacValidationObservation,
    entries: Vec<UnisocPacEntry>,
    loaders: Vec<UnisocLoaderEvidence>,
    assessment: C06Assessment,
    proof_level: Option<C06StaticProofLevel>,
    limitations: Vec<String>,
}

fn resolve_unisoc_observation(
    source: &[u8],
    observation: UnisocPacObservation,
    limits: C06Limits,
) -> Result<UnisocResolution, C06Error> {
    validate_optional_string(observation.product_name.as_deref(), limits)?;
    validate_optional_string(observation.product_version.as_deref(), limits)?;
    validate_optional_string(observation.product_alias.as_deref(), limits)?;
    validate_limitations(&observation.limitations, limits)?;
    let entries = validate_unisoc_entries(source, observation.entries, limits)?;
    let loaders = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.role,
                UnisocComponentRole::Fdl1 | UnisocComponentRole::Fdl2
            )
        })
        .map(|entry| UnisocLoaderEvidence {
            role: entry.role,
            component_path: entry.path.clone(),
            sha256: entry.sha256.clone(),
            base_address: entry.addresses[0],
            compatibility: C06TrustAssessment::NotEstablished,
        })
        .collect();

    let validation = observation.validation;
    let structural_checks = validation.magic_validated
        && validation.header_crc_validated
        && validation.table_crc_validated;
    let mut limitations = observation.limitations;
    append_unisoc_validation_limitations(&mut limitations, observation.complete_claim, validation);
    let assessment = if observation.complete_claim && structural_checks && limitations.is_empty() {
        C06Assessment::Complete
    } else {
        C06Assessment::Partial
    };
    let proof_level = if structural_checks {
        Some(C06StaticProofLevel::StructureChecked)
    } else if entries.is_empty() {
        None
    } else {
        Some(C06StaticProofLevel::InventoryOnly)
    };

    Ok(UnisocResolution {
        product_name: observation.product_name,
        product_version: observation.product_version,
        product_alias: observation.product_alias,
        validation,
        entries,
        loaders,
        assessment,
        proof_level,
        limitations,
    })
}

fn append_unisoc_validation_limitations(
    limitations: &mut Vec<String>,
    complete_claim: bool,
    validation: UnisocPacValidationObservation,
) {
    if !complete_claim {
        limitations.push("PAC Provider did not claim complete C06-supported semantics".to_owned());
    }
    if !validation.magic_validated {
        limitations
            .push("PAC magic/header family was not independently validated by Provider".to_owned());
    }
    if !validation.header_crc_validated {
        limitations.push("PAC header CRC/check semantics were not validated".to_owned());
    }
    if !validation.table_crc_validated {
        limitations.push("PAC file-table CRC/check semantics were not validated".to_owned());
    }
}

fn validate_unisoc_entries(
    source: &[u8],
    observations: Vec<UnisocPacEntryObservation>,
    limits: C06Limits,
) -> Result<Vec<UnisocPacEntry>, C06Error> {
    if observations.len() > limits.max_entries {
        return Err(C06Error::TooManyEntries);
    }
    let source_size = u64::try_from(source.len()).map_err(|_| C06Error::AccountingOverflow)?;
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut entries = Vec::with_capacity(observations.len());
    for observation in observations {
        validate_path(&observation.path, limits)?;
        validate_optional_string(observation.file_version.as_deref(), limits)?;
        validate_sha256(&observation.expected_sha256)?;
        if !ids.insert(observation.file_id) || !paths.insert(observation.path.clone()) {
            return Err(C06Error::DuplicateEntry);
        }
        let range = validate_unisoc_entry_range(
            source_size,
            observation.data_offset,
            observation.byte_size,
        )?;
        let start = usize::try_from(range.start).map_err(|_| C06Error::AccountingOverflow)?;
        let end = usize::try_from(range.end_exclusive).map_err(|_| C06Error::AccountingOverflow)?;
        let actual = sha256_bytes(&source[start..end]);
        if actual != observation.expected_sha256 {
            return Err(C06Error::DigestMismatch);
        }
        entries.push(UnisocPacEntry {
            file_id: observation.file_id,
            path: observation.path,
            file_version: observation.file_version,
            range,
            flags: observation.flags,
            check_flag: observation.check_flag,
            addresses: observation.addresses,
            role: observation.role,
            sha256: actual,
        });
    }
    entries.sort_by(|left, right| {
        left.range
            .start
            .cmp(&right.range.start)
            .then_with(|| left.path.cmp(&right.path))
    });
    let ranges = entries.iter().map(|entry| entry.range).collect::<Vec<_>>();
    validate_non_overlapping_ranges(&ranges)?;
    Ok(entries)
}

fn validate_unisoc_entry_range(
    source_size: u64,
    data_offset: u64,
    byte_size: u64,
) -> Result<C06ByteRange, C06Error> {
    let end = data_offset
        .checked_add(byte_size)
        .ok_or(C06Error::RangeOverflow)?;
    if end > source_size {
        return Err(C06Error::RangeOutsideSource);
    }
    Ok(C06ByteRange {
        start: data_offset,
        end_exclusive: end,
    })
}

/// Materialize one exact embedded PAC component.
///
/// # Errors
/// Rejects stale/mutated reports, changed source bytes, unknown paths and configured bounds.
pub fn materialize_unisoc_component(
    source: &[u8],
    report: &UnisocPacReport,
    path: &str,
    context: &C06Context,
    limits: C06Limits,
) -> Result<UnisocMaterialization, C06Error> {
    validate_context(context)?;
    validate_limits(limits)?;
    validate_unisoc_report_integrity(report)?;
    validate_path(path, limits)?;
    validate_source_binding(
        source,
        report.source_size,
        &report.source_sha256,
        &report.source_revision_ref,
        context,
    )?;
    let entry = report
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .ok_or(C06Error::ChildNotFound)?;
    let size = entry
        .range
        .end_exclusive
        .checked_sub(entry.range.start)
        .ok_or(C06Error::RangeOverflow)?;
    if size > limits.max_materialized_bytes {
        return Err(C06Error::MaterializationTooLarge);
    }
    let start = usize::try_from(entry.range.start).map_err(|_| C06Error::AccountingOverflow)?;
    let end =
        usize::try_from(entry.range.end_exclusive).map_err(|_| C06Error::AccountingOverflow)?;
    let bytes = source[start..end].to_vec();
    if sha256_bytes(&bytes) != entry.sha256 {
        return Err(C06Error::ReportIntegrityMismatch);
    }
    Ok(UnisocMaterialization {
        name: entry.path.clone(),
        source_revision_ref: report.source_revision_ref.clone(),
        sha256: entry.sha256.clone(),
        bytes,
    })
}

/// Compare two sealed Unisoc static reports without manufacturing FDL/device compatibility.
#[must_use]
pub fn compare_unisoc_packages(
    left: &UnisocPacReport,
    right: &UnisocPacReport,
) -> UnisocComparison {
    let left_shape = unisoc_shape(left);
    let right_shape = unisoc_shape(right);
    let left_components = unisoc_component_identity(left);
    let right_components = unisoc_component_identity(right);
    let mut differences = Vec::new();
    if left_shape != right_shape {
        differences.push("pac_structure_changed".to_owned());
    } else if left_components != right_components {
        differences.push("pac_component_bytes_changed".to_owned());
    }
    let level = if left_shape == right_shape
        && left.source_sha256 == right.source_sha256
        && left.source_size == right.source_size
        && left_components == right_components
    {
        C06ComparisonLevel::ByteExact
    } else if left_shape == right_shape && left_components == right_components {
        C06ComparisonLevel::ComponentExact
    } else if left_shape == right_shape {
        C06ComparisonLevel::Structural
    } else {
        C06ComparisonLevel::Different
    };
    UnisocComparison {
        left_source_revision_ref: left.source_revision_ref.clone(),
        right_source_revision_ref: right.source_revision_ref.clone(),
        level,
        differences,
    }
}

/* ---------------------------- Qualcomm bundle ---------------------------- */

/// Static Qualcomm package component family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QualcommComponentKind {
    /// Qualcomm MBN image/container.
    Mbn,
    /// ELF image/container.
    Elf,
    /// Device-side Firehose programmer executable.
    FirehoseProgrammer,
    /// Rawprogram XML plan.
    RawprogramXml,
    /// Patch XML plan.
    PatchXml,
    /// Other exact bundle component.
    Other,
}

/// One exact sibling component observation from an untrusted bundle Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualcommBundleEntryObservation {
    /// Canonical relative path.
    pub path: String,
    /// Exact recovered bytes.
    pub recovered_bytes: Vec<u8>,
    /// Provider-declared lowercase SHA-256.
    pub expected_sha256: String,
    /// Static component family.
    pub kind: QualcommComponentKind,
}

/// One normalized rawprogram operation observation.
///
/// This is a static plan record only. C06 has no API that executes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualcommProgramOperationObservation {
    /// XML component that declared the operation.
    pub xml_path: String,
    /// Referenced sibling image path when present.
    pub filename: Option<String>,
    /// Optional partition label.
    pub label: Option<String>,
    /// Exact starting sector.
    pub start_sector: u64,
    /// Exact sector count.
    pub num_partition_sectors: u64,
    /// Exact sector size in bytes.
    pub sector_size: u64,
    /// Exact LUN/physical partition.
    pub physical_partition: u32,
}

/// One normalized patch operation observation.
///
/// Patch semantics are retained for static review only; C06 cannot execute them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualcommPatchOperationObservation {
    /// XML component that declared the operation.
    pub xml_path: String,
    /// Exact starting sector.
    pub start_sector: u64,
    /// Byte offset within the starting sector.
    pub byte_offset: u64,
    /// Exact patch byte length.
    pub size_bytes: u64,
    /// Exact sector size in bytes.
    pub sector_size: u64,
    /// Exact LUN/physical partition.
    pub physical_partition: u32,
}

/// Static programmer metadata observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualcommProgrammerObservation {
    /// Exact bundle component path.
    pub component_path: String,
    /// Optional target/chip claim retained as evidence.
    pub target_claim: Option<String>,
    /// Optional HWID/MSM-family claim retained as evidence.
    pub hwid_claim: Option<String>,
    /// Optional PKHash/public-key claim retained as sensitive evidence.
    pub pkhash_claim: Option<String>,
    /// Provider observed signature/authentication metadata.
    pub signature_observed: bool,
}

/// Bounded Qualcomm sibling bundle observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualcommBundleObservation {
    /// Exact recovered sibling entries.
    pub entries: Vec<QualcommBundleEntryObservation>,
    /// Normalized rawprogram operations.
    pub program_operations: Vec<QualcommProgramOperationObservation>,
    /// Normalized patch operations.
    pub patch_operations: Vec<QualcommPatchOperationObservation>,
    /// Optional static programmer metadata.
    pub programmer: Option<QualcommProgrammerObservation>,
    /// Provider claim that all C06-supported bundle semantics were enumerated.
    pub complete_claim: bool,
    /// Explicit unsupported or partial semantics.
    pub limitations: Vec<String>,
}

/// Replaceable Qualcomm MBN/ELF/Firehose/XML mechanical boundary.
pub trait QualcommBundleProvider: Send + Sync {
    /// Stable backend-local Provider alias/evidence identifier.
    fn provider_id(&self) -> &str;

    /// Inspect sibling bundle bytes and static Firehose XML relationships.
    ///
    /// # Errors
    /// Returns a Provider-specific mechanical failure.
    fn inspect_bundle(
        &self,
        primary_source: &[u8],
        limits: C06Limits,
    ) -> Result<QualcommBundleObservation, String>;
}

/// Validated exact Qualcomm bundle component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualcommBundleEntry {
    /// Canonical relative path.
    pub path: String,
    /// Exact recovered byte size.
    pub byte_size: u64,
    /// Exact recovered SHA-256.
    pub sha256: String,
    /// Static family.
    pub kind: QualcommComponentKind,
    recovered_bytes: Vec<u8>,
}

impl QualcommBundleEntry {
    /// Read-only exact recovered bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.recovered_bytes
    }
}

/// Validated static rawprogram operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualcommProgramOperation {
    /// Exact XML component.
    pub xml_path: String,
    /// Referenced component path when present.
    pub filename: Option<String>,
    /// Optional partition label.
    pub label: Option<String>,
    /// Exact LUN/physical partition.
    pub physical_partition: u32,
    /// Exact sector size.
    pub sector_size: u64,
    /// Exact sector range expressed in bytes relative to the LUN.
    pub byte_range: C06ByteRange,
    /// Whether a referenced filename resolved to exact bundle bytes.
    pub component_resolved: bool,
}

/// Validated static patch operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualcommPatchOperation {
    /// Exact XML component.
    pub xml_path: String,
    /// Exact LUN/physical partition.
    pub physical_partition: u32,
    /// Exact sector size.
    pub sector_size: u64,
    /// Exact patch byte range relative to the LUN.
    pub byte_range: C06ByteRange,
}

/// Validated static programmer evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualcommProgrammerEvidence {
    /// Exact programmer component path.
    pub component_path: String,
    /// Exact programmer digest.
    pub sha256: String,
    /// Static component kind.
    pub kind: QualcommComponentKind,
    /// Optional target claim.
    pub target_claim: Option<String>,
    /// Optional HWID claim.
    pub hwid_claim: Option<String>,
    /// Optional `PKHash` claim.
    pub pkhash_claim: Option<String>,
    /// Signature/authentication metadata was observed.
    pub signature_observed: bool,
    /// Exact device/programmer compatibility remains unestablished.
    pub compatibility: C06TrustAssessment,
}

/// Source-bound Qualcomm static bundle report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualcommBundleReport {
    /// Exact immutable primary/index Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact immutable primary/index SHA-256.
    pub source_sha256: String,
    /// Exact immutable primary/index byte size.
    pub source_size: u64,
    /// Mechanical Provider alias.
    pub provider_alias: String,
    /// Exact bundle components.
    pub entries: Vec<QualcommBundleEntry>,
    /// Static rawprogram plan.
    pub program_operations: Vec<QualcommProgramOperation>,
    /// Static patch plan.
    pub patch_operations: Vec<QualcommPatchOperation>,
    /// Optional static programmer evidence.
    pub programmer: Option<QualcommProgrammerEvidence>,
    /// Structural/semantic truth.
    pub assessment: C06Assessment,
    /// Device mutation/execution trust.
    pub trust: C06TrustAssessment,
    /// Mechanically earned static proof level.
    pub proof_level: Option<C06StaticProofLevel>,
    /// Explicit unsupported or incomplete boundaries.
    pub limitations: Vec<String>,
    projection_sha256: String,
}

impl QualcommBundleReport {
    /// Produce exact source-bound A07 Views.
    ///
    /// # Errors
    /// Rejects mutated reports or mismatched source context.
    pub fn view_specs(&self, context: &C06Context) -> Result<Vec<ViewSpec>, C06Error> {
        validate_context(context)?;
        validate_qualcomm_report_integrity(self)?;
        if self.source_revision_ref != context.source_revision_ref {
            return Err(C06Error::SourceBindingMismatch);
        }
        Ok(vec![
            c06_view_spec(
                context,
                "qualcomm.bundle.inventory",
                "qualcomm-bundle-inventory",
            ),
            c06_view_spec(context, "qualcomm.firehose.plan", "qualcomm-firehose-plan"),
            c06_view_spec(
                context,
                "qualcomm.programmer.evidence",
                "qualcomm-programmer-evidence",
            ),
            c06_view_spec(context, "c06.proof_levels", "proof-levels"),
        ])
    }
}

/// Exact recovered Qualcomm sibling component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualcommMaterialization {
    /// Canonical sibling path.
    pub name: String,
    /// Exact primary/index source Revision.
    pub source_revision_ref: EntityRef,
    /// Exact child SHA-256.
    pub sha256: String,
    bytes: Vec<u8>,
}

impl QualcommMaterialization {
    /// Read-only exact recovered bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Build exact source-bound A07 registration.
    ///
    /// # Errors
    /// Rejects context that does not bind the exact package/index Revision.
    pub fn registration_spec(&self, context: &C06Context) -> Result<RegisterObjectSpec, C06Error> {
        validate_context(context)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C06Error::SourceBindingMismatch);
        }
        Ok(RegisterObjectSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            object_class: "qualcomm.firmware.bundle_component".to_owned(),
            declared_name: Some(self.name.clone()),
            source_refs: vec![self.source_revision_ref.clone()],
            revision_role: RevisionRole::Recovered,
            origin_class: OriginClass::Unknown,
            created_reason: "C06 recovered exact Qualcomm sibling bundle component".to_owned(),
            production: context.production.clone(),
            expected_sha256: Some(self.sha256.clone()),
        })
    }

    /// Build package-reference-to-component A07 Relationship.
    ///
    /// # Errors
    /// Rejects mismatched registration bytes or canonical endpoint kinds.
    pub fn relationship_spec(
        &self,
        context: &C06Context,
        registration: &Registration,
    ) -> Result<RelationshipSpec, C06Error> {
        validate_materialization_registration(
            self.sha256.as_str(),
            self.bytes.len(),
            registration,
        )?;
        validate_context(context)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C06Error::SourceBindingMismatch);
        }
        Ok(RelationshipSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            subject_refs: vec![self.source_revision_ref.clone()],
            relationship_type: "references.qualcomm_firmware_component".to_owned(),
            object_refs: vec![
                registration.object_ref.clone(),
                registration.revision_ref.clone(),
            ],
            production: context.production.clone(),
        })
    }
}

/// Source-bound Qualcomm comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualcommComparison {
    /// Left source Revision.
    pub left_source_revision_ref: EntityRef,
    /// Right source Revision.
    pub right_source_revision_ref: EntityRef,
    /// Strongest mechanically established level.
    pub level: C06ComparisonLevel,
    /// Deterministic differences.
    pub differences: Vec<String>,
}

/// Inspect one immutable Qualcomm bundle/index source plus sibling MBN/ELF/Firehose/XML evidence.
///
/// USB EDL presence, Sahara state, programmer loading and Firehose configuration are deliberately
/// outside this static pack. A programmer or XML plan never grants execution/write authority.
///
/// # Errors
/// Fails closed for unsafe paths, digest lies, invalid plan ranges, unresolved XML sources,
/// malformed programmer references or configured bounds.
pub fn inspect_qualcomm_bundle(
    primary_source: &[u8],
    context: &C06Context,
    limits: C06Limits,
    provider: &dyn QualcommBundleProvider,
) -> Result<QualcommBundleReport, C06Error> {
    validate_context(context)?;
    validate_limits(limits)?;
    let source_size =
        u64::try_from(primary_source.len()).map_err(|_| C06Error::AccountingOverflow)?;
    if source_size > limits.max_source_bytes {
        return Err(C06Error::SourceTooLarge);
    }
    validate_string(provider.provider_id(), limits)?;
    let observation = provider
        .inspect_bundle(primary_source, limits)
        .map_err(C06Error::QualcommProvider)?;
    let resolved = resolve_qualcomm_observation(observation, limits)?;

    Ok(seal_qualcomm_report(QualcommBundleReport {
        source_revision_ref: context.source_revision_ref.clone(),
        source_sha256: sha256_bytes(primary_source),
        source_size,
        provider_alias: provider.provider_id().to_owned(),
        entries: resolved.entries,
        program_operations: resolved.program_operations,
        patch_operations: resolved.patch_operations,
        programmer: resolved.programmer,
        assessment: resolved.assessment,
        trust: C06TrustAssessment::NotEstablished,
        proof_level: resolved.proof_level,
        limitations: resolved.limitations,
        projection_sha256: String::new(),
    }))
}

struct QualcommResolution {
    entries: Vec<QualcommBundleEntry>,
    program_operations: Vec<QualcommProgramOperation>,
    patch_operations: Vec<QualcommPatchOperation>,
    programmer: Option<QualcommProgrammerEvidence>,
    assessment: C06Assessment,
    proof_level: Option<C06StaticProofLevel>,
    limitations: Vec<String>,
}

fn resolve_qualcomm_observation(
    observation: QualcommBundleObservation,
    limits: C06Limits,
) -> Result<QualcommResolution, C06Error> {
    validate_limitations(&observation.limitations, limits)?;
    let operation_count = observation
        .program_operations
        .len()
        .checked_add(observation.patch_operations.len())
        .ok_or(C06Error::AccountingOverflow)?;
    if operation_count > limits.max_operations {
        return Err(C06Error::TooManyOperations);
    }

    let entries = validate_qualcomm_entries(observation.entries, limits)?;
    let entry_map: BTreeMap<&str, &QualcommBundleEntry> = entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let (program_operations, unresolved) =
        resolve_qualcomm_program_operations(observation.program_operations, &entry_map, limits)?;
    let patch_operations =
        resolve_qualcomm_patch_operations(observation.patch_operations, &entry_map, limits)?;
    let programmer = resolve_qualcomm_programmer(observation.programmer, &entry_map, limits)?;

    let mut limitations = observation.limitations;
    if !observation.complete_claim {
        limitations
            .push("Qualcomm Provider did not claim complete C06-supported semantics".to_owned());
    }
    if unresolved != 0 {
        limitations.push(format!(
            "{unresolved} rawprogram component reference(s) unresolved"
        ));
    }
    let assessment = if observation.complete_claim && unresolved == 0 && limitations.is_empty() {
        C06Assessment::Complete
    } else {
        C06Assessment::Partial
    };
    let plan_present = !program_operations.is_empty() || !patch_operations.is_empty();
    let proof_level = if plan_present && unresolved == 0 {
        Some(C06StaticProofLevel::PlanLinked)
    } else if entries.is_empty() {
        Some(C06StaticProofLevel::InventoryOnly)
    } else {
        Some(C06StaticProofLevel::ComponentsLinked)
    };

    Ok(QualcommResolution {
        entries,
        program_operations,
        patch_operations,
        programmer,
        assessment,
        proof_level,
        limitations,
    })
}

fn validate_qualcomm_entries(
    observations: Vec<QualcommBundleEntryObservation>,
    limits: C06Limits,
) -> Result<Vec<QualcommBundleEntry>, C06Error> {
    if observations.len() > limits.max_entries {
        return Err(C06Error::TooManyEntries);
    }
    let mut paths = BTreeSet::new();
    let mut total = 0u64;
    let mut entries = Vec::with_capacity(observations.len());
    for observation in observations {
        validate_path(&observation.path, limits)?;
        if !paths.insert(observation.path.clone()) {
            return Err(C06Error::DuplicateEntry);
        }
        validate_sha256(&observation.expected_sha256)?;
        let actual = sha256_bytes(&observation.recovered_bytes);
        if actual != observation.expected_sha256 {
            return Err(C06Error::DigestMismatch);
        }
        let byte_size = u64::try_from(observation.recovered_bytes.len())
            .map_err(|_| C06Error::AccountingOverflow)?;
        total = total
            .checked_add(byte_size)
            .ok_or(C06Error::AccountingOverflow)?;
        if total > limits.max_recovered_bytes {
            return Err(C06Error::TooManyRecoveredBytes);
        }
        entries.push(QualcommBundleEntry {
            path: observation.path,
            byte_size,
            sha256: actual,
            kind: observation.kind,
            recovered_bytes: observation.recovered_bytes,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

fn resolve_qualcomm_program_operations(
    observations: Vec<QualcommProgramOperationObservation>,
    entries: &BTreeMap<&str, &QualcommBundleEntry>,
    limits: C06Limits,
) -> Result<(Vec<QualcommProgramOperation>, usize), C06Error> {
    let mut unresolved = 0usize;
    let mut operations = Vec::with_capacity(observations.len());
    for observation in observations {
        validate_path(&observation.xml_path, limits)?;
        validate_optional_string(observation.label.as_deref(), limits)?;
        let xml = entries
            .get(observation.xml_path.as_str())
            .copied()
            .ok_or(C06Error::PlanSourceNotFound)?;
        if xml.kind != QualcommComponentKind::RawprogramXml {
            return Err(C06Error::InvalidPlanSourceKind);
        }
        let byte_range = sector_range(
            observation.start_sector,
            observation.num_partition_sectors,
            observation.sector_size,
        )?;
        let component_resolved = if let Some(filename) = observation.filename.as_deref() {
            validate_path(filename, limits)?;
            entries.contains_key(filename)
        } else {
            false
        };
        if observation.filename.is_some() && !component_resolved {
            unresolved = unresolved
                .checked_add(1)
                .ok_or(C06Error::AccountingOverflow)?;
        }
        operations.push(QualcommProgramOperation {
            xml_path: observation.xml_path,
            filename: observation.filename,
            label: observation.label,
            physical_partition: observation.physical_partition,
            sector_size: observation.sector_size,
            byte_range,
            component_resolved,
        });
    }
    Ok((operations, unresolved))
}

fn resolve_qualcomm_patch_operations(
    observations: Vec<QualcommPatchOperationObservation>,
    entries: &BTreeMap<&str, &QualcommBundleEntry>,
    limits: C06Limits,
) -> Result<Vec<QualcommPatchOperation>, C06Error> {
    let mut operations = Vec::with_capacity(observations.len());
    for observation in observations {
        validate_path(&observation.xml_path, limits)?;
        let xml = entries
            .get(observation.xml_path.as_str())
            .copied()
            .ok_or(C06Error::PlanSourceNotFound)?;
        if xml.kind != QualcommComponentKind::PatchXml {
            return Err(C06Error::InvalidPlanSourceKind);
        }
        if observation.sector_size == 0 {
            return Err(C06Error::InvalidSectorSize);
        }
        if observation.byte_offset >= observation.sector_size {
            return Err(C06Error::InvalidPatchRange);
        }
        let sector_start = observation
            .start_sector
            .checked_mul(observation.sector_size)
            .ok_or(C06Error::RangeOverflow)?;
        let start = sector_start
            .checked_add(observation.byte_offset)
            .ok_or(C06Error::RangeOverflow)?;
        let end = start
            .checked_add(observation.size_bytes)
            .ok_or(C06Error::RangeOverflow)?;
        operations.push(QualcommPatchOperation {
            xml_path: observation.xml_path,
            physical_partition: observation.physical_partition,
            sector_size: observation.sector_size,
            byte_range: C06ByteRange {
                start,
                end_exclusive: end,
            },
        });
    }
    Ok(operations)
}

fn resolve_qualcomm_programmer(
    observation: Option<QualcommProgrammerObservation>,
    entries: &BTreeMap<&str, &QualcommBundleEntry>,
    limits: C06Limits,
) -> Result<Option<QualcommProgrammerEvidence>, C06Error> {
    let Some(observation) = observation else {
        return Ok(None);
    };
    validate_path(&observation.component_path, limits)?;
    validate_optional_string(observation.target_claim.as_deref(), limits)?;
    validate_optional_string(observation.hwid_claim.as_deref(), limits)?;
    validate_optional_string(observation.pkhash_claim.as_deref(), limits)?;
    let entry = entries
        .get(observation.component_path.as_str())
        .copied()
        .ok_or(C06Error::ProgrammerNotFound)?;
    if !matches!(
        entry.kind,
        QualcommComponentKind::FirehoseProgrammer
            | QualcommComponentKind::Mbn
            | QualcommComponentKind::Elf
    ) {
        return Err(C06Error::InvalidProgrammerKind);
    }
    Ok(Some(QualcommProgrammerEvidence {
        component_path: entry.path.clone(),
        sha256: entry.sha256.clone(),
        kind: entry.kind,
        target_claim: observation.target_claim,
        hwid_claim: observation.hwid_claim,
        pkhash_claim: observation.pkhash_claim,
        signature_observed: observation.signature_observed,
        compatibility: C06TrustAssessment::NotEstablished,
    }))
}

fn sector_range(
    start_sector: u64,
    sector_count: u64,
    sector_size: u64,
) -> Result<C06ByteRange, C06Error> {
    if sector_size == 0 {
        return Err(C06Error::InvalidSectorSize);
    }
    let start = start_sector
        .checked_mul(sector_size)
        .ok_or(C06Error::RangeOverflow)?;
    let length = sector_count
        .checked_mul(sector_size)
        .ok_or(C06Error::RangeOverflow)?;
    let end = start.checked_add(length).ok_or(C06Error::RangeOverflow)?;
    Ok(C06ByteRange {
        start,
        end_exclusive: end,
    })
}

/// Materialize one exact Qualcomm sibling component.
///
/// # Errors
/// Rejects stale/mutated reports, changed primary source, unknown paths and configured bounds.
pub fn materialize_qualcomm_component(
    primary_source: &[u8],
    report: &QualcommBundleReport,
    path: &str,
    context: &C06Context,
    limits: C06Limits,
) -> Result<QualcommMaterialization, C06Error> {
    validate_context(context)?;
    validate_limits(limits)?;
    validate_qualcomm_report_integrity(report)?;
    validate_path(path, limits)?;
    validate_source_binding(
        primary_source,
        report.source_size,
        &report.source_sha256,
        &report.source_revision_ref,
        context,
    )?;
    let entry = report
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .ok_or(C06Error::ChildNotFound)?;
    if entry.byte_size > limits.max_materialized_bytes {
        return Err(C06Error::MaterializationTooLarge);
    }
    if sha256_bytes(&entry.recovered_bytes) != entry.sha256 {
        return Err(C06Error::ReportIntegrityMismatch);
    }
    Ok(QualcommMaterialization {
        name: entry.path.clone(),
        source_revision_ref: report.source_revision_ref.clone(),
        sha256: entry.sha256.clone(),
        bytes: entry.recovered_bytes.clone(),
    })
}

/// Compare two sealed Qualcomm static reports without manufacturing programmer/device compatibility.
#[must_use]
pub fn compare_qualcomm_bundles(
    left: &QualcommBundleReport,
    right: &QualcommBundleReport,
) -> QualcommComparison {
    let left_shape = qualcomm_shape(left);
    let right_shape = qualcomm_shape(right);
    let left_components = qualcomm_component_identity(left);
    let right_components = qualcomm_component_identity(right);
    let mut differences = Vec::new();
    if left_shape != right_shape {
        differences.push("qualcomm_bundle_or_plan_structure_changed".to_owned());
    } else if left_components != right_components {
        differences.push("qualcomm_component_bytes_changed".to_owned());
    }
    let level = if left_shape == right_shape
        && left.source_sha256 == right.source_sha256
        && left.source_size == right.source_size
        && left_components == right_components
    {
        C06ComparisonLevel::ByteExact
    } else if left_shape == right_shape && left_components == right_components {
        C06ComparisonLevel::ComponentExact
    } else if left_shape == right_shape {
        C06ComparisonLevel::Structural
    } else {
        C06ComparisonLevel::Different
    };
    QualcommComparison {
        left_source_revision_ref: left.source_revision_ref.clone(),
        right_source_revision_ref: right.source_revision_ref.clone(),
        level,
        differences,
    }
}

/* ------------------------------- Errors ------------------------------- */

/// C06 failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum C06Error {
    /// Workspace reference is not canonical.
    #[error("C06 workspace reference must be core.workspace")]
    InvalidWorkspaceRef,
    /// Source must bind an exact Object Revision.
    #[error("C06 source must be an exact object.revision reference")]
    InvalidSourceRevision,
    /// One configured resource limit is zero.
    #[error("C06 limits must all be greater than zero")]
    InvalidLimits,
    /// Primary source exceeds configured bounds.
    #[error("C06 source exceeds max_source_bytes")]
    SourceTooLarge,
    /// Package/bundle entry count exceeds configured bounds.
    #[error("C06 entry count exceeds configured limit")]
    TooManyEntries,
    /// Aggregate recovered sibling bytes exceed configured bounds.
    #[error("C06 recovered bytes exceed configured limit")]
    TooManyRecoveredBytes,
    /// Plan operation count exceeds configured bounds.
    #[error("C06 plan operation count exceeds configured limit")]
    TooManyOperations,
    /// String/path is invalid or exceeds configured bounds.
    #[error("C06 invalid bounded string/path")]
    InvalidString,
    /// Path is unsafe or non-canonical.
    #[error("C06 path is unsafe or non-canonical")]
    InvalidPath,
    /// Duplicate component identity/path.
    #[error("C06 duplicate component identity/path")]
    DuplicateEntry,
    /// Provider-declared digest is malformed or mismatched.
    #[error("C06 recovered component digest mismatch")]
    DigestMismatch,
    /// Numeric range arithmetic overflowed.
    #[error("C06 range arithmetic overflow")]
    RangeOverflow,
    /// PAC entry points outside the immutable source.
    #[error("C06 PAC entry range lies outside immutable source")]
    RangeOutsideSource,
    /// PAC entry ranges overlap.
    #[error("C06 PAC entry ranges overlap")]
    OverlappingRanges,
    /// Unisoc mechanical Provider failed.
    #[error("C06 Unisoc PAC Provider failed: {0}")]
    UnisocProvider(String),
    /// Qualcomm mechanical Provider failed.
    #[error("C06 Qualcomm Provider failed: {0}")]
    QualcommProvider(String),
    /// XML plan source is absent.
    #[error("C06 Firehose plan source component was not found")]
    PlanSourceNotFound,
    /// XML plan source has the wrong static component kind.
    #[error("C06 Firehose plan source component kind is invalid")]
    InvalidPlanSourceKind,
    /// Sector size is zero.
    #[error("C06 Firehose sector size must be greater than zero")]
    InvalidSectorSize,
    /// Patch byte offset/range is invalid.
    #[error("C06 Firehose patch range is invalid")]
    InvalidPatchRange,
    /// Programmer component is absent.
    #[error("C06 programmer component was not found")]
    ProgrammerNotFound,
    /// Programmer component has an invalid static kind.
    #[error("C06 programmer component kind is invalid")]
    InvalidProgrammerKind,
    /// Numeric accounting overflowed.
    #[error("C06 byte accounting overflow")]
    AccountingOverflow,
    /// Report/source/context binding mismatch.
    #[error("C06 exact source binding mismatch")]
    SourceBindingMismatch,
    /// Report was mutated after inspection.
    #[error("C06 report integrity seal mismatch")]
    ReportIntegrityMismatch,
    /// Requested exact component does not exist.
    #[error("C06 requested component was not found")]
    ChildNotFound,
    /// Materialization exceeds configured bounds.
    #[error("C06 materialization exceeds configured limit")]
    MaterializationTooLarge,
    /// Registered A07 endpoints have invalid kinds.
    #[error("C06 component registration has invalid canonical endpoint kinds")]
    InvalidRegistration,
    /// Registration bytes do not match exact component bytes.
    #[error("C06 component registration does not match exact bytes")]
    RegistrationMismatch,
}

/* ------------------------------ Validators ------------------------------ */

fn validate_context(context: &C06Context) -> Result<(), C06Error> {
    if context.workspace_ref.entity_kind.as_str() != "core.workspace" {
        return Err(C06Error::InvalidWorkspaceRef);
    }
    if context.source_revision_ref.entity_kind.as_str() != "object.revision" {
        return Err(C06Error::InvalidSourceRevision);
    }
    Ok(())
}

fn validate_limits(limits: C06Limits) -> Result<(), C06Error> {
    if limits.max_source_bytes == 0
        || limits.max_entries == 0
        || limits.max_recovered_bytes == 0
        || limits.max_string_bytes == 0
        || limits.max_operations == 0
        || limits.max_materialized_bytes == 0
    {
        return Err(C06Error::InvalidLimits);
    }
    Ok(())
}

fn validate_string(value: &str, limits: C06Limits) -> Result<(), C06Error> {
    if value.is_empty() || value.len() > limits.max_string_bytes || value.contains('\0') {
        return Err(C06Error::InvalidString);
    }
    Ok(())
}

fn validate_optional_string(value: Option<&str>, limits: C06Limits) -> Result<(), C06Error> {
    if let Some(value) = value {
        validate_string(value, limits)?;
    }
    Ok(())
}

fn validate_limitations(values: &[String], limits: C06Limits) -> Result<(), C06Error> {
    for value in values {
        validate_string(value, limits)?;
    }
    Ok(())
}

fn validate_path(path: &str, limits: C06Limits) -> Result<(), C06Error> {
    validate_string(path, limits)?;
    if path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.ends_with('/')
        || has_windows_drive_prefix(path)
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(C06Error::InvalidPath);
    }
    Ok(())
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn validate_sha256(value: &str) -> Result<(), C06Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(C06Error::DigestMismatch);
    }
    Ok(())
}

fn validate_non_overlapping_ranges(ranges: &[C06ByteRange]) -> Result<(), C06Error> {
    let mut sorted = ranges.to_vec();
    sorted.sort_by_key(|range| (range.start, range.end_exclusive));
    for pair in sorted.windows(2) {
        if pair[0].end_exclusive > pair[1].start {
            return Err(C06Error::OverlappingRanges);
        }
    }
    Ok(())
}

fn validate_source_binding(
    source: &[u8],
    expected_size: u64,
    expected_sha256: &str,
    source_revision_ref: &EntityRef,
    context: &C06Context,
) -> Result<(), C06Error> {
    let source_size = u64::try_from(source.len()).map_err(|_| C06Error::AccountingOverflow)?;
    if source_revision_ref != &context.source_revision_ref
        || source_size != expected_size
        || sha256_bytes(source) != expected_sha256
    {
        return Err(C06Error::SourceBindingMismatch);
    }
    Ok(())
}

fn validate_materialization_registration(
    sha256: &str,
    byte_len: usize,
    registration: &Registration,
) -> Result<(), C06Error> {
    if registration.object_ref.entity_kind.as_str() != "object.object"
        || registration.revision_ref.entity_kind.as_str() != "object.revision"
    {
        return Err(C06Error::InvalidRegistration);
    }
    let byte_size = u64::try_from(byte_len).map_err(|_| C06Error::AccountingOverflow)?;
    if registration.sha256 != sha256 || registration.byte_size != byte_size {
        return Err(C06Error::RegistrationMismatch);
    }
    Ok(())
}

/* ---------------------------- Report sealing ---------------------------- */

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnisocEntryShape {
    file_id: u32,
    path: String,
    file_version: Option<String>,
    range: C06ByteRange,
    flags: u32,
    check_flag: u32,
    addresses: [Option<u64>; 5],
    role: UnisocComponentRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnisocShape {
    product_name: Option<String>,
    product_version: Option<String>,
    product_alias: Option<String>,
    validation: UnisocPacValidationObservation,
    entries: Vec<UnisocEntryShape>,
}

fn unisoc_shape(report: &UnisocPacReport) -> UnisocShape {
    UnisocShape {
        product_name: report.product_name.clone(),
        product_version: report.product_version.clone(),
        product_alias: report.product_alias.clone(),
        validation: report.validation,
        entries: report
            .entries
            .iter()
            .map(|entry| UnisocEntryShape {
                file_id: entry.file_id,
                path: entry.path.clone(),
                file_version: entry.file_version.clone(),
                range: entry.range,
                flags: entry.flags,
                check_flag: entry.check_flag,
                addresses: entry.addresses,
                role: entry.role,
            })
            .collect(),
    }
}

fn unisoc_component_identity(report: &UnisocPacReport) -> Vec<String> {
    report
        .entries
        .iter()
        .map(|entry| {
            format!(
                "{}:{}:{}:{}",
                entry.file_id,
                entry.path,
                entry.range.end_exclusive - entry.range.start,
                entry.sha256
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QualcommProgrammerShape {
    component_path: String,
    kind: QualcommComponentKind,
    target_claim: Option<String>,
    hwid_claim: Option<String>,
    pkhash_claim: Option<String>,
    signature_observed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QualcommShape {
    entries: Vec<(String, QualcommComponentKind)>,
    program_operations: Vec<QualcommProgramOperation>,
    patch_operations: Vec<QualcommPatchOperation>,
    programmer_shape: Option<QualcommProgrammerShape>,
}

fn qualcomm_shape(report: &QualcommBundleReport) -> QualcommShape {
    QualcommShape {
        entries: report
            .entries
            .iter()
            .map(|entry| (entry.path.clone(), entry.kind))
            .collect(),
        program_operations: report.program_operations.clone(),
        patch_operations: report.patch_operations.clone(),
        programmer_shape: report
            .programmer
            .as_ref()
            .map(|programmer| QualcommProgrammerShape {
                component_path: programmer.component_path.clone(),
                kind: programmer.kind,
                target_claim: programmer.target_claim.clone(),
                hwid_claim: programmer.hwid_claim.clone(),
                pkhash_claim: programmer.pkhash_claim.clone(),
                signature_observed: programmer.signature_observed,
            }),
    }
}

fn qualcomm_component_identity(report: &QualcommBundleReport) -> Vec<String> {
    report
        .entries
        .iter()
        .map(|entry| {
            format!(
                "{}:{:?}:{}:{}",
                entry.path, entry.kind, entry.byte_size, entry.sha256
            )
        })
        .collect()
}

fn unisoc_projection_digest(report: &UnisocPacReport) -> String {
    let mut hasher = Sha256::new();
    hash_guard_text(
        &mut hasher,
        &serde_json::to_string(&report.source_revision_ref).unwrap_or_default(),
    );
    hash_guard_text(&mut hasher, &report.source_sha256);
    hasher.update(report.source_size.to_le_bytes());
    hash_guard_text(&mut hasher, &report.provider_alias);
    hash_guard_text(&mut hasher, &format!("{:?}", report.product_name));
    hash_guard_text(&mut hasher, &format!("{:?}", report.product_version));
    hash_guard_text(&mut hasher, &format!("{:?}", report.product_alias));
    hash_guard_text(&mut hasher, &format!("{:?}", report.validation));
    hash_guard_text(&mut hasher, &format!("{:?}", report.entries));
    hash_guard_text(&mut hasher, &format!("{:?}", report.loaders));
    hash_guard_text(&mut hasher, &format!("{:?}", report.assessment));
    hash_guard_text(&mut hasher, &format!("{:?}", report.trust));
    hash_guard_text(&mut hasher, &format!("{:?}", report.proof_level));
    hash_guard_text(&mut hasher, &format!("{:?}", report.limitations));
    format!("{:x}", hasher.finalize())
}

fn qualcomm_projection_digest(report: &QualcommBundleReport) -> String {
    let mut hasher = Sha256::new();
    hash_guard_text(
        &mut hasher,
        &serde_json::to_string(&report.source_revision_ref).unwrap_or_default(),
    );
    hash_guard_text(&mut hasher, &report.source_sha256);
    hasher.update(report.source_size.to_le_bytes());
    hash_guard_text(&mut hasher, &report.provider_alias);
    for entry in &report.entries {
        hash_guard_text(&mut hasher, &entry.path);
        hasher.update(entry.byte_size.to_le_bytes());
        hash_guard_text(&mut hasher, &entry.sha256);
        hash_guard_text(&mut hasher, &format!("{:?}", entry.kind));
    }
    hash_guard_text(&mut hasher, &format!("{:?}", report.program_operations));
    hash_guard_text(&mut hasher, &format!("{:?}", report.patch_operations));
    hash_guard_text(&mut hasher, &format!("{:?}", report.programmer));
    hash_guard_text(&mut hasher, &format!("{:?}", report.assessment));
    hash_guard_text(&mut hasher, &format!("{:?}", report.trust));
    hash_guard_text(&mut hasher, &format!("{:?}", report.proof_level));
    hash_guard_text(&mut hasher, &format!("{:?}", report.limitations));
    format!("{:x}", hasher.finalize())
}

fn seal_unisoc_report(mut report: UnisocPacReport) -> UnisocPacReport {
    report.projection_sha256 = unisoc_projection_digest(&report);
    report
}

fn seal_qualcomm_report(mut report: QualcommBundleReport) -> QualcommBundleReport {
    report.projection_sha256 = qualcomm_projection_digest(&report);
    report
}

fn validate_unisoc_report_integrity(report: &UnisocPacReport) -> Result<(), C06Error> {
    if report.projection_sha256.is_empty()
        || report.projection_sha256 != unisoc_projection_digest(report)
    {
        return Err(C06Error::ReportIntegrityMismatch);
    }
    Ok(())
}

fn validate_qualcomm_report_integrity(report: &QualcommBundleReport) -> Result<(), C06Error> {
    if report.projection_sha256.is_empty()
        || report.projection_sha256 != qualcomm_projection_digest(report)
    {
        return Err(C06Error::ReportIntegrityMismatch);
    }
    Ok(())
}

fn c06_view_spec(context: &C06Context, view_kind: &str, suffix: &str) -> ViewSpec {
    ViewSpec {
        workspace_ref: context.workspace_ref.clone(),
        authority_ref: context.authority_ref.clone(),
        view_kind: view_kind.to_owned(),
        view_schema_id: format!("urn:ptah:schema:c06:{suffix}:0.1.0"),
        view_schema_version: "0.1.0".to_owned(),
        source_revision_refs: vec![context.source_revision_ref.clone()],
        origin_class: OriginClass::DecodedResource,
        production: context.production.clone(),
    }
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
