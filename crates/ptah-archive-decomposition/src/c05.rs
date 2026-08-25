use ptah_identifiers::EntityRef;
use ptah_object_store::{
    OriginClass, ProductionEvidence, RegisterObjectSpec, Registration, RelationshipSpec,
    RevisionRole, ViewSpec,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::str;
use thiserror::Error;

/// Bounded resource limits for one C05 inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediatekLimits {
    /// Maximum immutable scatter bytes accepted by one inspection.
    pub max_source_bytes: u64,
    /// Maximum partition records parsed from one scatter file.
    pub max_partitions: usize,
    /// Maximum bundle entries retained from an untrusted Provider.
    pub max_bundle_entries: usize,
    /// Maximum total recovered bundle bytes retained in one report.
    pub max_recovered_bytes: u64,
    /// Maximum bytes retained for one bounded string or path.
    pub max_string_bytes: usize,
    /// Maximum input lines parsed from the scatter source.
    pub max_lines: usize,
    /// Maximum partition names accepted from one evidence Provider.
    pub max_evidence_partitions: usize,
    /// Maximum exact child bytes materialized by one request.
    pub max_materialized_bytes: u64,
}

impl Default for MediatekLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 16 * 1024 * 1024,
            max_partitions: 16_384,
            max_bundle_entries: 131_072,
            max_recovered_bytes: 16 * 1024 * 1024 * 1024,
            max_string_bytes: 8192,
            max_lines: 262_144,
            max_evidence_partitions: 16_384,
            max_materialized_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}

/// Exact immutable source and A04 production context.
#[derive(Debug, Clone)]
pub struct MediatekContext {
    /// Workspace owning source and derived plans.
    pub workspace_ref: EntityRef,
    /// Authority for canonical plans.
    pub authority_ref: EntityRef,
    /// Exact immutable scatter Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact producing evidence.
    pub production: ProductionEvidence,
}

/// Truth status of one C05 report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediatekAssessment {
    /// All C05-supported supplied semantics were validated.
    Complete,
    /// Exact supported semantics exist but explicit limitations remain.
    Partial,
    /// A trustworthy C05 projection could not be established.
    Inconclusive,
}

/// Device-write, loader and security trust remain outside static C05 authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediatekTrustAssessment {
    /// Static package analysis and read-only observations grant no mutation authority.
    NotEstablished,
}

/// Mechanically earned C05 static proof level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MediatekStaticProofLevel {
    /// Exact source identity and a bounded partition inventory exist.
    InventoryOnly,
    /// Scatter grammar, required fields and partition ranges were validated.
    StructureChecked,
    /// Every scatter-referenced component resolves to exact digest-bound bundle bytes.
    BundleLinked,
    /// Bundle linkage plus supplied lawful read-only device evidence are mutually consistent.
    EvidenceCorrelated,
    /// Compared retained component identities and digests are exact.
    ComponentExact,
    /// Compared scatter source bytes and retained component identities are exact.
    ByteExact,
}

/// One exact inclusive/exclusive `MediaTek` partition range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediatekPartitionRange {
    /// Inclusive byte start.
    pub start: u64,
    /// Exclusive byte end.
    pub end_exclusive: u64,
}

/// One validated `MediaTek` scatter partition relationship.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatekPartition {
    /// Scatter partition index token such as `SYS0`.
    pub partition_index: String,
    /// Partition name.
    pub partition_name: String,
    /// Referenced sibling image path, or `None` for `NONE`.
    pub file_name: Option<String>,
    /// Scatter `is_download` declaration retained as metadata only.
    pub is_download: bool,
    /// Scatter image/partition type token.
    pub image_type: String,
    /// Exact linear range from the scatter record.
    pub linear_range: MediatekPartitionRange,
    /// Exact physical range from the scatter record.
    pub physical_range: MediatekPartitionRange,
    /// Scatter region token.
    pub region: String,
    /// Scatter storage token.
    pub storage: String,
    /// Exact linked bundle component size when resolved.
    pub linked_component_size: Option<u64>,
    /// Exact linked bundle component lowercase SHA-256 when resolved.
    pub linked_component_sha256: Option<String>,
}

/// One exact recovered bundle-entry observation from an untrusted Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatekBundleEntryObservation {
    /// Provider-recovered canonical relative path candidate.
    pub path: String,
    /// Exact recovered bytes.
    pub recovered_bytes: Vec<u8>,
    /// Provider-declared lowercase SHA-256 for those bytes.
    pub expected_sha256: String,
}

/// Bounded `MediaTek` bundle inventory returned by a replaceable Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatekBundleObservation {
    /// Exact recovered sibling entries.
    pub entries: Vec<MediatekBundleEntryObservation>,
    /// Provider claim that all C05-supported bundle semantics were enumerated.
    pub complete_claim: bool,
    /// Explicit unsupported or partial semantics.
    pub limitations: Vec<String>,
}

/// Replaceable `MediaTek` package/bundle boundary.
pub trait MediatekBundleProvider: Send + Sync {
    /// Stable backend-local Provider alias/evidence identifier.
    fn provider_id(&self) -> &str;

    /// Recover exact sibling package bytes associated with the immutable scatter source.
    ///
    /// # Errors
    /// Returns a Provider-specific mechanical failure.
    fn inspect_bundle(
        &self,
        scatter_source: &[u8],
        limits: MediatekLimits,
    ) -> Result<MediatekBundleObservation, String>;
}

/// Validated exact sibling bundle entry retained by Core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatekBundleEntry {
    /// Canonical relative forward-slash path.
    pub path: String,
    /// Exact recovered byte size.
    pub byte_size: u64,
    /// Exact recovered lowercase SHA-256.
    pub sha256: String,
    recovered_bytes: Vec<u8>,
}

impl MediatekBundleEntry {
    /// Read-only exact recovered bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.recovered_bytes
    }
}

/// `MediaTek` transport/service mode observed by a lawful evidence Facility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MediatekMode {
    /// `BootROM` mode.
    Brom,
    /// Preloader mode.
    Preloader,
    /// Download Agent/service mode.
    Da,
    /// V6/preloader-mode workflow family.
    V6,
    /// META mode.
    Meta,
    /// Normal stock runtime.
    Stock,
    /// Provider could not establish a mode.
    Unknown,
}

/// Strongest mechanically validated level of supplied read-only device evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MediatekEvidenceLevel {
    /// No transport or service proof was supplied.
    Unestablished,
    /// Exact USB VID/PID transport presence was supplied.
    TransportPresence,
    /// A distinct device/service mode was supplied in addition to any transport evidence.
    ModePresence,
    /// A read-only service-session receipt was explicitly supplied.
    ServiceSessionEvidence,
    /// The service session supplied a bounded partition-layout inventory.
    LayoutEvidence,
}

/// Bounded read-only MTK/META observation from an untrusted evidence Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatekEvidenceObservation {
    /// Observed device/service mode.
    pub mode: MediatekMode,
    /// Optional exact USB vendor identifier.
    pub usb_vid: Option<u16>,
    /// Optional exact USB product identifier.
    pub usb_pid: Option<u16>,
    /// Optional platform/SoC claim such as `MT6789`.
    pub platform: Option<String>,
    /// Optional storage-family claim such as `EMMC` or `UFS`.
    pub storage: Option<String>,
    /// Partition names returned by a read-only layout inventory.
    pub partition_names: Vec<String>,
    /// Provider explicitly supplied evidence of a valid read-only service session.
    pub service_session_established: bool,
    /// Provider explicitly supplied evidence that the layout was inventoried through that session.
    pub layout_inventoried: bool,
    /// Provider claim that all C05-supported evidence semantics were supplied.
    pub complete_claim: bool,
    /// Explicit unsupported or partial semantics.
    pub limitations: Vec<String>,
}

/// Replaceable lawful read-only MTK/META evidence boundary.
pub trait MediatekEvidenceProvider: Send + Sync {
    /// Stable backend-local Provider alias/evidence identifier.
    fn provider_id(&self) -> &str;

    /// Return bounded read-only evidence associated with the package inspection.
    ///
    /// # Errors
    /// Returns a Provider-specific mechanical failure.
    fn inspect_evidence(
        &self,
        scatter_source: &[u8],
        limits: MediatekLimits,
    ) -> Result<MediatekEvidenceObservation, String>;
}

/// Validated lawful read-only evidence projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatekEvidence {
    /// Backend-local Provider alias/evidence identifier.
    pub provider_alias: String,
    /// Observed mode.
    pub mode: MediatekMode,
    /// Optional exact USB VID.
    pub usb_vid: Option<u16>,
    /// Optional exact USB PID.
    pub usb_pid: Option<u16>,
    /// Optional platform claim.
    pub platform: Option<String>,
    /// Optional storage-family claim.
    pub storage: Option<String>,
    /// Bounded partition names.
    pub partition_names: Vec<String>,
    /// Explicit service-session evidence flag.
    pub service_session_established: bool,
    /// Explicit layout-inventory evidence flag.
    pub layout_inventoried: bool,
    /// Strongest mechanically validated evidence level.
    pub level: MediatekEvidenceLevel,
    /// Provider completeness claim.
    pub complete_claim: bool,
    /// Explicit unsupported or partial semantics.
    pub limitations: Vec<String>,
}

/// Static scatter-to-read-only-evidence correlation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatekEvidenceCorrelation {
    /// Platform claim comparison when supplied.
    pub platform_matches: Option<bool>,
    /// Storage claim comparison when supplied.
    pub storage_matches: Option<bool>,
    /// Exact partition-name-set comparison when a layout was inventoried.
    pub partition_names_match: Option<bool>,
}

/// Source-bound C05 report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatekReport {
    /// Exact scatter Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact immutable whole-scatter SHA-256.
    pub source_sha256: String,
    /// Exact immutable scatter byte size.
    pub source_size: u64,
    /// Optional scatter config version.
    pub config_version: Option<String>,
    /// Scatter platform/SoC claim.
    pub platform: String,
    /// Scatter storage-family claim.
    pub storage: String,
    /// Structural/semantic truth status.
    pub assessment: MediatekAssessment,
    /// Static C05 grants no device mutation trust.
    pub trust: MediatekTrustAssessment,
    /// Mechanically earned static proof level.
    pub proof_level: Option<MediatekStaticProofLevel>,
    /// Backend-local bundle Provider alias when one was used.
    pub bundle_provider_alias: Option<String>,
    /// Exact recovered sibling entries.
    pub bundle_entries: Vec<MediatekBundleEntry>,
    /// Exact partition relationships parsed from the scatter file.
    pub partitions: Vec<MediatekPartition>,
    /// Optional lawful read-only device evidence.
    pub evidence: Option<MediatekEvidence>,
    /// Optional static-to-read-only evidence correlation.
    pub evidence_correlation: Option<MediatekEvidenceCorrelation>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
    /// Explicit unsupported, ambiguous or incomplete boundaries.
    pub limitations: Vec<String>,
    projection_sha256: String,
}

impl MediatekReport {
    /// Produce exact source-bound A07 Views.
    ///
    /// # Errors
    /// Rejects mutated reports or mismatched source context.
    pub fn view_specs(&self, context: &MediatekContext) -> Result<Vec<ViewSpec>, C05Error> {
        validate_context(context)?;
        validate_report_integrity(self)?;
        if self.source_revision_ref != context.source_revision_ref {
            return Err(C05Error::SourceBindingMismatch);
        }
        Ok(vec![
            view_spec(context, "mediatek.scatter.inventory", "scatter-inventory"),
            view_spec(
                context,
                "mediatek.partition.relationships",
                "partition-relationships",
            ),
            view_spec(context, "mediatek.lawful_evidence", "lawful-evidence"),
            view_spec(context, "mediatek.proof_levels", "proof-levels"),
        ])
    }
}

/// Exact recovered `MediaTek` sibling component bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatekMaterialization {
    /// Canonical referenced component path.
    pub name: String,
    /// A07 object class used for registration.
    pub object_class: String,
    /// Exact scatter source Revision that referenced this component.
    pub source_revision_ref: EntityRef,
    /// Exact recovered SHA-256.
    pub sha256: String,
    bytes: Vec<u8>,
}

impl MediatekMaterialization {
    /// Read-only exact recovered bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Build exact source-bound A07 registration.
    ///
    /// Bundle siblings are referenced by the scatter source rather than embedded in it, so the
    /// origin remains `Unknown` until a wider package Object supplies stronger provenance.
    ///
    /// # Errors
    /// Rejects context that does not bind the exact scatter Revision.
    pub fn registration_spec(
        &self,
        context: &MediatekContext,
    ) -> Result<RegisterObjectSpec, C05Error> {
        validate_context(context)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C05Error::SourceBindingMismatch);
        }
        Ok(RegisterObjectSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            object_class: self.object_class.clone(),
            declared_name: Some(self.name.clone()),
            source_refs: vec![self.source_revision_ref.clone()],
            revision_role: RevisionRole::Recovered,
            origin_class: OriginClass::Unknown,
            created_reason: "C05 recovered exact MediaTek bundle component referenced by scatter"
                .to_owned(),
            production: context.production.clone(),
            expected_sha256: Some(self.sha256.clone()),
        })
    }

    /// Build scatter-reference-to-component A07 Relationship after exact registration.
    ///
    /// # Errors
    /// Rejects mismatched registration bytes or canonical endpoint kinds.
    pub fn relationship_spec(
        &self,
        context: &MediatekContext,
        registration: &Registration,
    ) -> Result<RelationshipSpec, C05Error> {
        validate_context(context)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C05Error::SourceBindingMismatch);
        }
        if registration.object_ref.entity_kind.as_str() != "object.object"
            || registration.revision_ref.entity_kind.as_str() != "object.revision"
        {
            return Err(C05Error::InvalidRegistration);
        }
        let byte_size =
            u64::try_from(self.bytes.len()).map_err(|_| C05Error::AccountingOverflow)?;
        if registration.sha256 != self.sha256 || registration.byte_size != byte_size {
            return Err(C05Error::RegistrationMismatch);
        }
        Ok(RelationshipSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            subject_refs: vec![self.source_revision_ref.clone()],
            relationship_type: "references.mediatek_firmware_component".to_owned(),
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
pub enum MediatekComparisonLevel {
    /// Structural projections differ.
    Different,
    /// Structure matches but retained component digests differ.
    Structural,
    /// Retained component identities and digests match while scatter bytes differ.
    ComponentExact,
    /// Scatter bytes and retained component identities are digest-identical.
    ByteExact,
}

/// Source-bound C05 comparison report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediatekComparison {
    /// Left scatter source Revision.
    pub left_source_revision_ref: EntityRef,
    /// Right scatter source Revision.
    pub right_source_revision_ref: EntityRef,
    /// Strongest mechanically established comparison level.
    pub level: MediatekComparisonLevel,
    /// Deterministic differences.
    pub differences: Vec<String>,
}

/// C05 failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum C05Error {
    /// Workspace reference is not canonical.
    #[error("C05 workspace reference must be core.workspace")]
    InvalidWorkspaceRef,
    /// Source must bind an exact Object Revision.
    #[error("C05 source must be an exact object.revision reference")]
    InvalidSourceRevision,
    /// One configured resource limit is zero.
    #[error("C05 limits must all be greater than zero")]
    InvalidLimits,
    /// Scatter source exceeds configured bytes.
    #[error("C05 source exceeds max_source_bytes")]
    SourceTooLarge,
    /// Scatter source is not valid UTF-8.
    #[error("C05 scatter source is not valid UTF-8")]
    InvalidUtf8,
    /// Scatter grammar or required fields are invalid.
    #[error("C05 invalid MediaTek scatter structure")]
    InvalidScatter,
    /// Input line count exceeds configured bounds.
    #[error("C05 scatter line count exceeds configured limit")]
    TooManyLines,
    /// Partition count exceeds configured bounds.
    #[error("C05 partition count exceeds configured limit")]
    TooManyPartitions,
    /// Bundle entry count exceeds configured bounds.
    #[error("C05 bundle entry count exceeds configured limit")]
    TooManyEntries,
    /// Total recovered bundle bytes exceed configured bounds.
    #[error("C05 recovered bundle bytes exceed configured limit")]
    TooManyRecoveredBytes,
    /// String or path exceeds configured bounds or violates grammar.
    #[error("C05 invalid bounded string/path")]
    InvalidString,
    /// Bundle path is unsafe or non-canonical.
    #[error("C05 bundle path is unsafe or non-canonical")]
    InvalidBundlePath,
    /// Duplicate canonical bundle path.
    #[error("C05 duplicate canonical bundle path")]
    DuplicateBundlePath,
    /// Duplicate partition index or partition name.
    #[error("C05 duplicate partition identity")]
    DuplicatePartition,
    /// Scatter numeric field is invalid.
    #[error("C05 invalid scatter numeric field")]
    InvalidNumber,
    /// Partition range arithmetic overflowed.
    #[error("C05 partition range overflow")]
    PartitionRangeOverflow,
    /// Provider-declared digest is malformed or mismatched.
    #[error("C05 recovered entry digest mismatch")]
    DigestMismatch,
    /// Bundle Provider failed.
    #[error("C05 bundle Provider failed: {0}")]
    BundleProvider(String),
    /// Lawful evidence Provider failed.
    #[error("C05 evidence Provider failed: {0}")]
    EvidenceProvider(String),
    /// Evidence observation violates monotonic proof-level rules.
    #[error("C05 invalid lawful evidence observation")]
    InvalidEvidenceObservation,
    /// Numeric accounting overflowed.
    #[error("C05 byte accounting overflow")]
    AccountingOverflow,
    /// Report/source/context binding mismatch.
    #[error("C05 exact source binding mismatch")]
    SourceBindingMismatch,
    /// Report was mutated after inspection.
    #[error("C05 report integrity seal mismatch")]
    ReportIntegrityMismatch,
    /// Requested exact referenced component does not exist.
    #[error("C05 requested MediaTek bundle component was not found")]
    ChildNotFound,
    /// Materialization exceeds configured bounds.
    #[error("C05 materialization exceeds configured limit")]
    MaterializationTooLarge,
    /// Registered A07 endpoints have invalid kinds.
    #[error("C05 component registration has invalid canonical endpoint kinds")]
    InvalidRegistration,
    /// Registration bytes do not match exact recovered component.
    #[error("C05 component registration does not match exact bytes")]
    RegistrationMismatch,
}

/// Inspect one immutable `MediaTek` scatter source plus optional sibling bundle/read-only evidence.
///
/// # Errors
/// Fails closed for malformed scatter grammar, Provider output, paths, digests, bounds or
/// non-monotonic evidence claims.
pub fn inspect_mediatek_package(
    source: &[u8],
    context: &MediatekContext,
    limits: MediatekLimits,
    bundle_provider: Option<&dyn MediatekBundleProvider>,
    evidence_provider: Option<&dyn MediatekEvidenceProvider>,
) -> Result<MediatekReport, C05Error> {
    validate_context(context)?;
    validate_limits(limits)?;
    let source_size = u64::try_from(source.len()).map_err(|_| C05Error::AccountingOverflow)?;
    if source_size > limits.max_source_bytes {
        return Err(C05Error::SourceTooLarge);
    }
    let text = str::from_utf8(source).map_err(|_| C05Error::InvalidUtf8)?;
    let parsed = parse_scatter(text, limits)?;
    let ParsedScatter {
        config_version,
        platform,
        storage,
        mut partitions,
    } = parsed;
    let source_sha256 = sha256_bytes(source);
    let referenced_paths: BTreeSet<String> = partitions
        .iter()
        .filter_map(|partition| partition.file_name.clone())
        .collect();

    let bundle = resolve_bundle(source, &referenced_paths, bundle_provider, limits)?;
    link_partition_components(&mut partitions, &bundle.entries);
    let evidence = resolve_evidence(
        source,
        &platform,
        &storage,
        &partitions,
        evidence_provider,
        limits,
    )?;

    let assessment = if bundle.partial || evidence.partial {
        MediatekAssessment::Partial
    } else {
        MediatekAssessment::Complete
    };
    let mut limitations = bundle.limitations;
    limitations.extend(evidence.limitations);
    let proof_level = if bundle.linked && evidence.correlated {
        Some(MediatekStaticProofLevel::EvidenceCorrelated)
    } else if bundle.linked && !referenced_paths.is_empty() {
        Some(MediatekStaticProofLevel::BundleLinked)
    } else {
        Some(MediatekStaticProofLevel::StructureChecked)
    };

    Ok(seal_report(MediatekReport {
        source_revision_ref: context.source_revision_ref.clone(),
        source_sha256,
        source_size,
        config_version,
        platform,
        storage,
        assessment,
        trust: MediatekTrustAssessment::NotEstablished,
        proof_level,
        bundle_provider_alias: bundle.provider_alias,
        bundle_entries: bundle.entries,
        partitions,
        evidence: evidence.evidence,
        evidence_correlation: evidence.correlation,
        warnings: Vec::new(),
        limitations,
        projection_sha256: String::new(),
    }))
}

struct BundleResolution {
    provider_alias: Option<String>,
    entries: Vec<MediatekBundleEntry>,
    linked: bool,
    partial: bool,
    limitations: Vec<String>,
}

fn resolve_bundle(
    source: &[u8],
    referenced_paths: &BTreeSet<String>,
    bundle_provider: Option<&dyn MediatekBundleProvider>,
    limits: MediatekLimits,
) -> Result<BundleResolution, C05Error> {
    if referenced_paths.is_empty() {
        return Ok(BundleResolution {
            provider_alias: None,
            entries: Vec::new(),
            linked: true,
            partial: false,
            limitations: Vec::new(),
        });
    }
    let Some(provider) = bundle_provider else {
        return Ok(BundleResolution {
            provider_alias: None,
            entries: Vec::new(),
            linked: false,
            partial: true,
            limitations: vec![
      "scatter references sibling components but no MediaTek bundle Provider was supplied"
.to_owned(),
  ],
        });
    };
    validate_string(provider.provider_id(), limits)?;
    let observation = provider
        .inspect_bundle(source, limits)
        .map_err(C05Error::BundleProvider)?;
    let (entries, complete_claim, mut limitations) =
        validate_bundle_observation(observation, limits)?;
    let entry_map: BTreeMap<&str, &MediatekBundleEntry> = entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let unresolved = referenced_paths
        .iter()
        .filter(|path| !entry_map.contains_key(path.as_str()))
        .count();
    if !complete_claim {
        limitations
            .push("bundle Provider did not claim complete C05-supported inventory".to_owned());
    }
    if unresolved != 0 {
        limitations.push(format!(
            "{unresolved} scatter-referenced bundle component(s) unresolved"
        ));
    }
    Ok(BundleResolution {
        provider_alias: Some(provider.provider_id().to_owned()),
        entries,
        linked: complete_claim && unresolved == 0,
        partial: !complete_claim || unresolved != 0,
        limitations,
    })
}

fn link_partition_components(
    partitions: &mut [MediatekPartition],
    entries: &[MediatekBundleEntry],
) {
    let entry_map: BTreeMap<&str, &MediatekBundleEntry> = entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    for partition in partitions {
        if let Some(entry) = partition
            .file_name
            .as_deref()
            .and_then(|file_name| entry_map.get(file_name).copied())
        {
            partition.linked_component_size = Some(entry.byte_size);
            partition.linked_component_sha256 = Some(entry.sha256.clone());
        }
    }
}

struct EvidenceResolution {
    evidence: Option<MediatekEvidence>,
    correlation: Option<MediatekEvidenceCorrelation>,
    correlated: bool,
    partial: bool,
    limitations: Vec<String>,
}

fn resolve_evidence(
    source: &[u8],
    platform: &str,
    storage: &str,
    partitions: &[MediatekPartition],
    evidence_provider: Option<&dyn MediatekEvidenceProvider>,
    limits: MediatekLimits,
) -> Result<EvidenceResolution, C05Error> {
    let Some(provider) = evidence_provider else {
        return Ok(EvidenceResolution {
            evidence: None,
            correlation: None,
            correlated: false,
            partial: false,
            limitations: Vec::new(),
        });
    };
    validate_string(provider.provider_id(), limits)?;
    let observation = provider
        .inspect_evidence(source, limits)
        .map_err(C05Error::EvidenceProvider)?;
    let mut validated = validate_evidence_observation(observation, provider.provider_id(), limits)?;
    let correlation = correlate_evidence(platform, storage, partitions, &validated);
    let mismatch = matches!(correlation.platform_matches, Some(false))
        || matches!(correlation.storage_matches, Some(false))
        || matches!(correlation.partition_names_match, Some(false));
    let mut limitations = Vec::new();
    if mismatch {
        limitations.push(
            "supplied lawful MTK/META evidence contradicts scatter platform/storage/layout claims"
                .to_owned(),
        );
    }
    if !validated.complete_claim {
        validated.limitations.push(
            "evidence Provider did not claim complete C05-supported read-only evidence".to_owned(),
        );
    }
    limitations.extend(validated.limitations.iter().cloned());
    let correlated = validated.complete_claim
        && validated.level == MediatekEvidenceLevel::LayoutEvidence
        && correlation.platform_matches == Some(true)
        && correlation.storage_matches == Some(true)
        && correlation.partition_names_match == Some(true)
        && !mismatch;
    Ok(EvidenceResolution {
        evidence: Some(validated),
        correlation: Some(correlation),
        correlated,
        partial: mismatch
            || limitations.iter().any(|value| {
                value.contains("did not claim complete C05-supported read-only evidence")
            }),
        limitations,
    })
}

/// Materialize one exact bundle component referenced by the scatter source.
///
/// # Errors
/// Rejects mutated/stale reports, unreferenced or missing entries and configured bounds.
pub fn materialize_mediatek_component(
    source: &[u8],
    report: &MediatekReport,
    path: &str,
    context: &MediatekContext,
    limits: MediatekLimits,
) -> Result<MediatekMaterialization, C05Error> {
    validate_materialization_source(source, report, context, limits)?;
    validate_bundle_path(path, limits)?;
    if !report
        .partitions
        .iter()
        .any(|partition| partition.file_name.as_deref() == Some(path))
    {
        return Err(C05Error::ChildNotFound);
    }
    let entry = report
        .bundle_entries
        .iter()
        .find(|entry| entry.path == path)
        .ok_or(C05Error::ChildNotFound)?;
    ensure_materialization_size(entry.byte_size, limits)?;
    if sha256_bytes(&entry.recovered_bytes) != entry.sha256 {
        return Err(C05Error::ReportIntegrityMismatch);
    }
    Ok(MediatekMaterialization {
        name: entry.path.clone(),
        object_class: "mediatek.firmware.bundle_component".to_owned(),
        source_revision_ref: report.source_revision_ref.clone(),
        sha256: entry.sha256.clone(),
        bytes: entry.recovered_bytes.clone(),
    })
}

/// Compare two sealed C05 reports without manufacturing device-write compatibility.
#[must_use]
pub fn compare_mediatek_packages(
    left: &MediatekReport,
    right: &MediatekReport,
) -> MediatekComparison {
    let mut differences = Vec::new();
    let left_shape = report_shape(left);
    let right_shape = report_shape(right);
    if left_shape != right_shape {
        differences.push("scatter_or_partition_structure_changed".to_owned());
    }
    let component_exact = report_component_identity(left) == report_component_identity(right);
    if left_shape == right_shape && !component_exact {
        differences.push("bundle_component_bytes_changed".to_owned());
    }
    let level = if left.source_sha256 == right.source_sha256
        && left.source_size == right.source_size
        && component_exact
    {
        MediatekComparisonLevel::ByteExact
    } else if left_shape == right_shape && component_exact {
        MediatekComparisonLevel::ComponentExact
    } else if left_shape == right_shape {
        MediatekComparisonLevel::Structural
    } else {
        MediatekComparisonLevel::Different
    };
    MediatekComparison {
        left_source_revision_ref: left.source_revision_ref.clone(),
        right_source_revision_ref: right.source_revision_ref.clone(),
        level,
        differences,
    }
}

/// Convert comparison evidence into an explicit C05 static proof level.
#[must_use]
pub fn assess_mediatek_rebuild(
    original: &MediatekReport,
    rebuilt: &MediatekReport,
) -> Option<MediatekStaticProofLevel> {
    match compare_mediatek_packages(original, rebuilt).level {
        MediatekComparisonLevel::Different => None,
        MediatekComparisonLevel::Structural => Some(MediatekStaticProofLevel::StructureChecked),
        MediatekComparisonLevel::ComponentExact => Some(MediatekStaticProofLevel::ComponentExact),
        MediatekComparisonLevel::ByteExact => Some(MediatekStaticProofLevel::ByteExact),
    }
}

#[derive(Debug)]
struct ParsedScatter {
    config_version: Option<String>,
    platform: String,
    storage: String,
    partitions: Vec<MediatekPartition>,
}

#[derive(Debug)]
enum PartitionFileName {
    Absent,
    Path(String),
}

#[derive(Debug, Default)]
struct PartitionBuilder {
    partition_index: Option<String>,
    partition_name: Option<String>,
    file_name: Option<PartitionFileName>,
    is_download: Option<bool>,
    image_type: Option<String>,
    linear_start_addr: Option<u64>,
    physical_start_addr: Option<u64>,
    partition_size: Option<u64>,
    region: Option<String>,
    storage: Option<String>,
    seen_keys: BTreeSet<&'static str>,
}

fn parse_scatter(text: &str, limits: MediatekLimits) -> Result<ParsedScatter, C05Error> {
    let mut config_version = None;
    let mut platform = None;
    let mut storage = None;
    let mut partitions = Vec::new();
    let mut current: Option<PartitionBuilder> = None;
    let mut line_count = 0usize;

    for raw_line in text.lines() {
        line_count = line_count
            .checked_add(1)
            .ok_or(C05Error::AccountingOverflow)?;
        if line_count > limits.max_lines {
            return Err(C05Error::TooManyLines);
        }
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(value) = line.strip_prefix("- partition_index:") {
            if let Some(builder) = current.take() {
                push_partition(&mut partitions, builder, limits)?;
            }
            if partitions.len() >= limits.max_partitions {
                return Err(C05Error::TooManyPartitions);
            }
            let mut builder = PartitionBuilder::default();
            set_partition_string(
                &mut builder.partition_index,
                &mut builder.seen_keys,
                "partition_index",
                clean_value(value),
                limits,
            )?;
            current = Some(builder);
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once(':') else {
            continue;
        };
        let key = raw_key.trim().trim_start_matches('-').trim();
        let value = clean_value(raw_value);
        if let Some(builder) = current.as_mut() {
            parse_partition_field(builder, key, value, limits)?;
        } else {
            parse_scatter_header_field(
                &mut config_version,
                &mut platform,
                &mut storage,
                key,
                value,
                limits,
            )?;
        }
    }
    if let Some(builder) = current.take() {
        push_partition(&mut partitions, builder, limits)?;
    }
    if partitions.is_empty() {
        return Err(C05Error::InvalidScatter);
    }
    let platform = platform.ok_or(C05Error::InvalidScatter)?;
    let storage = storage.ok_or(C05Error::InvalidScatter)?;
    validate_partition_uniqueness(&partitions)?;
    Ok(ParsedScatter {
        config_version,
        platform,
        storage,
        partitions,
    })
}

fn parse_partition_field(
    builder: &mut PartitionBuilder,
    key: &str,
    value: &str,
    limits: MediatekLimits,
) -> Result<(), C05Error> {
    match key {
        "partition_name" => set_partition_string(
            &mut builder.partition_name,
            &mut builder.seen_keys,
            "partition_name",
            value,
            limits,
        ),
        "file_name" => {
            mark_partition_key(&mut builder.seen_keys, "file_name")?;
            if value.eq_ignore_ascii_case("NONE") {
                builder.file_name = Some(PartitionFileName::Absent);
            } else {
                validate_bundle_path(value, limits)?;
                builder.file_name = Some(PartitionFileName::Path(value.to_owned()));
            }
            Ok(())
        }
        "is_download" => {
            mark_partition_key(&mut builder.seen_keys, "is_download")?;
            builder.is_download = Some(parse_bool(value)?);
            Ok(())
        }
        "type" => set_partition_string(
            &mut builder.image_type,
            &mut builder.seen_keys,
            "type",
            value,
            limits,
        ),
        "linear_start_addr" => {
            mark_partition_key(&mut builder.seen_keys, "linear_start_addr")?;
            builder.linear_start_addr = Some(parse_u64(value)?);
            Ok(())
        }
        "physical_start_addr" => {
            mark_partition_key(&mut builder.seen_keys, "physical_start_addr")?;
            builder.physical_start_addr = Some(parse_u64(value)?);
            Ok(())
        }
        "partition_size" => {
            mark_partition_key(&mut builder.seen_keys, "partition_size")?;
            builder.partition_size = Some(parse_u64(value)?);
            Ok(())
        }
        "region" => set_partition_string(
            &mut builder.region,
            &mut builder.seen_keys,
            "region",
            value,
            limits,
        ),
        "storage" => set_partition_string(
            &mut builder.storage,
            &mut builder.seen_keys,
            "storage",
            value,
            limits,
        ),
        _ => Ok(()),
    }
}

fn parse_scatter_header_field(
    config_version: &mut Option<String>,
    platform: &mut Option<String>,
    storage: &mut Option<String>,
    key: &str,
    value: &str,
    limits: MediatekLimits,
) -> Result<(), C05Error> {
    let target = match key {
        "config_version" if config_version.is_none() => Some(config_version),
        "platform" if platform.is_none() => Some(platform),
        "storage" if storage.is_none() => Some(storage),
        _ => None,
    };
    if let Some(target) = target {
        validate_string(value, limits)?;
        *target = Some(value.to_owned());
    }
    Ok(())
}

fn clean_value(raw: &str) -> &str {
    let value = raw.trim();
    let bytes = value.as_bytes();
    if value.len() >= 2
        && ((bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\''))
    {
        return &value[1..value.len() - 1];
    }
    value
}

fn set_partition_string(
    target: &mut Option<String>,
    seen: &mut BTreeSet<&'static str>,
    key: &'static str,
    value: &str,
    limits: MediatekLimits,
) -> Result<(), C05Error> {
    mark_partition_key(seen, key)?;
    validate_string(value, limits)?;
    *target = Some(value.to_owned());
    Ok(())
}

fn mark_partition_key(
    seen: &mut BTreeSet<&'static str>,
    key: &'static str,
) -> Result<(), C05Error> {
    if !seen.insert(key) {
        return Err(C05Error::InvalidScatter);
    }
    Ok(())
}

fn push_partition(
    partitions: &mut Vec<MediatekPartition>,
    builder: PartitionBuilder,
    limits: MediatekLimits,
) -> Result<(), C05Error> {
    if partitions.len() >= limits.max_partitions {
        return Err(C05Error::TooManyPartitions);
    }
    let partition_index = builder.partition_index.ok_or(C05Error::InvalidScatter)?;
    let partition_name = builder.partition_name.ok_or(C05Error::InvalidScatter)?;
    let file_name = match builder.file_name.ok_or(C05Error::InvalidScatter)? {
        PartitionFileName::Absent => None,
        PartitionFileName::Path(path) => Some(path),
    };
    let is_download = builder.is_download.ok_or(C05Error::InvalidScatter)?;
    let image_type = builder.image_type.ok_or(C05Error::InvalidScatter)?;
    let linear_start = builder.linear_start_addr.ok_or(C05Error::InvalidScatter)?;
    let physical_start = builder
        .physical_start_addr
        .ok_or(C05Error::InvalidScatter)?;
    let partition_size = builder.partition_size.ok_or(C05Error::InvalidScatter)?;
    let region = builder.region.ok_or(C05Error::InvalidScatter)?;
    let storage = builder.storage.ok_or(C05Error::InvalidScatter)?;
    let linear_end = linear_start
        .checked_add(partition_size)
        .ok_or(C05Error::PartitionRangeOverflow)?;
    let physical_end = physical_start
        .checked_add(partition_size)
        .ok_or(C05Error::PartitionRangeOverflow)?;
    partitions.push(MediatekPartition {
        partition_index,
        partition_name,
        file_name,
        is_download,
        image_type,
        linear_range: MediatekPartitionRange {
            start: linear_start,
            end_exclusive: linear_end,
        },
        physical_range: MediatekPartitionRange {
            start: physical_start,
            end_exclusive: physical_end,
        },
        region,
        storage,
        linked_component_size: None,
        linked_component_sha256: None,
    });
    Ok(())
}

fn validate_partition_uniqueness(partitions: &[MediatekPartition]) -> Result<(), C05Error> {
    let mut indexes = BTreeSet::new();
    let mut names = BTreeSet::new();
    for partition in partitions {
        if !indexes.insert(partition.partition_index.as_str())
            || !names.insert(partition.partition_name.as_str())
        {
            return Err(C05Error::DuplicatePartition);
        }
    }
    Ok(())
}

fn parse_bool(value: &str) -> Result<bool, C05Error> {
    if value.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(C05Error::InvalidScatter)
    }
}

fn parse_u64(value: &str) -> Result<u64, C05Error> {
    if value.is_empty() || value.starts_with('-') || value.starts_with('+') {
        return Err(C05Error::InvalidNumber);
    }
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(C05Error::InvalidNumber);
        }
        u64::from_str_radix(hex, 16).map_err(|_| C05Error::InvalidNumber)
    } else {
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(C05Error::InvalidNumber);
        }
        value.parse::<u64>().map_err(|_| C05Error::InvalidNumber)
    }
}

fn validate_bundle_observation(
    observation: MediatekBundleObservation,
    limits: MediatekLimits,
) -> Result<(Vec<MediatekBundleEntry>, bool, Vec<String>), C05Error> {
    if observation.entries.len() > limits.max_bundle_entries {
        return Err(C05Error::TooManyEntries);
    }
    validate_limitations(&observation.limitations, limits)?;
    let mut paths = BTreeSet::new();
    let mut total = 0u64;
    let mut entries = Vec::with_capacity(observation.entries.len());
    for entry in observation.entries {
        validate_bundle_path(&entry.path, limits)?;
        if !paths.insert(entry.path.clone()) {
            return Err(C05Error::DuplicateBundlePath);
        }
        validate_sha256(&entry.expected_sha256)?;
        let actual = sha256_bytes(&entry.recovered_bytes);
        if actual != entry.expected_sha256 {
            return Err(C05Error::DigestMismatch);
        }
        let byte_size =
            u64::try_from(entry.recovered_bytes.len()).map_err(|_| C05Error::AccountingOverflow)?;
        total = total
            .checked_add(byte_size)
            .ok_or(C05Error::AccountingOverflow)?;
        if total > limits.max_recovered_bytes {
            return Err(C05Error::TooManyRecoveredBytes);
        }
        entries.push(MediatekBundleEntry {
            path: entry.path,
            byte_size,
            sha256: actual,
            recovered_bytes: entry.recovered_bytes,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok((entries, observation.complete_claim, observation.limitations))
}

fn validate_evidence_observation(
    observation: MediatekEvidenceObservation,
    provider_id: &str,
    limits: MediatekLimits,
) -> Result<MediatekEvidence, C05Error> {
    validate_string(provider_id, limits)?;
    validate_optional_string(observation.platform.as_deref(), limits)?;
    validate_optional_string(observation.storage.as_deref(), limits)?;
    validate_limitations(&observation.limitations, limits)?;
    if observation.partition_names.len() > limits.max_evidence_partitions {
        return Err(C05Error::InvalidEvidenceObservation);
    }
    let transport_present = match (observation.usb_vid, observation.usb_pid) {
        (Some(_), Some(_)) => true,
        (None, None) => false,
        _ => return Err(C05Error::InvalidEvidenceObservation),
    };
    if observation.service_session_established
        && (!transport_present || observation.mode == MediatekMode::Unknown)
    {
        return Err(C05Error::InvalidEvidenceObservation);
    }
    if observation.layout_inventoried && !observation.service_session_established {
        return Err(C05Error::InvalidEvidenceObservation);
    }
    if observation.layout_inventoried && observation.partition_names.is_empty() {
        return Err(C05Error::InvalidEvidenceObservation);
    }
    let mut names = BTreeSet::new();
    for name in &observation.partition_names {
        validate_string(name, limits)?;
        if !names.insert(name.as_str()) {
            return Err(C05Error::InvalidEvidenceObservation);
        }
    }
    let level = if observation.layout_inventoried {
        MediatekEvidenceLevel::LayoutEvidence
    } else if observation.service_session_established {
        MediatekEvidenceLevel::ServiceSessionEvidence
    } else if observation.mode != MediatekMode::Unknown {
        MediatekEvidenceLevel::ModePresence
    } else if transport_present {
        MediatekEvidenceLevel::TransportPresence
    } else {
        MediatekEvidenceLevel::Unestablished
    };
    Ok(MediatekEvidence {
        provider_alias: provider_id.to_owned(),
        mode: observation.mode,
        usb_vid: observation.usb_vid,
        usb_pid: observation.usb_pid,
        platform: observation.platform,
        storage: observation.storage,
        partition_names: observation.partition_names,
        service_session_established: observation.service_session_established,
        layout_inventoried: observation.layout_inventoried,
        level,
        complete_claim: observation.complete_claim,
        limitations: observation.limitations,
    })
}

fn correlate_evidence(
    platform: &str,
    storage: &str,
    partitions: &[MediatekPartition],
    evidence: &MediatekEvidence,
) -> MediatekEvidenceCorrelation {
    let platform_matches = evidence
        .platform
        .as_deref()
        .map(|value| value.eq_ignore_ascii_case(platform));
    let storage_matches = evidence
        .storage
        .as_deref()
        .map(|value| value.eq_ignore_ascii_case(storage));
    let partition_names_match = if evidence.layout_inventoried {
        let scatter_names: BTreeSet<&str> = partitions
            .iter()
            .map(|partition| partition.partition_name.as_str())
            .collect();
        let evidence_names: BTreeSet<&str> = evidence
            .partition_names
            .iter()
            .map(String::as_str)
            .collect();
        Some(scatter_names == evidence_names)
    } else {
        None
    };
    MediatekEvidenceCorrelation {
        platform_matches,
        storage_matches,
        partition_names_match,
    }
}

fn validate_materialization_source(
    source: &[u8],
    report: &MediatekReport,
    context: &MediatekContext,
    limits: MediatekLimits,
) -> Result<(), C05Error> {
    validate_context(context)?;
    validate_limits(limits)?;
    validate_report_integrity(report)?;
    if report.source_revision_ref != context.source_revision_ref
        || report.source_size
            != u64::try_from(source.len()).map_err(|_| C05Error::AccountingOverflow)?
        || report.source_sha256 != sha256_bytes(source)
    {
        return Err(C05Error::SourceBindingMismatch);
    }
    Ok(())
}

fn ensure_materialization_size(size: u64, limits: MediatekLimits) -> Result<(), C05Error> {
    if size > limits.max_materialized_bytes {
        return Err(C05Error::MaterializationTooLarge);
    }
    Ok(())
}

fn validate_context(context: &MediatekContext) -> Result<(), C05Error> {
    if context.workspace_ref.entity_kind.as_str() != "core.workspace" {
        return Err(C05Error::InvalidWorkspaceRef);
    }
    if context.source_revision_ref.entity_kind.as_str() != "object.revision" {
        return Err(C05Error::InvalidSourceRevision);
    }
    Ok(())
}

fn validate_limits(limits: MediatekLimits) -> Result<(), C05Error> {
    if limits.max_source_bytes == 0
        || limits.max_partitions == 0
        || limits.max_bundle_entries == 0
        || limits.max_recovered_bytes == 0
        || limits.max_string_bytes == 0
        || limits.max_lines == 0
        || limits.max_evidence_partitions == 0
        || limits.max_materialized_bytes == 0
    {
        return Err(C05Error::InvalidLimits);
    }
    Ok(())
}

fn validate_bundle_path(path: &str, limits: MediatekLimits) -> Result<(), C05Error> {
    validate_string(path, limits)?;
    if path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains('\0')
        || path.ends_with('/')
        || has_windows_drive_prefix(path)
    {
        return Err(C05Error::InvalidBundlePath);
    }
    if path
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(C05Error::InvalidBundlePath);
    }
    Ok(())
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn validate_optional_string(value: Option<&str>, limits: MediatekLimits) -> Result<(), C05Error> {
    if let Some(value) = value {
        validate_string(value, limits)?;
    }
    Ok(())
}

fn validate_string(value: &str, limits: MediatekLimits) -> Result<(), C05Error> {
    if value.is_empty() || value.len() > limits.max_string_bytes || value.contains('\0') {
        return Err(C05Error::InvalidString);
    }
    Ok(())
}

fn validate_limitations(values: &[String], limits: MediatekLimits) -> Result<(), C05Error> {
    for value in values {
        validate_string(value, limits)?;
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), C05Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(C05Error::DigestMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PartitionShape {
    partition_index: String,
    partition_name: String,
    file_name: Option<String>,
    is_download: bool,
    image_type: String,
    linear_range: MediatekPartitionRange,
    physical_range: MediatekPartitionRange,
    region: String,
    storage: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportShape {
    config_version: Option<String>,
    platform: String,
    storage: String,
    partitions: Vec<PartitionShape>,
}

fn report_shape(report: &MediatekReport) -> ReportShape {
    ReportShape {
        config_version: report.config_version.clone(),
        platform: report.platform.clone(),
        storage: report.storage.clone(),
        partitions: report
            .partitions
            .iter()
            .map(|partition| PartitionShape {
                partition_index: partition.partition_index.clone(),
                partition_name: partition.partition_name.clone(),
                file_name: partition.file_name.clone(),
                is_download: partition.is_download,
                image_type: partition.image_type.clone(),
                linear_range: partition.linear_range,
                physical_range: partition.physical_range,
                region: partition.region.clone(),
                storage: partition.storage.clone(),
            })
            .collect(),
    }
}

fn report_component_identity(report: &MediatekReport) -> Vec<String> {
    report
        .bundle_entries
        .iter()
        .map(|entry| format!("bundle:{}:{}:{}", entry.path, entry.byte_size, entry.sha256))
        .collect()
}

fn report_projection_digest(report: &MediatekReport) -> String {
    let mut hasher = Sha256::new();
    hash_guard_text(
        &mut hasher,
        &serde_json::to_string(&report.source_revision_ref).unwrap_or_default(),
    );
    hash_guard_text(&mut hasher, &report.source_sha256);
    hasher.update(report.source_size.to_le_bytes());
    hash_guard_text(&mut hasher, &format!("{:?}", report.config_version));
    hash_guard_text(&mut hasher, &report.platform);
    hash_guard_text(&mut hasher, &report.storage);
    hash_guard_text(&mut hasher, &format!("{:?}", report.assessment));
    hash_guard_text(&mut hasher, &format!("{:?}", report.trust));
    hash_guard_text(&mut hasher, &format!("{:?}", report.proof_level));
    hash_guard_text(&mut hasher, &format!("{:?}", report.bundle_provider_alias));
    for entry in &report.bundle_entries {
        hash_guard_text(&mut hasher, &entry.path);
        hasher.update(entry.byte_size.to_le_bytes());
        hash_guard_text(&mut hasher, &entry.sha256);
    }
    hash_guard_text(&mut hasher, &format!("{:?}", report.partitions));
    hash_guard_text(&mut hasher, &format!("{:?}", report.evidence));
    hash_guard_text(&mut hasher, &format!("{:?}", report.evidence_correlation));
    hash_guard_text(&mut hasher, &format!("{:?}", report.warnings));
    hash_guard_text(&mut hasher, &format!("{:?}", report.limitations));
    format!("{:x}", hasher.finalize())
}

fn seal_report(mut report: MediatekReport) -> MediatekReport {
    report.projection_sha256 = report_projection_digest(&report);
    report
}

fn validate_report_integrity(report: &MediatekReport) -> Result<(), C05Error> {
    if report.projection_sha256.is_empty()
        || report.projection_sha256 != report_projection_digest(report)
    {
        return Err(C05Error::ReportIntegrityMismatch);
    }
    Ok(())
}

fn hash_guard_text(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn view_spec(context: &MediatekContext, view_kind: &str, suffix: &str) -> ViewSpec {
    ViewSpec {
        workspace_ref: context.workspace_ref.clone(),
        authority_ref: context.authority_ref.clone(),
        view_kind: view_kind.to_owned(),
        view_schema_id: format!("urn:ptah:schema:c05:{suffix}:0.1.0"),
        view_schema_version: "0.1.0".to_owned(),
        source_revision_refs: vec![context.source_revision_ref.clone()],
        origin_class: OriginClass::DecodedResource,
        production: context.production.clone(),
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
