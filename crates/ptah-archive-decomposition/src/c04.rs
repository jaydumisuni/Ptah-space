use ptah_identifiers::EntityRef;
use ptah_object_store::{
    OriginClass, ProductionEvidence, RegisterObjectSpec, Registration, RelationshipSpec,
    RevisionRole, ViewSpec,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

const ZIP_LOCAL_MAGIC: &[u8; 4] = b"PK\x03\x04";
const ZIP_EMPTY_MAGIC: &[u8; 4] = b"PK\x05\x06";
const ZIP_SPANNED_MAGIC: &[u8; 4] = b"PK\x07\x08";
const DER_SEQUENCE: u8 = 0x30;
const DER_IA5_STRING: u8 = 0x16;
const DER_OCTET_STRING: u8 = 0x04;
const DER_CONTEXT_0: u8 = 0xa0;
const DER_CONTEXT_1: u8 = 0xa1;

/// Bounded resource limits for one C04 inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppleFirmwareLimits {
    /// Maximum immutable source bytes accepted by one inspection.
    pub max_source_bytes: u64,
    /// Maximum archive entries retained from an untrusted Provider.
    pub max_archive_entries: usize,
    /// Maximum total recovered archive bytes retained in one report.
    pub max_recovered_bytes: u64,
    /// Maximum manifest components returned by a manifest Provider.
    pub max_manifest_components: usize,
    /// Maximum bytes retained for one string or path.
    pub max_string_bytes: usize,
    /// Maximum DER nesting depth followed by C04.
    pub max_der_depth: usize,
    /// Maximum DER elements parsed by C04.
    pub max_der_elements: usize,
    /// Maximum exact child bytes materialized by one request.
    pub max_materialized_bytes: u64,
}

impl Default for AppleFirmwareLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 16 * 1024 * 1024 * 1024,
            max_archive_entries: 131_072,
            max_recovered_bytes: 8 * 1024 * 1024 * 1024,
            max_manifest_components: 65_536,
            max_string_bytes: 8192,
            max_der_depth: 32,
            max_der_elements: 131_072,
            max_materialized_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// Exact immutable source and A04 production context.
#[derive(Debug, Clone)]
pub struct AppleFirmwareContext {
    /// Workspace owning source and derived plans.
    pub workspace_ref: EntityRef,
    /// Authority for canonical plans.
    pub authority_ref: EntityRef,
    /// Exact immutable source Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact producing evidence.
    pub production: ProductionEvidence,
}

/// Caller-declared role for ZIP-framed Apple firmware archives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppleArchiveRole {
    /// Apple IPSW restore/update bundle.
    Ipsw,
    /// Apple OTA update bundle.
    Ota,
}

/// C04 artifact family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppleFirmwareArtifactKind {
    /// ZIP-framed IPSW archive.
    IpswArchive,
    /// ZIP-framed Apple OTA archive.
    OtaArchive,
    /// IMG4 container.
    Img4,
    /// Standalone IM4P payload object.
    Im4p,
    /// Standalone IM4M manifest/signing object.
    Im4m,
    /// Standalone IM4R restore object.
    Im4r,
}

/// Caller declarations needed only where source framing is ambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AppleInspectRequest {
    /// Required for ZIP framing because ZIP magic does not distinguish IPSW from OTA.
    pub archive_role: Option<AppleArchiveRole>,
}

/// Truth status of one C04 report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleAssessment {
    /// All C04-supported semantics supplied for this artifact were validated.
    Complete,
    /// Exact supported semantics exist but explicit limitations remain.
    Partial,
    /// A trustworthy C04 projection could not be established.
    Inconclusive,
}

/// Signing/restore trust remains separate from structural parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleTrustAssessment {
    /// C04 has not established Apple signing, personalization, restore or boot trust.
    NotEstablished,
}

/// Mechanically earned C04 proof level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppleStaticProofLevel {
    /// Exact source identity and a bounded inventory exist.
    InventoryOnly,
    /// Required framing, bounds, paths and retained digests were validated.
    StructureChecked,
    /// Validated manifest references resolve to exact retained archive entries.
    ManifestLinked,
    /// Compared retained component identities and digests are exact.
    ComponentExact,
    /// Compared immutable source bytes are digest-identical.
    ByteExact,
}

/// One exact recovered archive entry observation from an untrusted Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleArchiveEntryObservation {
    /// Provider-recovered archive path.
    pub path: String,
    /// Exact recovered bytes.
    pub recovered_bytes: Vec<u8>,
    /// Provider-declared lowercase `SHA-256` for those bytes.
    pub expected_sha256: String,
}

/// Bounded archive inventory returned by a replaceable Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleArchiveObservation {
    /// Exact recovered entries.
    pub entries: Vec<AppleArchiveEntryObservation>,
    /// Provider claim that all C04-supported archive semantics were enumerated.
    pub complete_claim: bool,
    /// Explicit unsupported or partial semantics.
    pub limitations: Vec<String>,
}

/// Replaceable ZIP archive boundary.
pub trait AppleArchiveProvider: Send + Sync {
    /// Stable backend-local Provider alias/evidence identifier.
    fn provider_id(&self) -> &str;

    /// Recover exact archive entries from immutable source bytes.
    ///
    /// # Errors
    /// Returns a Provider-specific mechanical failure.
    fn inspect_archive(
        &self,
        source: &[u8],
        role: AppleArchiveRole,
        limits: AppleFirmwareLimits,
    ) -> Result<AppleArchiveObservation, String>;
}

/// One manifest component-path observation from an untrusted Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleManifestComponentObservation {
    /// Component name from the manifest semantics.
    pub name: String,
    /// Archive path referenced by that component.
    pub path: String,
}

/// Bounded BuildManifest/restore-manifest semantics returned by a Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleManifestObservation {
    /// Optional build identity string.
    pub build_id: Option<String>,
    /// Optional product-version string.
    pub product_version: Option<String>,
    /// Component path references.
    pub components: Vec<AppleManifestComponentObservation>,
    /// Provider claim that all C04-supported manifest semantics were decoded.
    pub complete_claim: bool,
    /// Explicit unsupported or partial semantics.
    pub limitations: Vec<String>,
}

/// Replaceable plist/manifest semantic boundary.
pub trait AppleManifestProvider: Send + Sync {
    /// Stable backend-local Provider alias/evidence identifier.
    fn provider_id(&self) -> &str;

    /// Decode exact recovered manifest bytes.
    ///
    /// # Errors
    /// Returns a Provider-specific mechanical failure.
    fn inspect_manifest(
        &self,
        manifest_bytes: &[u8],
        role: AppleArchiveRole,
        limits: AppleFirmwareLimits,
    ) -> Result<AppleManifestObservation, String>;
}

/// Validated exact archive entry retained by Core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleArchiveEntry {
    /// Canonical relative forward-slash path.
    pub path: String,
    /// Exact recovered byte size.
    pub byte_size: u64,
    /// Exact recovered lowercase `SHA-256`.
    pub sha256: String,
    /// Whether the path is a C04 manifest candidate.
    pub manifest_candidate: bool,
    recovered_bytes: Vec<u8>,
}

impl AppleArchiveEntry {
    /// Read-only exact recovered bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.recovered_bytes
    }
}

/// One validated manifest component resolved to an exact archive entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleManifestComponent {
    /// Manifest component name.
    pub name: String,
    /// Canonical referenced archive path.
    pub path: String,
    /// Exact recovered entry digest.
    pub entry_sha256: String,
    /// Exact recovered entry byte size.
    pub byte_size: u64,
}

/// Validated manifest projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleManifest {
    /// Exact manifest archive path.
    pub manifest_path: String,
    /// Exact recovered manifest digest.
    pub manifest_sha256: String,
    /// Backend-local manifest Provider alias/evidence.
    pub provider_alias: String,
    /// Optional build identity.
    pub build_id: Option<String>,
    /// Optional product version.
    pub product_version: Option<String>,
    /// Exact resolved component references.
    pub components: Vec<AppleManifestComponent>,
    /// Canonical component paths that did not resolve.
    pub unresolved_paths: Vec<String>,
    /// Explicit unsupported or partial semantics.
    pub limitations: Vec<String>,
    /// Whether the Provider claimed complete supported semantics.
    pub complete_claim: bool,
}

/// Exact source-backed DER component class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppleDerComponentKind {
    /// Exact encoded IM4P child object.
    Im4pObject,
    /// Exact encoded IM4M child object.
    Im4mObject,
    /// Exact encoded IM4R child object.
    Im4rObject,
    /// Exact IM4P payload octet-string content.
    Im4pPayload,
    /// Exact IM4M signing/certificate material octet-string content.
    SigningMaterial,
    /// Exact IM4R payload octet-string content.
    Im4rPayload,
}

/// One exact immutable source byte range in an `IMG4`-family object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleDerComponent {
    /// Stable component class.
    pub kind: AppleDerComponentKind,
    /// Deterministic component name.
    pub name: String,
    /// Inclusive source byte start.
    pub byte_start: u64,
    /// Exclusive source byte end.
    pub byte_end_exclusive: u64,
    /// Exact lowercase `SHA-256` of the source range.
    pub sha256: String,
}

/// Source-bound C04 report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleFirmwareReport {
    /// Exact source Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact immutable whole-source `SHA-256`.
    pub source_sha256: String,
    /// Exact immutable source byte size.
    pub source_size: u64,
    /// Artifact family.
    pub kind: AppleFirmwareArtifactKind,
    /// Structural/semantic truth status.
    pub assessment: AppleAssessment,
    /// Signing/restore trust state.
    pub trust: AppleTrustAssessment,
    /// Mechanically earned static proof level, absent when no bounded inventory exists.
    pub proof_level: Option<AppleStaticProofLevel>,
    /// Backend-local archive Provider alias when one was used.
    pub archive_provider_alias: Option<String>,
    /// Validated exact recovered archive entries.
    pub archive_entries: Vec<AppleArchiveEntry>,
    /// Validated BuildManifest/restore-manifest projection when available.
    pub manifest: Option<AppleManifest>,
    /// Exact source-backed `IMG4`-family components.
    pub der_components: Vec<AppleDerComponent>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
    /// Explicit unsupported, ambiguous or incomplete boundaries.
    pub limitations: Vec<String>,
    projection_sha256: String,
}

impl AppleFirmwareReport {
    /// Produce exact source-bound A07 Views.
    ///
    /// # Errors
    /// Rejects mutated reports or mismatched source context.
    pub fn view_specs(
        &self,
        context: &AppleFirmwareContext,
    ) -> Result<Vec<ViewSpec>, C04Error> {
        validate_context(context)?;
        validate_report_integrity(self)?;
        if self.source_revision_ref != context.source_revision_ref {
            return Err(C04Error::SourceBindingMismatch);
        }
        Ok(vec![
            view_spec(context, "apple.firmware.inventory", "inventory"),
            view_spec(context, "apple.firmware.manifest", "manifest"),
            view_spec(context, "apple.firmware.proof_levels", "proof-levels"),
        ])
    }
}

/// Exact recovered archive or DER child bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleMaterialization {
    /// Deterministic child name/path.
    pub name: String,
    /// A07 object class used for registration.
    pub object_class: String,
    /// Exact parent source Revision.
    pub source_revision_ref: EntityRef,
    /// Exact recovered `SHA-256`.
    pub sha256: String,
    bytes: Vec<u8>,
}

impl AppleMaterialization {
    /// Read-only exact child bytes.
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
        context: &AppleFirmwareContext,
    ) -> Result<RegisterObjectSpec, C04Error> {
        validate_context(context)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C04Error::SourceBindingMismatch);
        }
        Ok(RegisterObjectSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            object_class: self.object_class.clone(),
            declared_name: Some(self.name.clone()),
            source_refs: vec![self.source_revision_ref.clone()],
            revision_role: RevisionRole::Recovered,
            origin_class: OriginClass::RecoveredEmbeddedSource,
            created_reason: "C04 recovered exact Apple firmware child bytes".to_owned(),
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
        context: &AppleFirmwareContext,
        registration: &Registration,
    ) -> Result<RelationshipSpec, C04Error> {
        validate_context(context)?;
        if context.source_revision_ref != self.source_revision_ref {
            return Err(C04Error::SourceBindingMismatch);
        }
        if registration.object_ref.entity_kind.as_str() != "object.object"
            || registration.revision_ref.entity_kind.as_str() != "object.revision"
        {
            return Err(C04Error::InvalidRegistration);
        }
        let byte_size =
            u64::try_from(self.bytes.len()).map_err(|_| C04Error::AccountingOverflow)?;
        if registration.sha256 != self.sha256 || registration.byte_size != byte_size {
            return Err(C04Error::RegistrationMismatch);
        }
        Ok(RelationshipSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            subject_refs: vec![self.source_revision_ref.clone()],
            relationship_type: "contains.apple_firmware_child".to_owned(),
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
pub enum AppleComparisonLevel {
    /// Structural projections differ.
    Different,
    /// Structure matches but retained component digests differ.
    Structural,
    /// Retained component identities and digests match while whole source differs.
    ComponentExact,
    /// Whole immutable source digest and size match.
    ByteExact,
}

/// Source-bound C04 comparison report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleComparison {
    /// Left source Revision.
    pub left_source_revision_ref: EntityRef,
    /// Right source Revision.
    pub right_source_revision_ref: EntityRef,
    /// Strongest mechanically established comparison level.
    pub level: AppleComparisonLevel,
    /// Deterministic differences.
    pub differences: Vec<String>,
}

/// C04 failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum C04Error {
    /// Workspace reference is not canonical.
    #[error("C04 workspace reference must be core.workspace")]
    InvalidWorkspaceRef,
    /// Source must bind an exact Object Revision.
    #[error("C04 source must be an exact object.revision reference")]
    InvalidSourceRevision,
    /// One configured resource limit is zero.
    #[error("C04 limits must all be greater than zero")]
    InvalidLimits,
    /// Source exceeds configured bytes.
    #[error("C04 source exceeds max_source_bytes")]
    SourceTooLarge,
    /// Source framing is not a C04 family.
    #[error("C04 Apple firmware framing is unsupported")]
    UnsupportedArtifact,
    /// ZIP framing requires explicit IPSW versus OTA role.
    #[error("C04 ZIP source requires explicit IPSW or OTA role")]
    ArchiveRoleRequired,
    /// Archive Provider failed.
    #[error("C04 archive Provider failed: {0}")]
    ArchiveProvider(String),
    /// Manifest Provider failed.
    #[error("C04 manifest Provider failed: {0}")]
    ManifestProvider(String),
    /// Archive entry count exceeds configured bounds.
    #[error("C04 archive entry count exceeds configured limit")]
    TooManyEntries,
    /// Total recovered archive bytes exceed configured bounds.
    #[error("C04 recovered archive bytes exceed configured limit")]
    TooManyRecoveredBytes,
    /// Manifest component count exceeds configured bounds.
    #[error("C04 manifest component count exceeds configured limit")]
    TooManyManifestComponents,
    /// String or path exceeds configured bounds or violates grammar.
    #[error("C04 invalid bounded string/path")]
    InvalidString,
    /// Archive path is unsafe or non-canonical.
    #[error("C04 archive path is unsafe or non-canonical")]
    InvalidArchivePath,
    /// Duplicate canonical archive path.
    #[error("C04 duplicate canonical archive path")]
    DuplicateArchivePath,
    /// Provider-declared digest is malformed or mismatched.
    #[error("C04 recovered entry digest mismatch")]
    DigestMismatch,
    /// Provider manifest observation is structurally inconsistent.
    #[error("C04 invalid manifest Provider observation")]
    InvalidManifestObservation,
    /// DER framing is malformed, non-minimal or out of bounds.
    #[error("C04 malformed DER/IMG4 framing: {0}")]
    MalformedDer(&'static str),
    /// DER depth exceeds configured bounds.
    #[error("C04 DER depth exceeds configured limit")]
    DerDepthExceeded,
    /// DER element count exceeds configured bounds.
    #[error("C04 DER element count exceeds configured limit")]
    DerElementsExceeded,
    /// Numeric accounting overflowed.
    #[error("C04 byte accounting overflow")]
    AccountingOverflow,
    /// Report/source/context binding mismatch.
    #[error("C04 exact source binding mismatch")]
    SourceBindingMismatch,
    /// Report was mutated after inspection.
    #[error("C04 report integrity seal mismatch")]
    ReportIntegrityMismatch,
    /// Requested exact child does not exist.
    #[error("C04 requested Apple firmware child was not found")]
    ChildNotFound,
    /// Materialization exceeds configured bounds.
    #[error("C04 materialization exceeds configured limit")]
    MaterializationTooLarge,
    /// Registered A07 endpoints have invalid kinds.
    #[error("C04 child registration has invalid canonical endpoint kinds")]
    InvalidRegistration,
    /// Registration bytes do not match exact recovered child.
    #[error("C04 child registration does not match exact bytes")]
    RegistrationMismatch,
}

/// Inspect one immutable Apple firmware archive or `IMG4`-family object.
///
/// # Errors
/// Fails closed for malformed framing, Provider output, bounds, paths, digests or DER violations.
pub fn inspect_apple_firmware(
    source: &[u8],
    context: &AppleFirmwareContext,
    request: AppleInspectRequest,
    limits: AppleFirmwareLimits,
    archive_provider: Option<&dyn AppleArchiveProvider>,
    manifest_provider: Option<&dyn AppleManifestProvider>,
) -> Result<AppleFirmwareReport, C04Error> {
    validate_context(context)?;
    validate_limits(limits)?;
    let source_size = u64::try_from(source.len()).map_err(|_| C04Error::AccountingOverflow)?;
    if source_size > limits.max_source_bytes {
        return Err(C04Error::SourceTooLarge);
    }
    let source_sha256 = sha256_bytes(source);
    if looks_like_zip(source) {
        let role = request.archive_role.ok_or(C04Error::ArchiveRoleRequired)?;
        return inspect_archive(
            source,
            context,
            role,
            source_sha256,
            limits,
            archive_provider,
            manifest_provider,
        );
    }
    inspect_der(source, context, source_sha256, limits)
}

/// Materialize one exact recovered archive entry.
///
/// # Errors
/// Rejects mutated/stale reports, missing entries and configured bounds.
pub fn materialize_apple_archive_entry(
    source: &[u8],
    report: &AppleFirmwareReport,
    path: &str,
    context: &AppleFirmwareContext,
    limits: AppleFirmwareLimits,
) -> Result<AppleMaterialization, C04Error> {
    validate_materialization_source(source, report, context, limits)?;
    if !matches!(
        report.kind,
        AppleFirmwareArtifactKind::IpswArchive | AppleFirmwareArtifactKind::OtaArchive
    ) {
        return Err(C04Error::ChildNotFound);
    }
    let entry = report
        .archive_entries
        .iter()
        .find(|entry| entry.path == path)
        .ok_or(C04Error::ChildNotFound)?;
    ensure_materialization_size(entry.byte_size, limits)?;
    if sha256_bytes(&entry.recovered_bytes) != entry.sha256 {
        return Err(C04Error::ReportIntegrityMismatch);
    }
    Ok(AppleMaterialization {
        name: entry.path.clone(),
        object_class: "apple.firmware.archive_entry".to_owned(),
        source_revision_ref: report.source_revision_ref.clone(),
        sha256: entry.sha256.clone(),
        bytes: entry.recovered_bytes.clone(),
    })
}

/// Materialize one exact source-backed `IMG4`-family component.
///
/// # Errors
/// Rejects mutated/stale reports, missing components and configured bounds.
pub fn materialize_apple_der_component(
    source: &[u8],
    report: &AppleFirmwareReport,
    component_name: &str,
    context: &AppleFirmwareContext,
    limits: AppleFirmwareLimits,
) -> Result<AppleMaterialization, C04Error> {
    validate_materialization_source(source, report, context, limits)?;
    let component = report
        .der_components
        .iter()
        .find(|component| component.name == component_name)
        .ok_or(C04Error::ChildNotFound)?;
    let length = component
        .byte_end_exclusive
        .checked_sub(component.byte_start)
        .ok_or(C04Error::AccountingOverflow)?;
    ensure_materialization_size(length, limits)?;
    let start = usize::try_from(component.byte_start).map_err(|_| C04Error::AccountingOverflow)?;
    let end = usize::try_from(component.byte_end_exclusive)
        .map_err(|_| C04Error::AccountingOverflow)?;
    let bytes = source
        .get(start..end)
        .ok_or(C04Error::SourceBindingMismatch)?
        .to_vec();
    if sha256_bytes(&bytes) != component.sha256 {
        return Err(C04Error::SourceBindingMismatch);
    }
    Ok(AppleMaterialization {
        name: component.name.clone(),
        object_class: "apple.firmware.der_component".to_owned(),
        source_revision_ref: report.source_revision_ref.clone(),
        sha256: component.sha256.clone(),
        bytes,
    })
}

/// Compare two sealed C04 reports without making signing, restore or boot claims.
#[must_use]
pub fn compare_apple_firmware(
    left: &AppleFirmwareReport,
    right: &AppleFirmwareReport,
) -> AppleComparison {
    let mut differences = Vec::new();
    let left_shape = report_shape(left);
    let right_shape = report_shape(right);
    if left.kind != right.kind {
        differences.push(format!("kind:{:?}->{:?}", left.kind, right.kind));
    }
    if left_shape != right_shape {
        differences.push("component_structure_changed".to_owned());
    }
    let component_exact = report_component_identity(left) == report_component_identity(right);
    if left_shape == right_shape && !component_exact {
        differences.push("component_bytes_changed".to_owned());
    }
    let level = if left.source_sha256 == right.source_sha256 && left.source_size == right.source_size {
        AppleComparisonLevel::ByteExact
    } else if left.kind == right.kind && left_shape == right_shape && component_exact {
        AppleComparisonLevel::ComponentExact
    } else if left.kind == right.kind && left_shape == right_shape {
        AppleComparisonLevel::Structural
    } else {
        AppleComparisonLevel::Different
    };
    AppleComparison {
        left_source_revision_ref: left.source_revision_ref.clone(),
        right_source_revision_ref: right.source_revision_ref.clone(),
        level,
        differences,
    }
}

/// Convert comparison evidence into an explicit C04 rebuild proof level.
#[must_use]
pub fn assess_apple_rebuild(
    original: &AppleFirmwareReport,
    rebuilt: &AppleFirmwareReport,
) -> Option<AppleStaticProofLevel> {
    match compare_apple_firmware(original, rebuilt).level {
        AppleComparisonLevel::Different => None,
        AppleComparisonLevel::Structural => Some(AppleStaticProofLevel::StructureChecked),
        AppleComparisonLevel::ComponentExact => Some(AppleStaticProofLevel::ComponentExact),
        AppleComparisonLevel::ByteExact => Some(AppleStaticProofLevel::ByteExact),
    }
}

fn inspect_archive(
    source: &[u8],
    context: &AppleFirmwareContext,
    role: AppleArchiveRole,
    source_sha256: String,
    limits: AppleFirmwareLimits,
    archive_provider: Option<&dyn AppleArchiveProvider>,
    manifest_provider: Option<&dyn AppleManifestProvider>,
) -> Result<AppleFirmwareReport, C04Error> {
    let kind = match role {
        AppleArchiveRole::Ipsw => AppleFirmwareArtifactKind::IpswArchive,
        AppleArchiveRole::Ota => AppleFirmwareArtifactKind::OtaArchive,
    };
    let Some(provider) = archive_provider else {
        return Ok(seal_report(AppleFirmwareReport {
            source_revision_ref: context.source_revision_ref.clone(),
            source_sha256,
            source_size: u64::try_from(source.len()).map_err(|_| C04Error::AccountingOverflow)?,
            kind,
            assessment: AppleAssessment::Inconclusive,
            trust: AppleTrustAssessment::NotEstablished,
            proof_level: None,
            archive_provider_alias: None,
            archive_entries: Vec::new(),
            manifest: None,
            der_components: Vec::new(),
            warnings: Vec::new(),
            limitations: vec!["archive Provider not supplied; ZIP framing alone is not inventory".to_owned()],
            projection_sha256: String::new(),
        }));
    };
    validate_string(provider.provider_id(), limits)?;
    let observation = provider
        .inspect_archive(source, role, limits)
        .map_err(C04Error::ArchiveProvider)?;
    build_archive_report(
        context,
        kind,
        source,
        source_sha256,
        limits,
        provider.provider_id(),
        observation,
        manifest_provider,
        role,
    )
}

struct ArchiveReportInput<'a> {
    context: &'a AppleFirmwareContext,
    kind: AppleFirmwareArtifactKind,
    source: &'a [u8],
    source_sha256: String,
    limits: AppleFirmwareLimits,
    provider_id: &'a str,
    observation: AppleArchiveObservation,
    manifest_provider: Option<&'a dyn AppleManifestProvider>,
    role: AppleArchiveRole,
}

fn build_archive_report(
    context: &AppleFirmwareContext,
    kind: AppleFirmwareArtifactKind,
    source: &[u8],
    source_sha256: String,
    limits: AppleFirmwareLimits,
    provider_id: &str,
    observation: AppleArchiveObservation,
    manifest_provider: Option<&dyn AppleManifestProvider>,
    role: AppleArchiveRole,
) -> Result<AppleFirmwareReport, C04Error> {
    let input = ArchiveReportInput {
        context,
        kind,
        source,
        source_sha256,
        limits,
        provider_id,
        observation,
        manifest_provider,
        role,
    };
    build_archive_report_inner(input)
}

fn build_archive_report_inner(input: ArchiveReportInput<'_>) -> Result<AppleFirmwareReport, C04Error> {
    let (entries, archive_complete, mut limitations) = validate_archive_observation(
        input.observation,
        input.provider_id,
        input.limits,
    )?;
    let manifest = inspect_manifest_if_available(
        &entries,
        input.role,
        input.limits,
        input.manifest_provider,
        &mut limitations,
    )?;
    let manifest_linked = manifest.as_ref().is_some_and(|manifest| {
        manifest.complete_claim
            && manifest.unresolved_paths.is_empty()
            && manifest.limitations.is_empty()
    });
    let proof_level = if manifest_linked {
        Some(AppleStaticProofLevel::ManifestLinked)
    } else if archive_complete {
        Some(AppleStaticProofLevel::StructureChecked)
    } else {
        Some(AppleStaticProofLevel::InventoryOnly)
    };
    let assessment = if archive_complete && manifest_linked && limitations.is_empty() {
        AppleAssessment::Complete
    } else {
        AppleAssessment::Partial
    };
    Ok(seal_report(AppleFirmwareReport {
        source_revision_ref: input.context.source_revision_ref.clone(),
        source_sha256: input.source_sha256,
        source_size: u64::try_from(input.source.len()).map_err(|_| C04Error::AccountingOverflow)?,
        kind: input.kind,
        assessment,
        trust: AppleTrustAssessment::NotEstablished,
        proof_level,
        archive_provider_alias: Some(input.provider_id.to_owned()),
        archive_entries: entries,
        manifest,
        der_components: Vec::new(),
        warnings: Vec::new(),
        limitations,
        projection_sha256: String::new(),
    }))
}

fn validate_archive_observation(
    observation: AppleArchiveObservation,
    provider_id: &str,
    limits: AppleFirmwareLimits,
) -> Result<(Vec<AppleArchiveEntry>, bool, Vec<String>), C04Error> {
    validate_string(provider_id, limits)?;
    validate_limitations(&observation.limitations, limits)?;
    if observation.entries.len() > limits.max_archive_entries {
        return Err(C04Error::TooManyEntries);
    }
    let mut seen = BTreeSet::new();
    let mut total_bytes = 0_u64;
    let mut entries = Vec::with_capacity(observation.entries.len());
    for entry in observation.entries {
        validate_archive_path(&entry.path, limits)?;
        if !seen.insert(entry.path.clone()) {
            return Err(C04Error::DuplicateArchivePath);
        }
        validate_sha256(&entry.expected_sha256)?;
        let computed = sha256_bytes(&entry.recovered_bytes);
        if computed != entry.expected_sha256 {
            return Err(C04Error::DigestMismatch);
        }
        let byte_size =
            u64::try_from(entry.recovered_bytes.len()).map_err(|_| C04Error::AccountingOverflow)?;
        total_bytes = total_bytes
            .checked_add(byte_size)
            .ok_or(C04Error::AccountingOverflow)?;
        if total_bytes > limits.max_recovered_bytes {
            return Err(C04Error::TooManyRecoveredBytes);
        }
        entries.push(AppleArchiveEntry {
            manifest_candidate: is_manifest_candidate(&entry.path),
            path: entry.path,
            byte_size,
            sha256: computed,
            recovered_bytes: entry.recovered_bytes,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let mut limitations = observation.limitations;
    if !observation.complete_claim {
        limitations.push("archive Provider did not claim complete supported inventory".to_owned());
    }
    Ok((entries, observation.complete_claim, limitations))
}

fn inspect_manifest_if_available(
    entries: &[AppleArchiveEntry],
    role: AppleArchiveRole,
    limits: AppleFirmwareLimits,
    provider: Option<&dyn AppleManifestProvider>,
    limitations: &mut Vec<String>,
) -> Result<Option<AppleManifest>, C04Error> {
    let candidate = entries.iter().find(|entry| entry.manifest_candidate);
    let Some(provider) = provider else {
        limitations.push("manifest Provider not supplied; archive inventory is not manifest linkage".to_owned());
        return Ok(None);
    };
    validate_string(provider.provider_id(), limits)?;
    let Some(candidate) = candidate else {
        limitations.push("no BuildManifest/restore-manifest candidate was retained".to_owned());
        return Ok(None);
    };
    let observation = provider
        .inspect_manifest(&candidate.recovered_bytes, role, limits)
        .map_err(C04Error::ManifestProvider)?;
    let manifest = validate_manifest_observation(
        provider.provider_id(),
        candidate,
        entries,
        observation,
        limits,
    )?;
    limitations.extend(manifest.limitations.iter().cloned());
    if !manifest.unresolved_paths.is_empty() {
        limitations.push("one or more manifest component paths did not resolve exactly".to_owned());
    }
    Ok(Some(manifest))
}

fn validate_manifest_observation(
    provider_id: &str,
    manifest_entry: &AppleArchiveEntry,
    entries: &[AppleArchiveEntry],
    observation: AppleManifestObservation,
    limits: AppleFirmwareLimits,
) -> Result<AppleManifest, C04Error> {
    validate_string(provider_id, limits)?;
    validate_optional_string(observation.build_id.as_deref(), limits)?;
    validate_optional_string(observation.product_version.as_deref(), limits)?;
    validate_limitations(&observation.limitations, limits)?;
    if observation.components.len() > limits.max_manifest_components {
        return Err(C04Error::TooManyManifestComponents);
    }
    let mut names = BTreeSet::new();
    let mut components = Vec::new();
    let mut unresolved_paths = Vec::new();
    for component in observation.components {
        validate_string(&component.name, limits)?;
        validate_archive_path(&component.path, limits)?;
        if !names.insert(component.name.clone()) {
            return Err(C04Error::InvalidManifestObservation);
        }
        if let Some(entry) = entries.iter().find(|entry| entry.path == component.path) {
            components.push(AppleManifestComponent {
                name: component.name,
                path: component.path,
                entry_sha256: entry.sha256.clone(),
                byte_size: entry.byte_size,
            });
        } else {
            unresolved_paths.push(component.path);
        }
    }
    components.sort_by(|left, right| left.name.cmp(&right.name));
    unresolved_paths.sort();
    let mut provider_limitations = observation.limitations;
    if !observation.complete_claim {
        provider_limitations.push(
            "manifest Provider did not claim complete supported semantics".to_owned(),
        );
    }
    Ok(AppleManifest {
        manifest_path: manifest_entry.path.clone(),
        manifest_sha256: manifest_entry.sha256.clone(),
        provider_alias: provider_id.to_owned(),
        build_id: observation.build_id,
        product_version: observation.product_version,
        components,
        unresolved_paths,
        limitations: provider_limitations,
        complete_claim: observation.complete_claim,
    })
}

fn inspect_der(
    source: &[u8],
    context: &AppleFirmwareContext,
    source_sha256: String,
    limits: AppleFirmwareLimits,
) -> Result<AppleFirmwareReport, C04Error> {
    if source.first().copied() != Some(DER_SEQUENCE) {
        return Err(C04Error::UnsupportedArtifact);
    }
    let mut budget = DerBudget::default();
    let (outer, children) = parse_constructed(source, 0, DER_SEQUENCE, 0, &mut budget, limits)?;
    if outer.end != source.len() {
        return Err(C04Error::MalformedDer("trailing bytes after top-level sequence"));
    }
    let marker = marker_from_children(source, &children, limits)?;
    let mut components = Vec::new();
    let kind = match marker.as_str() {
        "IMG4" => {
            inspect_img4_children(source, &children, &mut components, &mut budget, limits)?;
            AppleFirmwareArtifactKind::Img4
        }
        "IM4P" => {
            inspect_im4p_children(source, &children, "im4p", &mut components, limits)?;
            AppleFirmwareArtifactKind::Im4p
        }
        "IM4M" => {
            inspect_im4m_children(source, &children, "im4m", &mut components, limits)?;
            AppleFirmwareArtifactKind::Im4m
        }
        "IM4R" => {
            inspect_im4r_children(source, &children, "im4r", &mut components, limits)?;
            AppleFirmwareArtifactKind::Im4r
        }
        _ => return Err(C04Error::MalformedDer("unsupported IMG4-family marker")),
    };
    Ok(seal_report(AppleFirmwareReport {
        source_revision_ref: context.source_revision_ref.clone(),
        source_sha256,
        source_size: u64::try_from(source.len()).map_err(|_| C04Error::AccountingOverflow)?,
        kind,
        assessment: AppleAssessment::Complete,
        trust: AppleTrustAssessment::NotEstablished,
        proof_level: Some(AppleStaticProofLevel::StructureChecked),
        archive_provider_alias: None,
        archive_entries: Vec::new(),
        manifest: None,
        der_components: components,
        warnings: Vec::new(),
        limitations: Vec::new(),
        projection_sha256: String::new(),
    }))
}

fn inspect_img4_children(
    source: &[u8],
    children: &[DerTlv],
    components: &mut Vec<AppleDerComponent>,
    budget: &mut DerBudget,
    limits: AppleFirmwareLimits,
) -> Result<(), C04Error> {
    if children.len() < 2 || children[1].tag != DER_SEQUENCE {
        return Err(C04Error::MalformedDer("IMG4 does not contain IM4P sequence"));
    }
    let im4p = children[1];
    let (_, im4p_children) =
        parse_constructed(source, im4p.start, DER_SEQUENCE, 1, budget, limits)?;
    require_marker(source, &im4p_children, "IM4P", limits)?;
    push_der_component(
        source,
        components,
        AppleDerComponentKind::Im4pObject,
        "img4.im4p",
        im4p.start,
        im4p.end,
        limits,
    )?;
    inspect_im4p_children(source, &im4p_children, "img4.im4p", components, limits)?;
    let mut seen_context = BTreeSet::new();
    for wrapper in &children[2..] {
        if !matches!(wrapper.tag, DER_CONTEXT_0 | DER_CONTEXT_1)
            || !seen_context.insert(wrapper.tag)
        {
            return Err(C04Error::MalformedDer("invalid or duplicate IMG4 context wrapper"));
        }
        inspect_img4_wrapper(source, *wrapper, components, budget, limits)?;
    }
    Ok(())
}

fn inspect_img4_wrapper(
    source: &[u8],
    wrapper: DerTlv,
    components: &mut Vec<AppleDerComponent>,
    budget: &mut DerBudget,
    limits: AppleFirmwareLimits,
) -> Result<(), C04Error> {
    let (_, wrapped) = parse_constructed(source, wrapper.start, wrapper.tag, 1, budget, limits)?;
    if wrapped.len() != 1 || wrapped[0].tag != DER_SEQUENCE {
        return Err(C04Error::MalformedDer("IMG4 context wrapper must contain one sequence"));
    }
    let child = wrapped[0];
    let (_, child_elements) =
        parse_constructed(source, child.start, DER_SEQUENCE, 2, budget, limits)?;
    match wrapper.tag {
        DER_CONTEXT_0 => {
            require_marker(source, &child_elements, "IM4M", limits)?;
            push_der_component(
                source,
                components,
                AppleDerComponentKind::Im4mObject,
                "img4.im4m",
                child.start,
                child.end,
                limits,
            )?;
            inspect_im4m_children(source, &child_elements, "img4.im4m", components, limits)
        }
        DER_CONTEXT_1 => {
            require_marker(source, &child_elements, "IM4R", limits)?;
            push_der_component(
                source,
                components,
                AppleDerComponentKind::Im4rObject,
                "img4.im4r",
                child.start,
                child.end,
                limits,
            )?;
            inspect_im4r_children(source, &child_elements, "img4.im4r", components, limits)
        }
        _ => Err(C04Error::MalformedDer("unsupported IMG4 context wrapper")),
    }
}

fn inspect_im4p_children(
    source: &[u8],
    children: &[DerTlv],
    prefix: &str,
    components: &mut Vec<AppleDerComponent>,
    limits: AppleFirmwareLimits,
) -> Result<(), C04Error> {
    require_marker(source, children, "IM4P", limits)?;
    if children.len() < 4
        || children[1].tag != DER_IA5_STRING
        || children[2].tag != DER_IA5_STRING
        || children[3].tag != DER_OCTET_STRING
    {
        return Err(C04Error::MalformedDer("IM4P required fields are missing"));
    }
    let component_type = der_text(source, children[1], limits)?;
    let description = der_text(source, children[2], limits)?;
    if component_type.is_empty() || description.is_empty() {
        return Err(C04Error::MalformedDer("IM4P type/description is empty"));
    }
    let payload = children[3];
    push_der_component(
        source,
        components,
        AppleDerComponentKind::Im4pPayload,
        &format!("{prefix}.payload"),
        payload.content_start,
        payload.end,
        limits,
    )
}

fn inspect_im4m_children(
    source: &[u8],
    children: &[DerTlv],
    prefix: &str,
    components: &mut Vec<AppleDerComponent>,
    limits: AppleFirmwareLimits,
) -> Result<(), C04Error> {
    require_marker(source, children, "IM4M", limits)?;
    let mut signing_index = 0_usize;
    for element in &children[1..] {
        if element.tag == DER_OCTET_STRING {
            push_der_component(
                source,
                components,
                AppleDerComponentKind::SigningMaterial,
                &format!("{prefix}.signing.{signing_index}"),
                element.content_start,
                element.end,
                limits,
            )?;
            signing_index = signing_index
                .checked_add(1)
                .ok_or(C04Error::AccountingOverflow)?;
        }
    }
    if signing_index == 0 {
        return Err(C04Error::MalformedDer("IM4M contains no signing material octets"));
    }
    Ok(())
}

fn inspect_im4r_children(
    source: &[u8],
    children: &[DerTlv],
    prefix: &str,
    components: &mut Vec<AppleDerComponent>,
    limits: AppleFirmwareLimits,
) -> Result<(), C04Error> {
    require_marker(source, children, "IM4R", limits)?;
    if let Some(payload) = children[1..]
        .iter()
        .find(|element| element.tag == DER_OCTET_STRING)
    {
        push_der_component(
            source,
            components,
            AppleDerComponentKind::Im4rPayload,
            &format!("{prefix}.payload"),
            payload.content_start,
            payload.end,
            limits,
        )?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DerTlv {
    tag: u8,
    start: usize,
    content_start: usize,
    end: usize,
}

#[derive(Debug, Default)]
struct DerBudget {
    elements: usize,
}

fn parse_constructed(
    source: &[u8],
    offset: usize,
    expected_tag: u8,
    depth: usize,
    budget: &mut DerBudget,
    limits: AppleFirmwareLimits,
) -> Result<(DerTlv, Vec<DerTlv>), C04Error> {
    let outer = parse_tlv(source, offset, depth, budget, limits)?;
    if outer.tag != expected_tag {
        return Err(C04Error::MalformedDer("unexpected constructed DER tag"));
    }
    let mut children = Vec::new();
    let mut cursor = outer.content_start;
    while cursor < outer.end {
        let child = parse_tlv(source, cursor, depth.saturating_add(1), budget, limits)?;
        if child.end > outer.end {
            return Err(C04Error::MalformedDer("child exceeds containing DER object"));
        }
        children.push(child);
        cursor = child.end;
    }
    if cursor != outer.end {
        return Err(C04Error::MalformedDer("constructed DER length mismatch"));
    }
    Ok((outer, children))
}

fn parse_tlv(
    source: &[u8],
    offset: usize,
    depth: usize,
    budget: &mut DerBudget,
    limits: AppleFirmwareLimits,
) -> Result<DerTlv, C04Error> {
    if depth > limits.max_der_depth {
        return Err(C04Error::DerDepthExceeded);
    }
    budget.elements = budget
        .elements
        .checked_add(1)
        .ok_or(C04Error::AccountingOverflow)?;
    if budget.elements > limits.max_der_elements {
        return Err(C04Error::DerElementsExceeded);
    }
    let tag = *source
        .get(offset)
        .ok_or(C04Error::MalformedDer("truncated DER tag"))?;
    if tag & 0x1f == 0x1f {
        return Err(C04Error::MalformedDer("high-tag-number form is outside C04"));
    }
    let length_offset = offset.checked_add(1).ok_or(C04Error::AccountingOverflow)?;
    let (length, length_bytes) = parse_der_length(source, length_offset)?;
    let content_start = length_offset
        .checked_add(length_bytes)
        .ok_or(C04Error::AccountingOverflow)?;
    let end = content_start
        .checked_add(length)
        .ok_or(C04Error::AccountingOverflow)?;
    if end > source.len() {
        return Err(C04Error::MalformedDer("DER value exceeds source bounds"));
    }
    Ok(DerTlv {
        tag,
        start: offset,
        content_start,
        end,
    })
}

fn parse_der_length(source: &[u8], offset: usize) -> Result<(usize, usize), C04Error> {
    let first = *source
        .get(offset)
        .ok_or(C04Error::MalformedDer("truncated DER length"))?;
    if first < 0x80 {
        return Ok((usize::from(first), 1));
    }
    if first == 0x80 {
        return Err(C04Error::MalformedDer("indefinite DER length is forbidden"));
    }
    let width = usize::from(first & 0x7f);
    if width == 0 || width > std::mem::size_of::<usize>() {
        return Err(C04Error::MalformedDer("unsupported DER length width"));
    }
    let start = offset.checked_add(1).ok_or(C04Error::AccountingOverflow)?;
    let end = start.checked_add(width).ok_or(C04Error::AccountingOverflow)?;
    let bytes = source
        .get(start..end)
        .ok_or(C04Error::MalformedDer("truncated long-form DER length"))?;
    if bytes.first().copied() == Some(0) {
        return Err(C04Error::MalformedDer("non-minimal DER length has leading zero"));
    }
    let mut value = 0_usize;
    for byte in bytes {
        value = value
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(C04Error::AccountingOverflow)?;
    }
    if value < 128 {
        return Err(C04Error::MalformedDer("non-minimal long-form DER length"));
    }
    Ok((value, width + 1))
}

fn marker_from_children(
    source: &[u8],
    children: &[DerTlv],
    limits: AppleFirmwareLimits,
) -> Result<String, C04Error> {
    let marker = children
        .first()
        .copied()
        .ok_or(C04Error::MalformedDer("DER sequence is empty"))?;
    if marker.tag != DER_IA5_STRING {
        return Err(C04Error::MalformedDer("IMG4-family marker is not IA5String"));
    }
    der_text(source, marker, limits)
}

fn require_marker(
    source: &[u8],
    children: &[DerTlv],
    expected: &str,
    limits: AppleFirmwareLimits,
) -> Result<(), C04Error> {
    if marker_from_children(source, children, limits)? != expected {
        return Err(C04Error::MalformedDer("IMG4-family marker mismatch"));
    }
    Ok(())
}

fn der_text(
    source: &[u8],
    tlv: DerTlv,
    limits: AppleFirmwareLimits,
) -> Result<String, C04Error> {
    if tlv.tag != DER_IA5_STRING {
        return Err(C04Error::MalformedDer("expected IA5String"));
    }
    let bytes = source
        .get(tlv.content_start..tlv.end)
        .ok_or(C04Error::MalformedDer("IA5String exceeds source"))?;
    if bytes.iter().any(|byte| !byte.is_ascii()) {
        return Err(C04Error::InvalidString);
    }
    let value = std::str::from_utf8(bytes).map_err(|_| C04Error::InvalidString)?;
    validate_string(value, limits)?;
    Ok(value.to_owned())
}

fn push_der_component(
    source: &[u8],
    components: &mut Vec<AppleDerComponent>,
    kind: AppleDerComponentKind,
    name: &str,
    start: usize,
    end: usize,
    limits: AppleFirmwareLimits,
) -> Result<(), C04Error> {
    validate_string(name, limits)?;
    let bytes = source
        .get(start..end)
        .ok_or(C04Error::MalformedDer("DER component exceeds source"))?;
    components.push(AppleDerComponent {
        kind,
        name: name.to_owned(),
        byte_start: u64::try_from(start).map_err(|_| C04Error::AccountingOverflow)?,
        byte_end_exclusive: u64::try_from(end).map_err(|_| C04Error::AccountingOverflow)?,
        sha256: sha256_bytes(bytes),
    });
    Ok(())
}

fn validate_materialization_source(
    source: &[u8],
    report: &AppleFirmwareReport,
    context: &AppleFirmwareContext,
    limits: AppleFirmwareLimits,
) -> Result<(), C04Error> {
    validate_context(context)?;
    validate_limits(limits)?;
    validate_report_integrity(report)?;
    if report.source_revision_ref != context.source_revision_ref
        || report.source_size
            != u64::try_from(source.len()).map_err(|_| C04Error::AccountingOverflow)?
        || report.source_sha256 != sha256_bytes(source)
    {
        return Err(C04Error::SourceBindingMismatch);
    }
    Ok(())
}

fn ensure_materialization_size(
    size: u64,
    limits: AppleFirmwareLimits,
) -> Result<(), C04Error> {
    if size > limits.max_materialized_bytes {
        return Err(C04Error::MaterializationTooLarge);
    }
    Ok(())
}

fn validate_context(context: &AppleFirmwareContext) -> Result<(), C04Error> {
    if context.workspace_ref.entity_kind.as_str() != "core.workspace" {
        return Err(C04Error::InvalidWorkspaceRef);
    }
    if context.source_revision_ref.entity_kind.as_str() != "object.revision" {
        return Err(C04Error::InvalidSourceRevision);
    }
    Ok(())
}

fn validate_limits(limits: AppleFirmwareLimits) -> Result<(), C04Error> {
    if limits.max_source_bytes == 0
        || limits.max_archive_entries == 0
        || limits.max_recovered_bytes == 0
        || limits.max_manifest_components == 0
        || limits.max_string_bytes == 0
        || limits.max_der_depth == 0
        || limits.max_der_elements == 0
        || limits.max_materialized_bytes == 0
    {
        return Err(C04Error::InvalidLimits);
    }
    Ok(())
}

fn validate_archive_path(path: &str, limits: AppleFirmwareLimits) -> Result<(), C04Error> {
    validate_string(path, limits)?;
    if path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains('\0')
        || path.ends_with('/')
        || has_windows_drive_prefix(path)
    {
        return Err(C04Error::InvalidArchivePath);
    }
    if path.split('/').any(|component| {
        component.is_empty() || component == "." || component == ".."
    }) {
        return Err(C04Error::InvalidArchivePath);
    }
    Ok(())
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn validate_optional_string(
    value: Option<&str>,
    limits: AppleFirmwareLimits,
) -> Result<(), C04Error> {
    if let Some(value) = value {
        validate_string(value, limits)?;
    }
    Ok(())
}

fn validate_string(value: &str, limits: AppleFirmwareLimits) -> Result<(), C04Error> {
    if value.is_empty() || value.len() > limits.max_string_bytes || value.contains('\0') {
        return Err(C04Error::InvalidString);
    }
    Ok(())
}

fn validate_limitations(
    values: &[String],
    limits: AppleFirmwareLimits,
) -> Result<(), C04Error> {
    for value in values {
        validate_string(value, limits)?;
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), C04Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(C04Error::DigestMismatch);
    }
    Ok(())
}

fn is_manifest_candidate(path: &str) -> bool {
    path == "BuildManifest.plist"
        || path.ends_with("/BuildManifest.plist")
        || path == "Restore.plist"
        || path.ends_with("/Restore.plist")
}

fn looks_like_zip(source: &[u8]) -> bool {
    source.starts_with(ZIP_LOCAL_MAGIC)
        || source.starts_with(ZIP_EMPTY_MAGIC)
        || source.starts_with(ZIP_SPANNED_MAGIC)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportShape {
    kind: AppleFirmwareArtifactKind,
    archive: Vec<(String, u64, bool)>,
    manifest: Option<(String, Vec<(String, String)>)>,
    der: Vec<(AppleDerComponentKind, String, u64, u64)>,
}

fn report_shape(report: &AppleFirmwareReport) -> ReportShape {
    ReportShape {
        kind: report.kind,
        archive: report
            .archive_entries
            .iter()
            .map(|entry| (entry.path.clone(), entry.byte_size, entry.manifest_candidate))
            .collect(),
        manifest: report.manifest.as_ref().map(|manifest| {
            (
                manifest.manifest_path.clone(),
                manifest
                    .components
                    .iter()
                    .map(|component| (component.name.clone(), component.path.clone()))
                    .collect(),
            )
        }),
        der: report
            .der_components
            .iter()
            .map(|component| {
                (
                    component.kind,
                    component.name.clone(),
                    component.byte_start,
                    component.byte_end_exclusive,
                )
            })
            .collect(),
    }
}

fn report_component_identity(report: &AppleFirmwareReport) -> Vec<String> {
    let mut identities = Vec::new();
    for entry in &report.archive_entries {
        identities.push(format!(
            "archive:{}:{}:{}",
            entry.path, entry.byte_size, entry.sha256
        ));
    }
    for component in &report.der_components {
        identities.push(format!(
            "der:{:?}:{}:{}:{}:{}",
            component.kind,
            component.name,
            component.byte_start,
            component.byte_end_exclusive,
            component.sha256
        ));
    }
    if let Some(manifest) = &report.manifest {
        identities.push(format!(
            "manifest:{}:{}",
            manifest.manifest_path, manifest.manifest_sha256
        ));
    }
    identities
}

fn report_projection_digest(report: &AppleFirmwareReport) -> String {
    let mut hasher = Sha256::new();
    hash_guard_text(
        &mut hasher,
        &serde_json::to_string(&report.source_revision_ref).unwrap_or_default(),
    );
    hash_guard_text(&mut hasher, &report.source_sha256);
    hasher.update(report.source_size.to_le_bytes());
    hash_guard_text(&mut hasher, &format!("{:?}", report.kind));
    hash_guard_text(&mut hasher, &format!("{:?}", report.assessment));
    hash_guard_text(&mut hasher, &format!("{:?}", report.trust));
    hash_guard_text(&mut hasher, &format!("{:?}", report.proof_level));
    hash_guard_text(&mut hasher, &format!("{:?}", report.archive_provider_alias));
    for entry in &report.archive_entries {
        hash_guard_text(&mut hasher, &entry.path);
        hasher.update(entry.byte_size.to_le_bytes());
        hash_guard_text(&mut hasher, &entry.sha256);
        hasher.update([u8::from(entry.manifest_candidate)]);
    }
    hash_guard_text(&mut hasher, &format!("{:?}", report.manifest));
    hash_guard_text(&mut hasher, &format!("{:?}", report.der_components));
    hash_guard_text(&mut hasher, &format!("{:?}", report.warnings));
    hash_guard_text(&mut hasher, &format!("{:?}", report.limitations));
    format!("{:x}", hasher.finalize())
}

fn seal_report(mut report: AppleFirmwareReport) -> AppleFirmwareReport {
    report.projection_sha256 = report_projection_digest(&report);
    report
}

fn validate_report_integrity(report: &AppleFirmwareReport) -> Result<(), C04Error> {
    if report.projection_sha256.is_empty()
        || report.projection_sha256 != report_projection_digest(report)
    {
        return Err(C04Error::ReportIntegrityMismatch);
    }
    Ok(())
}

fn hash_guard_text(hasher: &mut Sha256, value: &str) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn view_spec(context: &AppleFirmwareContext, view_kind: &str, suffix: &str) -> ViewSpec {
    ViewSpec {
        workspace_ref: context.workspace_ref.clone(),
        authority_ref: context.authority_ref.clone(),
        view_kind: view_kind.to_owned(),
        view_schema_id: format!("urn:ptah:schema:c04:{suffix}:0.1.0"),
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
