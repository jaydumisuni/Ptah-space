use crate::{TypeAgreement, TypeAssessment};
use ptah_identifiers::EntityRef;
use ptah_object_store::{
    OriginClass, ProductionEvidence, RegisterObjectSpec, RelationshipSpec, RevisionRole, ViewSpec,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

/// Executable or package family selected from B02 agreed type truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableClass {
    /// Microsoft Portable Executable or PE-format library.
    Pe,
    /// ELF executable or shared library.
    Elf,
    /// Mach-O executable or dynamic library.
    MachO,
    /// Android application package.
    Apk,
    /// Android application bundle.
    Aab,
    /// Dalvik executable bytecode container.
    Dex,
}

/// Bounded static-analysis limits enforced by Core after Provider work returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutableLimits {
    /// Maximum retained metadata fields.
    pub max_metadata_fields: usize,
    /// Maximum retained sections.
    pub max_sections: usize,
    /// Maximum retained imports.
    pub max_imports: usize,
    /// Maximum retained exports.
    pub max_exports: usize,
    /// Maximum retained signature observations.
    pub max_signatures: usize,
    /// Maximum retained embedded children.
    pub max_children: usize,
    /// Maximum bytes retained for one embedded child.
    pub max_child_bytes: usize,
    /// Maximum aggregate retained embedded-child bytes.
    pub max_total_child_bytes: usize,
}

impl Default for ExecutableLimits {
    fn default() -> Self {
        Self {
            max_metadata_fields: 256,
            max_sections: 4096,
            max_imports: 65_536,
            max_exports: 65_536,
            max_signatures: 256,
            max_children: 4096,
            max_child_bytes: 64 * 1024 * 1024,
            max_total_child_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Whether a static-analysis Provider may use a potentially active capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticIsolationPolicy {
    /// Capability is denied.
    Denied,
    /// Capability is allowed.
    Allowed,
}

/// Passive isolation declaration required from every B05 Provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticIsolation {
    /// Execute, load or initialize analyzed code.
    pub code_execution: StaticIsolationPolicy,
    /// Provider-originated network access.
    pub network_access: StaticIsolationPolicy,
    /// Resolve or load external resources referenced by the source.
    pub external_resource_loading: StaticIsolationPolicy,
}

impl StaticIsolation {
    /// Strict passive B05 isolation policy.
    #[must_use]
    pub const fn passive() -> Self {
        Self {
            code_execution: StaticIsolationPolicy::Denied,
            network_access: StaticIsolationPolicy::Denied,
            external_resource_loading: StaticIsolationPolicy::Denied,
        }
    }

    const fn is_safe(self) -> bool {
        matches!(self.code_execution, StaticIsolationPolicy::Denied)
            && matches!(self.network_access, StaticIsolationPolicy::Denied)
            && matches!(self.external_resource_loading, StaticIsolationPolicy::Denied)
    }
}

/// Exact source and A04 evidence used by B05 registration plans.
#[derive(Debug, Clone)]
pub struct ExecutableContext {
    /// Workspace owning source and recovered child records.
    pub workspace_ref: EntityRef,
    /// Exact authority for the static-analysis operation.
    pub authority_ref: EntityRef,
    /// Immutable source Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact producing A04 evidence.
    pub production: ProductionEvidence,
}

/// Technical metadata observation from a passive Provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableMetadata {
    /// Stable metadata key.
    pub key: String,
    /// Exact observed value.
    pub value: String,
}

/// One executable section or segment observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableSection {
    /// Provider-reported section name.
    pub name: String,
    /// Byte offset within the immutable source.
    pub offset: u64,
    /// Byte size within the immutable source.
    pub size: u64,
    /// Provider-reported flags, retained as passive metadata.
    pub flags: Vec<String>,
    /// Whether this region is packed, opaque or otherwise not statically understood.
    pub packed_or_unknown: bool,
}

/// Passive signature observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureObservation {
    /// Signature scheme or container.
    pub scheme: String,
    /// Signer identity text when mechanically available.
    pub signer: Option<String>,
    /// Verification status token supplied by the passive Provider.
    pub status: SignatureStatus,
}

/// Bounded signature verification vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Signature verified under the Provider's declared static verifier.
    Verified,
    /// Signature was present but failed verification.
    Invalid,
    /// Signature was observed but not independently verified.
    Unverified,
}

/// Provider-produced embedded child before B05 attaches canonical provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterEmbeddedChild {
    /// Safe logical path or package-local name.
    pub logical_path: String,
    /// Exact observed child media type.
    pub media_type: String,
    /// Exact recovered bytes.
    pub bytes: Vec<u8>,
}

/// Passive Provider output before Core validation and retention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterExecutable {
    /// Technical/package metadata.
    pub metadata: Vec<ExecutableMetadata>,
    /// Sections or segments.
    pub sections: Vec<ExecutableSection>,
    /// Imported symbol/library names.
    pub imports: Vec<String>,
    /// Exported symbol names.
    pub exports: Vec<String>,
    /// Signature observations.
    pub signatures: Vec<SignatureObservation>,
    /// Recovered embedded package/application children.
    pub children: Vec<AdapterEmbeddedChild>,
    /// Number of source bytes mechanically inspected.
    pub observed_source_bytes: u64,
    /// Provider claim that all supported static regions were understood.
    pub complete_claim: bool,
    /// Explicit opaque, encrypted, packed or unsupported regions.
    pub unknown_regions: Vec<String>,
    /// Provider warnings.
    pub warnings: Vec<String>,
    /// Provider limitations.
    pub limitations: Vec<String>,
}

/// Replaceable passive B05 static-analysis Provider boundary.
pub trait ExecutableAdapter: Send + Sync {
    /// Stable Provider adapter identity.
    fn adapter_id(&self) -> &str;

    /// Whether the Provider supports the exact normalized B02 agreed type.
    fn supports_media_type(&self, media_type: &str) -> bool;

    /// Passive isolation declaration.
    fn isolation(&self) -> StaticIsolation;

    /// Inspect immutable bytes without loading or executing analyzed code.
    ///
    /// # Errors
    /// Returns a Provider-specific mechanical failure.
    fn inspect(
        &self,
        source_bytes: &[u8],
        media_type: &str,
        limits: ExecutableLimits,
    ) -> Result<AdapterExecutable, String>;
}

/// Static execution truth. B05 never executes the source under analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionAssessment {
    /// No execution-success claim exists because B05 is static-only.
    NotExecuted,
}

/// Recovered embedded child bound to one exact immutable source Revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedExecutableChild {
    /// Safe package-local logical path.
    pub logical_path: String,
    /// Normalized observed media type.
    pub media_type: String,
    /// Exact recovered bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of exact recovered bytes.
    pub sha256: String,
    /// Frozen exact parent source Revision.
    pub source_revision_ref: EntityRef,
}

impl EmbeddedExecutableChild {
    /// Build an A07 registration request for this recovered child.
    #[must_use]
    pub fn registration_spec(&self, context: &ExecutableContext) -> RegisterObjectSpec {
        RegisterObjectSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            object_class: "executable.embedded".to_owned(),
            declared_name: Some(self.logical_path.clone()),
            source_refs: vec![self.source_revision_ref.clone()],
            revision_role: RevisionRole::Recovered,
            origin_class: OriginClass::RecoveredEmbeddedSource,
            created_reason: "B05 recovered embedded executable/package child".to_owned(),
            production: context.production.clone(),
            expected_sha256: Some(self.sha256.clone()),
        }
    }

    /// Build the canonical parent-to-child Relationship after A07 child registration.
    ///
    /// # Errors
    /// Returns [`B05Error::InvalidChildRevision`] when the supplied child reference is not an
    /// exact Object Revision.
    pub fn relationship_spec(
        &self,
        context: &ExecutableContext,
        child_revision_ref: &EntityRef,
    ) -> Result<RelationshipSpec, B05Error> {
        if child_revision_ref.entity_kind.as_str() != "object.revision" {
            return Err(B05Error::InvalidChildRevision);
        }
        Ok(RelationshipSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            subject_refs: vec![self.source_revision_ref.clone()],
            relationship_type: "contains.embedded".to_owned(),
            object_refs: vec![child_revision_ref.clone()],
            production: context.production.clone(),
        })
    }
}

/// Truthful B05 static-analysis coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableCoverage {
    /// Whether complete supported static coverage may be claimed.
    pub complete_claim: bool,
    /// Number of source bytes mechanically inspected.
    pub observed_source_bytes: u64,
    /// Explicit opaque, packed, encrypted, unsupported or truncated regions.
    pub unknown_regions: Vec<String>,
    /// Aggregate retained bytes across recovered embedded children.
    pub retained_child_bytes: u64,
}

/// B05 static executable/package report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableReport {
    /// SHA-256 of immutable source bytes.
    pub source_sha256: String,
    /// Frozen exact source Revision.
    pub source_revision_ref: EntityRef,
    /// Normalized B02 agreed type when one exists.
    pub agreed_media_type: Option<String>,
    /// Selected executable/package family.
    pub executable_class: Option<ExecutableClass>,
    /// Selected Provider identity.
    pub adapter_id: Option<String>,
    /// Retained metadata.
    pub metadata: Vec<ExecutableMetadata>,
    /// Retained sections.
    pub sections: Vec<ExecutableSection>,
    /// Retained imports.
    pub imports: Vec<String>,
    /// Retained exports.
    pub exports: Vec<String>,
    /// Retained signature observations.
    pub signatures: Vec<SignatureObservation>,
    /// Retained embedded children.
    pub children: Vec<EmbeddedExecutableChild>,
    /// Static coverage truth.
    pub coverage: ExecutableCoverage,
    /// Explicit execution truth.
    pub execution_assessment: ExecutionAssessment,
    /// Warnings.
    pub warnings: Vec<String>,
    /// Limitations.
    pub limitations: Vec<String>,
}

impl ExecutableReport {
    /// Build canonical A07 View plans over this report's frozen source Revision.
    #[must_use]
    pub fn view_specs(&self, context: &ExecutableContext) -> Vec<ViewSpec> {
        let mut views = Vec::new();
        if !self.metadata.is_empty() {
            views.push(view_spec(
                context,
                &self.source_revision_ref,
                "executable.metadata",
                "urn:ptah:schema:executable:metadata-view:0.1.0",
            ));
        }
        if !self.sections.is_empty() {
            views.push(view_spec(
                context,
                &self.source_revision_ref,
                "executable.sections",
                "urn:ptah:schema:executable:sections-view:0.1.0",
            ));
        }
        if !self.imports.is_empty() {
            views.push(view_spec(
                context,
                &self.source_revision_ref,
                "executable.imports",
                "urn:ptah:schema:executable:imports-view:0.1.0",
            ));
        }
        if !self.exports.is_empty() {
            views.push(view_spec(
                context,
                &self.source_revision_ref,
                "executable.exports",
                "urn:ptah:schema:executable:exports-view:0.1.0",
            ));
        }
        if !self.signatures.is_empty() {
            views.push(view_spec(
                context,
                &self.source_revision_ref,
                "executable.signatures",
                "urn:ptah:schema:executable:signatures-view:0.1.0",
            ));
        }
        views.push(view_spec(
            context,
            &self.source_revision_ref,
            "executable.coverage",
            "urn:ptah:schema:executable:coverage-view:0.1.0",
        ));
        views
    }
}

/// B05 failures that prevent truthful static interpretation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum B05Error {
    /// Source reference is not an exact Object Revision.
    #[error("B05 source must be an exact object.revision reference")]
    InvalidSourceRevision,
    /// At least one resource limit is zero.
    #[error("B05 executable limits must all be greater than zero")]
    InvalidLimits,
    /// Adapter identity is empty.
    #[error("B05 adapter identity must not be empty")]
    EmptyAdapterId,
    /// Adapter identity is duplicated.
    #[error("duplicate B05 adapter identity: {0}")]
    DuplicateAdapterId(String),
    /// More than one Provider claims the same exact media type.
    #[error("ambiguous B05 adapters for media type {0}")]
    AmbiguousAdapter(String),
    /// Provider isolation is not passive.
    #[error("B05 adapter does not deny execution, network and external resource loading: {0}")]
    UnsafeAdapterIsolation(String),
    /// Provider failed mechanically.
    #[error("B05 adapter failed: {0}")]
    Adapter(String),
    /// Provider claimed source bytes outside the immutable source.
    #[error("B05 adapter observed source bytes outside the immutable source")]
    InvalidObservedSourceBytes,
    /// Provider returned a section outside immutable source bounds.
    #[error("B05 section lies outside immutable source bounds")]
    InvalidSectionExtent,
    /// Provider returned a duplicate section identity.
    #[error("B05 adapter emitted duplicate section identity")]
    DuplicateSection,
    /// Provider returned an empty required string.
    #[error("B05 adapter emitted an empty required field: {0}")]
    EmptyField(&'static str),
    /// Provider returned a malformed or escaping child path.
    #[error("B05 embedded child path is unsafe")]
    UnsafeChildPath,
    /// Provider returned duplicate child logical identity.
    #[error("B05 adapter emitted duplicate embedded child path")]
    DuplicateChildPath,
    /// Provider returned an empty embedded child payload.
    #[error("B05 adapter emitted an empty embedded child payload")]
    EmptyChild,
    /// Numeric accounting overflowed.
    #[error("B05 byte accounting overflow")]
    AccountingOverflow,
    /// A relationship target is not an Object Revision.
    #[error("B05 child relationship target must be an exact object.revision reference")]
    InvalidChildRevision,
}

/// Perform passive executable/application-package analysis under exact B02 type truth.
///
/// Unknown, disputed, unsupported and provider-missing types produce explicit partial reports.
/// B05 never executes, loads or initializes analyzed code.
///
/// # Errors
/// Fails on invalid context/limits, ambiguous or unsafe Providers, malformed Provider output,
/// Provider failure or accounting overflow.
pub fn inspect_executable(
    source_bytes: &[u8],
    type_assessment: &TypeAssessment,
    context: &ExecutableContext,
    limits: ExecutableLimits,
    adapters: &[&dyn ExecutableAdapter],
) -> Result<ExecutableReport, B05Error> {
    validate_context(context)?;
    validate_limits(limits)?;
    validate_adapter_ids(adapters)?;

    let source_sha256 = sha256_bytes(source_bytes);
    let agreed_media_type = match &type_assessment.agreement {
        TypeAgreement::Agreed(value) => Some(normalize(value)),
        TypeAgreement::Unknown | TypeAgreement::Disputed(_) => None,
    };
    let mut report = empty_report(
        source_sha256.clone(),
        context.source_revision_ref.clone(),
        agreed_media_type.clone(),
    );

    let Some(media_type) = agreed_media_type else {
        report.coverage.unknown_regions.push(match &type_assessment.agreement {
            TypeAgreement::Unknown => "B02 did not establish an agreed executable/package type".to_owned(),
            TypeAgreement::Disputed(values) => format!(
                "B02 detector disagreement prevents B05 adapter selection: {}",
                values.join(", ")
            ),
            TypeAgreement::Agreed(_) => unreachable!("agreed media type was extracted above"),
        });
        return Ok(report);
    };

    let Some(executable_class) = executable_class_for_type(&media_type) else {
        report.coverage.unknown_regions.push(format!(
            "B02 agreed type {media_type} is outside the B05 executable/application-package domain"
        ));
        return Ok(report);
    };
    report.executable_class = Some(executable_class);

    let matching: Vec<&dyn ExecutableAdapter> = adapters
        .iter()
        .copied()
        .filter(|adapter| adapter.supports_media_type(&media_type))
        .collect();
    if matching.len() > 1 {
        return Err(B05Error::AmbiguousAdapter(media_type));
    }
    let Some(adapter) = matching.first().copied() else {
        report.coverage.unknown_regions.push(format!(
            "no B05 static-analysis adapter is registered for agreed type {media_type}"
        ));
        return Ok(report);
    };
    let adapter_id = adapter.adapter_id().trim().to_owned();
    if !adapter.isolation().is_safe() {
        return Err(B05Error::UnsafeAdapterIsolation(adapter_id));
    }

    let output = adapter
        .inspect(source_bytes, &media_type, limits)
        .map_err(B05Error::Adapter)?;
    validate_output(&output, source_bytes.len())?;
    apply_output(&mut report, output, context, source_bytes.len(), limits, &adapter_id)?;
    dedup_strings(&mut report.coverage.unknown_regions);
    dedup_strings(&mut report.warnings);
    dedup_strings(&mut report.limitations);
    debug_assert_eq!(source_sha256, sha256_bytes(source_bytes));
    Ok(report)
}

fn apply_output(
    report: &mut ExecutableReport,
    output: AdapterExecutable,
    context: &ExecutableContext,
    source_len: usize,
    limits: ExecutableLimits,
    adapter_id: &str,
) -> Result<(), B05Error> {
    report.adapter_id = Some(adapter_id.to_owned());
    report.coverage.complete_claim = output.complete_claim;
    report.coverage.observed_source_bytes = output.observed_source_bytes;
    report.coverage.unknown_regions.extend(output.unknown_regions);
    report.warnings = output.warnings;
    report.limitations = output.limitations;

    retain_bounded(
        &mut report.metadata,
        output.metadata,
        limits.max_metadata_fields,
        &mut report.coverage,
        "metadata fields",
    );
    retain_bounded(
        &mut report.sections,
        output.sections,
        limits.max_sections,
        &mut report.coverage,
        "sections",
    );
    retain_bounded(
        &mut report.imports,
        output.imports,
        limits.max_imports,
        &mut report.coverage,
        "imports",
    );
    retain_bounded(
        &mut report.exports,
        output.exports,
        limits.max_exports,
        &mut report.coverage,
        "exports",
    );
    retain_bounded(
        &mut report.signatures,
        output.signatures,
        limits.max_signatures,
        &mut report.coverage,
        "signature observations",
    );

    let source_len_u64 = u64::try_from(source_len).map_err(|_| B05Error::AccountingOverflow)?;
    if report.coverage.observed_source_bytes < source_len_u64 {
        mark_gap(report, "static Provider inspected only part of the immutable source bytes".to_owned());
    }
    for section in &report.sections {
        if section.packed_or_unknown {
            mark_gap(report, format!("section {} is packed or statically unknown", section.name));
        }
    }
    if !report.coverage.complete_claim && report.coverage.unknown_regions.is_empty() {
        mark_gap(report, "static Provider reported partial supported coverage".to_owned());
    }
    retain_children(report, output.children, context, limits)?;
    if !report.coverage.unknown_regions.is_empty() {
        report.coverage.complete_claim = false;
    }
    Ok(())
}

fn retain_children(
    report: &mut ExecutableReport,
    children: Vec<AdapterEmbeddedChild>,
    context: &ExecutableContext,
    limits: ExecutableLimits,
) -> Result<(), B05Error> {
    let produced = children.len();
    for child in children.into_iter().take(limits.max_children) {
        if child.bytes.len() > limits.max_child_bytes {
            mark_gap(
                report,
                format!("embedded child {} exceeded max_child_bytes", child.logical_path),
            );
            continue;
        }
        let child_bytes = u64::try_from(child.bytes.len()).map_err(|_| B05Error::AccountingOverflow)?;
        let max_total = u64::try_from(limits.max_total_child_bytes)
            .map_err(|_| B05Error::AccountingOverflow)?;
        let Some(next) = report.coverage.retained_child_bytes.checked_add(child_bytes) else {
            return Err(B05Error::AccountingOverflow);
        };
        if next > max_total {
            mark_gap(
                report,
                format!("embedded child {} exceeded aggregate child-byte policy", child.logical_path),
            );
            continue;
        }
        report.coverage.retained_child_bytes = next;
        let sha256 = sha256_bytes(&child.bytes);
        report.children.push(EmbeddedExecutableChild {
            logical_path: child.logical_path,
            media_type: normalize(&child.media_type),
            bytes: child.bytes,
            sha256,
            source_revision_ref: context.source_revision_ref.clone(),
        });
    }
    if produced > limits.max_children {
        mark_gap(report, "embedded children exceeded max_children".to_owned());
    }
    Ok(())
}

fn validate_context(context: &ExecutableContext) -> Result<(), B05Error> {
    if context.source_revision_ref.entity_kind.as_str() != "object.revision" {
        return Err(B05Error::InvalidSourceRevision);
    }
    Ok(())
}

fn validate_limits(limits: ExecutableLimits) -> Result<(), B05Error> {
    if limits.max_metadata_fields == 0
        || limits.max_sections == 0
        || limits.max_imports == 0
        || limits.max_exports == 0
        || limits.max_signatures == 0
        || limits.max_children == 0
        || limits.max_child_bytes == 0
        || limits.max_total_child_bytes == 0
    {
        return Err(B05Error::InvalidLimits);
    }
    Ok(())
}

fn validate_adapter_ids(adapters: &[&dyn ExecutableAdapter]) -> Result<(), B05Error> {
    let mut seen = HashSet::new();
    for adapter in adapters {
        let id = adapter.adapter_id().trim();
        if id.is_empty() {
            return Err(B05Error::EmptyAdapterId);
        }
        if !seen.insert(id.to_owned()) {
            return Err(B05Error::DuplicateAdapterId(id.to_owned()));
        }
    }
    Ok(())
}

fn validate_output(output: &AdapterExecutable, source_len: usize) -> Result<(), B05Error> {
    let source_len = u64::try_from(source_len).map_err(|_| B05Error::InvalidObservedSourceBytes)?;
    if output.observed_source_bytes > source_len {
        return Err(B05Error::InvalidObservedSourceBytes);
    }
    for metadata in &output.metadata {
        if metadata.key.trim().is_empty() {
            return Err(B05Error::EmptyField("metadata key"));
        }
    }
    let mut section_ids = HashSet::new();
    for section in &output.sections {
        if section.name.trim().is_empty() {
            return Err(B05Error::EmptyField("section name"));
        }
        let Some(end) = section.offset.checked_add(section.size) else {
            return Err(B05Error::InvalidSectionExtent);
        };
        if end > source_len {
            return Err(B05Error::InvalidSectionExtent);
        }
        if !section_ids.insert((section.name.clone(), section.offset)) {
            return Err(B05Error::DuplicateSection);
        }
    }
    validate_names(&output.imports, "import")?;
    validate_names(&output.exports, "export")?;
    for signature in &output.signatures {
        if signature.scheme.trim().is_empty() {
            return Err(B05Error::EmptyField("signature scheme"));
        }
    }
    let mut child_paths = HashSet::new();
    for child in &output.children {
        if child.bytes.is_empty() {
            return Err(B05Error::EmptyChild);
        }
        if normalize(&child.media_type).is_empty() {
            return Err(B05Error::EmptyField("child media type"));
        }
        if !safe_child_path(&child.logical_path) {
            return Err(B05Error::UnsafeChildPath);
        }
        if !child_paths.insert(child.logical_path.clone()) {
            return Err(B05Error::DuplicateChildPath);
        }
    }
    Ok(())
}

fn validate_names(values: &[String], label: &'static str) -> Result<(), B05Error> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(B05Error::EmptyField(label));
    }
    Ok(())
}

fn safe_child_path(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && !trimmed.starts_with('/')
        && !trimmed.starts_with('\\')
        && !trimmed.contains('\\')
        && trimmed
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn empty_report(
    source_sha256: String,
    source_revision_ref: EntityRef,
    agreed_media_type: Option<String>,
) -> ExecutableReport {
    ExecutableReport {
        source_sha256,
        source_revision_ref,
        agreed_media_type,
        executable_class: None,
        adapter_id: None,
        metadata: Vec::new(),
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        signatures: Vec::new(),
        children: Vec::new(),
        coverage: ExecutableCoverage {
            complete_claim: false,
            observed_source_bytes: 0,
            unknown_regions: Vec::new(),
            retained_child_bytes: 0,
        },
        execution_assessment: ExecutionAssessment::NotExecuted,
        warnings: Vec::new(),
        limitations: Vec::new(),
    }
}

fn retain_bounded<T>(
    target: &mut Vec<T>,
    source: Vec<T>,
    limit: usize,
    coverage: &mut ExecutableCoverage,
    label: &str,
) {
    let produced = source.len();
    target.extend(source.into_iter().take(limit));
    if produced > limit {
        coverage.complete_claim = false;
        coverage
            .unknown_regions
            .push(format!("B05 {label} exceeded retention policy"));
    }
}

fn mark_gap(report: &mut ExecutableReport, reason: String) {
    report.coverage.complete_claim = false;
    report.coverage.unknown_regions.push(reason);
}

fn view_spec(
    context: &ExecutableContext,
    source_revision_ref: &EntityRef,
    view_kind: &str,
    schema_id: &str,
) -> ViewSpec {
    ViewSpec {
        workspace_ref: context.workspace_ref.clone(),
        authority_ref: context.authority_ref.clone(),
        view_kind: view_kind.to_owned(),
        view_schema_id: schema_id.to_owned(),
        view_schema_version: "0.1.0".to_owned(),
        source_revision_refs: vec![source_revision_ref.clone()],
        origin_class: OriginClass::DecodedResource,
        production: context.production.clone(),
    }
}

fn executable_class_for_type(media_type: &str) -> Option<ExecutableClass> {
    match media_type {
        "application/vnd.microsoft.portable-executable" | "application/x-msdownload"
        | "application/x-dosexec" => Some(ExecutableClass::Pe),
        "application/x-elf" | "application/x-executable" | "application/x-sharedlib" => {
            Some(ExecutableClass::Elf)
        }
        "application/x-mach-binary" | "application/x-mach-o" => Some(ExecutableClass::MachO),
        "application/vnd.android.package-archive" => Some(ExecutableClass::Apk),
        "application/vnd.android.aab" | "application/x-android-app-bundle" => {
            Some(ExecutableClass::Aab)
        }
        "application/vnd.android.dex" | "application/x-dex" => Some(ExecutableClass::Dex),
        _ => None,
    }
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn dedup_strings(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
