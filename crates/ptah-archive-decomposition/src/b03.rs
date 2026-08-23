use crate::{TypeAgreement, TypeAssessment};
use ptah_identifiers::EntityRef;
use ptah_object_store::{
    OriginClass, ProductionEvidence, RegisterObjectSpec, RevisionRole, ViewSpec,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

/// Maximum work accepted by the B03 document layer for one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentLimits {
    /// Maximum retained extracted UTF-8 bytes.
    pub max_text_bytes: usize,
    /// Maximum retained page/render Views.
    pub max_pages: usize,
    /// Maximum retained bytes for any one rendered page.
    pub max_page_render_bytes: usize,
    /// Maximum retained safe-preview bytes.
    pub max_preview_bytes: usize,
    /// Maximum retained converted-output bytes.
    pub max_conversion_bytes: usize,
}

impl Default for DocumentLimits {
    fn default() -> Self {
        Self {
            max_text_bytes: 4 * 1024 * 1024,
            max_pages: 512,
            max_page_render_bytes: 8 * 1024 * 1024,
            max_preview_bytes: 512 * 1024,
            max_conversion_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Whether one document-derived capability is denied or permitted by an adapter boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationPolicy {
    /// The capability is denied.
    Denied,
    /// The capability is permitted.
    Allowed,
}

/// Mechanical isolation declaration required from a B03 document adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentIsolation {
    /// Execution of active content embedded in the document.
    pub active_content_execution: IsolationPolicy,
    /// Adapter-originated network access while inspecting the document.
    pub network_access: IsolationPolicy,
    /// Loading external resources referenced by the document.
    pub external_resource_loading: IsolationPolicy,
}

impl DocumentIsolation {
    /// Strict passive-document policy accepted by B03.
    #[must_use]
    pub const fn passive() -> Self {
        Self {
            active_content_execution: IsolationPolicy::Denied,
            network_access: IsolationPolicy::Denied,
            external_resource_loading: IsolationPolicy::Denied,
        }
    }

    const fn is_safe(self) -> bool {
        matches!(self.active_content_execution, IsolationPolicy::Denied)
            && matches!(self.network_access, IsolationPolicy::Denied)
            && matches!(self.external_resource_loading, IsolationPolicy::Denied)
    }
}

/// Exact B03 source and A04 authority context.
#[derive(Debug, Clone)]
pub struct DocumentContext {
    /// Workspace owning the source Revision and derived records.
    pub workspace_ref: EntityRef,
    /// Authority authorizing the bounded B03 work.
    pub authority_ref: EntityRef,
    /// Exact immutable source Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact A04 production evidence for derived records.
    pub production: ProductionEvidence,
}

/// Adapter-supplied metadata field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentMetadata {
    /// Stable metadata key.
    pub key: String,
    /// Exact extracted value.
    pub value: String,
}

/// Adapter text fragment before B03 attaches source authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterTextSpan {
    /// Extracted UTF-8 text.
    pub text: String,
    /// Exact source byte range when the adapter can prove one.
    pub source_byte_range: Option<(u64, u64)>,
    /// One-based source page when known.
    pub page: Option<u32>,
}

/// Adapter-rendered page before B03 attaches source authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterPage {
    /// One-based page number.
    pub page: u32,
    /// Passive render media type such as `image/png` or `text/plain`.
    pub media_type: String,
    /// Exact rendered bytes.
    pub bytes: Vec<u8>,
    /// Exact source byte range when the adapter can prove one.
    pub source_byte_range: Option<(u64, u64)>,
}

/// Optional adapter conversion result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterConversion {
    /// Converted output media type.
    pub media_type: String,
    /// Exact converted bytes.
    pub bytes: Vec<u8>,
}

/// Bounded mechanical result returned by one passive document adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterDocument {
    /// Extracted metadata.
    pub metadata: Vec<DocumentMetadata>,
    /// Extracted text spans.
    pub text: Vec<AdapterTextSpan>,
    /// Rendered pages.
    pub pages: Vec<AdapterPage>,
    /// Optional safe conversion.
    pub conversion: Option<AdapterConversion>,
    /// Whether active content was observed and deliberately not executed.
    pub active_content_observed: bool,
    /// Whether the adapter claims complete coverage of its supported interpretation.
    pub complete_claim: bool,
    /// Adapter warnings.
    pub warnings: Vec<String>,
    /// Adapter limitations.
    pub limitations: Vec<String>,
}

/// Replaceable passive B03 document adapter.
pub trait DocumentAdapter {
    /// Stable adapter identity.
    fn adapter_id(&self) -> &str;

    /// Whether this adapter supports the normalized agreed media type.
    fn supports_media_type(&self, media_type: &str) -> bool;

    /// Isolation boundary declared by this adapter implementation.
    fn isolation(&self) -> DocumentIsolation;

    /// Inspect immutable source bytes without executing document active content.
    ///
    /// # Errors
    /// Returns an adapter-specific mechanical failure. B03 never converts that failure into a
    /// successful extraction claim.
    fn inspect(&self, bytes: &[u8], media_type: &str) -> Result<AdapterDocument, String>;
}

/// Exact source anchor attached to text, citations and page renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceAnchor {
    /// Exact source Object Revision.
    pub source_revision_ref: EntityRef,
    /// Inclusive source byte start when known.
    pub byte_start: Option<u64>,
    /// Exclusive source byte end when known.
    pub byte_end_exclusive: Option<u64>,
    /// One-based source page when known.
    pub page: Option<u32>,
}

/// Extracted text with exact source anchoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredText {
    /// Extracted UTF-8 text.
    pub text: String,
    /// Source anchor proving where this text came from.
    pub anchor: SourceAnchor,
}

/// Passive page/render View payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentPageView {
    /// One-based page number.
    pub page: u32,
    /// Passive render media type.
    pub media_type: String,
    /// Render bytes.
    pub bytes: Vec<u8>,
    /// Source anchor.
    pub anchor: SourceAnchor,
}

/// Safe non-active preview payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafePreview {
    /// Preview media type. Built-in B03 previews are passive text.
    pub media_type: String,
    /// Exact preview bytes.
    pub bytes: Vec<u8>,
    /// Whether active/external content was removed or never interpreted.
    pub sanitized: bool,
    /// Exact source Revision.
    pub source_revision_ref: EntityRef,
}

/// Converted output that remains explicitly derived from one exact source Revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertedDocument {
    /// Converted media type.
    pub media_type: String,
    /// Exact converted bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of converted bytes.
    pub sha256: String,
    /// Exact source Revision.
    pub source_revision_ref: EntityRef,
    /// SHA-256 of immutable source bytes.
    pub source_sha256: String,
    /// Adapter that produced this output.
    pub adapter_id: String,
}

impl ConvertedDocument {
    /// Build the A07 registration request for these converted bytes.
    ///
    /// The resulting Object is a new converted Revision whose source reference comes from the
    /// frozen conversion result itself. A caller cannot rebind converted provenance by supplying a
    /// different `DocumentContext::source_revision_ref` later.
    #[must_use]
    pub fn registration_spec(&self, context: &DocumentContext) -> RegisterObjectSpec {
        RegisterObjectSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            object_class: "document.converted".to_owned(),
            declared_name: None,
            source_refs: vec![self.source_revision_ref.clone()],
            revision_role: RevisionRole::Converted,
            origin_class: OriginClass::Generated,
            created_reason: format!("B03 passive document conversion by {}", self.adapter_id),
            production: context.production.clone(),
            expected_sha256: Some(self.sha256.clone()),
        }
    }
}

/// Truthful coverage statement for one B03 inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentCoverage {
    /// Whether the retained result can claim complete adapter coverage.
    pub complete_claim: bool,
    /// Total UTF-8 bytes retained in extracted text.
    pub retained_text_bytes: u64,
    /// Number of page/render Views retained.
    pub retained_pages: usize,
    /// Explicit unknown or unsupported regions.
    pub unknown_gaps: Vec<String>,
}

/// B03 document/structured-text result.
#[derive(Debug, Clone)]
pub struct DocumentReport {
    /// SHA-256 of immutable source bytes.
    pub source_sha256: String,
    /// Exact source Revision.
    pub source_revision_ref: EntityRef,
    /// B02-agreed normalized media type when one exists.
    pub agreed_media_type: Option<String>,
    /// Adapter selected for this report.
    pub adapter_id: Option<String>,
    /// Extracted metadata.
    pub metadata: Vec<DocumentMetadata>,
    /// Extracted text with source anchors.
    pub text: Vec<AnchoredText>,
    /// Passive page/render Views.
    pub pages: Vec<DocumentPageView>,
    /// Passive preview.
    pub preview: Option<SafePreview>,
    /// Optional converted output.
    pub conversion: Option<ConvertedDocument>,
    /// Whether active content was observed but not executed.
    pub active_content_observed: bool,
    /// Coverage truth.
    pub coverage: DocumentCoverage,
    /// Warnings.
    pub warnings: Vec<String>,
    /// Limitations.
    pub limitations: Vec<String>,
}

impl DocumentReport {
    /// Create canonical A07 View specifications for retained B03 interpretations.
    ///
    /// Source identity is taken from the frozen report, not from the supplied context, so a report
    /// cannot be rebound to a different Revision after inspection.
    #[must_use]
    pub fn view_specs(&self, context: &DocumentContext) -> Vec<ViewSpec> {
        let mut views = Vec::new();
        if !self.metadata.is_empty() {
            views.push(document_view_spec(
                context,
                &self.source_revision_ref,
                "document.metadata",
                "urn:ptah:schema:document:metadata-view:0.1.0",
            ));
        }
        if !self.text.is_empty() {
            views.push(document_view_spec(
                context,
                &self.source_revision_ref,
                "document.text",
                "urn:ptah:schema:document:text-view:0.1.0",
            ));
        }
        for _page in &self.pages {
            views.push(document_view_spec(
                context,
                &self.source_revision_ref,
                "document.page_render",
                "urn:ptah:schema:document:page-render-view:0.1.0",
            ));
        }
        if self.preview.is_some() {
            views.push(document_view_spec(
                context,
                &self.source_revision_ref,
                "document.safe_preview",
                "urn:ptah:schema:document:safe-preview-view:0.1.0",
            ));
        }
        views
    }
}

/// B03 failures that prevent a truthful bounded result.
#[derive(Debug, Error)]
pub enum B03Error {
    /// Source reference is not an Object Revision.
    #[error("B03 source must be an exact object.revision reference")]
    InvalidSourceRevision,
    /// One or more configured resource limits are zero.
    #[error("B03 document limits must all be greater than zero")]
    InvalidLimits,
    /// Adapter identity is empty.
    #[error("B03 document adapter identity must not be empty")]
    EmptyAdapterId,
    /// Adapter identity is duplicated.
    #[error("duplicate B03 document adapter identity: {0}")]
    DuplicateAdapterId(String),
    /// More than one adapter claims the same selected media type.
    #[error("ambiguous B03 document adapters for media type {0}")]
    AmbiguousAdapter(String),
    /// Selected adapter does not satisfy passive isolation policy.
    #[error("B03 adapter does not deny active content, network and external resource loading: {0}")]
    UnsafeAdapterIsolation(String),
    /// Adapter failed mechanically.
    #[error("B03 adapter failed: {0}")]
    Adapter(String),
    /// Adapter emitted an invalid source byte range.
    #[error("B03 adapter emitted an invalid source byte range")]
    InvalidSourceRange,
    /// Adapter emitted an invalid page number.
    #[error("B03 adapter emitted page zero or duplicate page identity")]
    InvalidPage,
    /// Adapter emitted an empty media type.
    #[error("B03 adapter emitted an empty media type")]
    EmptyMediaType,
    /// Adapter metadata key is empty.
    #[error("B03 adapter emitted an empty metadata key")]
    EmptyMetadataKey,
    /// Retained byte accounting exceeded representable bounds.
    #[error("B03 retained byte accounting overflow")]
    AccountingOverflow,
}

/// Inspect one document under B02 type truth and B03 passive isolation policy.
///
/// Unknown, disputed and unsupported types return explicit partial reports rather than false
/// extraction success. The source slice is immutable and its digest is checked again before return.
///
/// # Errors
/// Fails for invalid source identity/limits/adapter configuration, unsafe isolation declarations,
/// invalid adapter output, accounting overflow or a mechanical adapter failure.
pub fn inspect_document(
    source_bytes: &[u8],
    type_assessment: &TypeAssessment,
    context: &DocumentContext,
    limits: DocumentLimits,
    adapters: &[&dyn DocumentAdapter],
) -> Result<DocumentReport, B03Error> {
    validate_context(context)?;
    validate_limits(limits)?;
    validate_adapter_ids(adapters)?;
    let source_sha256 = sha256_bytes(source_bytes);
    let agreed_media_type = match &type_assessment.agreement {
        TypeAgreement::Agreed(value) => Some(normalize_media_type(value)),
        TypeAgreement::Unknown | TypeAgreement::Disputed(_) => None,
    };
    let mut report = empty_report(
        source_sha256.clone(),
        context.source_revision_ref.clone(),
        agreed_media_type.clone(),
    );

    let Some(media_type) = agreed_media_type else {
        report
            .coverage
            .unknown_gaps
            .push(match &type_assessment.agreement {
                TypeAgreement::Unknown => {
                    "B02 did not establish an agreed document type".to_owned()
                }
                TypeAgreement::Disputed(values) => format!(
                    "B02 detector disagreement prevents document adapter selection: {}",
                    values.join(", ")
                ),
                TypeAgreement::Agreed(_) => unreachable!("agreed media type was extracted above"),
            });
        return Ok(report);
    };

    let matching: Vec<&dyn DocumentAdapter> = adapters
        .iter()
        .copied()
        .filter(|adapter| adapter.supports_media_type(&media_type))
        .collect();
    if matching.len() > 1 {
        return Err(B03Error::AmbiguousAdapter(media_type));
    }
    let Some(adapter) = matching.first().copied() else {
        report.coverage.unknown_gaps.push(format!(
            "no B03 document adapter is registered for agreed type {media_type}"
        ));
        return Ok(report);
    };
    let adapter_id = adapter.adapter_id().trim().to_owned();
    if !adapter.isolation().is_safe() {
        return Err(B03Error::UnsafeAdapterIsolation(adapter_id));
    }

    let output = adapter
        .inspect(source_bytes, &media_type)
        .map_err(B03Error::Adapter)?;
    validate_adapter_output(&output, source_bytes.len())?;
    report.adapter_id = Some(adapter_id.clone());
    report.active_content_observed = output.active_content_observed;
    report.metadata = output.metadata;
    report.warnings = output.warnings;
    report.limitations = output.limitations;
    report.coverage.complete_claim = output.complete_claim;

    retain_text(&mut report, output.text, context, limits.max_text_bytes)?;
    retain_pages(
        &mut report,
        output.pages,
        context,
        limits.max_pages,
        limits.max_page_render_bytes,
    );
    let (preview, preview_truncated) = build_preview(&report, context, limits.max_preview_bytes);
    report.preview = preview;
    if preview_truncated {
        mark_gap(
            &mut report,
            "safe preview truncated by B03 max_preview_bytes".to_owned(),
        );
    }
    report.conversion = retain_conversion(
        output.conversion,
        context,
        &source_sha256,
        &adapter_id,
        limits.max_conversion_bytes,
        &mut report.coverage,
        &mut report.limitations,
    );
    if report.active_content_observed {
        report
            .warnings
            .push("active document content was observed and not executed".to_owned());
    }
    dedup_strings(&mut report.coverage.unknown_gaps);
    dedup_strings(&mut report.warnings);
    dedup_strings(&mut report.limitations);
    debug_assert_eq!(source_sha256, sha256_bytes(source_bytes));
    Ok(report)
}

/// Built-in passive structured-text adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct SafeTextAdapter;

impl DocumentAdapter for SafeTextAdapter {
    fn adapter_id(&self) -> &'static str {
        "b03.safe-text"
    }

    fn supports_media_type(&self, media_type: &str) -> bool {
        matches!(
            media_type,
            "text/plain" | "application/json" | "text/csv" | "text/markdown"
        )
    }

    fn isolation(&self) -> DocumentIsolation {
        DocumentIsolation::passive()
    }

    fn inspect(&self, bytes: &[u8], media_type: &str) -> Result<AdapterDocument, String> {
        let valid_utf8 = std::str::from_utf8(bytes).is_ok();
        let text = String::from_utf8_lossy(bytes).into_owned();
        let line_count = text.lines().count().max(usize::from(!text.is_empty()));
        let source_len = u64::try_from(bytes.len())
            .map_err(|_| "structured-text source length exceeds u64".to_owned())?;
        let mut limitations = Vec::new();
        if !valid_utf8 {
            limitations.push(
                "invalid UTF-8 sequences were replaced; exact text coverage is partial".to_owned(),
            );
        }
        Ok(AdapterDocument {
            metadata: vec![
                DocumentMetadata {
                    key: "media_type".to_owned(),
                    value: media_type.to_owned(),
                },
                DocumentMetadata {
                    key: "line_count".to_owned(),
                    value: line_count.to_string(),
                },
                DocumentMetadata {
                    key: "source_byte_size".to_owned(),
                    value: bytes.len().to_string(),
                },
            ],
            text: vec![AdapterTextSpan {
                text: text.clone(),
                source_byte_range: valid_utf8.then_some((0, source_len)),
                page: None,
            }],
            pages: vec![AdapterPage {
                page: 1,
                media_type: "text/plain".to_owned(),
                bytes: text.into_bytes(),
                source_byte_range: valid_utf8.then_some((0, source_len)),
            }],
            conversion: None,
            active_content_observed: false,
            complete_claim: valid_utf8,
            warnings: Vec::new(),
            limitations,
        })
    }
}

/// Built-in passive HTML adapter. It extracts text only and never evaluates scripts, event
/// handlers, frames, objects, stylesheets or external resources.
#[derive(Debug, Default, Clone, Copy)]
pub struct SafeHtmlAdapter;

impl DocumentAdapter for SafeHtmlAdapter {
    fn adapter_id(&self) -> &'static str {
        "b03.safe-html"
    }

    fn supports_media_type(&self, media_type: &str) -> bool {
        matches!(media_type, "text/html" | "application/xhtml+xml")
    }

    fn isolation(&self) -> DocumentIsolation {
        DocumentIsolation::passive()
    }

    fn inspect(&self, bytes: &[u8], media_type: &str) -> Result<AdapterDocument, String> {
        let source = String::from_utf8_lossy(bytes);
        let active_content_observed = html_contains_active_content(&source);
        let title = extract_html_title(&source);
        let passive = remove_html_active_regions(&source);
        let text = html_to_text(&passive);
        let mut metadata = vec![
            DocumentMetadata {
                key: "media_type".to_owned(),
                value: media_type.to_owned(),
            },
            DocumentMetadata {
                key: "active_content_observed".to_owned(),
                value: active_content_observed.to_string(),
            },
        ];
        if let Some(title) = title {
            metadata.push(DocumentMetadata {
                key: "title".to_owned(),
                value: title,
            });
        }
        let mut limitations = vec![
            "HTML layout/CSS fidelity is not claimed by the passive text adapter".to_owned(),
            "external resources are not loaded".to_owned(),
        ];
        if std::str::from_utf8(bytes).is_err() {
            limitations
                .push("invalid UTF-8 sequences were replaced during HTML decoding".to_owned());
        }
        if active_content_observed {
            limitations
                .push("active/embedded HTML regions were removed before extraction".to_owned());
        }
        let converted = text.as_bytes().to_vec();
        Ok(AdapterDocument {
            metadata,
            text: vec![AdapterTextSpan {
                text: text.clone(),
                source_byte_range: None,
                page: None,
            }],
            pages: vec![AdapterPage {
                page: 1,
                media_type: "text/plain".to_owned(),
                bytes: converted.clone(),
                source_byte_range: None,
            }],
            conversion: Some(AdapterConversion {
                media_type: "text/plain".to_owned(),
                bytes: converted,
            }),
            active_content_observed,
            complete_claim: false,
            warnings: Vec::new(),
            limitations,
        })
    }
}

fn validate_context(context: &DocumentContext) -> Result<(), B03Error> {
    if context.source_revision_ref.entity_kind.as_str() != "object.revision" {
        return Err(B03Error::InvalidSourceRevision);
    }
    Ok(())
}

fn validate_limits(limits: DocumentLimits) -> Result<(), B03Error> {
    if limits.max_text_bytes == 0
        || limits.max_pages == 0
        || limits.max_page_render_bytes == 0
        || limits.max_preview_bytes == 0
        || limits.max_conversion_bytes == 0
    {
        return Err(B03Error::InvalidLimits);
    }
    Ok(())
}

fn validate_adapter_ids(adapters: &[&dyn DocumentAdapter]) -> Result<(), B03Error> {
    let mut seen = HashSet::new();
    for adapter in adapters {
        let id = adapter.adapter_id().trim();
        if id.is_empty() {
            return Err(B03Error::EmptyAdapterId);
        }
        if !seen.insert(id.to_owned()) {
            return Err(B03Error::DuplicateAdapterId(id.to_owned()));
        }
    }
    Ok(())
}

fn validate_adapter_output(output: &AdapterDocument, source_len: usize) -> Result<(), B03Error> {
    for field in &output.metadata {
        if field.key.trim().is_empty() {
            return Err(B03Error::EmptyMetadataKey);
        }
    }
    for span in &output.text {
        validate_range(span.source_byte_range, source_len)?;
        if span.page == Some(0) {
            return Err(B03Error::InvalidPage);
        }
    }
    let mut pages = HashSet::new();
    for page in &output.pages {
        if page.page == 0 || !pages.insert(page.page) {
            return Err(B03Error::InvalidPage);
        }
        if normalize_media_type(&page.media_type).is_empty() {
            return Err(B03Error::EmptyMediaType);
        }
        validate_range(page.source_byte_range, source_len)?;
    }
    if let Some(conversion) = &output.conversion
        && normalize_media_type(&conversion.media_type).is_empty()
    {
        return Err(B03Error::EmptyMediaType);
    }
    Ok(())
}

fn validate_range(range: Option<(u64, u64)>, source_len: usize) -> Result<(), B03Error> {
    if let Some((start, end)) = range {
        let source_len = u64::try_from(source_len).map_err(|_| B03Error::InvalidSourceRange)?;
        if start > end || end > source_len {
            return Err(B03Error::InvalidSourceRange);
        }
    }
    Ok(())
}

fn empty_report(
    source_sha256: String,
    source_revision_ref: EntityRef,
    agreed_media_type: Option<String>,
) -> DocumentReport {
    DocumentReport {
        source_sha256,
        source_revision_ref,
        agreed_media_type,
        adapter_id: None,
        metadata: Vec::new(),
        text: Vec::new(),
        pages: Vec::new(),
        preview: None,
        conversion: None,
        active_content_observed: false,
        coverage: DocumentCoverage {
            complete_claim: false,
            retained_text_bytes: 0,
            retained_pages: 0,
            unknown_gaps: Vec::new(),
        },
        warnings: Vec::new(),
        limitations: Vec::new(),
    }
}

fn retain_text(
    report: &mut DocumentReport,
    spans: Vec<AdapterTextSpan>,
    context: &DocumentContext,
    max_text_bytes: usize,
) -> Result<(), B03Error> {
    let mut remaining = max_text_bytes;
    for span in spans {
        if remaining == 0 {
            mark_gap(
                report,
                "text extraction truncated by B03 max_text_bytes".to_owned(),
            );
            break;
        }
        let (text, truncated) = truncate_utf8(&span.text, remaining);
        remaining = remaining.saturating_sub(text.len());
        let retained = u64::try_from(text.len()).map_err(|_| B03Error::AccountingOverflow)?;
        report.coverage.retained_text_bytes = report
            .coverage
            .retained_text_bytes
            .checked_add(retained)
            .ok_or(B03Error::AccountingOverflow)?;
        let (byte_start, byte_end_exclusive) = if truncated {
            (None, None)
        } else {
            span.source_byte_range
                .map_or((None, None), |(start, end)| (Some(start), Some(end)))
        };
        report.text.push(AnchoredText {
            text,
            anchor: SourceAnchor {
                source_revision_ref: context.source_revision_ref.clone(),
                byte_start,
                byte_end_exclusive,
                page: span.page,
            },
        });
        if truncated {
            mark_gap(
                report,
                "text extraction truncated by B03 max_text_bytes".to_owned(),
            );
            break;
        }
    }
    Ok(())
}

fn retain_pages(
    report: &mut DocumentReport,
    pages: Vec<AdapterPage>,
    context: &DocumentContext,
    max_pages: usize,
    max_page_render_bytes: usize,
) {
    let produced_page_count = pages.len();
    for page in pages.into_iter().take(max_pages) {
        if page.bytes.len() > max_page_render_bytes {
            mark_gap(
                report,
                format!(
                    "page {} render exceeds B03 max_page_render_bytes",
                    page.page
                ),
            );
            continue;
        }
        let (byte_start, byte_end_exclusive) = page
            .source_byte_range
            .map_or((None, None), |(start, end)| (Some(start), Some(end)));
        report.pages.push(DocumentPageView {
            page: page.page,
            media_type: normalize_media_type(&page.media_type),
            bytes: page.bytes,
            anchor: SourceAnchor {
                source_revision_ref: context.source_revision_ref.clone(),
                byte_start,
                byte_end_exclusive,
                page: Some(page.page),
            },
        });
    }
    if produced_page_count > max_pages {
        mark_gap(
            report,
            "page/render coverage exceeded B03 max_pages".to_owned(),
        );
    }
    report.coverage.retained_pages = report.pages.len();
}

fn build_preview(
    report: &DocumentReport,
    context: &DocumentContext,
    max_preview_bytes: usize,
) -> (Option<SafePreview>, bool) {
    let mut joined = String::new();
    for span in &report.text {
        if !joined.is_empty() {
            joined.push('\n');
        }
        joined.push_str(&span.text);
    }
    if joined.is_empty() {
        return (None, false);
    }
    let (text, truncated) = truncate_utf8(&joined, max_preview_bytes);
    (
        Some(SafePreview {
            media_type: "text/plain".to_owned(),
            bytes: text.into_bytes(),
            sanitized: true,
            source_revision_ref: context.source_revision_ref.clone(),
        }),
        truncated,
    )
}

fn retain_conversion(
    conversion: Option<AdapterConversion>,
    context: &DocumentContext,
    source_sha256: &str,
    adapter_id: &str,
    max_conversion_bytes: usize,
    coverage: &mut DocumentCoverage,
    limitations: &mut Vec<String>,
) -> Option<ConvertedDocument> {
    let conversion = conversion?;
    if conversion.bytes.len() > max_conversion_bytes {
        coverage.complete_claim = false;
        coverage
            .unknown_gaps
            .push("converted output exceeded B03 max_conversion_bytes".to_owned());
        limitations.push("converted output was not retained because it exceeded policy".to_owned());
        return None;
    }
    let sha256 = sha256_bytes(&conversion.bytes);
    Some(ConvertedDocument {
        media_type: normalize_media_type(&conversion.media_type),
        bytes: conversion.bytes,
        sha256,
        source_revision_ref: context.source_revision_ref.clone(),
        source_sha256: source_sha256.to_owned(),
        adapter_id: adapter_id.to_owned(),
    })
}

fn document_view_spec(
    context: &DocumentContext,
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

fn mark_gap(report: &mut DocumentReport, reason: String) {
    report.coverage.complete_claim = false;
    report.coverage.unknown_gaps.push(reason);
}

fn normalize_media_type(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn truncate_utf8(value: &str, max_bytes: usize) -> (String, bool) {
    if value.len() <= max_bytes {
        return (value.to_owned(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}

fn html_contains_active_content(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    ["<script", "<iframe", "<object", "<embed", "javascript:"]
        .iter()
        .any(|needle| lower.contains(needle))
        || contains_event_handler_attribute(&lower)
}

fn contains_event_handler_attribute(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut index = 0usize;
    while index + 3 < bytes.len() {
        if (bytes[index].is_ascii_whitespace() || bytes[index] == b'<')
            && bytes.get(index + 1) == Some(&b'o')
            && bytes.get(index + 2) == Some(&b'n')
        {
            let mut cursor = index + 3;
            let start = cursor;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric()
                    || matches!(bytes[cursor], b'_' | b'-' | b':'))
            {
                cursor += 1;
            }
            if cursor > start {
                while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
                if bytes.get(cursor) == Some(&b'=') {
                    return true;
                }
            }
        }
        index += 1;
    }
    false
}

fn remove_html_active_regions(value: &str) -> String {
    let without_scripts = remove_html_element(value, "script");
    let without_styles = remove_html_element(&without_scripts, "style");
    let without_iframes = remove_html_element(&without_styles, "iframe");
    let without_objects = remove_html_element(&without_iframes, "object");
    remove_html_void_tag(&without_objects, "embed")
}

fn remove_html_element(value: &str, tag: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let mut out = String::with_capacity(value.len());
    let mut cursor = 0usize;
    while let Some(start) = find_html_tag_start(&lower, cursor, tag, false) {
        out.push_str(&value[cursor..start]);
        let Some(open_end_relative) = lower[start..].find('>') else {
            cursor = value.len();
            break;
        };
        let open_end = start + open_end_relative;
        if tag_is_self_closing(&lower[start..=open_end]) {
            cursor = open_end + 1;
            continue;
        }

        let mut depth = 1usize;
        let mut scan = open_end + 1;
        let mut closed = false;
        while depth > 0 {
            let next_open = find_html_tag_start(&lower, scan, tag, false);
            let next_close = find_html_tag_start(&lower, scan, tag, true);
            let (next_start, is_close) = match (next_open, next_close) {
                (Some(open_start), Some(close_start)) if open_start < close_start => {
                    (open_start, false)
                }
                (_, Some(close_start)) => (close_start, true),
                (Some(open_start), None) => (open_start, false),
                (None, None) => {
                    scan = value.len();
                    break;
                }
            };
            let Some(end_relative) = lower[next_start..].find('>') else {
                scan = value.len();
                break;
            };
            let end = next_start + end_relative;
            if is_close {
                depth -= 1;
                if depth == 0 {
                    closed = true;
                }
            } else if !tag_is_self_closing(&lower[next_start..=end]) {
                depth += 1;
            }
            scan = end + 1;
        }
        if !closed {
            cursor = value.len();
            break;
        }
        cursor = scan;
    }
    if cursor < value.len() {
        out.push_str(&value[cursor..]);
    }
    out
}

fn find_html_tag_start(lower: &str, from: usize, tag: &str, closing: bool) -> Option<usize> {
    let needle = if closing {
        format!("</{tag}")
    } else {
        format!("<{tag}")
    };
    let mut cursor = from;
    while let Some(relative) = lower[cursor..].find(&needle) {
        let start = cursor + relative;
        let boundary = start + needle.len();
        let accepted = lower.as_bytes().get(boundary).is_none_or(|byte| {
            byte.is_ascii_whitespace() || matches!(*byte, b'>' | b'/')
        });
        if accepted {
            return Some(start);
        }
        cursor = boundary;
    }
    None
}

fn tag_is_self_closing(tag_source: &str) -> bool {
    tag_source
        .strip_suffix('>')
        .is_some_and(|prefix| prefix.trim_end().ends_with('/'))
}

fn remove_html_void_tag(value: &str, tag: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let open = format!("<{tag}");
    let mut out = String::with_capacity(value.len());
    let mut cursor = 0usize;
    while let Some(relative_start) = lower[cursor..].find(&open) {
        let start = cursor + relative_start;
        out.push_str(&value[cursor..start]);
        let Some(end_relative) = lower[start..].find('>') else {
            cursor = value.len();
            break;
        };
        cursor = start + end_relative + 1;
    }
    if cursor < value.len() {
        out.push_str(&value[cursor..]);
    }
    out
}

fn extract_html_title(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let start = start + lower[start..].find('>')? + 1;
    let end = start + lower[start..].find("</title>")?;
    let title = html_to_text(&value[start..end]);
    (!title.is_empty()).then_some(title)
}

fn html_to_text(value: &str) -> String {
    let mut raw = String::with_capacity(value.len());
    let mut in_tag = false;
    for ch in value.chars() {
        match ch {
            '<' => {
                in_tag = true;
                raw.push(' ');
            }
            '>' => {
                in_tag = false;
                raw.push(' ');
            }
            _ if !in_tag => raw.push(ch),
            _ => {}
        }
    }
    let decoded = raw
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
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
