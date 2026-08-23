use crate::{TypeAgreement, TypeAssessment};
use ptah_identifiers::EntityRef;
use ptah_object_store::{
    ArtifactPromotionSpec, OriginClass, ProductionEvidence, RegisterObjectSpec, RevisionRole,
    ViewSpec,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

/// B04 media family selected from B02 agreed type truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaClass {
    /// Image media such as PNG, JPEG, WebP or other image Provider formats.
    Image,
    /// Audio media.
    Audio,
    /// Video media.
    Video,
}

impl MediaClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Audio => "audio",
            Self::Video => "video",
        }
    }
}

/// Resource and cache bounds applied by the B04 Core boundary after Provider work returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaLimits {
    /// Maximum retained metadata fields.
    pub max_metadata_fields: usize,
    /// Maximum retained thumbnail bytes.
    pub max_thumbnail_bytes: usize,
    /// Maximum retained preview bytes.
    pub max_preview_bytes: usize,
    /// Maximum retained frame count.
    pub max_frames: usize,
    /// Maximum retained bytes for any one sampled frame.
    pub max_frame_bytes: usize,
    /// Maximum retained waveform-view bytes.
    pub max_waveform_bytes: usize,
    /// Maximum aggregate bytes retained across thumbnail/preview/frame/waveform Views.
    pub max_cached_view_bytes: usize,
    /// Maximum retained bytes for one transformed or transcoded derivative.
    pub max_derived_bytes: usize,
}

impl Default for MediaLimits {
    fn default() -> Self {
        Self {
            max_metadata_fields: 256,
            max_thumbnail_bytes: 2 * 1024 * 1024,
            max_preview_bytes: 8 * 1024 * 1024,
            max_frames: 32,
            max_frame_bytes: 8 * 1024 * 1024,
            max_waveform_bytes: 2 * 1024 * 1024,
            max_cached_view_bytes: 64 * 1024 * 1024,
            max_derived_bytes: 128 * 1024 * 1024,
        }
    }
}

/// Whether a media Provider is permitted to use one potentially active capability during B04 work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaIsolationPolicy {
    /// Capability is denied.
    Denied,
    /// Capability is allowed.
    Allowed,
}

/// Passive isolation declaration required from a B04 media Provider adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaIsolation {
    /// Execute active content embedded in media/container metadata.
    pub active_content_execution: MediaIsolationPolicy,
    /// Provider-originated network access while inspecting or transforming source bytes.
    pub network_access: MediaIsolationPolicy,
    /// Load external resources referenced by media/container metadata.
    pub external_resource_loading: MediaIsolationPolicy,
}

impl MediaIsolation {
    /// Strict passive B04 policy.
    #[must_use]
    pub const fn passive() -> Self {
        Self {
            active_content_execution: MediaIsolationPolicy::Denied,
            network_access: MediaIsolationPolicy::Denied,
            external_resource_loading: MediaIsolationPolicy::Denied,
        }
    }

    const fn is_safe(self) -> bool {
        matches!(self.active_content_execution, MediaIsolationPolicy::Denied)
            && matches!(self.network_access, MediaIsolationPolicy::Denied)
            && matches!(self.external_resource_loading, MediaIsolationPolicy::Denied)
    }
}

/// Exact source and A04 evidence used by B04 registration plans.
#[derive(Debug, Clone)]
pub struct MediaContext {
    /// Workspace owning source and derived records.
    pub workspace_ref: EntityRef,
    /// Exact authority for the B04 operation.
    pub authority_ref: EntityRef,
    /// Immutable source Object Revision.
    pub source_revision_ref: EntityRef,
    /// Exact producing A04 evidence.
    pub production: ProductionEvidence,
}

/// Image transform requested by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageTransformOperation {
    /// Resize to exact non-zero pixel dimensions.
    Resize {
        /// Target width.
        width: u32,
        /// Target height.
        height: u32,
    },
    /// Rotate clockwise by one, two or three quarter-turns.
    RotateQuarterTurns {
        /// Number of clockwise 90-degree turns.
        quarter_turns: u8,
    },
    /// Re-encode without a geometric transform.
    Reencode,
}

/// Controlled image transformation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageTransformRequest {
    /// Exact requested output media type.
    pub target_media_type: String,
    /// Exact transformation operation.
    pub operation: ImageTransformOperation,
}

/// Controlled audio/video transcode request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscodeRequest {
    /// Exact requested output media type. B04 requires the same media family as the source.
    pub target_media_type: String,
}

/// Caller-selected B04 outputs. Expensive derivatives are never produced implicitly by Core.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MediaRequest {
    /// Request one bounded thumbnail View.
    pub thumbnail: bool,
    /// Request one bounded preview View.
    pub preview: bool,
    /// Optional controlled image transform.
    pub image_transform: Option<ImageTransformRequest>,
    /// Video frame timestamps requested in milliseconds.
    pub frame_timestamps_ms: Vec<u64>,
    /// Request one bounded waveform View for audio-bearing media.
    pub waveform: bool,
    /// Optional controlled audio/video transcode.
    pub transcode: Option<TranscodeRequest>,
}

/// Provider-supplied metadata field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaMetadata {
    /// Stable technical key.
    pub key: String,
    /// Exact observed value.
    pub value: String,
}

/// Pixel dimensions when mechanically established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelDimensions {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

/// Duration observation. `complete` distinguishes a bounded estimate/partial probe from full duration truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaDuration {
    /// Observed duration in milliseconds.
    pub milliseconds: u64,
    /// Whether the Provider mechanically established full duration coverage.
    pub complete: bool,
}

/// Provider payload for a passive thumbnail, preview or waveform View.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterMediaView {
    /// Payload media type.
    pub media_type: String,
    /// Exact payload bytes.
    pub bytes: Vec<u8>,
}

/// Provider-produced sampled video frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterMediaFrame {
    /// Requested sample timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Frame payload media type.
    pub media_type: String,
    /// Exact frame bytes.
    pub bytes: Vec<u8>,
}

/// Kind of caller-requested derived media output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DerivedMediaKind {
    /// Image transformation output.
    ImageTransform,
    /// Audio/video transcode output.
    Transcode,
}

impl DerivedMediaKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ImageTransform => "image_transform",
            Self::Transcode => "transcode",
        }
    }
}

/// Provider-produced derivative before B04 attaches immutable source provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterDerivedMedia {
    /// Requested derivative kind.
    pub kind: DerivedMediaKind,
    /// Exact output media type.
    pub media_type: String,
    /// Exact output bytes.
    pub bytes: Vec<u8>,
}

/// Bounded mechanical output returned by one media Provider adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterMedia {
    /// Technical metadata observations.
    pub metadata: Vec<MediaMetadata>,
    /// Pixel dimensions when established.
    pub dimensions: Option<PixelDimensions>,
    /// Duration observation when applicable.
    pub duration: Option<MediaDuration>,
    /// Number of source bytes mechanically inspected by the Provider.
    pub observed_source_bytes: u64,
    /// Optional requested thumbnail.
    pub thumbnail: Option<AdapterMediaView>,
    /// Optional requested preview.
    pub preview: Option<AdapterMediaView>,
    /// Requested sampled frames produced by the Provider.
    pub frames: Vec<AdapterMediaFrame>,
    /// Optional requested waveform.
    pub waveform: Option<AdapterMediaView>,
    /// Caller-requested transformed/transcoded outputs.
    pub derivatives: Vec<AdapterDerivedMedia>,
    /// Whether the Provider claims complete supported media coverage.
    pub complete_claim: bool,
    /// Explicit unknown/unsupported ranges or semantic gaps.
    pub unknown_gaps: Vec<String>,
    /// Provider warnings.
    pub warnings: Vec<String>,
    /// Provider limitations.
    pub limitations: Vec<String>,
}

/// Replaceable passive B04 media Provider boundary.
pub trait MediaAdapter: Send + Sync {
    /// Stable Provider adapter identity.
    fn adapter_id(&self) -> &str;

    /// Whether this adapter supports the exact normalized B02 agreed media type.
    fn supports_media_type(&self, media_type: &str) -> bool;

    /// Passive isolation declaration.
    fn isolation(&self) -> MediaIsolation;

    /// Inspect and optionally derive media under the exact caller request and declared limits.
    ///
    /// Core still validates and independently bounds every returned payload; Provider acknowledgement
    /// cannot create a B04 success claim by itself.
    ///
    /// # Errors
    /// Returns a Provider-specific mechanical failure.
    fn inspect(
        &self,
        source_bytes: &[u8],
        media_type: &str,
        request: &MediaRequest,
        limits: MediaLimits,
    ) -> Result<AdapterMedia, String>;
}

/// Retained passive media View payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaView {
    /// View media type.
    pub media_type: String,
    /// Exact retained bytes.
    pub bytes: Vec<u8>,
    /// Frozen exact source Revision.
    pub source_revision_ref: EntityRef,
}

/// Retained sampled video frame View.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaFrameView {
    /// Requested sample timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Frame media type.
    pub media_type: String,
    /// Exact retained frame bytes.
    pub bytes: Vec<u8>,
    /// Frozen exact source Revision.
    pub source_revision_ref: EntityRef,
}

/// Transformed/transcoded bytes bound to one exact immutable source Revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedMedia {
    /// Derivative operation class.
    pub kind: DerivedMediaKind,
    /// Exact output media type.
    pub media_type: String,
    /// Exact derived bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of derived bytes.
    pub sha256: String,
    /// Frozen exact source Revision.
    pub source_revision_ref: EntityRef,
    /// SHA-256 of immutable source bytes.
    pub source_sha256: String,
    /// Adapter that produced these bytes.
    pub adapter_id: String,
}

impl DerivedMedia {
    /// Build the A07 registration request for this derivative as a new immutable converted Revision.
    ///
    /// Source provenance comes from this frozen result, never from a later caller context.
    #[must_use]
    pub fn registration_spec(&self, context: &MediaContext) -> RegisterObjectSpec {
        RegisterObjectSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            object_class: format!("media.{}", self.kind.as_str()),
            declared_name: None,
            source_refs: vec![self.source_revision_ref.clone()],
            revision_role: RevisionRole::Converted,
            origin_class: OriginClass::Generated,
            created_reason: format!(
                "B04 {} derivative produced by {}",
                self.kind.as_str(),
                self.adapter_id
            ),
            production: context.production.clone(),
            expected_sha256: Some(self.sha256.clone()),
        }
    }

    /// Build the explicit second-step A07 Artifact-promotion request.
    ///
    /// The caller must supply distinct promotion production evidence; A07 validates that it targets
    /// the exact registered derivative Revision and is not the derivative-production operation.
    #[must_use]
    pub fn artifact_promotion_spec(
        &self,
        context: &MediaContext,
        promotion_production: ProductionEvidence,
    ) -> ArtifactPromotionSpec {
        ArtifactPromotionSpec {
            workspace_ref: context.workspace_ref.clone(),
            authority_ref: context.authority_ref.clone(),
            artifact_type: format!("media.{}", self.kind.as_str()),
            artifact_version: "1".to_owned(),
            purpose: format!(
                "Promote reviewed B04 {} derivative from exact source Revision",
                self.kind.as_str()
            ),
            subject_refs: vec![self.source_revision_ref.clone()],
            production: promotion_production,
        }
    }
}

/// Truthful B04 coverage and cache accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaCoverage {
    /// Whether complete supported coverage may be claimed.
    pub complete_claim: bool,
    /// Number of source bytes the Provider reported inspecting.
    pub observed_source_bytes: u64,
    /// Aggregate retained bytes across cacheable thumbnail/preview/frame/waveform Views.
    pub cached_view_bytes: u64,
    /// Number of sampled frames retained.
    pub retained_frames: usize,
    /// Explicit omitted/partial/unsupported regions.
    pub unknown_gaps: Vec<String>,
}

/// B04 media inspection/derivation result.
#[derive(Debug, Clone)]
pub struct MediaReport {
    /// SHA-256 of immutable source bytes.
    pub source_sha256: String,
    /// Frozen exact source Revision.
    pub source_revision_ref: EntityRef,
    /// Normalized B02 agreed media type when one exists.
    pub agreed_media_type: Option<String>,
    /// Media family selected from the agreed type.
    pub media_class: Option<MediaClass>,
    /// Selected adapter identity.
    pub adapter_id: Option<String>,
    /// Retained technical metadata.
    pub metadata: Vec<MediaMetadata>,
    /// Pixel dimensions when established.
    pub dimensions: Option<PixelDimensions>,
    /// Duration observation when applicable.
    pub duration: Option<MediaDuration>,
    /// Optional retained thumbnail View.
    pub thumbnail: Option<MediaView>,
    /// Optional retained preview View.
    pub preview: Option<MediaView>,
    /// Retained sampled frame Views.
    pub frames: Vec<MediaFrameView>,
    /// Optional retained waveform View.
    pub waveform: Option<MediaView>,
    /// Retained transformed/transcoded outputs awaiting A07 registration/promotion.
    pub derivatives: Vec<DerivedMedia>,
    /// Coverage/cache truth.
    pub coverage: MediaCoverage,
    /// Warnings.
    pub warnings: Vec<String>,
    /// Limitations.
    pub limitations: Vec<String>,
}

impl MediaReport {
    /// Build canonical A07 View specifications over the exact source Revision.
    ///
    /// A later caller context cannot rebind the report to another source Revision.
    #[must_use]
    pub fn view_specs(&self, context: &MediaContext) -> Vec<ViewSpec> {
        let mut views = Vec::new();
        if !self.metadata.is_empty() || self.dimensions.is_some() || self.duration.is_some() {
            views.push(media_view_spec(
                context,
                &self.source_revision_ref,
                "media.technical_metadata",
                "urn:ptah:schema:media:technical-metadata-view:0.1.0",
            ));
        }
        if self.thumbnail.is_some() {
            views.push(media_view_spec(
                context,
                &self.source_revision_ref,
                "media.thumbnail",
                "urn:ptah:schema:media:thumbnail-view:0.1.0",
            ));
        }
        if self.preview.is_some() {
            views.push(media_view_spec(
                context,
                &self.source_revision_ref,
                "media.preview",
                "urn:ptah:schema:media:preview-view:0.1.0",
            ));
        }
        for _frame in &self.frames {
            views.push(media_view_spec(
                context,
                &self.source_revision_ref,
                "media.frame",
                "urn:ptah:schema:media:frame-view:0.1.0",
            ));
        }
        if self.waveform.is_some() {
            views.push(media_view_spec(
                context,
                &self.source_revision_ref,
                "media.waveform",
                "urn:ptah:schema:media:waveform-view:0.1.0",
            ));
        }
        if self.adapter_id.is_some() {
            views.push(media_view_spec(
                context,
                &self.source_revision_ref,
                "media.coverage",
                "urn:ptah:schema:media:coverage-view:0.1.0",
            ));
        }
        views
    }
}

/// B04 errors that prevent truthful media interpretation or derivation.
#[derive(Debug, Error)]
pub enum B04Error {
    /// Source reference is not an exact Object Revision.
    #[error("B04 source must be an exact object.revision reference")]
    InvalidSourceRevision,
    /// One or more resource limits are zero.
    #[error("B04 media limits must all be greater than zero")]
    InvalidLimits,
    /// Caller requested an operation incompatible with the selected media family or limits.
    #[error("invalid B04 media request: {0}")]
    InvalidRequest(&'static str),
    /// Adapter identity is empty.
    #[error("B04 media adapter identity must not be empty")]
    EmptyAdapterId,
    /// Adapter identity is duplicated.
    #[error("duplicate B04 media adapter identity: {0}")]
    DuplicateAdapterId(String),
    /// More than one adapter claims the exact same selected media type.
    #[error("ambiguous B04 media adapters for media type {0}")]
    AmbiguousAdapter(String),
    /// Adapter isolation declaration is not passive.
    #[error(
        "B04 media adapter does not deny active content, network and external resource loading: {0}"
    )]
    UnsafeAdapterIsolation(String),
    /// Provider failed mechanically.
    #[error("B04 media adapter failed: {0}")]
    Adapter(String),
    /// Provider claims to have inspected more bytes than exist.
    #[error("B04 media adapter observed source bytes outside the immutable source")]
    InvalidObservedSourceBytes,
    /// Provider emitted an empty metadata key.
    #[error("B04 media adapter emitted an empty metadata key")]
    EmptyMetadataKey,
    /// Provider emitted zero pixel dimensions.
    #[error("B04 media adapter emitted zero pixel dimensions")]
    InvalidDimensions,
    /// Provider emitted an empty/invalid payload media type.
    #[error("B04 media adapter emitted an empty media type")]
    EmptyMediaType,
    /// Provider emitted an empty retained/derived payload.
    #[error("B04 media adapter emitted an empty payload")]
    EmptyPayload,
    /// Provider emitted work that the caller did not request.
    #[error("B04 media adapter emitted unrequested output: {0}")]
    UnrequestedOutput(&'static str),
    /// Provider emitted a duplicate sampled frame timestamp or derivative kind.
    #[error("B04 media adapter emitted duplicate output identity")]
    DuplicateOutput,
    /// Provider returned output that does not match the exact caller request.
    #[error("B04 media adapter output does not match the exact caller request")]
    RequestOutputMismatch,
    /// Numeric accounting exceeded representable bounds.
    #[error("B04 media byte accounting overflow")]
    AccountingOverflow,
}

/// Inspect and optionally derive one media Object under B02 type truth and B04 passive policy.
///
/// Unknown, disputed and non-media agreed types remain explicit partial results. Expensive outputs
/// exist only when the caller requests them. B04 never mutates source bytes and never promotes a
/// derivative to Artifact implicitly.
///
/// # Errors
/// Fails on invalid source/context/limits/request, ambiguous/unsafe adapters, malformed Provider
/// output, Provider failure or accounting overflow.
pub fn inspect_media(
    source_bytes: &[u8],
    type_assessment: &TypeAssessment,
    context: &MediaContext,
    request: &MediaRequest,
    limits: MediaLimits,
    adapters: &[&dyn MediaAdapter],
) -> Result<MediaReport, B04Error> {
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
                TypeAgreement::Unknown => "B02 did not establish an agreed media type".to_owned(),
                TypeAgreement::Disputed(values) => format!(
                    "B02 detector disagreement prevents media adapter selection: {}",
                    values.join(", ")
                ),
                TypeAgreement::Agreed(_) => unreachable!("agreed media type was extracted above"),
            });
        return Ok(report);
    };

    let Some(media_class) = media_class_for_type(&media_type) else {
        report.coverage.unknown_gaps.push(format!(
            "B02 agreed type {media_type} is outside the B04 image/audio/video domain"
        ));
        return Ok(report);
    };
    report.media_class = Some(media_class);
    validate_request(request, media_class, limits)?;

    let matching: Vec<&dyn MediaAdapter> = adapters
        .iter()
        .copied()
        .filter(|adapter| adapter.supports_media_type(&media_type))
        .collect();
    if matching.len() > 1 {
        return Err(B04Error::AmbiguousAdapter(media_type));
    }
    let Some(adapter) = matching.first().copied() else {
        report.coverage.unknown_gaps.push(format!(
            "no B04 media adapter is registered for agreed type {media_type}"
        ));
        return Ok(report);
    };
    let adapter_id = adapter.adapter_id().trim().to_owned();
    if !adapter.isolation().is_safe() {
        return Err(B04Error::UnsafeAdapterIsolation(adapter_id));
    }

    let output = adapter
        .inspect(source_bytes, &media_type, request, limits)
        .map_err(B04Error::Adapter)?;
    validate_adapter_output(&output, source_bytes.len(), media_class, request)?;

    report.adapter_id = Some(adapter_id.clone());
    report.metadata = retain_metadata(
        output.metadata,
        limits.max_metadata_fields,
        &mut report.coverage,
    );
    report.dimensions = output.dimensions;
    report.duration = output.duration;
    report.coverage.observed_source_bytes = output.observed_source_bytes;
    report.coverage.complete_claim = output.complete_claim;
    report.coverage.unknown_gaps.extend(output.unknown_gaps);
    report.warnings = output.warnings;
    report.limitations = output.limitations;

    let source_len = u64::try_from(source_bytes.len()).map_err(|_| B04Error::AccountingOverflow)?;
    if report.coverage.observed_source_bytes < source_len {
        mark_gap(
            &mut report,
            "media Provider inspected only part of the immutable source bytes".to_owned(),
        );
        if let Some(duration) = &mut report.duration {
            duration.complete = false;
        }
    }
    if !output.complete_claim && report.coverage.unknown_gaps.is_empty() {
        mark_gap(
            &mut report,
            "media Provider reported partial supported coverage".to_owned(),
        );
    }
    if report.duration.is_some_and(|duration| !duration.complete) {
        mark_gap(
            &mut report,
            "full media duration was not mechanically established".to_owned(),
        );
    }

    report.thumbnail = retain_view(
        output.thumbnail,
        context,
        "thumbnail",
        limits.max_thumbnail_bytes,
        limits.max_cached_view_bytes,
        &mut report.coverage,
        &mut report.limitations,
    )?;
    if request.thumbnail && report.thumbnail.is_none() {
        mark_gap(
            &mut report,
            "requested media thumbnail was not retained".to_owned(),
        );
    }

    report.preview = retain_view(
        output.preview,
        context,
        "preview",
        limits.max_preview_bytes,
        limits.max_cached_view_bytes,
        &mut report.coverage,
        &mut report.limitations,
    )?;
    if request.preview && report.preview.is_none() {
        mark_gap(
            &mut report,
            "requested media preview was not retained".to_owned(),
        );
    }

    retain_frames(
        &mut report,
        output.frames,
        context,
        limits.max_frames,
        limits.max_frame_bytes,
        limits.max_cached_view_bytes,
    )?;
    for timestamp in &request.frame_timestamps_ms {
        if !report
            .frames
            .iter()
            .any(|frame| frame.timestamp_ms == *timestamp)
        {
            mark_gap(
                &mut report,
                format!("requested frame at {timestamp} ms was not retained"),
            );
        }
    }

    report.waveform = retain_view(
        output.waveform,
        context,
        "waveform",
        limits.max_waveform_bytes,
        limits.max_cached_view_bytes,
        &mut report.coverage,
        &mut report.limitations,
    )?;
    if request.waveform && report.waveform.is_none() {
        mark_gap(
            &mut report,
            "requested media waveform was not retained".to_owned(),
        );
    }

    retain_derivatives(
        &mut report,
        output.derivatives,
        context,
        request,
        limits.max_derived_bytes,
        &source_sha256,
        &adapter_id,
    );
    if request.image_transform.is_some()
        && !report
            .derivatives
            .iter()
            .any(|derived| derived.kind == DerivedMediaKind::ImageTransform)
    {
        mark_gap(
            &mut report,
            "requested image transformation was not retained".to_owned(),
        );
    }
    if request.transcode.is_some()
        && !report
            .derivatives
            .iter()
            .any(|derived| derived.kind == DerivedMediaKind::Transcode)
    {
        mark_gap(
            &mut report,
            "requested media transcode was not retained".to_owned(),
        );
    }

    if !report.coverage.unknown_gaps.is_empty() {
        report.coverage.complete_claim = false;
    }
    dedup_strings(&mut report.coverage.unknown_gaps);
    dedup_strings(&mut report.warnings);
    dedup_strings(&mut report.limitations);
    debug_assert_eq!(source_sha256, sha256_bytes(source_bytes));
    Ok(report)
}

fn validate_context(context: &MediaContext) -> Result<(), B04Error> {
    if context.source_revision_ref.entity_kind.as_str() != "object.revision" {
        return Err(B04Error::InvalidSourceRevision);
    }
    Ok(())
}

fn validate_limits(limits: MediaLimits) -> Result<(), B04Error> {
    if limits.max_metadata_fields == 0
        || limits.max_thumbnail_bytes == 0
        || limits.max_preview_bytes == 0
        || limits.max_frames == 0
        || limits.max_frame_bytes == 0
        || limits.max_waveform_bytes == 0
        || limits.max_cached_view_bytes == 0
        || limits.max_derived_bytes == 0
    {
        return Err(B04Error::InvalidLimits);
    }
    Ok(())
}

fn validate_adapter_ids(adapters: &[&dyn MediaAdapter]) -> Result<(), B04Error> {
    let mut seen = HashSet::new();
    for adapter in adapters {
        let id = adapter.adapter_id().trim();
        if id.is_empty() {
            return Err(B04Error::EmptyAdapterId);
        }
        if !seen.insert(id.to_owned()) {
            return Err(B04Error::DuplicateAdapterId(id.to_owned()));
        }
    }
    Ok(())
}

fn validate_request(
    request: &MediaRequest,
    media_class: MediaClass,
    limits: MediaLimits,
) -> Result<(), B04Error> {
    if request.frame_timestamps_ms.len() > limits.max_frames {
        return Err(B04Error::InvalidRequest(
            "requested frame count exceeds max_frames",
        ));
    }
    let mut frame_times = HashSet::new();
    if !request
        .frame_timestamps_ms
        .iter()
        .all(|timestamp| frame_times.insert(*timestamp))
    {
        return Err(B04Error::InvalidRequest(
            "duplicate requested frame timestamp",
        ));
    }
    if !request.frame_timestamps_ms.is_empty() && media_class != MediaClass::Video {
        return Err(B04Error::InvalidRequest(
            "frame sampling requires video media",
        ));
    }
    if request.waveform && media_class == MediaClass::Image {
        return Err(B04Error::InvalidRequest(
            "waveform generation requires audio or video media",
        ));
    }
    if let Some(transform) = &request.image_transform {
        if media_class != MediaClass::Image {
            return Err(B04Error::InvalidRequest(
                "image transformation requires image media",
            ));
        }
        require_target_class(&transform.target_media_type, MediaClass::Image)?;
        match transform.operation {
            ImageTransformOperation::Resize { width, height } if width == 0 || height == 0 => {
                return Err(B04Error::InvalidRequest(
                    "image resize dimensions must be non-zero",
                ));
            }
            ImageTransformOperation::RotateQuarterTurns { quarter_turns }
                if !(1..=3).contains(&quarter_turns) =>
            {
                return Err(B04Error::InvalidRequest(
                    "quarter-turn rotation must be one, two or three",
                ));
            }
            _ => {}
        }
    }
    if let Some(transcode) = &request.transcode {
        if media_class == MediaClass::Image {
            return Err(B04Error::InvalidRequest(
                "audio/video transcode cannot be requested for image media",
            ));
        }
        require_target_class(&transcode.target_media_type, media_class)?;
    }
    Ok(())
}

fn require_target_class(value: &str, expected: MediaClass) -> Result<(), B04Error> {
    let normalized = normalize_media_type(value);
    if normalized.is_empty() || media_class_for_type(&normalized) != Some(expected) {
        return Err(B04Error::InvalidRequest(
            "target media type must remain in the requested media family",
        ));
    }
    Ok(())
}

fn validate_adapter_output(
    output: &AdapterMedia,
    source_len: usize,
    media_class: MediaClass,
    request: &MediaRequest,
) -> Result<(), B04Error> {
    let source_len = u64::try_from(source_len).map_err(|_| B04Error::InvalidObservedSourceBytes)?;
    if output.observed_source_bytes > source_len {
        return Err(B04Error::InvalidObservedSourceBytes);
    }
    if output
        .metadata
        .iter()
        .any(|field| field.key.trim().is_empty())
    {
        return Err(B04Error::EmptyMetadataKey);
    }
    if output
        .dimensions
        .is_some_and(|dimensions| dimensions.width == 0 || dimensions.height == 0)
    {
        return Err(B04Error::InvalidDimensions);
    }
    validate_optional_view(&output.thumbnail)?;
    validate_optional_view(&output.preview)?;
    validate_optional_view(&output.waveform)?;
    if output.thumbnail.is_some() && !request.thumbnail {
        return Err(B04Error::UnrequestedOutput("thumbnail"));
    }
    if output.preview.is_some() && !request.preview {
        return Err(B04Error::UnrequestedOutput("preview"));
    }
    if output.waveform.is_some() && !request.waveform {
        return Err(B04Error::UnrequestedOutput("waveform"));
    }

    let requested_frames: HashSet<u64> = request.frame_timestamps_ms.iter().copied().collect();
    let mut returned_frames = HashSet::new();
    for frame in &output.frames {
        validate_payload(&frame.media_type, &frame.bytes)?;
        if !requested_frames.contains(&frame.timestamp_ms) {
            return Err(B04Error::UnrequestedOutput("frame"));
        }
        if !returned_frames.insert(frame.timestamp_ms) {
            return Err(B04Error::DuplicateOutput);
        }
    }

    let mut derivative_kinds = HashSet::new();
    for derived in &output.derivatives {
        validate_payload(&derived.media_type, &derived.bytes)?;
        if !derivative_kinds.insert(derived.kind) {
            return Err(B04Error::DuplicateOutput);
        }
        match derived.kind {
            DerivedMediaKind::ImageTransform => {
                let Some(transform) = &request.image_transform else {
                    return Err(B04Error::UnrequestedOutput("image_transform"));
                };
                if media_class != MediaClass::Image
                    || normalize_media_type(&derived.media_type)
                        != normalize_media_type(&transform.target_media_type)
                {
                    return Err(B04Error::RequestOutputMismatch);
                }
            }
            DerivedMediaKind::Transcode => {
                let Some(transcode) = &request.transcode else {
                    return Err(B04Error::UnrequestedOutput("transcode"));
                };
                if media_class == MediaClass::Image
                    || normalize_media_type(&derived.media_type)
                        != normalize_media_type(&transcode.target_media_type)
                {
                    return Err(B04Error::RequestOutputMismatch);
                }
            }
        }
    }
    Ok(())
}

fn validate_optional_view(view: &Option<AdapterMediaView>) -> Result<(), B04Error> {
    if let Some(view) = view {
        validate_payload(&view.media_type, &view.bytes)?;
    }
    Ok(())
}

fn validate_payload(media_type: &str, bytes: &[u8]) -> Result<(), B04Error> {
    if normalize_media_type(media_type).is_empty() {
        return Err(B04Error::EmptyMediaType);
    }
    if bytes.is_empty() {
        return Err(B04Error::EmptyPayload);
    }
    Ok(())
}

fn empty_report(
    source_sha256: String,
    source_revision_ref: EntityRef,
    agreed_media_type: Option<String>,
) -> MediaReport {
    MediaReport {
        source_sha256,
        source_revision_ref,
        agreed_media_type,
        media_class: None,
        adapter_id: None,
        metadata: Vec::new(),
        dimensions: None,
        duration: None,
        thumbnail: None,
        preview: None,
        frames: Vec::new(),
        waveform: None,
        derivatives: Vec::new(),
        coverage: MediaCoverage {
            complete_claim: false,
            observed_source_bytes: 0,
            cached_view_bytes: 0,
            retained_frames: 0,
            unknown_gaps: Vec::new(),
        },
        warnings: Vec::new(),
        limitations: Vec::new(),
    }
}

fn retain_metadata(
    metadata: Vec<MediaMetadata>,
    max_fields: usize,
    coverage: &mut MediaCoverage,
) -> Vec<MediaMetadata> {
    let produced = metadata.len();
    let retained: Vec<_> = metadata.into_iter().take(max_fields).collect();
    if produced > max_fields {
        coverage.complete_claim = false;
        coverage
            .unknown_gaps
            .push("media metadata exceeded B04 max_metadata_fields".to_owned());
    }
    retained
}

fn retain_view(
    view: Option<AdapterMediaView>,
    context: &MediaContext,
    label: &str,
    max_payload_bytes: usize,
    max_cached_view_bytes: usize,
    coverage: &mut MediaCoverage,
    limitations: &mut Vec<String>,
) -> Result<Option<MediaView>, B04Error> {
    let Some(view) = view else {
        return Ok(None);
    };
    if view.bytes.len() > max_payload_bytes {
        coverage.complete_claim = false;
        coverage.unknown_gaps.push(format!(
            "media {label} exceeded its B04 per-View byte limit"
        ));
        limitations.push(format!("oversized media {label} was not retained"));
        return Ok(None);
    }
    if !cache_bytes_fit(coverage, view.bytes.len(), max_cached_view_bytes)? {
        coverage.complete_claim = false;
        coverage.unknown_gaps.push(format!(
            "media {label} exceeded B04 aggregate cached-View policy"
        ));
        limitations.push(format!(
            "media {label} was not retained because the cached-View budget was exhausted"
        ));
        return Ok(None);
    }
    Ok(Some(MediaView {
        media_type: normalize_media_type(&view.media_type),
        bytes: view.bytes,
        source_revision_ref: context.source_revision_ref.clone(),
    }))
}

fn retain_frames(
    report: &mut MediaReport,
    frames: Vec<AdapterMediaFrame>,
    context: &MediaContext,
    max_frames: usize,
    max_frame_bytes: usize,
    max_cached_view_bytes: usize,
) -> Result<(), B04Error> {
    let produced = frames.len();
    for frame in frames.into_iter().take(max_frames) {
        if frame.bytes.len() > max_frame_bytes {
            mark_gap(
                report,
                format!(
                    "frame at {} ms exceeded B04 max_frame_bytes",
                    frame.timestamp_ms
                ),
            );
            report.limitations.push(format!(
                "oversized frame at {} ms was not retained",
                frame.timestamp_ms
            ));
            continue;
        }
        if !cache_bytes_fit(
            &mut report.coverage,
            frame.bytes.len(),
            max_cached_view_bytes,
        )? {
            mark_gap(
                report,
                format!(
                    "frame at {} ms exceeded B04 aggregate cached-View policy",
                    frame.timestamp_ms
                ),
            );
            report.limitations.push(format!(
                "frame at {} ms was not retained because the cached-View budget was exhausted",
                frame.timestamp_ms
            ));
            continue;
        }
        report.frames.push(MediaFrameView {
            timestamp_ms: frame.timestamp_ms,
            media_type: normalize_media_type(&frame.media_type),
            bytes: frame.bytes,
            source_revision_ref: context.source_revision_ref.clone(),
        });
    }
    if produced > max_frames {
        mark_gap(report, "sampled frames exceeded B04 max_frames".to_owned());
    }
    report.coverage.retained_frames = report.frames.len();
    Ok(())
}

fn cache_bytes_fit(
    coverage: &mut MediaCoverage,
    additional: usize,
    max_cached_view_bytes: usize,
) -> Result<bool, B04Error> {
    let additional = u64::try_from(additional).map_err(|_| B04Error::AccountingOverflow)?;
    let max = u64::try_from(max_cached_view_bytes).map_err(|_| B04Error::AccountingOverflow)?;
    let Some(next) = coverage.cached_view_bytes.checked_add(additional) else {
        return Err(B04Error::AccountingOverflow);
    };
    if next > max {
        return Ok(false);
    }
    coverage.cached_view_bytes = next;
    Ok(true)
}

fn retain_derivatives(
    report: &mut MediaReport,
    derivatives: Vec<AdapterDerivedMedia>,
    context: &MediaContext,
    _request: &MediaRequest,
    max_derived_bytes: usize,
    source_sha256: &str,
    adapter_id: &str,
) {
    for derivative in derivatives {
        if derivative.bytes.len() > max_derived_bytes {
            mark_gap(
                report,
                format!(
                    "{} output exceeded B04 max_derived_bytes",
                    derivative.kind.as_str()
                ),
            );
            report.limitations.push(format!(
                "oversized {} output was not retained",
                derivative.kind.as_str()
            ));
            continue;
        }
        let sha256 = sha256_bytes(&derivative.bytes);
        report.derivatives.push(DerivedMedia {
            kind: derivative.kind,
            media_type: normalize_media_type(&derivative.media_type),
            bytes: derivative.bytes,
            sha256,
            source_revision_ref: context.source_revision_ref.clone(),
            source_sha256: source_sha256.to_owned(),
            adapter_id: adapter_id.to_owned(),
        });
    }
}

fn media_view_spec(
    context: &MediaContext,
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

fn mark_gap(report: &mut MediaReport, reason: String) {
    report.coverage.complete_claim = false;
    report.coverage.unknown_gaps.push(reason);
}

fn media_class_for_type(media_type: &str) -> Option<MediaClass> {
    if media_type.starts_with("image/") {
        Some(MediaClass::Image)
    } else if media_type.starts_with("audio/") {
        Some(MediaClass::Audio)
    } else if media_type.starts_with("video/") {
        Some(MediaClass::Video)
    } else {
        None
    }
}

fn normalize_media_type(value: &str) -> String {
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
