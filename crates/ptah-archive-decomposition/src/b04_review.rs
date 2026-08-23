use crate::{b02::TypeAssessment, b04};
use ptah_identifiers::EntityRef;
use ptah_object_store::{OriginClass, ViewSpec};

const COMPLETE_DURATION_FRAME_SENTINEL: &str = "ptah.b04.provider_frame_beyond_complete_duration";

struct DurationCheckedAdapter<'a> {
    inner: &'a dyn b04::MediaAdapter,
}

impl b04::MediaAdapter for DurationCheckedAdapter<'_> {
    fn adapter_id(&self) -> &str {
        self.inner.adapter_id()
    }

    fn supports_media_type(&self, media_type: &str) -> bool {
        self.inner.supports_media_type(media_type)
    }

    fn isolation(&self) -> b04::MediaIsolation {
        self.inner.isolation()
    }

    fn inspect(
        &self,
        source_bytes: &[u8],
        media_type: &str,
        request: &b04::MediaRequest,
        limits: b04::MediaLimits,
    ) -> Result<b04::AdapterMedia, String> {
        let output = self
            .inner
            .inspect(source_bytes, media_type, request, limits)?;
        if output.duration.is_some_and(|duration| {
            duration.complete
                && output
                    .frames
                    .iter()
                    .any(|frame| frame.timestamp_ms > duration.milliseconds)
        }) {
            return Err(COMPLETE_DURATION_FRAME_SENTINEL.to_owned());
        }
        Ok(output)
    }
}

/// Reviewed B04 media inspection/derivation result exposed by the crate's public boundary.
#[derive(Debug, Clone)]
pub struct MediaReport {
    /// SHA-256 of immutable source bytes.
    pub source_sha256: String,
    /// Frozen exact source Revision.
    pub source_revision_ref: EntityRef,
    /// Normalized B02 agreed media type when one exists.
    pub agreed_media_type: Option<String>,
    /// Media family selected from the agreed type.
    pub media_class: Option<b04::MediaClass>,
    /// Selected adapter identity.
    pub adapter_id: Option<String>,
    /// Retained technical metadata.
    pub metadata: Vec<b04::MediaMetadata>,
    /// Pixel dimensions when established.
    pub dimensions: Option<b04::PixelDimensions>,
    /// Duration observation when applicable.
    pub duration: Option<b04::MediaDuration>,
    /// Optional retained thumbnail View.
    pub thumbnail: Option<b04::MediaView>,
    /// Optional retained preview View.
    pub preview: Option<b04::MediaView>,
    /// Retained sampled frame Views.
    pub frames: Vec<b04::MediaFrameView>,
    /// Optional retained waveform View.
    pub waveform: Option<b04::MediaView>,
    /// Retained transformed/transcoded outputs awaiting A07 registration/promotion.
    pub derivatives: Vec<b04::DerivedMedia>,
    /// Coverage/cache truth.
    pub coverage: b04::MediaCoverage,
    /// Warnings.
    pub warnings: Vec<String>,
    /// Limitations.
    pub limitations: Vec<String>,
}

impl From<b04::MediaReport> for MediaReport {
    fn from(report: b04::MediaReport) -> Self {
        Self {
            source_sha256: report.source_sha256,
            source_revision_ref: report.source_revision_ref,
            agreed_media_type: report.agreed_media_type,
            media_class: report.media_class,
            adapter_id: report.adapter_id,
            metadata: report.metadata,
            dimensions: report.dimensions,
            duration: report.duration,
            thumbnail: report.thumbnail,
            preview: report.preview,
            frames: report.frames,
            waveform: report.waveform,
            derivatives: report.derivatives,
            coverage: report.coverage,
            warnings: report.warnings,
            limitations: report.limitations,
        }
    }
}

impl MediaReport {
    /// Build canonical A07 View specifications over the exact source Revision.
    ///
    /// Coverage is always represented, including disputed type truth, non-media outcomes and
    /// agreed media types for which no adapter is registered.
    #[must_use]
    pub fn view_specs(&self, context: &b04::MediaContext) -> Vec<ViewSpec> {
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
        views.push(media_view_spec(
            context,
            &self.source_revision_ref,
            "media.coverage",
            "urn:ptah:schema:media:coverage-view:0.1.0",
        ));
        views
    }
}

/// Inspect and optionally derive one media Object through the reviewed B04 public boundary.
///
/// Every Provider adapter is wrapped before Core invocation so a Provider cannot report a sampled
/// frame beyond a duration it simultaneously claims was mechanically established as complete.
///
/// # Errors
/// Returns the underlying B04 error surface and maps impossible complete-duration frame output to
/// `B04Error::RequestOutputMismatch`.
pub fn inspect_media(
    source_bytes: &[u8],
    type_assessment: &TypeAssessment,
    context: &b04::MediaContext,
    request: &b04::MediaRequest,
    limits: b04::MediaLimits,
    adapters: &[&dyn b04::MediaAdapter],
) -> Result<MediaReport, b04::B04Error> {
    let guarded: Vec<_> = adapters
        .iter()
        .copied()
        .map(|inner| DurationCheckedAdapter { inner })
        .collect();
    let guarded_refs: Vec<&dyn b04::MediaAdapter> = guarded
        .iter()
        .map(|adapter| adapter as &dyn b04::MediaAdapter)
        .collect();

    match b04::inspect_media(
        source_bytes,
        type_assessment,
        context,
        request,
        limits,
        &guarded_refs,
    ) {
        Ok(report) => Ok(report.into()),
        Err(b04::B04Error::Adapter(message)) if message == COMPLETE_DURATION_FRAME_SENTINEL => {
            Err(b04::B04Error::RequestOutputMismatch)
        }
        Err(error) => Err(error),
    }
}

fn media_view_spec(
    context: &b04::MediaContext,
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
