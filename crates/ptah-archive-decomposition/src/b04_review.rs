use crate::{b02::TypeAssessment, b04};
use ptah_object_store::{OriginClass, ViewSpec};
use std::ops::{Deref, DerefMut};

const COMPLETE_DURATION_FRAME_SENTINEL: &str =
    "ptah.b04.provider_frame_beyond_complete_duration";

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

/// Reviewed B04 media report exposed by the crate's public boundary.
///
/// The wrapper preserves the underlying report surface through `Deref` while ensuring partial,
/// unsupported and no-adapter outcomes always retain a canonical coverage registration plan.
#[derive(Debug, Clone)]
pub struct MediaReport {
    inner: b04::MediaReport,
}

impl Deref for MediaReport {
    type Target = b04::MediaReport;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for MediaReport {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl MediaReport {
    /// Build canonical A07 View specifications over the exact source Revision.
    ///
    /// Coverage is always represented, including disputed type truth, non-media outcomes and
    /// agreed media types for which no adapter is registered.
    #[must_use]
    pub fn view_specs(&self, context: &b04::MediaContext) -> Vec<ViewSpec> {
        let mut views = self.inner.view_specs(context);
        if !views.iter().any(|view| view.view_kind == "media.coverage") {
            views.push(ViewSpec {
                workspace_ref: context.workspace_ref.clone(),
                authority_ref: context.authority_ref.clone(),
                view_kind: "media.coverage".to_owned(),
                view_schema_id: "urn:ptah:schema:media:coverage-view:0.1.0".to_owned(),
                view_schema_version: "0.1.0".to_owned(),
                source_revision_refs: vec![self.inner.source_revision_ref.clone()],
                origin_class: OriginClass::DecodedResource,
                production: context.production.clone(),
            });
        }
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
        Ok(report) => Ok(MediaReport { inner: report }),
        Err(b04::B04Error::Adapter(message))
            if message == COMPLETE_DURATION_FRAME_SENTINEL =>
        {
            Err(b04::B04Error::RequestOutputMismatch)
        }
        Err(error) => Err(error),
    }
}
