//! B04 semantic Review regressions for coverage registration and complete-duration frame truth.

use ptah_archive_decomposition::{
    AdapterMedia, AdapterMediaFrame, B04Error, MediaAdapter, MediaContext, MediaDuration,
    MediaIsolation, MediaLimits, MediaRequest, TypeAgreement, TypeAssessment, inspect_media,
};
use ptah_identifiers::EntityRef;
use ptah_object_store::ProductionEvidence;

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid fixture reference")
}

fn production() -> ProductionEvidence {
    ProductionEvidence {
        activity_ref: reference("core.activity"),
        operation_ref: reference("core.operation"),
        attempt_ref: reference("core.attempt"),
        receipt_refs: vec![reference("proof.receipt")],
    }
}

fn context() -> MediaContext {
    MediaContext {
        workspace_ref: reference("core.workspace"),
        authority_ref: reference("auth.authority"),
        source_revision_ref: reference("object.revision"),
        production: production(),
    }
}

fn agreed(media_type: &str) -> TypeAssessment {
    TypeAssessment {
        declared_type: Some(media_type.to_owned()),
        detector_evidence: Vec::new(),
        agreement: TypeAgreement::Agreed(media_type.to_owned()),
        declared_matches_agreed_type: Some(true),
    }
}

#[test]
fn partial_and_no_adapter_reports_emit_coverage_view_plans() {
    let disputed = TypeAssessment {
        declared_type: Some("image/png".to_owned()),
        detector_evidence: Vec::new(),
        agreement: TypeAgreement::Disputed(vec!["image/png".to_owned(), "image/jpeg".to_owned()]),
        declared_matches_agreed_type: None,
    };
    let disputed_report = inspect_media(
        b"ambiguous-media",
        &disputed,
        &context(),
        &MediaRequest::default(),
        MediaLimits::default(),
        &[],
    )
    .expect("disputed media remains a truthful partial report");
    assert!(disputed_report.adapter_id.is_none());
    assert!(!disputed_report.coverage.unknown_gaps.is_empty());
    assert!(
        disputed_report
            .view_specs(&context())
            .iter()
            .any(|view| view.view_kind == "media.coverage")
    );

    let no_adapter_report = inspect_media(
        b"known-media",
        &agreed("image/png"),
        &context(),
        &MediaRequest::default(),
        MediaLimits::default(),
        &[],
    )
    .expect("known media without an adapter remains a truthful partial report");
    assert!(no_adapter_report.adapter_id.is_none());
    assert!(!no_adapter_report.coverage.unknown_gaps.is_empty());
    assert!(
        no_adapter_report
            .view_specs(&context())
            .iter()
            .any(|view| view.view_kind == "media.coverage")
    );
}

struct ImpossibleFrameAdapter;

impl MediaAdapter for ImpossibleFrameAdapter {
    fn adapter_id(&self) -> &'static str {
        "b04.review.impossible-frame"
    }

    fn supports_media_type(&self, media_type: &str) -> bool {
        media_type == "video/mp4"
    }

    fn isolation(&self) -> MediaIsolation {
        MediaIsolation::passive()
    }

    fn inspect(
        &self,
        source_bytes: &[u8],
        _media_type: &str,
        request: &MediaRequest,
        _limits: MediaLimits,
    ) -> Result<AdapterMedia, String> {
        let timestamp_ms = request
            .frame_timestamps_ms
            .first()
            .copied()
            .ok_or_else(|| "fixture requires one requested frame".to_owned())?;
        Ok(AdapterMedia {
            metadata: Vec::new(),
            dimensions: None,
            duration: Some(MediaDuration {
                milliseconds: 1_000,
                complete: true,
            }),
            observed_source_bytes: source_bytes.len() as u64,
            thumbnail: None,
            preview: None,
            frames: vec![AdapterMediaFrame {
                timestamp_ms,
                media_type: "image/png".to_owned(),
                bytes: b"impossible-frame".to_vec(),
            }],
            waveform: None,
            derivatives: Vec::new(),
            complete_claim: true,
            unknown_gaps: Vec::new(),
            warnings: Vec::new(),
            limitations: Vec::new(),
        })
    }
}

#[test]
fn frame_beyond_complete_duration_is_rejected_before_core_acceptance() {
    let request = MediaRequest {
        frame_timestamps_ms: vec![1_001],
        ..MediaRequest::default()
    };
    let error = inspect_media(
        b"video",
        &agreed("video/mp4"),
        &context(),
        &request,
        MediaLimits::default(),
        &[&ImpossibleFrameAdapter],
    )
    .expect_err("frame beyond complete duration must fail closed");
    assert!(matches!(error, B04Error::RequestOutputMismatch));
}
