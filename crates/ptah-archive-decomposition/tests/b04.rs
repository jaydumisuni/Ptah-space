use ptah_archive_decomposition::{
    AdapterDerivedMedia, AdapterMedia, AdapterMediaFrame, AdapterMediaView, B04Error,
    DerivedMediaKind, ImageTransformOperation, ImageTransformRequest, MediaAdapter, MediaClass,
    MediaContext, MediaDuration, MediaIsolation, MediaLimits, MediaMetadata, MediaRequest,
    PixelDimensions, TranscodeRequest, TypeAgreement, TypeAssessment, inspect_media,
};
use ptah_identifiers::EntityRef;
use ptah_object_store::{ProductionEvidence, RevisionRole};
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicUsize, Ordering},
};

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

#[derive(Debug, Default)]
struct FullAdapter;

impl MediaAdapter for FullAdapter {
    fn adapter_id(&self) -> &'static str {
        "b04.fixture.full"
    }

    fn supports_media_type(&self, media_type: &str) -> bool {
        matches!(media_type, "image/png" | "audio/wav" | "video/mp4")
    }

    fn isolation(&self) -> MediaIsolation {
        MediaIsolation::passive()
    }

    fn inspect(
        &self,
        source_bytes: &[u8],
        media_type: &str,
        request: &MediaRequest,
        _limits: MediaLimits,
    ) -> Result<AdapterMedia, String> {
        let (dimensions, duration) = match media_type {
            "image/png" => (Some(PixelDimensions { width: 640, height: 480 }), None),
            "audio/wav" => (
                None,
                Some(MediaDuration {
                    milliseconds: 1_500,
                    complete: true,
                }),
            ),
            "video/mp4" => (
                Some(PixelDimensions {
                    width: 1_920,
                    height: 1_080,
                }),
                Some(MediaDuration {
                    milliseconds: 3_000,
                    complete: true,
                }),
            ),
            _ => return Err("unsupported fixture type".to_owned()),
        };
        let thumbnail = request.thumbnail.then(|| AdapterMediaView {
            media_type: "image/png".to_owned(),
            bytes: b"thumb".to_vec(),
        });
        let preview = request.preview.then(|| AdapterMediaView {
            media_type: if media_type == "audio/wav" {
                "audio/wav".to_owned()
            } else {
                "image/png".to_owned()
            },
            bytes: b"preview".to_vec(),
        });
        let frames = request
            .frame_timestamps_ms
            .iter()
            .map(|timestamp| AdapterMediaFrame {
                timestamp_ms: *timestamp,
                media_type: "image/png".to_owned(),
                bytes: format!("frame-{timestamp}").into_bytes(),
            })
            .collect();
        let waveform = request.waveform.then(|| AdapterMediaView {
            media_type: "application/vnd.ptah.waveform+json".to_owned(),
            bytes: b"[-2,0,2]".to_vec(),
        });
        let mut derivatives = Vec::new();
        if let Some(transform) = &request.image_transform {
            derivatives.push(AdapterDerivedMedia {
                kind: DerivedMediaKind::ImageTransform,
                media_type: transform.target_media_type.clone(),
                bytes: b"image-derived".to_vec(),
            });
        }
        if let Some(transcode) = &request.transcode {
            derivatives.push(AdapterDerivedMedia {
                kind: DerivedMediaKind::Transcode,
                media_type: transcode.target_media_type.clone(),
                bytes: b"transcoded-media".to_vec(),
            });
        }
        Ok(AdapterMedia {
            metadata: vec![
                MediaMetadata {
                    key: "container".to_owned(),
                    value: media_type.to_owned(),
                },
                MediaMetadata {
                    key: "fixture".to_owned(),
                    value: "full".to_owned(),
                },
            ],
            dimensions,
            duration,
            observed_source_bytes: source_bytes.len() as u64,
            thumbnail,
            preview,
            frames,
            waveform,
            derivatives,
            complete_claim: true,
            unknown_gaps: Vec::new(),
            warnings: Vec::new(),
            limitations: Vec::new(),
        })
    }
}

#[test]
fn image_inspection_retains_metadata_thumbnail_preview_and_frozen_views() {
    let source = b"immutable-png-fixture".to_vec();
    let source_before = source.clone();
    let source_context = context();
    let request = MediaRequest {
        thumbnail: true,
        preview: true,
        ..MediaRequest::default()
    };
    let report = inspect_media(
        &source,
        &agreed("image/png"),
        &source_context,
        &request,
        MediaLimits::default(),
        &[&FullAdapter],
    )
    .expect("image inspection");

    assert_eq!(source, source_before);
    assert_eq!(report.media_class, Some(MediaClass::Image));
    assert_eq!(
        report.dimensions,
        Some(PixelDimensions {
            width: 640,
            height: 480
        })
    );
    assert!(report.thumbnail.is_some());
    assert!(report.preview.is_some());
    assert!(report.coverage.complete_claim);

    let mut different_context = source_context.clone();
    different_context.source_revision_ref = reference("object.revision");
    assert_ne!(
        source_context.source_revision_ref,
        different_context.source_revision_ref
    );
    let views = report.view_specs(&different_context);
    assert!(views.len() >= 4);
    assert!(views.iter().all(|view| {
        view.source_revision_refs == vec![source_context.source_revision_ref.clone()]
    }));
}

#[test]
fn image_transform_is_new_converted_revision_and_requires_explicit_artifact_promotion() {
    let source_context = context();
    let request = MediaRequest {
        image_transform: Some(ImageTransformRequest {
            target_media_type: "image/webp".to_owned(),
            operation: ImageTransformOperation::Resize {
                width: 320,
                height: 240,
            },
        }),
        ..MediaRequest::default()
    };
    let report = inspect_media(
        b"image-source",
        &agreed("image/png"),
        &source_context,
        &request,
        MediaLimits::default(),
        &[&FullAdapter],
    )
    .expect("image transform");
    let derived = report.derivatives.first().expect("derived image");
    assert_eq!(derived.kind, DerivedMediaKind::ImageTransform);
    assert_eq!(derived.media_type, "image/webp");

    let mut different_context = source_context.clone();
    different_context.source_revision_ref = reference("object.revision");
    let registration = derived.registration_spec(&different_context);
    assert_eq!(
        registration.source_refs,
        vec![source_context.source_revision_ref.clone()]
    );
    assert_eq!(registration.revision_role, RevisionRole::Converted);
    assert_eq!(registration.expected_sha256, Some(derived.sha256.clone()));

    let promotion_production = production();
    let promotion = derived.artifact_promotion_spec(&different_context, promotion_production.clone());
    assert_eq!(promotion.artifact_type, "media.image_transform");
    assert_eq!(promotion.production.activity_ref, promotion_production.activity_ref);
    assert_eq!(
        promotion.subject_refs,
        vec![source_context.source_revision_ref]
    );
}

#[test]
fn audio_probe_retains_duration_waveform_and_controlled_transcode() {
    let request = MediaRequest {
        waveform: true,
        transcode: Some(TranscodeRequest {
            target_media_type: "audio/flac".to_owned(),
        }),
        ..MediaRequest::default()
    };
    let report = inspect_media(
        b"audio-source",
        &agreed("audio/wav"),
        &context(),
        &request,
        MediaLimits::default(),
        &[&FullAdapter],
    )
    .expect("audio probe");

    assert_eq!(report.media_class, Some(MediaClass::Audio));
    assert_eq!(
        report.duration,
        Some(MediaDuration {
            milliseconds: 1_500,
            complete: true
        })
    );
    assert!(report.waveform.is_some());
    assert!(report
        .derivatives
        .iter()
        .any(|item| item.kind == DerivedMediaKind::Transcode && item.media_type == "audio/flac"));
}

#[test]
fn video_probe_retains_requested_frames_preview_and_transcode() {
    let request = MediaRequest {
        preview: true,
        frame_timestamps_ms: vec![100, 500],
        waveform: true,
        transcode: Some(TranscodeRequest {
            target_media_type: "video/webm".to_owned(),
        }),
        ..MediaRequest::default()
    };
    let report = inspect_media(
        b"video-source",
        &agreed("video/mp4"),
        &context(),
        &request,
        MediaLimits::default(),
        &[&FullAdapter],
    )
    .expect("video probe");

    assert_eq!(report.media_class, Some(MediaClass::Video));
    assert_eq!(report.frames.len(), 2);
    assert_eq!(report.frames[0].timestamp_ms, 100);
    assert_eq!(report.frames[1].timestamp_ms, 500);
    assert_eq!(report.coverage.retained_frames, 2);
    assert!(report.preview.is_some());
    assert!(report.waveform.is_some());
    assert!(report.derivatives.iter().any(|item| {
        item.kind == DerivedMediaKind::Transcode && item.media_type == "video/webm"
    }));
}

struct PartialAdapter;

impl MediaAdapter for PartialAdapter {
    fn adapter_id(&self) -> &'static str {
        "b04.fixture.partial"
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
        _request: &MediaRequest,
        _limits: MediaLimits,
    ) -> Result<AdapterMedia, String> {
        Ok(AdapterMedia {
            metadata: Vec::new(),
            dimensions: None,
            duration: Some(MediaDuration {
                milliseconds: 9_999,
                complete: true,
            }),
            observed_source_bytes: (source_bytes.len() / 2) as u64,
            thumbnail: None,
            preview: None,
            frames: Vec::new(),
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
fn partial_source_probe_cannot_claim_full_duration_or_coverage() {
    let report = inspect_media(
        b"0123456789",
        &agreed("video/mp4"),
        &context(),
        &MediaRequest::default(),
        MediaLimits::default(),
        &[&PartialAdapter],
    )
    .expect("partial probe");

    assert!(!report.coverage.complete_claim);
    assert_eq!(report.coverage.observed_source_bytes, 5);
    assert_eq!(report.duration.expect("duration").complete, false);
    assert!(report
        .coverage
        .unknown_gaps
        .iter()
        .any(|gap| gap.contains("only part")));
    assert!(report
        .coverage
        .unknown_gaps
        .iter()
        .any(|gap| gap.contains("duration")));
}

#[test]
fn cached_view_budget_drops_late_view_and_records_partial_truth() {
    let request = MediaRequest {
        thumbnail: true,
        preview: true,
        ..MediaRequest::default()
    };
    let report = inspect_media(
        b"image-source",
        &agreed("image/png"),
        &context(),
        &request,
        MediaLimits {
            max_cached_view_bytes: 8,
            ..MediaLimits::default()
        },
        &[&FullAdapter],
    )
    .expect("bounded cache");

    assert_eq!(report.thumbnail.expect("thumbnail").bytes, b"thumb");
    assert!(report.preview.is_none());
    assert_eq!(report.coverage.cached_view_bytes, 5);
    assert!(!report.coverage.complete_claim);
    assert!(report
        .coverage
        .unknown_gaps
        .iter()
        .any(|gap| gap.contains("cached-View")));
}

#[test]
fn oversized_derivative_is_not_retained_or_promoted_by_claim() {
    let request = MediaRequest {
        transcode: Some(TranscodeRequest {
            target_media_type: "audio/flac".to_owned(),
        }),
        ..MediaRequest::default()
    };
    let report = inspect_media(
        b"audio-source",
        &agreed("audio/wav"),
        &context(),
        &request,
        MediaLimits {
            max_derived_bytes: 4,
            ..MediaLimits::default()
        },
        &[&FullAdapter],
    )
    .expect("bounded derivative");

    assert!(report.derivatives.is_empty());
    assert!(!report.coverage.complete_claim);
    assert!(report
        .coverage
        .unknown_gaps
        .iter()
        .any(|gap| gap.contains("max_derived_bytes")));
}

struct CountingAdapter<'a>(&'a AtomicUsize);

impl MediaAdapter for CountingAdapter<'_> {
    fn adapter_id(&self) -> &'static str {
        "b04.fixture.counting"
    }

    fn supports_media_type(&self, _media_type: &str) -> bool {
        true
    }

    fn isolation(&self) -> MediaIsolation {
        MediaIsolation::passive()
    }

    fn inspect(
        &self,
        _source_bytes: &[u8],
        _media_type: &str,
        _request: &MediaRequest,
        _limits: MediaLimits,
    ) -> Result<AdapterMedia, String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err("must not be called".to_owned())
    }
}

#[test]
fn disputed_and_non_media_type_truth_never_selects_a_media_adapter() {
    let calls = AtomicUsize::new(0);
    let adapter = CountingAdapter(&calls);
    let disputed = TypeAssessment {
        declared_type: Some("video/mp4".to_owned()),
        detector_evidence: Vec::new(),
        agreement: TypeAgreement::Disputed(vec!["video/mp4".to_owned(), "image/png".to_owned()]),
        declared_matches_agreed_type: None,
    };
    let disputed_report = inspect_media(
        b"bytes",
        &disputed,
        &context(),
        &MediaRequest::default(),
        MediaLimits::default(),
        &[&adapter],
    )
    .expect("disputed truth remains partial");
    assert!(disputed_report.adapter_id.is_none());

    let non_media_report = inspect_media(
        b"text",
        &agreed("text/plain"),
        &context(),
        &MediaRequest::default(),
        MediaLimits::default(),
        &[&adapter],
    )
    .expect("non-media truth remains outside B04");
    assert!(non_media_report.adapter_id.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

struct UnsafeAdapter<'a>(&'a AtomicUsize);

impl MediaAdapter for UnsafeAdapter<'_> {
    fn adapter_id(&self) -> &'static str {
        "b04.fixture.unsafe"
    }

    fn supports_media_type(&self, media_type: &str) -> bool {
        media_type == "image/png"
    }

    fn isolation(&self) -> MediaIsolation {
        MediaIsolation {
            active_content_execution: ptah_archive_decomposition::MediaIsolationPolicy::Allowed,
            network_access: ptah_archive_decomposition::MediaIsolationPolicy::Denied,
            external_resource_loading: ptah_archive_decomposition::MediaIsolationPolicy::Denied,
        }
    }

    fn inspect(
        &self,
        _source_bytes: &[u8],
        _media_type: &str,
        _request: &MediaRequest,
        _limits: MediaLimits,
    ) -> Result<AdapterMedia, String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err("unsafe adapter must never inspect source bytes".to_owned())
    }
}

#[test]
fn unsafe_adapter_is_rejected_before_media_bytes_are_inspected() {
    let calls = AtomicUsize::new(0);
    let adapter = UnsafeAdapter(&calls);
    let error = inspect_media(
        b"image",
        &agreed("image/png"),
        &context(),
        &MediaRequest::default(),
        MediaLimits::default(),
        &[&adapter],
    )
    .expect_err("unsafe adapter must fail closed");

    assert!(matches!(error, B04Error::UnsafeAdapterIsolation(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn ambiguous_media_adapters_fail_closed_without_provider_selection() {
    let error = inspect_media(
        b"image",
        &agreed("image/png"),
        &context(),
        &MediaRequest::default(),
        MediaLimits::default(),
        &[&FullAdapter, &FullAdapter],
    )
    .expect_err("ambiguous adapters must fail");
    assert!(matches!(error, B04Error::DuplicateAdapterId(_)));

    struct OtherAdapter;
    impl MediaAdapter for OtherAdapter {
        fn adapter_id(&self) -> &'static str {
            "b04.fixture.other"
        }
        fn supports_media_type(&self, media_type: &str) -> bool {
            media_type == "image/png"
        }
        fn isolation(&self) -> MediaIsolation {
            MediaIsolation::passive()
        }
        fn inspect(
            &self,
            _source_bytes: &[u8],
            _media_type: &str,
            _request: &MediaRequest,
            _limits: MediaLimits,
        ) -> Result<AdapterMedia, String> {
            unreachable!("ambiguity is rejected before inspection")
        }
    }

    let error = inspect_media(
        b"image",
        &agreed("image/png"),
        &context(),
        &MediaRequest::default(),
        MediaLimits::default(),
        &[&FullAdapter, &OtherAdapter],
    )
    .expect_err("two distinct matching adapters must fail closed");
    assert!(matches!(error, B04Error::AmbiguousAdapter(_)));
}

struct UnrequestedPreviewAdapter;

impl MediaAdapter for UnrequestedPreviewAdapter {
    fn adapter_id(&self) -> &'static str {
        "b04.fixture.unrequested"
    }

    fn supports_media_type(&self, media_type: &str) -> bool {
        media_type == "image/png"
    }

    fn isolation(&self) -> MediaIsolation {
        MediaIsolation::passive()
    }

    fn inspect(
        &self,
        source_bytes: &[u8],
        _media_type: &str,
        _request: &MediaRequest,
        _limits: MediaLimits,
    ) -> Result<AdapterMedia, String> {
        Ok(AdapterMedia {
            metadata: Vec::new(),
            dimensions: None,
            duration: None,
            observed_source_bytes: source_bytes.len() as u64,
            thumbnail: None,
            preview: Some(AdapterMediaView {
                media_type: "image/png".to_owned(),
                bytes: b"surprise".to_vec(),
            }),
            frames: Vec::new(),
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
fn provider_cannot_smuggle_unrequested_expensive_output() {
    let error = inspect_media(
        b"image",
        &agreed("image/png"),
        &context(),
        &MediaRequest::default(),
        MediaLimits::default(),
        &[&UnrequestedPreviewAdapter],
    )
    .expect_err("unrequested output must be rejected");
    assert!(matches!(error, B04Error::UnrequestedOutput("preview")));
}

#[test]
fn cross_family_or_unbounded_requests_fail_before_provider_work() {
    let audio_frames = MediaRequest {
        frame_timestamps_ms: vec![0],
        ..MediaRequest::default()
    };
    assert!(matches!(
        inspect_media(
            b"audio",
            &agreed("audio/wav"),
            &context(),
            &audio_frames,
            MediaLimits::default(),
            &[&FullAdapter]
        ),
        Err(B04Error::InvalidRequest(_))
    ));

    let video_image_transform = MediaRequest {
        image_transform: Some(ImageTransformRequest {
            target_media_type: "image/png".to_owned(),
            operation: ImageTransformOperation::Reencode,
        }),
        ..MediaRequest::default()
    };
    assert!(matches!(
        inspect_media(
            b"video",
            &agreed("video/mp4"),
            &context(),
            &video_image_transform,
            MediaLimits::default(),
            &[&FullAdapter]
        ),
        Err(B04Error::InvalidRequest(_))
    ));

    let image_transcode = MediaRequest {
        transcode: Some(TranscodeRequest {
            target_media_type: "image/webp".to_owned(),
        }),
        ..MediaRequest::default()
    };
    assert!(matches!(
        inspect_media(
            b"image",
            &agreed("image/png"),
            &context(),
            &image_transcode,
            MediaLimits::default(),
            &[&FullAdapter]
        ),
        Err(B04Error::InvalidRequest(_))
    ));
}

struct OverclaimAdapter;

impl MediaAdapter for OverclaimAdapter {
    fn adapter_id(&self) -> &'static str {
        "b04.fixture.overclaim"
    }

    fn supports_media_type(&self, media_type: &str) -> bool {
        media_type == "audio/wav"
    }

    fn isolation(&self) -> MediaIsolation {
        MediaIsolation::passive()
    }

    fn inspect(
        &self,
        source_bytes: &[u8],
        _media_type: &str,
        _request: &MediaRequest,
        _limits: MediaLimits,
    ) -> Result<AdapterMedia, String> {
        Ok(AdapterMedia {
            metadata: Vec::new(),
            dimensions: None,
            duration: None,
            observed_source_bytes: source_bytes.len() as u64 + 1,
            thumbnail: None,
            preview: None,
            frames: Vec::new(),
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
fn provider_cannot_claim_observation_beyond_source_extent() {
    let error = inspect_media(
        b"audio",
        &agreed("audio/wav"),
        &context(),
        &MediaRequest::default(),
        MediaLimits::default(),
        &[&OverclaimAdapter],
    )
    .expect_err("source overclaim must fail");
    assert!(matches!(error, B04Error::InvalidObservedSourceBytes));
}

struct BlockingTranscodeAdapter {
    started: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl MediaAdapter for BlockingTranscodeAdapter {
    fn adapter_id(&self) -> &'static str {
        "b04.fixture.blocking-transcode"
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
        self.started.wait();
        self.release.wait();
        let transcode = request
            .transcode
            .as_ref()
            .ok_or_else(|| "fixture requires transcode".to_owned())?;
        Ok(AdapterMedia {
            metadata: Vec::new(),
            dimensions: None,
            duration: Some(MediaDuration {
                milliseconds: 1,
                complete: true,
            }),
            observed_source_bytes: source_bytes.len() as u64,
            thumbnail: None,
            preview: None,
            frames: Vec::new(),
            waveform: None,
            derivatives: vec![AdapterDerivedMedia {
                kind: DerivedMediaKind::Transcode,
                media_type: transcode.target_media_type.clone(),
                bytes: b"heavy-result".to_vec(),
            }],
            complete_claim: true,
            unknown_gaps: Vec::new(),
            warnings: Vec::new(),
            limitations: Vec::new(),
        })
    }
}

#[test]
fn blocked_heavy_transcode_does_not_serialize_unrelated_media_inspection() {
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let blocking = BlockingTranscodeAdapter {
        started: Arc::clone(&started),
        release: Arc::clone(&release),
    };
    let heavy_request = MediaRequest {
        transcode: Some(TranscodeRequest {
            target_media_type: "video/webm".to_owned(),
        }),
        ..MediaRequest::default()
    };
    let heavy_context = context();

    std::thread::scope(|scope| {
        let heavy = scope.spawn(|| {
            inspect_media(
                b"heavy-video",
                &agreed("video/mp4"),
                &heavy_context,
                &heavy_request,
                MediaLimits::default(),
                &[&blocking],
            )
        });

        started.wait();
        let quick = inspect_media(
            b"independent-image",
            &agreed("image/png"),
            &context(),
            &MediaRequest::default(),
            MediaLimits::default(),
            &[&FullAdapter],
        )
        .expect("unrelated inspection must remain runnable");
        assert_eq!(quick.media_class, Some(MediaClass::Image));
        release.wait();

        let heavy = heavy.join().expect("heavy thread joins").expect("heavy result");
        assert!(heavy
            .derivatives
            .iter()
            .any(|item| item.kind == DerivedMediaKind::Transcode));
    });
}
