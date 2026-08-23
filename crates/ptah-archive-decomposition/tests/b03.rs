//! B03 documents and structured-text acceptance regressions.

use ptah_archive_decomposition::{
    AdapterConversion, AdapterDocument, AdapterPage, AdapterTextSpan, B03Error, DocumentAdapter,
    DocumentContext, DocumentIsolation, DocumentLimits, DocumentMetadata, IsolationPolicy,
    SafeHtmlAdapter, SafeTextAdapter, TypeAgreement, TypeAssessment, inspect_document,
};
use ptah_identifiers::EntityRef;
use ptah_object_store::{ProductionEvidence, RevisionRole};
use std::cell::Cell;

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid fixture reference")
}

fn context() -> DocumentContext {
    DocumentContext {
        workspace_ref: reference("core.workspace"),
        authority_ref: reference("auth.authority"),
        source_revision_ref: reference("object.revision"),
        production: ProductionEvidence {
            activity_ref: reference("core.activity"),
            operation_ref: reference("core.operation"),
            attempt_ref: reference("core.attempt"),
            receipt_refs: vec![reference("proof.receipt")],
        },
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

struct FixtureAdapter {
    id: &'static str,
    media_types: &'static [&'static str],
    isolation: DocumentIsolation,
    output: AdapterDocument,
    calls: Cell<usize>,
}

impl FixtureAdapter {
    fn passive(
        id: &'static str,
        media_types: &'static [&'static str],
        output: AdapterDocument,
    ) -> Self {
        Self {
            id,
            media_types,
            isolation: DocumentIsolation::passive(),
            output,
            calls: Cell::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl DocumentAdapter for FixtureAdapter {
    fn adapter_id(&self) -> &str {
        self.id
    }

    fn supports_media_type(&self, media_type: &str) -> bool {
        self.media_types.contains(&media_type)
    }

    fn isolation(&self) -> DocumentIsolation {
        self.isolation
    }

    fn inspect(&self, _bytes: &[u8], _media_type: &str) -> Result<AdapterDocument, String> {
        self.calls.set(self.calls.get() + 1);
        Ok(self.output.clone())
    }
}

fn fixture_output(label: &str) -> AdapterDocument {
    AdapterDocument {
        metadata: vec![DocumentMetadata {
            key: "fixture".to_owned(),
            value: label.to_owned(),
        }],
        text: vec![AdapterTextSpan {
            text: format!("{label} extracted text"),
            source_byte_range: None,
            page: Some(1),
        }],
        pages: vec![AdapterPage {
            page: 1,
            media_type: "text/plain".to_owned(),
            bytes: format!("{label} rendered page").into_bytes(),
            source_byte_range: None,
        }],
        conversion: None,
        active_content_observed: false,
        complete_claim: false,
        warnings: Vec::new(),
        limitations: vec![format!("{label} fixture does not claim layout fidelity")],
    }
}

#[test]
fn structured_text_extracts_exact_byte_and_revision_anchor() {
    let source = b"first line\nsecond line\n";
    let context = context();
    let adapter = SafeTextAdapter;
    let report = inspect_document(
        source,
        &agreed("text/plain"),
        &context,
        DocumentLimits::default(),
        &[&adapter],
    )
    .expect("structured text inspection");

    assert_eq!(report.agreed_media_type.as_deref(), Some("text/plain"));
    assert_eq!(report.adapter_id.as_deref(), Some("b03.safe-text"));
    assert_eq!(report.text.len(), 1);
    assert_eq!(report.text[0].text, "first line\nsecond line\n");
    assert_eq!(
        report.text[0].anchor.source_revision_ref,
        context.source_revision_ref
    );
    assert_eq!(report.text[0].anchor.byte_start, Some(0));
    assert_eq!(
        report.text[0].anchor.byte_end_exclusive,
        Some(source.len() as u64)
    );
    assert!(report.coverage.complete_claim);
    assert_eq!(report.coverage.unknown_gaps, Vec::<String>::new());
}

#[test]
fn malicious_html_is_stripped_to_passive_preview_without_mutating_source() {
    let source = br#"<!doctype html><html><head><title>Safe title</title><script>window.evil='owned'</script><style>body{background:url(https://evil.invalid/x)}</style></head><body onclick="steal()">Hello <iframe src="https://evil.invalid/frame">frame payload</iframe> world<img src="https://evil.invalid/pixel"></body></html>"#;
    let original = source.to_vec();
    let context = context();
    let adapter = SafeHtmlAdapter;
    let report = inspect_document(
        source,
        &agreed("text/html"),
        &context,
        DocumentLimits::default(),
        &[&adapter],
    )
    .expect("safe HTML inspection");

    assert_eq!(source, original.as_slice());
    assert!(report.active_content_observed);
    assert!(!report.coverage.complete_claim);
    assert!(
        report
            .limitations
            .iter()
            .any(|item| item.contains("external resources"))
    );
    let preview = report.preview.expect("passive preview");
    let preview_text = String::from_utf8(preview.bytes).expect("UTF-8 preview");
    assert_eq!(preview.media_type, "text/plain");
    assert!(preview.sanitized);
    assert!(preview_text.contains("Hello"));
    assert!(preview_text.contains("world"));
    assert!(!preview_text.contains("window.evil"));
    assert!(!preview_text.contains("evil.invalid"));
    assert!(!preview_text.contains("steal()"));
    let conversion = report.conversion.expect("safe text conversion");
    assert_eq!(conversion.media_type, "text/plain");
    assert_eq!(conversion.source_revision_ref, context.source_revision_ref);
}

#[test]
fn disputed_type_remains_explicit_and_no_document_adapter_runs() {
    let output = fixture_output("unused");
    let adapter = FixtureAdapter::passive("fixture", &["application/pdf"], output);
    let assessment = TypeAssessment {
        declared_type: None,
        detector_evidence: Vec::new(),
        agreement: TypeAgreement::Disputed(vec![
            "application/pdf".to_owned(),
            "text/html".to_owned(),
        ]),
        declared_matches_agreed_type: None,
    };
    let report = inspect_document(
        b"disputed",
        &assessment,
        &context(),
        DocumentLimits::default(),
        &[&adapter],
    )
    .expect("explicit disputed report");

    assert_eq!(adapter.calls(), 0);
    assert!(report.adapter_id.is_none());
    assert!(!report.coverage.complete_claim);
    assert!(
        report
            .coverage
            .unknown_gaps
            .iter()
            .any(|item| item.contains("detector disagreement"))
    );
}

#[test]
fn unsupported_agreed_document_type_is_explicit_without_false_extraction() {
    let adapter = SafeTextAdapter;
    let report = inspect_document(
        b"opaque",
        &agreed("application/x-unknown-document"),
        &context(),
        DocumentLimits::default(),
        &[&adapter],
    )
    .expect("unsupported report");

    assert!(report.adapter_id.is_none());
    assert!(report.text.is_empty());
    assert!(report.pages.is_empty());
    assert!(
        report
            .coverage
            .unknown_gaps
            .iter()
            .any(|item| item.contains("no B03 document adapter"))
    );
}

#[test]
fn unsafe_adapter_is_rejected_before_document_bytes_are_inspected() {
    let mut adapter =
        FixtureAdapter::passive("unsafe-pdf", &["application/pdf"], fixture_output("pdf"));
    adapter.isolation.network_access = IsolationPolicy::Allowed;
    let result = inspect_document(
        b"%PDF-fixture",
        &agreed("application/pdf"),
        &context(),
        DocumentLimits::default(),
        &[&adapter],
    );

    assert!(matches!(result, Err(B03Error::UnsafeAdapterIsolation(ref id)) if id == "unsafe-pdf"));
    assert_eq!(adapter.calls(), 0);
}

#[test]
fn ambiguous_document_adapters_fail_closed_without_choosing_a_winner() {
    let first = FixtureAdapter::passive("pdf-a", &["application/pdf"], fixture_output("pdf-a"));
    let second = FixtureAdapter::passive("pdf-b", &["application/pdf"], fixture_output("pdf-b"));
    let result = inspect_document(
        b"%PDF-fixture",
        &agreed("application/pdf"),
        &context(),
        DocumentLimits::default(),
        &[&first, &second],
    );

    assert!(
        matches!(result, Err(B03Error::AmbiguousAdapter(ref value)) if value == "application/pdf")
    );
    assert_eq!(first.calls(), 0);
    assert_eq!(second.calls(), 0);
}

#[test]
fn pdf_and_office_adapter_boundaries_preserve_render_limitations_and_revision_anchors() {
    let pdf = FixtureAdapter::passive("lawful-pdf", &["application/pdf"], fixture_output("pdf"));
    let office = FixtureAdapter::passive(
        "lawful-office",
        &["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
        fixture_output("office"),
    );
    let context = context();
    let adapters: [&dyn DocumentAdapter; 2] = [&pdf, &office];

    let pdf_report = inspect_document(
        b"%PDF-fixture",
        &agreed("application/pdf"),
        &context,
        DocumentLimits::default(),
        &adapters,
    )
    .expect("PDF adapter report");
    assert_eq!(pdf.calls(), 1);
    assert_eq!(
        pdf_report.pages[0].anchor.source_revision_ref,
        context.source_revision_ref
    );
    assert!(
        pdf_report
            .limitations
            .iter()
            .any(|item| item.contains("layout fidelity"))
    );
    assert!(!pdf_report.coverage.complete_claim);

    let office_report = inspect_document(
        b"PK-office-fixture",
        &agreed("application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        &context,
        DocumentLimits::default(),
        &adapters,
    )
    .expect("office adapter report");
    assert_eq!(office.calls(), 1);
    assert_eq!(
        office_report.pages[0].anchor.source_revision_ref,
        context.source_revision_ref
    );
    assert!(
        office_report
            .limitations
            .iter()
            .any(|item| item.contains("layout fidelity"))
    );
}

#[test]
fn resource_limits_downgrade_coverage_and_never_overclaim_truncated_output() {
    let output = AdapterDocument {
        metadata: Vec::new(),
        text: vec![AdapterTextSpan {
            text: "abcdefghijklmnopqrstuvwxyz".to_owned(),
            source_byte_range: None,
            page: Some(1),
        }],
        pages: vec![
            AdapterPage {
                page: 1,
                media_type: "text/plain".to_owned(),
                bytes: b"page-one".to_vec(),
                source_byte_range: None,
            },
            AdapterPage {
                page: 2,
                media_type: "text/plain".to_owned(),
                bytes: b"page-two".to_vec(),
                source_byte_range: None,
            },
        ],
        conversion: Some(AdapterConversion {
            media_type: "text/plain".to_owned(),
            bytes: vec![b'x'; 32],
        }),
        active_content_observed: false,
        complete_claim: true,
        warnings: Vec::new(),
        limitations: Vec::new(),
    };
    let adapter = FixtureAdapter::passive("bounded", &["application/pdf"], output);
    let limits = DocumentLimits {
        max_text_bytes: 5,
        max_pages: 1,
        max_page_render_bytes: 16,
        max_preview_bytes: 4,
        max_conversion_bytes: 8,
    };
    let report = inspect_document(
        b"fixture-source",
        &agreed("application/pdf"),
        &context(),
        limits,
        &[&adapter],
    )
    .expect("bounded report");

    assert_eq!(report.text[0].text, "abcde");
    assert_eq!(report.pages.len(), 1);
    assert!(report.conversion.is_none());
    assert!(!report.coverage.complete_claim);
    assert!(
        report
            .coverage
            .unknown_gaps
            .iter()
            .any(|item| item.contains("max_text_bytes"))
    );
    assert!(
        report
            .coverage
            .unknown_gaps
            .iter()
            .any(|item| item.contains("max_pages"))
    );
    assert!(
        report
            .coverage
            .unknown_gaps
            .iter()
            .any(|item| item.contains("max_conversion_bytes"))
    );
    assert_eq!(report.preview.expect("preview").bytes, b"abcd");
}

#[test]
fn converted_output_registration_is_a_new_converted_revision_bound_to_exact_source() {
    let source = b"<html><body>convert me</body></html>";
    let context = context();
    let report = inspect_document(
        source,
        &agreed("text/html"),
        &context,
        DocumentLimits::default(),
        &[&SafeHtmlAdapter],
    )
    .expect("HTML conversion report");
    let conversion = report.conversion.expect("converted output");
    let spec = conversion.registration_spec(&context);

    assert_eq!(spec.source_refs, vec![context.source_revision_ref.clone()]);
    assert_eq!(spec.revision_role, RevisionRole::Converted);
    assert_eq!(spec.object_class, "document.converted");
    assert_eq!(
        spec.expected_sha256.as_deref(),
        Some(conversion.sha256.as_str())
    );
    assert_eq!(conversion.source_revision_ref, context.source_revision_ref);
    assert_ne!(conversion.source_sha256, conversion.sha256);
}

#[test]
fn canonical_view_specs_and_declared_mismatch_still_bind_the_observed_source_revision() {
    let context = context();
    let assessment = TypeAssessment {
        declared_type: Some("application/pdf".to_owned()),
        detector_evidence: Vec::new(),
        agreement: TypeAgreement::Agreed("text/plain".to_owned()),
        declared_matches_agreed_type: Some(false),
    };
    let report = inspect_document(
        b"observed text",
        &assessment,
        &context,
        DocumentLimits::default(),
        &[&SafeTextAdapter],
    )
    .expect("observed-type document report");
    let views = report.view_specs(&context);

    assert_eq!(report.agreed_media_type.as_deref(), Some("text/plain"));
    assert!(!views.is_empty());
    assert!(views.iter().all(|view| {
        view.source_revision_refs == vec![context.source_revision_ref.clone()]
            && view.workspace_ref == context.workspace_ref
            && view.authority_ref == context.authority_ref
    }));
}
