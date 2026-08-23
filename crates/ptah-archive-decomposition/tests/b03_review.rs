//! B03 review regressions for coverage truth and frozen source provenance.

use ptah_archive_decomposition::{
    DocumentContext, DocumentLimits, SafeHtmlAdapter, SafeTextAdapter, TypeAgreement,
    TypeAssessment, inspect_document,
};
use ptah_identifiers::EntityRef;
use ptah_object_store::{ProductionEvidence, RevisionRole};

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

#[test]
fn exact_page_limit_does_not_invent_truncation() {
    let report = inspect_document(
        b"one page",
        &agreed("text/plain"),
        &context(),
        DocumentLimits {
            max_pages: 1,
            ..DocumentLimits::default()
        },
        &[&SafeTextAdapter],
    )
    .expect("exact page boundary");

    assert_eq!(report.pages.len(), 1);
    assert!(report.coverage.complete_claim);
    assert!(
        !report
            .coverage
            .unknown_gaps
            .iter()
            .any(|gap| gap.contains("max_pages"))
    );
}

#[test]
fn preview_truncation_is_explicit_coverage_loss() {
    let report = inspect_document(
        b"abcdef",
        &agreed("text/plain"),
        &context(),
        DocumentLimits {
            max_preview_bytes: 3,
            ..DocumentLimits::default()
        },
        &[&SafeTextAdapter],
    )
    .expect("bounded preview");

    assert_eq!(report.preview.expect("preview").bytes, b"abc");
    assert!(!report.coverage.complete_claim);
    assert!(
        report
            .coverage
            .unknown_gaps
            .iter()
            .any(|gap| gap.contains("max_preview_bytes"))
    );
}

#[test]
fn view_specs_cannot_rebind_a_report_to_another_source_revision() {
    let source_context = context();
    let report = inspect_document(
        b"anchored",
        &agreed("text/plain"),
        &source_context,
        DocumentLimits::default(),
        &[&SafeTextAdapter],
    )
    .expect("anchored report");
    let mut other_context = source_context.clone();
    other_context.source_revision_ref = reference("object.revision");
    assert_ne!(
        source_context.source_revision_ref,
        other_context.source_revision_ref
    );

    let views = report.view_specs(&other_context);
    assert!(!views.is_empty());
    assert!(views.iter().all(|view| {
        view.source_revision_refs == vec![source_context.source_revision_ref.clone()]
    }));
}

#[test]
fn converted_registration_cannot_rebind_frozen_source_provenance() {
    let source_context = context();
    let report = inspect_document(
        b"<html><body>derived</body></html>",
        &agreed("text/html"),
        &source_context,
        DocumentLimits::default(),
        &[&SafeHtmlAdapter],
    )
    .expect("HTML conversion");
    let conversion = report.conversion.expect("conversion");
    let mut other_context = source_context.clone();
    other_context.source_revision_ref = reference("object.revision");

    let spec = conversion.registration_spec(&other_context);
    assert_eq!(spec.source_refs, vec![source_context.source_revision_ref]);
    assert_eq!(spec.revision_role, RevisionRole::Converted);
}

#[test]
fn generic_html_event_handler_is_observed_without_execution() {
    let report = inspect_document(
        br#"<html><body onmouseover="steal()">safe text</body></html>"#,
        &agreed("text/html"),
        &context(),
        DocumentLimits::default(),
        &[&SafeHtmlAdapter],
    )
    .expect("passive HTML");

    assert!(report.active_content_observed);
    let preview = String::from_utf8(report.preview.expect("preview").bytes).expect("UTF-8");
    assert!(preview.contains("safe text"));
    assert!(!preview.contains("steal()"));
}

#[test]
fn self_closing_embed_does_not_discard_following_benign_text() {
    let report = inspect_document(
        br#"<html><body>before <embed src="evil.bin"> after</body></html>"#,
        &agreed("text/html"),
        &context(),
        DocumentLimits::default(),
        &[&SafeHtmlAdapter],
    )
    .expect("passive HTML");

    assert!(report.active_content_observed);
    let preview = String::from_utf8(report.preview.expect("preview").bytes).expect("UTF-8");
    assert!(preview.contains("before"));
    assert!(preview.contains("after"));
    assert!(!preview.contains("evil.bin"));
}

#[test]
fn truncated_text_clears_exact_byte_anchor() {
    let report = inspect_document(
        b"abcdefgh",
        &agreed("text/plain"),
        &context(),
        DocumentLimits {
            max_text_bytes: 4,
            ..DocumentLimits::default()
        },
        &[&SafeTextAdapter],
    )
    .expect("bounded text");

    assert_eq!(report.text[0].text, "abcd");
    assert_eq!(report.text[0].anchor.byte_start, None);
    assert_eq!(report.text[0].anchor.byte_end_exclusive, None);
    assert!(
        report
            .coverage
            .unknown_gaps
            .iter()
            .any(|gap| gap.contains("max_text_bytes"))
    );
}

#[test]
fn nested_active_regions_are_removed_as_complete_outer_region() {
    let source = br"<html><body><script>evil1<script>evil2</script>evil3</script><p>safe</p></body></html>";
    let report = inspect_document(
        source,
        &agreed("text/html"),
        &context(),
        DocumentLimits::default(),
        &[&SafeHtmlAdapter],
    )
    .expect("nested active HTML");

    assert!(report.active_content_observed);
    let preview = String::from_utf8(report.preview.expect("preview").bytes).expect("UTF-8");
    assert!(preview.contains("safe"));
    assert!(!preview.contains("evil1"));
    assert!(!preview.contains("evil2"));
    assert!(!preview.contains("evil3"));
    let conversion =
        String::from_utf8(report.conversion.expect("conversion").bytes).expect("UTF-8 conversion");
    assert!(conversion.contains("safe"));
    assert!(!conversion.contains("evil1"));
    assert!(!conversion.contains("evil2"));
    assert!(!conversion.contains("evil3"));
}
