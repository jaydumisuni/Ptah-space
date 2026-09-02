//! D03 milestone acceptance tests.

use ptah_identifiers::EntityRef;
use ptah_knowledge_search::{
    CitationEvidence, D03Error, KnowledgeLimits, KnowledgeLocator, KnowledgeSourceClass,
    KnowledgeSourceRevision, KnowledgeSourceRevisionInput, require_knowledge_schema,
    validate_current_source,
};

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid reference")
}

fn source(class: KnowledgeSourceClass) -> KnowledgeSourceRevision {
    KnowledgeSourceRevision::new(KnowledgeSourceRevisionInput {
        workspace_ref: reference("core.workspace"),
        source_ref: reference("object.view"),
        source_record_revision: 7,
        object_revision_ref: Some(reference("object.revision")),
        content_sha256: HASH_A.to_owned(),
        class,
        provenance_ref: reference("evidence.receipt"),
        schema_id: "urn:ptah:schema:knowledge:source-revision:0.1.0".to_owned(),
    })
    .expect("valid source")
}

#[test]
fn all_six_sources_are_revision_bound_and_citations_are_non_authoritative() {
    let cases = [
        (
            KnowledgeSourceClass::Document,
            KnowledgeLocator::LineRange {
                start: 1,
                end_inclusive: 2,
            },
        ),
        (
            KnowledgeSourceClass::SourceSymbol,
            KnowledgeLocator::SourceSymbol {
                symbol: "Widget::open".to_owned(),
            },
        ),
        (
            KnowledgeSourceClass::FirmwareManifest,
            KnowledgeLocator::FirmwareComponent {
                component: "boot.img".to_owned(),
            },
        ),
        (
            KnowledgeSourceClass::PartitionData,
            KnowledgeLocator::PartitionRange {
                name: Some("system".to_owned()),
                byte_start: 4096,
                byte_end_exclusive: 8192,
            },
        ),
        (
            KnowledgeSourceClass::Dataset,
            KnowledgeLocator::DatasetRow {
                table: "rows".to_owned(),
                row: 0,
            },
        ),
        (
            KnowledgeSourceClass::Database,
            KnowledgeLocator::DatabaseRow {
                table: "users".to_owned(),
                row: 0,
            },
        ),
    ];
    for (class, locator) in cases {
        let citation = CitationEvidence::new(source(class), locator, "d03.acceptance", None)
            .expect("citation");
        assert!(!citation.authoritative);
        assert_eq!(citation.source.source_record_revision, 7);
        assert_eq!(citation.source.content_sha256, HASH_A);
    }
}

#[test]
fn source_rejects_zero_revision_wrong_revision_kind_and_bad_hash() {
    let workspace_ref = reference("core.workspace");
    let source_ref = reference("object.view");
    let provenance_ref = reference("evidence.receipt");
    let make = |revision, object_revision_ref, digest: &str| KnowledgeSourceRevisionInput {
        workspace_ref: workspace_ref.clone(),
        source_ref: source_ref.clone(),
        source_record_revision: revision,
        object_revision_ref,
        content_sha256: digest.to_owned(),
        class: KnowledgeSourceClass::Document,
        provenance_ref: provenance_ref.clone(),
        schema_id: "urn:ptah:schema:knowledge:source-revision:0.1.0".to_owned(),
    };
    assert!(matches!(
        KnowledgeSourceRevision::new(make(0, Some(reference("object.revision")), HASH_A)),
        Err(D03Error::InvalidSourceBinding(_))
    ));
    assert!(matches!(
        KnowledgeSourceRevision::new(make(1, Some(reference("object.view")), HASH_A)),
        Err(D03Error::InvalidSourceBinding(_))
    ));
    assert!(matches!(
        KnowledgeSourceRevision::new(make(1, Some(reference("object.revision")), "ABC")),
        Err(D03Error::InvalidSourceBinding(_))
    ));
}

#[test]
fn frozen_knowledge_schema_ids_are_reused() {
    for schema in [
        "urn:ptah:schema:data:database-connection-reference:0.1.0",
        "urn:ptah:schema:data:database-snapshot:0.1.0",
        "urn:ptah:schema:data:dataset:0.1.0",
        "urn:ptah:schema:data:dataset-revision:0.1.0",
        "urn:ptah:schema:knowledge:citation:0.1.0",
        "urn:ptah:schema:knowledge:query:0.1.0",
        "urn:ptah:schema:knowledge:query-run:0.1.0",
        "urn:ptah:schema:knowledge:result:0.1.0",
        "urn:ptah:schema:knowledge:result-set:0.1.0",
        "urn:ptah:schema:knowledge:source:0.1.0",
        "urn:ptah:schema:knowledge:source-revision:0.1.0",
        "urn:ptah:schema:knowledge:verification:0.1.0",
    ] {
        assert_eq!(
            require_knowledge_schema(schema)
                .expect("frozen schema")
                .schema_id,
            schema
        );
    }
}

#[test]
fn stale_source_revision_or_digest_fails_closed() {
    let expected = source(KnowledgeSourceClass::Document);
    assert!(validate_current_source(&expected, 7, HASH_A).is_ok());
    assert!(matches!(
        validate_current_source(&expected, 8, HASH_A),
        Err(D03Error::StaleSourceRevision)
    ));
    assert!(matches!(
        validate_current_source(&expected, 7, HASH_B),
        Err(D03Error::SourceDigestMismatch)
    ));
}

#[test]
fn citation_rejects_empty_mechanism_and_invalid_range() {
    assert!(matches!(
        CitationEvidence::new(
            source(KnowledgeSourceClass::Document),
            KnowledgeLocator::ByteRange {
                start: 10,
                end_exclusive: 10
            },
            "d03.acceptance",
            None,
        ),
        Err(D03Error::InvalidCitationBinding(_))
    ));
    assert!(matches!(
        CitationEvidence::new(
            source(KnowledgeSourceClass::Document),
            KnowledgeLocator::LineRange {
                start: 1,
                end_inclusive: 1
            },
            "",
            None,
        ),
        Err(D03Error::InvalidCitationBinding(_))
    ));
}

#[test]
fn default_limits_are_nonzero_and_validate() {
    let limits = KnowledgeLimits::default();
    assert!(limits.validate().is_ok());
    assert!(limits.max_sources > 0);
    assert!(limits.max_results > 0);
    assert!(limits.max_export_bytes > 0);
}
