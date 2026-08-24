//! B07 Search v1 positive, isolation, rebuild and source-binding corpus.

use ptah_archive_decomposition::{
    AnchoredText, SearchDocument, SearchDocumentKind, SearchDomain, SearchError, SearchField,
    SearchIndex, SearchLimits, SearchMetadata, SearchQuery, SearchSourceBinding, SourceAnchor,
    activity_search_document, artifact_search_document, document_text_search_document,
    filename_metadata_document, log_search_document, source_symbol_search_document,
};
use ptah_identifiers::EntityRef;

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid fixture reference")
}

fn binding(
    workspace_ref: &EntityRef,
    source_kind: &str,
    source_record_revision: u64,
    object_revision_ref: Option<EntityRef>,
) -> SearchSourceBinding {
    SearchSourceBinding {
        workspace_ref: workspace_ref.clone(),
        source_ref: reference(source_kind),
        source_record_revision,
        object_revision_ref,
    }
}

fn query(workspace_ref: &EntityRef, text: &str, domains: Vec<SearchDomain>) -> SearchQuery {
    SearchQuery {
        workspace_ref: workspace_ref.clone(),
        text: text.to_owned(),
        domains,
        limit: 20,
    }
}

#[test]
fn filename_and_b02_metadata_are_searchable_with_evidence_source() {
    let workspace = reference("core.workspace");
    let revision = reference("object.revision");
    let source = binding(&workspace, "object.object", 3, Some(revision));
    let metadata = vec![SearchMetadata {
        path: Some("bin/app.exe".to_owned()),
        key: "architecture".to_owned(),
        value: "x86_64".to_owned(),
        source: "b02.detector.fixture".to_owned(),
    }];
    let document = filename_metadata_document(source, Some("app.exe".to_owned()), &metadata)
        .expect("metadata document");
    let mut index = SearchIndex::new(SearchLimits::default()).expect("index");
    index.rebuild(&[document]).expect("rebuild");

    let filename = index
        .query(&query(&workspace, "APP.EXE", vec![SearchDomain::Filename]))
        .expect("filename query");
    assert_eq!(filename.hits.len(), 1);
    let metadata_hit = index
        .query(&query(
            &workspace,
            "architecture x86_64",
            vec![SearchDomain::Metadata],
        ))
        .expect("metadata query");
    assert_eq!(metadata_hit.hits.len(), 1);
    assert_eq!(
        metadata_hit.hits[0].matches[0].evidence_source,
        "b02.detector.fixture"
    );
}

#[test]
fn b03_anchored_document_text_is_searchable_and_exact_revision_bound() {
    let workspace = reference("core.workspace");
    let object_revision = reference("object.revision");
    let source = binding(&workspace, "object.view", 5, Some(object_revision.clone()));
    let spans = vec![AnchoredText {
        text: "Ptah recovery contract keeps evidence explicit".to_owned(),
        anchor: SourceAnchor {
            source_revision_ref: object_revision.clone(),
            byte_start: Some(10),
            byte_end_exclusive: Some(54),
            page: Some(2),
        },
    }];
    let document = document_text_search_document(source.clone(), &spans).expect("text document");
    let mut index = SearchIndex::new(SearchLimits::default()).expect("index");
    index.rebuild(&[document]).expect("rebuild");
    let response = index
        .query(&query(
            &workspace,
            "recovery evidence",
            vec![SearchDomain::DocumentText],
        ))
        .expect("document query");
    assert_eq!(response.hits.len(), 1);
    assert_eq!(response.hits[0].source, source);
    assert_eq!(
        response.hits[0].source.object_revision_ref,
        Some(object_revision)
    );
    assert_eq!(response.hits[0].matches[0].key.as_deref(), Some("page:2"));
}

#[test]
fn source_symbols_are_indexed_as_exact_revision_projection() {
    let workspace = reference("core.workspace");
    let source = binding(
        &workspace,
        "object.view",
        8,
        Some(reference("object.revision")),
    );
    let document = source_symbol_search_document(
        source.clone(),
        &["restore_checkpoint".to_owned(), "SearchIndex".to_owned()],
    )
    .expect("symbol document");
    let mut index = SearchIndex::new(SearchLimits::default()).expect("index");
    index.rebuild(&[document]).expect("rebuild");
    let response = index
        .query(&query(
            &workspace,
            "searchindex",
            vec![SearchDomain::SourceSymbol],
        ))
        .expect("symbol query");
    assert_eq!(response.hits.len(), 1);
    assert_eq!(response.hits[0].source, source);
}

#[test]
fn logs_activities_and_artifacts_are_independently_filterable() {
    let workspace = reference("core.workspace");
    let log = log_search_document(
        binding(&workspace, "core.attempt", 2, None),
        &["provider timeout during probe".to_owned()],
    )
    .expect("log document");
    let activity = activity_search_document(
        binding(&workspace, "core.activity", 7, None),
        &["restore completed with receipt".to_owned()],
    )
    .expect("activity document");
    let artifact = artifact_search_document(
        binding(
            &workspace,
            "object.artifact",
            4,
            Some(reference("object.revision")),
        ),
        &["proof bundle immutable report".to_owned()],
    )
    .expect("artifact document");
    let mut index = SearchIndex::new(SearchLimits::default()).expect("index");
    index.rebuild(&[log, activity, artifact]).expect("rebuild");

    assert_eq!(
        index
            .query(&query(&workspace, "timeout", vec![SearchDomain::Log]))
            .expect("log query")
            .hits
            .len(),
        1
    );
    assert_eq!(
        index
            .query(&query(
                &workspace,
                "restore receipt",
                vec![SearchDomain::Activity],
            ))
            .expect("activity query")
            .hits
            .len(),
        1
    );
    assert_eq!(
        index
            .query(&query(
                &workspace,
                "immutable report",
                vec![SearchDomain::Artifact],
            ))
            .expect("artifact query")
            .hits
            .len(),
        1
    );
}

#[test]
fn private_workspace_content_isolated_before_matching() {
    let alpha = reference("core.workspace");
    let beta = reference("core.workspace");
    let alpha_doc = log_search_document(
        binding(&alpha, "core.attempt", 1, None),
        &["private needle".to_owned()],
    )
    .expect("alpha");
    let beta_doc = log_search_document(
        binding(&beta, "core.attempt", 1, None),
        &["private needle".to_owned()],
    )
    .expect("beta");
    let mut index = SearchIndex::new(SearchLimits::default()).expect("index");
    index.rebuild(&[alpha_doc, beta_doc]).expect("rebuild");

    let alpha_hits = index
        .query(&query(&alpha, "needle", Vec::new()))
        .expect("alpha query");
    assert_eq!(alpha_hits.hits.len(), 1);
    assert_eq!(alpha_hits.hits[0].source.workspace_ref, alpha);
    let beta_hits = index
        .query(&query(&beta, "needle", Vec::new()))
        .expect("beta query");
    assert_eq!(beta_hits.hits.len(), 1);
    assert_eq!(beta_hits.hits[0].source.workspace_ref, beta);
}

#[test]
fn every_result_preserves_exact_source_record_and_object_revision() {
    let workspace = reference("core.workspace");
    let object_revision = reference("object.revision");
    let source = binding(
        &workspace,
        "object.artifact",
        19,
        Some(object_revision.clone()),
    );
    let document =
        artifact_search_document(source.clone(), &["firmware analysis report".to_owned()])
            .expect("artifact document");
    let mut index = SearchIndex::new(SearchLimits::default()).expect("index");
    index.rebuild(&[document]).expect("rebuild");
    let hit = index
        .query(&query(&workspace, "analysis", Vec::new()))
        .expect("query")
        .hits
        .pop()
        .expect("hit");
    assert_eq!(hit.source.source_ref, source.source_ref);
    assert_eq!(hit.source.source_record_revision, 19);
    assert_eq!(hit.source.object_revision_ref, Some(object_revision));
}

#[test]
fn clear_and_rebuild_do_not_mutate_canonical_inputs_and_digest_is_reproducible() {
    let workspace = reference("core.workspace");
    let document = log_search_document(
        binding(&workspace, "core.attempt", 1, None),
        &["stable canonical source".to_owned()],
    )
    .expect("document");
    let canonical_input = vec![document];
    let before = canonical_input.clone();
    let mut index = SearchIndex::new(SearchLimits::default()).expect("index");
    let first = index.rebuild(&canonical_input).expect("first rebuild");
    let cleared = index.clear().expect("clear");
    assert_eq!(cleared.document_count, 0);
    let second = index.rebuild(&canonical_input).expect("second rebuild");
    assert_eq!(canonical_input, before);
    assert_eq!(first.content_sha256, second.content_sha256);
    assert!(first.revision < cleared.revision && cleared.revision < second.revision);
}

#[test]
fn duplicate_exact_document_identity_is_rejected() {
    let workspace = reference("core.workspace");
    let document = log_search_document(
        binding(&workspace, "core.attempt", 1, None),
        &["duplicate".to_owned()],
    )
    .expect("document");
    let mut index = SearchIndex::new(SearchLimits::default()).expect("index");
    assert!(matches!(
        index.rebuild(&[document.clone(), document]),
        Err(SearchError::DuplicateDocument)
    ));
}

#[test]
fn malformed_workspace_revision_and_record_revision_bindings_fail_closed() {
    let workspace = reference("core.workspace");
    let bad_workspace = SearchSourceBinding {
        workspace_ref: reference("object.object"),
        source_ref: reference("core.activity"),
        source_record_revision: 1,
        object_revision_ref: None,
    };
    assert!(matches!(
        activity_search_document(bad_workspace, &["x".to_owned()]),
        Err(SearchError::InvalidWorkspaceRef)
    ));

    let bad_revision = SearchSourceBinding {
        workspace_ref: workspace.clone(),
        source_ref: reference("object.object"),
        source_record_revision: 1,
        object_revision_ref: Some(reference("object.object")),
    };
    assert!(matches!(
        artifact_search_document(bad_revision, &["x".to_owned()]),
        Err(SearchError::InvalidObjectRevisionRef)
    ));

    let bad_record = SearchSourceBinding {
        workspace_ref: workspace,
        source_ref: reference("core.activity"),
        source_record_revision: 0,
        object_revision_ref: None,
    };
    assert!(matches!(
        activity_search_document(bad_record, &["x".to_owned()]),
        Err(SearchError::InvalidSourceRecordRevision)
    ));
}

#[test]
fn field_document_and_query_resource_bounds_fail_closed() {
    let workspace = reference("core.workspace");
    let limits = SearchLimits {
        max_documents: 1,
        max_fields_per_document: 1,
        max_field_bytes: 4,
        max_query_bytes: 4,
        max_results: 1,
    };
    let mut index = SearchIndex::new(limits).expect("index");
    let source = binding(&workspace, "core.activity", 1, None);
    let too_large = SearchDocument {
        source: source.clone(),
        kind: SearchDocumentKind::Activity,
        fields: vec![SearchField {
            domain: SearchDomain::Activity,
            key: None,
            value: "12345".to_owned(),
            evidence_source: "test".to_owned(),
        }],
    };
    assert!(matches!(
        index.rebuild(&[too_large]),
        Err(SearchError::FieldTooLarge)
    ));

    let too_many_fields = SearchDocument {
        source: source.clone(),
        kind: SearchDocumentKind::Activity,
        fields: vec![
            SearchField {
                domain: SearchDomain::Activity,
                key: None,
                value: "one".to_owned(),
                evidence_source: "test".to_owned(),
            },
            SearchField {
                domain: SearchDomain::Activity,
                key: None,
                value: "two".to_owned(),
                evidence_source: "test".to_owned(),
            },
        ],
    };
    assert!(matches!(
        index.rebuild(&[too_many_fields]),
        Err(SearchError::TooManyFields)
    ));

    let okay = SearchDocument {
        source,
        kind: SearchDocumentKind::Activity,
        fields: vec![SearchField {
            domain: SearchDomain::Activity,
            key: None,
            value: "okay".to_owned(),
            evidence_source: "test".to_owned(),
        }],
    };
    index.rebuild(&[okay]).expect("bounded rebuild");
    let mut overlong_query = query(&workspace, "12345", Vec::new());
    overlong_query.limit = 1;
    assert!(matches!(
        index.query(&overlong_query),
        Err(SearchError::InvalidQuery)
    ));
    let mut too_many_results = query(&workspace, "okay", Vec::new());
    too_many_results.limit = 2;
    assert!(matches!(
        index.query(&too_many_results),
        Err(SearchError::InvalidResultLimit)
    ));
}

#[test]
fn domain_filter_prevents_cross_domain_false_positive() {
    let workspace = reference("core.workspace");
    let document = filename_metadata_document(
        binding(
            &workspace,
            "object.object",
            1,
            Some(reference("object.revision")),
        ),
        Some("needle.bin".to_owned()),
        &[SearchMetadata {
            path: None,
            key: "label".to_owned(),
            value: "needle metadata".to_owned(),
            source: "fixture".to_owned(),
        }],
    )
    .expect("document");
    let mut index = SearchIndex::new(SearchLimits::default()).expect("index");
    index.rebuild(&[document]).expect("rebuild");
    assert_eq!(
        index
            .query(&query(&workspace, "needle", vec![SearchDomain::Filename]))
            .expect("filename")
            .hits[0]
            .matches
            .len(),
        1
    );
    assert_eq!(
        index
            .query(&query(&workspace, "needle", vec![SearchDomain::Metadata]))
            .expect("metadata")
            .hits[0]
            .matches
            .len(),
        1
    );
    assert!(
        index
            .query(&query(&workspace, "needle", vec![SearchDomain::Log]))
            .expect("log filter")
            .hits
            .is_empty()
    );
}

#[test]
fn result_limit_and_order_are_deterministic_for_same_index_revision() {
    let workspace = reference("core.workspace");
    let first = log_search_document(
        binding(&workspace, "core.attempt", 1, None),
        &["same needle".to_owned()],
    )
    .expect("first");
    let second = log_search_document(
        binding(&workspace, "proof.receipt", 1, None),
        &["same needle".to_owned()],
    )
    .expect("second");
    let mut index = SearchIndex::new(SearchLimits::default()).expect("index");
    index.rebuild(&[second, first]).expect("rebuild");
    let mut search = query(&workspace, "needle", Vec::new());
    search.limit = 1;
    let left = index.query(&search).expect("left");
    let right = index.query(&search).expect("right");
    assert_eq!(left, right);
    assert_eq!(left.hits.len(), 1);
}

#[test]
fn mismatched_b03_anchor_is_rejected_before_indexing() {
    let workspace = reference("core.workspace");
    let source = binding(
        &workspace,
        "object.view",
        1,
        Some(reference("object.revision")),
    );
    let spans = vec![AnchoredText {
        text: "text".to_owned(),
        anchor: SourceAnchor {
            source_revision_ref: reference("object.revision"),
            byte_start: None,
            byte_end_exclusive: None,
            page: Some(1),
        },
    }];
    assert!(matches!(
        document_text_search_document(source, &spans),
        Err(SearchError::AnchorMismatch)
    ));
}

#[test]
fn query_is_case_insensitive_and_requires_all_terms() {
    let workspace = reference("core.workspace");
    let document = activity_search_document(
        binding(&workspace, "core.activity", 1, None),
        &["Checkpoint Recovery Verified".to_owned()],
    )
    .expect("activity");
    let mut index = SearchIndex::new(SearchLimits::default()).expect("index");
    index.rebuild(&[document]).expect("rebuild");
    assert_eq!(
        index
            .query(&query(&workspace, "checkpoint VERIFIED", Vec::new()))
            .expect("matching query")
            .hits
            .len(),
        1
    );
    assert!(
        index
            .query(&query(&workspace, "checkpoint missing", Vec::new()))
            .expect("AND query")
            .hits
            .is_empty()
    );
}
