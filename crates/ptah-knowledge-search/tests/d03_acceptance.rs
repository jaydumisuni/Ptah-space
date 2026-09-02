//! D03 milestone acceptance tests.

use ptah_identifiers::EntityRef;
use ptah_knowledge_search::{
    AggregateKind, AnchoredTextInput, C01InputProjection, C03InputProjection, C04InputProjection,
    C05InputProjection, C06InputProjection, CellValue, CitationEvidence, ColumnRef, ColumnType,
    D03Error, DatabaseColumnObservation, DatabaseConnectionReference, DatabaseQueryProvider,
    DatabaseQueryResult, DatabaseSchemaObservation, DatabaseSnapshotEvidence,
    DatabaseTableObservation, FirmwareComponentEvidence, JoinKind, JoinSpec, KnowledgeField,
    KnowledgeIndex, KnowledgeLimits, KnowledgeLocator, KnowledgeSearchDocument,
    KnowledgeSearchDomain, KnowledgeSourceClass, KnowledgeSourceRevision,
    KnowledgeSourceRevisionInput, KnowledgeTextQuery, PartitionEvidence, PartitionEvidenceInput,
    RelationalExpr, RelationalOrder, RelationalPredicate, RelationalQueryPlan, SelectItem,
    StructuredOrder, StructuredPredicate, StructuredQuery, TableRef, firmware_evidence_document,
    from_c01_partition_report, from_c03_android_report, from_c04_apple_report,
    from_c05_mediatek_report, from_c06_firmware_report, ingest_csv, ingest_json, ingest_json_lines,
    partition_evidence_document, query_dataset, require_knowledge_schema, validate_current_source,
};

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid reference")
}

fn document_source(document: &KnowledgeSearchDocument) -> &KnowledgeSourceRevision {
    match document {
        KnowledgeSearchDocument::ObjectMetadata { source, .. }
        | KnowledgeSearchDocument::B03DocumentText { source, .. }
        | KnowledgeSearchDocument::SourceSymbols { source, .. }
        | KnowledgeSearchDocument::FirmwareFields { source, .. }
        | KnowledgeSearchDocument::PartitionFields { source, .. } => source,
    }
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

fn source_in(
    workspace_ref: &EntityRef,
    class: KnowledgeSourceClass,
    digest: &str,
) -> KnowledgeSourceRevision {
    KnowledgeSourceRevision::new(KnowledgeSourceRevisionInput {
        workspace_ref: workspace_ref.clone(),
        source_ref: reference("object.view"),
        source_record_revision: 11,
        object_revision_ref: Some(reference("object.revision")),
        content_sha256: digest.to_owned(),
        class,
        provenance_ref: reference("evidence.receipt"),
        schema_id: "urn:ptah:schema:knowledge:source-revision:0.1.0".to_owned(),
    })
    .expect("source")
}

#[test]
fn b07_symbol_hit_becomes_source_bound_d03_citation() {
    let workspace = reference("core.workspace");
    let source = source_in(&workspace, KnowledgeSourceClass::SourceSymbol, HASH_A);
    let document = KnowledgeSearchDocument::SourceSymbols {
        source: source.clone(),
        symbols: vec!["Widget::open".to_owned(), "Widget::close".to_owned()],
    };
    let mut index = KnowledgeIndex::new(KnowledgeLimits::default()).expect("index");
    index.rebuild(&[document]).expect("rebuild");
    let result = index
        .search(
            &KnowledgeTextQuery::new(
                workspace,
                "widget open",
                vec![KnowledgeSearchDomain::SourceSymbol],
                10,
            )
            .expect("query"),
        )
        .expect("search");
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].citations[0].source, source);
    assert!(result.rows[0].citations.iter().any(|citation| matches!(
        citation.locator,
        KnowledgeLocator::SourceSymbol { ref symbol } if symbol == "Widget::open"
    )));
    assert!(!result.authoritative);
}

#[test]
fn b03_document_citation_preserves_exact_anchor() {
    let workspace = reference("core.workspace");
    let source = source_in(&workspace, KnowledgeSourceClass::Document, HASH_A);
    let object_revision_ref = source.object_revision_ref.clone().expect("revision");
    let document = KnowledgeSearchDocument::B03DocumentText {
        source: source.clone(),
        spans: vec![AnchoredTextInput {
            text: "exact anchored phrase".to_owned(),
            object_revision_ref,
            page: Some(3),
            byte_start: Some(20),
            byte_end_exclusive: Some(41),
        }],
    };
    let mut index = KnowledgeIndex::new(KnowledgeLimits::default()).expect("index");
    index.rebuild(&[document]).expect("rebuild");
    let result = index
        .search(
            &KnowledgeTextQuery::new(
                workspace,
                "anchored phrase",
                vec![KnowledgeSearchDomain::DocumentText],
                10,
            )
            .expect("query"),
        )
        .expect("search");
    assert!(matches!(
        result.rows[0].citations[0].locator,
        KnowledgeLocator::DocumentAnchor {
            page: Some(3),
            byte_start: Some(20),
            byte_end_exclusive: Some(41)
        }
    ));
    assert_eq!(result.rows[0].citations[0].source, source);
}

#[test]
fn index_digest_is_reproducible_and_workspace_filter_precedes_matching() {
    let workspace_a = reference("core.workspace");
    let workspace_b = reference("core.workspace");
    let doc_a = KnowledgeSearchDocument::ObjectMetadata {
        source: source_in(&workspace_a, KnowledgeSourceClass::Document, HASH_A),
        filename: Some("alpha.txt".to_owned()),
        metadata: vec![
            KnowledgeField::new(
                KnowledgeSearchDomain::Metadata,
                Some("class".to_owned()),
                "private token",
                "fixture",
            )
            .expect("field"),
        ],
    };
    let doc_b = KnowledgeSearchDocument::ObjectMetadata {
        source: source_in(&workspace_b, KnowledgeSourceClass::Document, HASH_B),
        filename: Some("beta.txt".to_owned()),
        metadata: vec![
            KnowledgeField::new(
                KnowledgeSearchDomain::Metadata,
                Some("class".to_owned()),
                "private token",
                "fixture",
            )
            .expect("field"),
        ],
    };
    let mut first = KnowledgeIndex::new(KnowledgeLimits::default()).expect("index");
    let rev1 = first
        .rebuild(&[doc_a.clone(), doc_b.clone()])
        .expect("rebuild");
    let mut second = KnowledgeIndex::new(KnowledgeLimits::default()).expect("index");
    let rev2 = second.rebuild(&[doc_b, doc_a]).expect("rebuild");
    assert_eq!(rev1.content_sha256, rev2.content_sha256);

    let result = first
        .search(
            &KnowledgeTextQuery::new(
                workspace_a.clone(),
                "private token",
                vec![KnowledgeSearchDomain::Metadata],
                10,
            )
            .expect("query"),
        )
        .expect("search");
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.source_refs[0].workspace_ref, workspace_a);
}

#[test]
fn ranking_changes_do_not_change_source_or_citation_truth() {
    let workspace = reference("core.workspace");
    let source = source_in(&workspace, KnowledgeSourceClass::SourceSymbol, HASH_A);
    let docs = [KnowledgeSearchDocument::SourceSymbols {
        source: source.clone(),
        symbols: vec!["alpha".to_owned(), "alpha helper".to_owned()],
    }];
    let mut index = KnowledgeIndex::new(KnowledgeLimits::default()).expect("index");
    index.rebuild(&docs).expect("rebuild");
    let broad = index
        .search(
            &KnowledgeTextQuery::new(
                workspace.clone(),
                "alpha",
                vec![KnowledgeSearchDomain::SourceSymbol],
                10,
            )
            .expect("query"),
        )
        .expect("search");
    let narrow = index
        .search(
            &KnowledgeTextQuery::new(
                workspace,
                "alpha helper",
                vec![KnowledgeSearchDomain::SourceSymbol],
                10,
            )
            .expect("query"),
        )
        .expect("search");
    assert_eq!(broad.rows[0].citations[0].source, source);
    assert_eq!(narrow.rows[0].citations[0].source, source);
    assert_eq!(
        broad.rows[0].citations[0].source.content_sha256,
        narrow.rows[0].citations[0].source.content_sha256
    );
}

#[test]
fn same_source_firmware_and_partition_evidence_share_one_private_b07_metadata_document() {
    let workspace = reference("core.workspace");
    let source = source_in(&workspace, KnowledgeSourceClass::FirmwareManifest, HASH_A);
    let firmware = firmware_evidence_document(
        source.clone(),
        &[FirmwareComponentEvidence::new(
            "boot.img",
            Some(HASH_B.to_owned()),
            Some((4096, 8192)),
            "c03.component",
        )
        .expect("firmware evidence")],
    )
    .expect("firmware document");
    let partition = partition_evidence_document(
        source.clone(),
        &[PartitionEvidence::new(PartitionEvidenceInput {
            name: Some("system".to_owned()),
            index: Some("1".to_owned()),
            byte_start: 8192,
            byte_end_exclusive: 16384,
            first_lba: Some(16),
            last_lba_inclusive: Some(31),
            storage: Some("UFS".to_owned()),
            physical_partition: Some(0),
            evidence_source: "c01.partition".to_owned(),
        })
        .expect("partition evidence")],
    )
    .expect("partition document");

    let mut index = KnowledgeIndex::new(KnowledgeLimits::default()).expect("index");
    index
        .rebuild(&[firmware, partition])
        .expect("same-source rebuild");

    let firmware_hits = index
        .search(
            &KnowledgeTextQuery::new(
                workspace.clone(),
                "boot",
                vec![KnowledgeSearchDomain::Firmware],
                10,
            )
            .expect("query"),
        )
        .expect("firmware search");
    assert_eq!(firmware_hits.rows.len(), 1);
    assert!(
        firmware_hits.rows[0]
            .citations
            .iter()
            .any(|citation| matches!(
                citation.locator,
                KnowledgeLocator::FirmwareComponent { ref component } if component == "boot.img"
            ))
    );

    let partition_hits = index
        .search(
            &KnowledgeTextQuery::new(
                workspace,
                "system",
                vec![KnowledgeSearchDomain::Partition],
                10,
            )
            .expect("query"),
        )
        .expect("partition search");
    assert_eq!(partition_hits.rows.len(), 1);
    assert!(
        partition_hits.rows[0]
            .citations
            .iter()
            .any(|citation| matches!(
                citation.locator,
                KnowledgeLocator::PartitionRange {
                    ref name,
                    byte_start: 8192,
                    byte_end_exclusive: 16384
                } if name.as_deref() == Some("system")
            ))
    );
}

#[test]
fn programme_c_evidence_types_do_not_expose_write_semantics() {
    let partition = PartitionEvidence::new(PartitionEvidenceInput {
        name: Some("boot".to_owned()),
        index: Some("SYS0".to_owned()),
        byte_start: 0x1000,
        byte_end_exclusive: 0x2000,
        first_lba: None,
        last_lba_inclusive: None,
        storage: Some("EMMC".to_owned()),
        physical_partition: None,
        evidence_source: "c05.scatter".to_owned(),
    })
    .expect("partition");
    let json = serde_json::to_string(&partition).expect("serialize");
    for forbidden in [
        "is_download",
        "flash",
        "erase",
        "write",
        "programmer",
        "fdl",
    ] {
        assert!(!json.to_ascii_lowercase().contains(forbidden));
    }
}

#[test]
fn programme_c_projection_contracts_bind_source_digest_and_remain_derived() {
    let workspace = reference("core.workspace");
    let source = source_in(&workspace, KnowledgeSourceClass::FirmwareManifest, HASH_A);
    let partition = PartitionEvidence::new(PartitionEvidenceInput {
        name: Some("system".to_owned()),
        index: Some("1".to_owned()),
        byte_start: 4096,
        byte_end_exclusive: 8192,
        first_lba: Some(8),
        last_lba_inclusive: Some(15),
        storage: Some("UFS".to_owned()),
        physical_partition: Some(0),
        evidence_source: "c01.partition".to_owned(),
    })
    .expect("partition");
    let firmware = FirmwareComponentEvidence::new(
        "boot.img",
        Some(HASH_B.to_owned()),
        Some((8192, 12288)),
        "c03.component",
    )
    .expect("firmware")
    .with_manifest_sha256(HASH_B)
    .expect("manifest binding");

    let c01 = C01InputProjection {
        source_sha256: HASH_A.to_owned(),
        partitions: vec![partition.clone()],
    };
    let c03 = C03InputProjection {
        source_sha256: HASH_A.to_owned(),
        firmware: vec![firmware.clone()],
        partitions: vec![partition.clone()],
    };
    let c04 = C04InputProjection {
        source_sha256: HASH_A.to_owned(),
        firmware: vec![firmware.clone()],
    };
    let c05 = C05InputProjection {
        source_sha256: HASH_A.to_owned(),
        firmware: vec![firmware.clone()],
        partitions: vec![partition.clone()],
    };
    let c06 = C06InputProjection {
        source_sha256: HASH_A.to_owned(),
        firmware: vec![firmware],
        partitions: vec![partition],
    };

    for docs in [
        from_c01_partition_report(source.clone(), &c01).expect("c01"),
        from_c03_android_report(source.clone(), &c03).expect("c03"),
        from_c04_apple_report(source.clone(), &c04).expect("c04"),
        from_c05_mediatek_report(source.clone(), &c05).expect("c05"),
        from_c06_firmware_report(source.clone(), &c06).expect("c06"),
    ] {
        assert!(!docs.is_empty());
        assert!(docs.iter().all(|doc| document_source(doc) == &source));
    }

    let mut stale = c01.clone();
    stale.source_sha256 = HASH_B.to_owned();
    assert_eq!(
        from_c01_partition_report(source, &stale),
        Err(D03Error::SourceDigestMismatch)
    );
}

#[test]
fn c03_manifest_binding_is_explicit_and_search_citation_stays_source_bound() {
    let workspace = reference("core.workspace");
    let source = source_in(&workspace, KnowledgeSourceClass::FirmwareManifest, HASH_A);
    let component =
        FirmwareComponentEvidence::new("system", Some(HASH_B.to_owned()), None, "c03.ota_manifest")
            .expect("component")
            .with_manifest_sha256(HASH_B)
            .expect("manifest binding");
    assert_eq!(component.manifest_sha256.as_deref(), Some(HASH_B));

    let projection = C03InputProjection {
        source_sha256: HASH_A.to_owned(),
        firmware: vec![component],
        partitions: Vec::new(),
    };
    let docs = from_c03_android_report(source.clone(), &projection).expect("projection");
    let mut index = KnowledgeIndex::new(KnowledgeLimits::default()).expect("index");
    index.rebuild(&docs).expect("rebuild");
    let result = index
        .search(
            &KnowledgeTextQuery::new(
                workspace,
                "system",
                vec![KnowledgeSearchDomain::Firmware],
                10,
            )
            .expect("query"),
        )
        .expect("search");
    assert_eq!(result.rows.len(), 1);
    assert!(!result.authoritative);
    assert!(
        result.rows[0]
            .citations
            .iter()
            .all(|citation| citation.source == source)
    );
}

#[test]
fn structured_json_digest_is_key_order_independent_and_types_are_exact() {
    let workspace = reference("core.workspace");
    let source = source_in(&workspace, KnowledgeSourceClass::Dataset, HASH_A);
    let left = ingest_json(
        source.clone(),
        "items",
        br#"[{"b":2,"a":1,"ratio":1.25},{"a":3,"b":null,"ratio":2.5}]"#,
        KnowledgeLimits::default(),
    )
    .expect("left snapshot");
    let right = ingest_json(
        source,
        "items",
        br#"[{"ratio":1.25,"a":1,"b":2},{"b":null,"ratio":2.5,"a":3}]"#,
        KnowledgeLimits::default(),
    )
    .expect("right snapshot");
    assert_eq!(left.content_sha256, right.content_sha256);
    assert_eq!(left.tables.len(), 1);
    let table = &left.tables[0];
    assert_eq!(
        table
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect::<Vec<_>>(),
        vec!["a", "b", "ratio"]
    );
    assert_eq!(table.columns[0].data_type, ColumnType::Integer);
    assert_eq!(table.columns[1].data_type, ColumnType::Integer);
    assert!(table.columns[1].nullable);
    assert_eq!(table.columns[2].data_type, ColumnType::Decimal);
    assert_eq!(table.rows[0][2], CellValue::Decimal("1.25".to_owned()));
    assert!(left.complete);
}

#[test]
fn malformed_jsonl_and_csv_fail_closed_without_inventing_rows() {
    let workspace = reference("core.workspace");
    let source = source_in(&workspace, KnowledgeSourceClass::Dataset, HASH_A);
    assert!(matches!(
        ingest_json_lines(
            source.clone(),
            "events",
            b"{\"id\":1}\n{broken}\n",
            KnowledgeLimits::default(),
        ),
        Err(D03Error::StructuredData(_))
    ));
    assert!(matches!(
        ingest_csv(
            source,
            "events",
            b"id,name\n1,\"unterminated\n",
            KnowledgeLimits::default(),
        ),
        Err(D03Error::StructuredData(_))
    ));
}

#[test]
fn structured_query_filter_order_projection_and_limit_are_deterministic() {
    let workspace = reference("core.workspace");
    let source = source_in(&workspace, KnowledgeSourceClass::Dataset, HASH_A);
    let snapshot = ingest_csv(
        source.clone(),
        "items",
        b"id,name,active\n2,beta,true\n1,alpha,false\n3,gamma,true\n",
        KnowledgeLimits::default(),
    )
    .expect("snapshot");
    let id = ColumnRef {
        table: Some("items".to_owned()),
        column: "id".to_owned(),
    };
    let query = StructuredQuery {
        table: "items".to_owned(),
        projection: vec!["name".to_owned(), "id".to_owned()],
        predicates: vec![StructuredPredicate::Ge(id.clone(), CellValue::Integer(1))],
        order: vec![StructuredOrder {
            column: id,
            descending: true,
        }],
        limit: 2,
        offset: 0,
    };
    let result = query_dataset(&snapshot, &query, KnowledgeLimits::default()).expect("query");
    assert_eq!(result.columns, vec!["name", "id"]);
    assert_eq!(
        result.rows[0].values,
        vec![CellValue::Text("gamma".to_owned()), CellValue::Integer(3)]
    );
    assert_eq!(
        result.rows[1].values,
        vec![CellValue::Text("beta".to_owned()), CellValue::Integer(2)]
    );
    assert!(!result.complete);
    assert!(!result.authoritative);
    assert!(
        result
            .rows
            .iter()
            .flat_map(|row| &row.citations)
            .all(|citation| {
                citation.source == source
                    && matches!(citation.locator, KnowledgeLocator::DatasetCell { .. })
                    && !citation.authoritative
            })
    );

    let mut full_query = query;
    full_query.limit = 3;
    let full = query_dataset(&snapshot, &full_query, KnowledgeLimits::default()).expect("full");
    assert!(full.complete);
    assert_ne!(result.query_plan_sha256, full.query_plan_sha256);
}

fn database_connection(read_only: bool) -> DatabaseConnectionReference {
    DatabaseConnectionReference {
        provider_kind: "sqlite".to_owned(),
        source_ref: reference("knowledge.source"),
        object_revision_ref: reference("object.revision"),
        expected_sha256: HASH_A.to_owned(),
        logical_name: "fixture_db".to_owned(),
        credential_ref: Some(reference("core.evidence")),
        read_only,
    }
}

fn base_relational_plan() -> RelationalQueryPlan {
    RelationalQueryPlan {
        from: TableRef {
            name: "users".to_owned(),
            alias: Some("u".to_owned()),
        },
        joins: Vec::new(),
        projection: vec![SelectItem {
            expr: RelationalExpr::Column(ColumnRef {
                table: Some("u".to_owned()),
                column: "id".to_owned(),
            }),
            alias: Some("user_id".to_owned()),
            aggregate: None,
        }],
        predicate: Some(RelationalPredicate::Ge(
            RelationalExpr::Column(ColumnRef {
                table: Some("u".to_owned()),
                column: "id".to_owned(),
            }),
            RelationalExpr::Value(CellValue::Integer(1)),
        )),
        group_by: Vec::new(),
        order: vec![RelationalOrder {
            expr: RelationalExpr::Column(ColumnRef {
                table: Some("u".to_owned()),
                column: "id".to_owned(),
            }),
            descending: false,
        }],
        limit: 10,
        offset: 0,
    }
}

#[test]
fn database_connection_reference_is_read_only_and_contains_no_raw_credentials() {
    let connection = database_connection(true);
    connection
        .validate()
        .expect("read-only database connection reference");
    let json = serde_json::to_string(&connection).expect("serialize connection");
    let lower = json.to_ascii_lowercase();
    for forbidden in ["password", "secret", "token", "dsn"] {
        assert!(!lower.contains(forbidden));
    }
    assert!(lower.contains("credential_ref"));

    let mut writable = connection.clone();
    writable.read_only = false;
    assert!(matches!(
        writable.validate(),
        Err(D03Error::ReadOnlyPolicyViolation(_))
    ));

    let mut wrong_revision = connection.clone();
    wrong_revision.object_revision_ref = reference("object.object");
    assert!(matches!(
        wrong_revision.validate(),
        Err(D03Error::InvalidRelationalPlan(_))
    ));

    let mut bad_hash = connection;
    bad_hash.expected_sha256 = "ABC".repeat(21) + "A";
    assert!(matches!(
        bad_hash.validate(),
        Err(D03Error::InvalidRelationalPlan(_))
    ));
}

#[test]
fn relational_plan_validation_rejects_unsafe_or_unbounded_shapes() {
    let limits = KnowledgeLimits::default();
    let plan = base_relational_plan();
    plan.validate(limits).expect("valid relational plan");
    let first_digest = plan.query_plan_sha256().expect("digest");
    assert_eq!(first_digest.len(), 64);
    assert_eq!(
        first_digest,
        plan.query_plan_sha256().expect("stable digest")
    );

    let mut zero = plan.clone();
    zero.limit = 0;
    assert!(matches!(
        zero.validate(limits),
        Err(D03Error::InvalidRelationalPlan(_))
    ));

    let mut oversized = plan.clone();
    oversized.limit = limits.max_results + 1;
    assert!(matches!(
        oversized.validate(limits),
        Err(D03Error::InvalidRelationalPlan(_))
    ));

    let mut empty_projection = plan.clone();
    empty_projection.projection.clear();
    assert!(matches!(
        empty_projection.validate(limits),
        Err(D03Error::InvalidRelationalPlan(_))
    ));

    let mut duplicate_alias = plan.clone();
    duplicate_alias.projection.push(SelectItem {
        expr: RelationalExpr::Value(CellValue::Integer(1)),
        alias: Some("user_id".to_owned()),
        aggregate: Some(AggregateKind::Count),
    });
    assert!(matches!(
        duplicate_alias.validate(limits),
        Err(D03Error::InvalidRelationalPlan(_))
    ));

    let mut unsafe_identifier = plan.clone();
    unsafe_identifier.from.name = "users;drop".to_owned();
    assert!(matches!(
        unsafe_identifier.validate(limits),
        Err(D03Error::InvalidRelationalPlan(_))
    ));

    let mut too_many_joins = plan.clone();
    too_many_joins.joins = (0..=limits.max_joins)
        .map(|index| JoinSpec {
            kind: JoinKind::Inner,
            table: TableRef {
                name: format!("join_{index}"),
                alias: Some(format!("j{index}")),
            },
            on: RelationalPredicate::Eq(
                RelationalExpr::Value(CellValue::Integer(1)),
                RelationalExpr::Value(CellValue::Integer(1)),
            ),
        })
        .collect();
    assert!(matches!(
        too_many_joins.validate(limits),
        Err(D03Error::InvalidRelationalPlan(_))
    ));

    let mut too_many_predicates = plan;
    too_many_predicates.predicate = Some(RelationalPredicate::And(
        (0..=limits.max_predicates)
            .map(|_| {
                RelationalPredicate::Eq(
                    RelationalExpr::Value(CellValue::Integer(1)),
                    RelationalExpr::Value(CellValue::Integer(1)),
                )
            })
            .collect(),
    ));
    assert!(matches!(
        too_many_predicates.validate(limits),
        Err(D03Error::InvalidRelationalPlan(_))
    ));
}

#[test]
fn database_observation_and_provider_contract_are_provider_neutral() {
    struct FixtureProvider;

    impl DatabaseQueryProvider for FixtureProvider {
        fn inspect_schema(
            &self,
            _connection: &DatabaseConnectionReference,
        ) -> Result<DatabaseSchemaObservation, D03Error> {
            Err(D03Error::DatabaseProviderUnavailable("fixture".to_owned()))
        }

        fn snapshot_evidence(
            &self,
            _connection: &DatabaseConnectionReference,
        ) -> Result<DatabaseSnapshotEvidence, D03Error> {
            Err(D03Error::DatabaseProviderUnavailable("fixture".to_owned()))
        }

        fn execute(
            &self,
            _connection: &DatabaseConnectionReference,
            _plan: &RelationalQueryPlan,
            _limits: KnowledgeLimits,
        ) -> Result<DatabaseQueryResult, D03Error> {
            Err(D03Error::DatabaseProviderUnavailable("fixture".to_owned()))
        }
    }

    let provider: &dyn DatabaseQueryProvider = &FixtureProvider;
    assert!(matches!(
        provider.snapshot_evidence(&database_connection(true)),
        Err(D03Error::DatabaseProviderUnavailable(_))
    ));
    let source = source_in(
        &reference("core.workspace"),
        KnowledgeSourceClass::Database,
        HASH_A,
    );
    let snapshot = DatabaseSnapshotEvidence {
        source,
        schema_sha256: HASH_B.to_owned(),
        provider_kind: "sqlite".to_owned(),
    };
    snapshot.validate().expect("snapshot evidence");
    let schema = DatabaseSchemaObservation {
        snapshot,
        tables: vec![DatabaseTableObservation {
            name: "users".to_owned(),
            columns: vec![DatabaseColumnObservation {
                name: "id".to_owned(),
                declared_type: "INTEGER".to_owned(),
                nullable: false,
                primary_key: true,
            }],
        }],
    };
    schema
        .validate(KnowledgeLimits::default())
        .expect("schema observation");
}
