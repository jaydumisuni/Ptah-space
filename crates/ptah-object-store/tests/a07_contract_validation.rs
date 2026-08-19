#[test]
fn registration_rejects_schema_invalid_caller_fields_before_publication() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);

    let mut invalid_class = register_spec(
        &workspace,
        &authority,
        evidence.production.clone(),
    );
    invalid_class.object_class = "Invalid-Class".to_owned();
    assert!(matches!(
        store.register_bytes(b"invalid class", invalid_class),
        Err(ObjectStoreError::TypeMismatch)
    ));

    let mut oversized_name = register_spec(&workspace, &authority, evidence.production);
    oversized_name.declared_name = Some("n".repeat(8193));
    assert!(matches!(
        store.register_bytes(b"oversized name", oversized_name),
        Err(ObjectStoreError::TypeMismatch)
    ));

    assert_eq!(
        fs::read_dir(temp.cas())
            .expect("read empty CAS root")
            .count(),
        0
    );
}

#[test]
fn graph_apis_reject_schema_invalid_tokens_and_versions() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::OutputOnly);

    assert!(matches!(
        store.create_relationship(RelationshipSpec {
            workspace_ref: workspace.clone(),
            authority_ref: authority.clone(),
            subject_refs: vec![reference("object.object")],
            relationship_type: "Derived-From".to_owned(),
            object_refs: vec![reference("object.object")],
            production: evidence.production.clone(),
        }),
        Err(ObjectStoreError::TypeMismatch)
    ));

    assert!(matches!(
        store.create_view(ViewSpec {
            workspace_ref: workspace.clone(),
            authority_ref: authority.clone(),
            view_kind: "structured_index".to_owned(),
            view_schema_id: "https://example.invalid/schema".to_owned(),
            view_schema_version: "0.1.0".to_owned(),
            source_revision_refs: vec![reference("object.revision")],
            origin_class: OriginClass::Generated,
            production: evidence.production.clone(),
        }),
        Err(ObjectStoreError::TypeMismatch)
    ));

    assert!(matches!(
        store.create_view(ViewSpec {
            workspace_ref: workspace.clone(),
            authority_ref: authority.clone(),
            view_kind: "structured_index".to_owned(),
            view_schema_id: OBJECT_SCHEMA_ID.to_owned(),
            view_schema_version: "01.0.0".to_owned(),
            source_revision_refs: vec![reference("object.revision")],
            origin_class: OriginClass::Generated,
            production: evidence.production.clone(),
        }),
        Err(ObjectStoreError::TypeMismatch)
    ));

    assert!(matches!(
        store.promote_artifact(
            EntityId::new_v7(),
            ArtifactPromotionSpec {
                workspace_ref: workspace,
                authority_ref: authority,
                artifact_type: "Build-Output".to_owned(),
                artifact_version: "1.0.0".to_owned(),
                purpose: "invalid stable key must fail before lookup".to_owned(),
                subject_refs: Vec::new(),
                production: evidence.production,
            },
        ),
        Err(ObjectStoreError::TypeMismatch)
    ));
}

#[test]
fn producer_version_respects_frozen_text_bound() {
    let temp = TempRoot::new();
    let mut store_config = config();
    store_config.producer_version = "v".repeat(257);
    assert!(matches!(
        ObjectStore::open(temp.ledger(), temp.cas(), store_config, fixed_clock()),
        Err(ObjectStoreError::TypeMismatch)
    ));
    assert!(!temp.cas().exists());
}

#[test]
fn kind_scan_reuses_a03_canonical_tamper_validation() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let bytes = b"canonical scan integrity";
    let first_evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let first = store
        .register_bytes(
            bytes,
            register_spec(&workspace, &authority, first_evidence.production),
        )
        .expect("first registration");

    let forged_authority = reference("identity.principal");
    let forged_json = serde_json::to_string(&forged_authority).expect("serialize forged authority");
    let connection = rusqlite::Connection::open(temp.ledger()).expect("open tamper connection");
    connection
        .execute(
            "UPDATE ptah_entity_records SET authority_ref_json = ?1 WHERE entity_id = ?2",
            rusqlite::params![forged_json, first.content_ref.entity_id.to_string()],
        )
        .expect("tamper canonical authority index");
    drop(connection);

    let second_evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    assert!(matches!(
        store.register_bytes(
            bytes,
            register_spec(&workspace, &authority, second_evidence.production),
        ),
        Err(ObjectStoreError::Ledger(_))
    ));
}
