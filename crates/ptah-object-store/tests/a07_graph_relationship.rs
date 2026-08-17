#[test]
fn relationship_and_view_foundations_update_object_projections() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");

    let first_evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let first = store
        .register_bytes(
            b"relationship subject",
            register_spec(&workspace, &authority, first_evidence.production),
        )
        .expect("first Object");
    let second_evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let second = store
        .register_bytes(
            b"relationship object",
            register_spec(&workspace, &authority, second_evidence.production),
        )
        .expect("second Object");

    let relation_evidence =
        create_evidence(&runtime, &workspace, &authority, EvidenceMode::OutputOnly);
    let relationship_ref = store
        .create_relationship(RelationshipSpec {
            workspace_ref: workspace.clone(),
            authority_ref: authority.clone(),
            subject_refs: vec![first.object_ref.clone()],
            relationship_type: "derived_from".to_owned(),
            object_refs: vec![second.object_ref.clone()],
            production: relation_evidence.production,
        })
        .expect("create Relationship");
    assert!(contains_ref(
        &ledger_document(&temp.ledger(), first.object_ref.entity_id),
        "relationship_refs",
        &relationship_ref
    ));
    assert!(contains_ref(
        &ledger_document(&temp.ledger(), second.object_ref.entity_id),
        "relationship_refs",
        &relationship_ref
    ));

    let view_evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::OutputOnly);
    let view_ref = store
        .create_view(ViewSpec {
            workspace_ref: workspace.clone(),
            authority_ref: authority.clone(),
            view_kind: "structured_index".to_owned(),
            view_schema_id: OBJECT_SCHEMA_ID.to_owned(),
            view_schema_version: "0.1.0".to_owned(),
            source_revision_refs: vec![first.revision_ref.clone()],
            origin_class: OriginClass::Generated,
            production: view_evidence.production,
        })
        .expect("create View");
    assert!(contains_ref(
        &ledger_document(&temp.ledger(), first.object_ref.entity_id),
        "view_refs",
        &view_ref
    ));
}
