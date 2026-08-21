#[test]
fn runtime_documents_keep_core_identity_separation() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let registration = store
        .register_bytes(
            b"identity separation",
            register_spec(&workspace, &authority, evidence.production),
        )
        .expect("register");

    let object = ledger_document(&temp.ledger(), registration.object_ref.entity_id);
    let revision = ledger_document(&temp.ledger(), registration.revision_ref.entity_id);
    let content = ledger_document(&temp.ledger(), registration.content_ref.entity_id);

    assert_eq!(
        object
            .get("envelope")
            .and_then(|value| value.get("schema_id"))
            .and_then(serde_json::Value::as_str),
        Some(OBJECT_SCHEMA_ID)
    );
    assert_eq!(
        revision
            .get("envelope")
            .and_then(|value| value.get("schema_id"))
            .and_then(serde_json::Value::as_str),
        Some(REVISION_SCHEMA_ID)
    );
    assert_eq!(
        content
            .get("envelope")
            .and_then(|value| value.get("schema_id"))
            .and_then(serde_json::Value::as_str),
        Some(CONTENT_SCHEMA_ID)
    );
    assert_ne!(
        registration.object_ref.entity_id,
        registration.revision_ref.entity_id
    );
    assert_ne!(
        registration.object_ref.entity_id,
        registration.content_ref.entity_id
    );
    assert_ne!(
        registration.revision_ref.entity_id,
        registration.content_ref.entity_id
    );
}
