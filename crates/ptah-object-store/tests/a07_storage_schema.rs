#[test]
fn location_uses_provider_relative_key_and_optional_fields_are_omitted() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let registration = store
        .register_bytes(
            b"schema omission proof",
            register_spec(&workspace, &authority, evidence.production),
        )
        .expect("register");

    let location = ledger_document(&temp.ledger(), registration.location_ref.entity_id);
    assert_eq!(
        location
            .get("envelope")
            .and_then(|value| value.get("schema_id"))
            .and_then(serde_json::Value::as_str),
        Some(LOCATION_SCHEMA_ID)
    );
    assert!(location.get("revision_ref").is_none());
    assert!(location.get("last_verified_at").is_none());
    let alias = location
        .get("backend_aliases")
        .and_then(serde_json::Value::as_array)
        .and_then(|items| items.first())
        .expect("object key alias");
    let alias_value = alias
        .get("alias_value")
        .and_then(serde_json::Value::as_str)
        .expect("alias value");
    assert!(alias_value.starts_with("sha256/"));
    assert!(!alias_value.contains(temp.root.to_string_lossy().as_ref()));

    let content = ledger_document(&temp.ledger(), registration.content_ref.entity_id);
    assert_eq!(
        content
            .get("envelope")
            .and_then(|value| value.get("schema_id"))
            .and_then(serde_json::Value::as_str),
        Some(CONTENT_SCHEMA_ID)
    );
    let hash_ref: EntityRef = serde_json::from_value(
        content
            .get("hash_observation_refs")
            .and_then(serde_json::Value::as_array)
            .and_then(|items| items.first())
            .cloned()
            .expect("Hash Observation ref"),
    )
    .expect("decode Hash Observation ref");
    let observation = ledger_document(&temp.ledger(), hash_ref.entity_id);
    assert_eq!(
        observation
            .get("envelope")
            .and_then(|value| value.get("schema_id"))
            .and_then(serde_json::Value::as_str),
        Some(HASH_OBSERVATION_SCHEMA_ID)
    );
    assert!(observation.get("location_or_stream_ref").is_none());
}
