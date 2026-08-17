#[test]
fn generated_revision_is_not_an_artifact_until_explicit_promotion() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let registration = store
        .register_bytes(
            b"generated candidate",
            register_spec(&workspace, &authority, evidence.production.clone()),
        )
        .expect("register generated candidate");

    let before = store
        .latest(registration.object_ref.entity_id)
        .expect("Object before promotion");
    assert_eq!(
        before
            .get("artifact_refs")
            .and_then(serde_json::Value::as_array)
            .expect("artifact refs")
            .len(),
        0
    );

    let artifact_ref = store
        .promote_artifact(
            registration.revision_ref.entity_id,
            ArtifactPromotionSpec {
                workspace_ref: workspace.clone(),
                authority_ref: authority.clone(),
                artifact_type: "build_output".to_owned(),
                artifact_version: "1.0.0".to_owned(),
                purpose: "explicit A07 promotion proof".to_owned(),
                subject_refs: Vec::new(),
                production: evidence.production.clone(),
            },
        )
        .expect("explicit promotion");
    let artifact = store
        .latest(artifact_ref.entity_id)
        .expect("Artifact projection");
    assert_eq!(
        artifact
            .get("envelope")
            .and_then(|value| value.get("schema_id"))
            .and_then(serde_json::Value::as_str),
        Some(ARTIFACT_SCHEMA_ID)
    );
    assert_eq!(
        artifact
            .get("lifecycle")
            .and_then(|value| value.get("current_state"))
            .and_then(serde_json::Value::as_str),
        Some("promoted")
    );
    let after = store
        .latest(registration.object_ref.entity_id)
        .expect("Object after promotion");
    assert!(contains_ref(&after, "artifact_refs", &artifact_ref));
}

#[test]
fn producing_activity_attempt_and_receipts_must_match_exactly() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let first = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let second = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let mut mixed = first.production.clone();
    mixed.attempt_ref = second.production.attempt_ref.clone();

    assert!(matches!(
        store.register_bytes(
            b"mixed provenance must fail",
            register_spec(&workspace, &authority, mixed),
        ),
        Err(ObjectStoreError::ProductionEvidenceMismatch)
    ));
}
