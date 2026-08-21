#[test]
fn generated_revision_requires_distinct_targeted_promotion_evidence() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let creation = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let registration = store
        .register_bytes(
            b"generated candidate",
            register_spec(&workspace, &authority, creation.production.clone()),
        )
        .expect("register generated candidate");
    let before = ledger_document(&temp.ledger(), registration.object_ref.entity_id);
    assert_eq!(
        before
            .get("artifact_refs")
            .and_then(serde_json::Value::as_array)
            .expect("artifact refs")
            .len(),
        0
    );

    let promotion = create_evidence_for_target(
        &runtime,
        &workspace,
        &authority,
        EvidenceMode::OutputOnly,
        registration.revision_ref.clone(),
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
                production: promotion.production.clone(),
            },
        )
        .expect("explicit promotion");
    let artifact = ledger_document(&temp.ledger(), artifact_ref.entity_id);
    assert_eq!(
        artifact
            .get("envelope")
            .and_then(|value| value.get("schema_id"))
            .and_then(serde_json::Value::as_str),
        Some(ARTIFACT_SCHEMA_ID)
    );
    let promotion_operation: EntityRef = serde_json::from_value(
        artifact
            .get("production_correlation")
            .and_then(|value| value.get("operation_ref"))
            .cloned()
            .expect("promotion operation ref"),
    )
    .expect("decode promotion operation");
    assert_eq!(promotion_operation, promotion.production.operation_ref);
    assert_ne!(promotion_operation, creation.production.operation_ref);
    let after = ledger_document(&temp.ledger(), registration.object_ref.entity_id);
    assert!(contains_ref(&after, "artifact_refs", &artifact_ref));
}

#[test]
fn unrelated_or_original_execution_evidence_cannot_promote_revision() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let creation = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let registration = store
        .register_bytes(
            b"promotion target",
            register_spec(&workspace, &authority, creation.production.clone()),
        )
        .expect("register generated candidate");

    for production in [
        creation.production,
        create_evidence(&runtime, &workspace, &authority, EvidenceMode::OutputOnly).production,
    ] {
        assert!(matches!(
            store.promote_artifact(
                registration.revision_ref.entity_id,
                ArtifactPromotionSpec {
                    workspace_ref: workspace.clone(),
                    authority_ref: authority.clone(),
                    artifact_type: "build_output".to_owned(),
                    artifact_version: "1.0.0".to_owned(),
                    purpose: "must have targeted promotion evidence".to_owned(),
                    subject_refs: Vec::new(),
                    production,
                },
            ),
            Err(ObjectStoreError::ProductionEvidenceMismatch)
        ));
    }
}

#[test]
fn claimed_authority_must_match_exact_a04_activity_and_operation() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let proven_authority = reference("identity.principal");
    let claimed_authority = reference("identity.principal");
    let evidence = create_evidence(
        &runtime,
        &workspace,
        &proven_authority,
        EvidenceMode::Register,
    );
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    assert!(matches!(
        store.register_bytes(
            b"authority claim must be evidenced",
            register_spec(&workspace, &claimed_authority, evidence.production),
        ),
        Err(ObjectStoreError::AuthorityMismatch)
    ));
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

#[test]
fn missing_execution_context_on_attempt_and_receipts_fails_closed() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    mutate_latest_document(&temp.ledger(), evidence.attempt_id, |document| {
        document
            .as_object_mut()
            .expect("Attempt document object")
            .remove("producer_version");
    });
    for receipt_ref in &evidence.production.receipt_refs {
        mutate_latest_document(&temp.ledger(), receipt_ref.entity_id, |document| {
            document
                .as_object_mut()
                .expect("Receipt document object")
                .remove("producer_version");
        });
    }

    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    assert!(matches!(
        store.register_bytes(
            b"missing context must not self-match",
            register_spec(&workspace, &authority, evidence.production),
        ),
        Err(ObjectStoreError::ProductionEvidenceMismatch)
    ));
}
