#[test]
fn integrity_verifier_records_success_then_detects_corruption() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let registration_evidence =
        create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let registration = store
        .register_bytes(
            b"integrity protected bytes",
            register_spec(
                &workspace,
                &authority,
                registration_evidence.production.clone(),
            ),
        )
        .expect("register");

    let verify_evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Readback);
    let report = store
        .verify_location(
            registration.location_ref.entity_id,
            VerificationSpec {
                workspace_ref: workspace.clone(),
                authority_ref: authority.clone(),
                production: verify_evidence.production.clone(),
            },
        )
        .expect("verify intact Location");
    assert_eq!(report.outcome, "verified");
    let location = ledger_document(&temp.ledger(), registration.location_ref.entity_id);
    assert_eq!(
        location
            .get("verification_state")
            .and_then(serde_json::Value::as_str),
        Some("verified")
    );

    let target = temp
        .cas()
        .join("sha256")
        .join(&registration.sha256[..2])
        .join(&registration.sha256);
    fs::write(&target, b"corrupted bytes").expect("corrupt CAS target");

    let corrupt_evidence =
        create_evidence(&runtime, &workspace, &authority, EvidenceMode::Readback);
    let corrupt = store
        .verify_location(
            registration.location_ref.entity_id,
            VerificationSpec {
                workspace_ref: workspace.clone(),
                authority_ref: authority.clone(),
                production: corrupt_evidence.production,
            },
        )
        .expect("record negative verification");
    assert_eq!(corrupt.outcome, "digest_mismatch");
    let location = ledger_document(&temp.ledger(), registration.location_ref.entity_id);
    assert_eq!(
        location
            .get("verification_state")
            .and_then(serde_json::Value::as_str),
        Some("failed")
    );
    assert_eq!(
        location
            .get("health_state")
            .and_then(serde_json::Value::as_str),
        Some("corrupt")
    );
}

#[test]
fn missing_location_is_reobserved_after_successful_rematerialization() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let store_config = config();
    let mut store = ObjectStore::open(
        temp.ledger(),
        temp.cas(),
        store_config,
        fixed_clock(),
    )
    .expect("open A07");
    let bytes = b"rematerialized bytes";
    let registration_evidence =
        create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let first = store
        .register_bytes(
            bytes,
            register_spec(&workspace, &authority, registration_evidence.production),
        )
        .expect("initial registration");
    let target = temp
        .cas()
        .join("sha256")
        .join(&first.sha256[..2])
        .join(&first.sha256);
    fs::remove_file(&target).expect("remove materialization");

    let missing_evidence =
        create_evidence(&runtime, &workspace, &authority, EvidenceMode::Readback);
    let missing = store
        .verify_location(
            first.location_ref.entity_id,
            VerificationSpec {
                workspace_ref: workspace.clone(),
                authority_ref: authority.clone(),
                production: missing_evidence.production,
            },
        )
        .expect("record missing Location");
    assert_eq!(missing.outcome, "missing");

    let replacement_evidence =
        create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let second = store
        .register_bytes(
            bytes,
            register_spec(&workspace, &authority, replacement_evidence.production),
        )
        .expect("rematerialize same Content");
    assert_eq!(first.content_ref, second.content_ref);
    assert_eq!(first.location_ref, second.location_ref);
    assert!(second.content_deduplicated);
    let location = ledger_document(&temp.ledger(), second.location_ref.entity_id);
    assert_eq!(
        location
            .get("health_state")
            .and_then(serde_json::Value::as_str),
        Some("healthy")
    );
    assert_eq!(
        location
            .get("verification_state")
            .and_then(serde_json::Value::as_str),
        Some("unverified")
    );
    assert_eq!(
        location
            .get("observation_refs")
            .and_then(serde_json::Value::as_array)
            .expect("Location observations")
            .len(),
        3
    );
}
