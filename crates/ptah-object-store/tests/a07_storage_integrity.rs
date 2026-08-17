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
    let location = store
        .latest(registration.location_ref.entity_id)
        .expect("verified Location");
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
    let location = store
        .latest(registration.location_ref.entity_id)
        .expect("failed Location");
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
    assert!(matches!(
        store.read_revision(registration.revision_ref.entity_id),
        Err(ObjectStoreError::VerificationFailed)
    ));
}
