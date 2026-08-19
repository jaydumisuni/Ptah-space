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

    let verify_evidence = create_evidence_for_target(
        &runtime,
        &workspace,
        &authority,
        EvidenceMode::Readback,
        registration.location_ref.clone(),
    );
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

    let corrupt_evidence = create_evidence_for_target(
        &runtime,
        &workspace,
        &authority,
        EvidenceMode::Readback,
        registration.location_ref.clone(),
    );
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
fn unrelated_readback_evidence_cannot_verify_location() {
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
            b"exact target verification",
            register_spec(&workspace, &authority, registration_evidence.production),
        )
        .expect("register");

    let unrelated = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Readback);
    assert!(matches!(
        store.verify_location(
            registration.location_ref.entity_id,
            VerificationSpec {
                workspace_ref: workspace,
                authority_ref: authority,
                production: unrelated.production,
            },
        ),
        Err(ObjectStoreError::ProductionEvidenceMismatch)
    ));
    let location = ledger_document(&temp.ledger(), registration.location_ref.entity_id);
    assert_eq!(
        location
            .get("verification_refs")
            .and_then(serde_json::Value::as_array)
            .expect("verification refs")
            .len(),
        0
    );
    assert_eq!(
        location
            .get("verification_state")
            .and_then(serde_json::Value::as_str),
        Some("unverified")
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

    let missing_evidence = create_evidence_for_target(
        &runtime,
        &workspace,
        &authority,
        EvidenceMode::Readback,
        first.location_ref.clone(),
    );
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

#[cfg(unix)]
#[test]
fn symlinked_cas_prefix_cannot_redirect_registration_outside_root() {
    use std::os::unix::fs::symlink;

    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let bytes = b"contained registration";
    let digest = ObjectStore::sha256(bytes);
    let algorithm_dir = temp.cas().join("sha256");
    fs::create_dir(&algorithm_dir).expect("create algorithm directory");
    let outside = temp.root.join("outside-write");
    fs::create_dir(&outside).expect("create outside directory");
    symlink(&outside, algorithm_dir.join(&digest[..2])).expect("symlink prefix outside CAS");

    let evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    assert!(matches!(
        store.register_bytes(
            bytes,
            register_spec(&workspace, &authority, evidence.production),
        ),
        Err(ObjectStoreError::CasIntegrityMismatch)
    ));
    assert!(!outside.join(&digest).exists());
}

#[cfg(unix)]
#[test]
fn symlinked_cas_prefix_cannot_redirect_verification_outside_root() {
    use std::os::unix::fs::symlink;

    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let registration = store
        .register_bytes(
            b"contained verification",
            register_spec(&workspace, &authority, evidence.production),
        )
        .expect("register");
    let prefix = temp.cas().join("sha256").join(&registration.sha256[..2]);
    let saved_prefix = temp.root.join("saved-prefix");
    fs::rename(&prefix, &saved_prefix).expect("move real prefix aside");
    let outside = temp.root.join("outside-read");
    fs::create_dir(&outside).expect("create outside directory");
    symlink(&outside, &prefix).expect("symlink prefix outside CAS");

    let readback = create_evidence_for_target(
        &runtime,
        &workspace,
        &authority,
        EvidenceMode::Readback,
        registration.location_ref.clone(),
    );
    assert!(matches!(
        store.verify_location(
            registration.location_ref.entity_id,
            VerificationSpec {
                workspace_ref: workspace,
                authority_ref: authority,
                production: readback.production,
            },
        ),
        Err(ObjectStoreError::CasIntegrityMismatch)
    ));
    let location = ledger_document(&temp.ledger(), registration.location_ref.entity_id);
    assert_eq!(
        location
            .get("verification_refs")
            .and_then(serde_json::Value::as_array)
            .expect("verification refs")
            .len(),
        0
    );
}
