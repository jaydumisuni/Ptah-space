#[test]
fn identical_bytes_deduplicate_content_without_collapsing_logical_objects() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let bytes = b"same bytes, separate logical objects";

    let first_evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let first = store
        .register_bytes(
            bytes,
            register_spec(&workspace, &authority, first_evidence.production.clone()),
        )
        .expect("first registration");
    complete_evidence(&runtime, &first_evidence, first.revision_ref.clone());

    let second_evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let second = store
        .register_bytes(
            bytes,
            register_spec(&workspace, &authority, second_evidence.production.clone()),
        )
        .expect("second registration");
    complete_evidence(&runtime, &second_evidence, second.revision_ref.clone());

    assert_eq!(first.content_ref.entity_id, second.content_ref.entity_id);
    assert_ne!(first.object_ref.entity_id, second.object_ref.entity_id);
    assert_ne!(first.revision_ref.entity_id, second.revision_ref.entity_id);
    assert_eq!(first.location_ref.entity_id, second.location_ref.entity_id);
    assert!(!first.content_deduplicated);
    assert!(second.content_deduplicated);
}

#[test]
fn changed_bytes_create_distinct_content_identity() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");

    let first_evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let first = store
        .register_bytes(
            b"revision-one",
            register_spec(&workspace, &authority, first_evidence.production.clone()),
        )
        .expect("first registration");

    let second_evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let second = store
        .register_bytes(
            b"revision-two",
            register_spec(&workspace, &authority, second_evidence.production.clone()),
        )
        .expect("second registration");

    assert_ne!(first.sha256, second.sha256);
    assert_ne!(first.content_ref.entity_id, second.content_ref.entity_id);
}

#[test]
fn expected_digest_mismatch_blocks_cas_and_metadata_registration() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let bytes = b"must not be registered";
    let observed = ObjectStore::sha256(bytes);
    let evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    let mut spec = register_spec(&workspace, &authority, evidence.production);
    spec.expected_sha256 = Some("0".repeat(64));

    assert!(matches!(
        store.register_bytes(bytes, spec),
        Err(ObjectStoreError::ExpectedDigestMismatch { .. })
    ));
    let target = temp
        .cas()
        .join("sha256")
        .join(&observed[..2])
        .join(&observed);
    assert!(!target.exists());
}

#[test]
fn existing_digest_target_is_verified_and_never_overwritten() {
    let temp = TempRoot::new();
    let runtime = runtime(&temp.ledger());
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let mut store =
        ObjectStore::open(temp.ledger(), temp.cas(), config(), fixed_clock()).expect("open A07");
    let bytes = b"correct bytes";
    let digest = ObjectStore::sha256(bytes);
    let target = temp.cas().join("sha256").join(&digest[..2]).join(&digest);
    fs::create_dir_all(target.parent().expect("target parent")).expect("create CAS directory");
    fs::write(&target, b"malicious or corrupt winner").expect("seed corrupt target");

    let evidence = create_evidence(&runtime, &workspace, &authority, EvidenceMode::Register);
    assert!(matches!(
        store.register_bytes(
            bytes,
            register_spec(&workspace, &authority, evidence.production),
        ),
        Err(ObjectStoreError::CasIntegrityMismatch)
    ));
    assert_eq!(
        fs::read(&target).expect("read retained target"),
        b"malicious or corrupt winner"
    );
}
