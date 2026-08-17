use super::*;
use super::documents_support::*;
use ptah_receipts::{
    AuthorityClass, ProofLevel, Receipt, ReceiptContext, ReceiptKind, ReceiptOutcome, ReceiptSpec,
};
use std::{
    ffi::OsString,
    process,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ptah-a07-object-store-{}-{serial}",
            process::id()
        ));
        fs::create_dir_all(&path).expect("create test root");
        Self(path)
    }

    fn ledger(&self) -> PathBuf {
        self.0.join("ledger.sqlite3")
    }

    fn cas(&self) -> PathBuf {
        self.0.join("cas")
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        for suffix in ["-wal", "-shm"] {
            let mut sidecar: OsString = self.ledger().as_os_str().to_owned();
            sidecar.push(suffix);
            let _ = fs::remove_file(PathBuf::from(sidecar));
        }
    }
}

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid test entity ref")
}

fn test_clock() -> Arc<dyn Fn() -> String + Send + Sync> {
    Arc::new(|| "2026-08-17T18:00:00Z".to_owned())
}

struct Evidence {
    workspace_ref: EntityRef,
    authority_ref: EntityRef,
    producer_ref: EntityRef,
    backend_ref: EntityRef,
    connection_ref: EntityRef,
    correlation: ProductionCorrelation,
}

fn seed_evidence(path: &Path) -> Evidence {
    let workspace_ref = reference("core.workspace");
    let authority_ref = reference("identity.principal");
    let activity_ref = reference("core.activity");
    let operation_ref = reference("core.operation");
    let attempt_ref = reference("core.attempt");
    let node_ref = reference("core.node");
    let provider_ref = reference("provider.instance");
    let facility_ref = reference("core.facility");
    let producer_ref = reference("proof.producer");
    let backend_ref = reference("storage.backend");
    let connection_ref = reference("storage.connection");
    let context = ReceiptContext {
        activity_ref: activity_ref.clone(),
        operation_ref: operation_ref.clone(),
        attempt_ref: attempt_ref.clone(),
        idempotency_key: Some("a07-test-idempotency".to_owned()),
        correlation_nonce: "a07-test-correlation".to_owned(),
        node_ref,
        node_generation: 1,
        provider_ref,
        provider_generation: 1,
        workload_generation: 1,
        connection_epoch: 1,
        facility_ref,
        producer_instance_ref: producer_ref.clone(),
        producer_version: "a07-test/1".to_owned(),
    };
    let runtime_envelope = |reference: &EntityRef, schema_id: &str| {
        json!({
            "entity_id": reference.entity_id,
            "entity_kind": reference.entity_kind,
            "schema_id": schema_id,
            "schema_version": SCHEMA_VERSION,
            "record_revision": 1,
            "created_at": "2026-08-17T18:00:00Z",
            "updated_at": "2026-08-17T18:00:00Z",
            "workspace_ref": workspace_ref,
            "authority_ref": authority_ref,
            "privacy_class": "internal",
            "audience": "workspace",
            "redaction_policy": "none",
            "retention_policy": {
                "policy_id": "ptah.a07.test",
                "policy_version": SCHEMA_VERSION,
                "retention_class": "historical"
            },
            "extensions": {}
        })
    };
    let activity = json!({
        "envelope": runtime_envelope(&activity_ref, ACTIVITY_SCHEMA_ID),
        "workspace_ref": workspace_ref
    });
    let operation = json!({
        "envelope": runtime_envelope(&operation_ref, OPERATION_SCHEMA_ID),
        "activity_ref": activity_ref
    });
    let attempt = json!({
        "envelope": runtime_envelope(&attempt_ref, ATTEMPT_SCHEMA_ID),
        "operation_ref": operation_ref
    });
    let mut ledger = Ledger::open(path).expect("open evidence ledger");
    let write = ledger.begin_write().expect("begin A04 hierarchy write");
    for document in [activity, operation, attempt] {
        let record = CanonicalRecord::from_document(document)
            .expect("canonical A04 hierarchy record");
        write.insert(&record).expect("insert A04 hierarchy record");
    }
    write.commit().expect("commit A04 hierarchy records");

    let claim_ref = reference("proof.claim");
    let specs = [
        (ReceiptKind::OutputObservation, ProofLevel::OutputCreated),
        (ReceiptKind::HashVerification, ProofLevel::OutputHashVerified),
        (ReceiptKind::OperationObservation, ProofLevel::OperationCompleted),
        (ReceiptKind::Readback, ProofLevel::OutputReadBack),
    ];
    let mut receipts = Vec::new();
    for (kind, level) in specs {
        let receipt = Receipt::prepare(ReceiptSpec {
            kind,
            outcome: ReceiptOutcome::Positive,
            authority_class: AuthorityClass::FacilityRuntime,
            context: context.clone(),
            producer_identity_evidence_refs: Vec::new(),
            proof_claim_refs: vec![claim_ref.clone()],
            proof_levels: vec![level],
            previous_or_superseded_receipt_refs: Vec::new(),
            summary: "A07 acceptance evidence".to_owned(),
            limitations: Vec::new(),
            occurred_at: "2026-08-17T18:00:00Z".to_owned(),
        })
        .expect("prepare A04 Receipt");
        let receipt_ref = EntityRef::from_id(receipt.id(), "proof.receipt")
            .expect("canonical Receipt ref");
        let record = CanonicalRecord::from_document(receipt.canonical_document())
            .expect("canonical Receipt record");
        let write = ledger.begin_write().expect("begin receipt write");
        write.insert(&record).expect("insert receipt");
        write.commit().expect("commit receipt");
        receipts.push(receipt_ref);
    }
    Evidence {
        workspace_ref,
        authority_ref,
        producer_ref,
        backend_ref,
        connection_ref,
        correlation: ProductionCorrelation {
            activity_ref,
            operation_ref,
            attempt_ref,
            receipt_refs: receipts,
        },
    }
}

fn registration_input(evidence: &Evidence) -> RegisterObject {
    RegisterObject {
        workspace_ref: evidence.workspace_ref.clone(),
        authority_ref: evidence.authority_ref.clone(),
        object_class: "source_file".to_owned(),
        declared_names: vec![DeclaredName {
            name: "alpha.bin".to_owned(),
            name_role: NameRole::Original,
            source_class: NameSource::Caller,
        }],
        source_refs: vec![reference("source.upload")],
        revision_role: RevisionRole::Original,
        origin_class: OriginClass::UploadedOriginal,
        created_reason: "A07 registration acceptance".to_owned(),
        deduplication_scope: DeduplicationScope::Workspace,
        deduplication_scope_ref: None,
        media_type_claim: None,
        producer_ref: evidence.producer_ref.clone(),
        producer_version: "a07-test/1".to_owned(),
        backend_ref: evidence.backend_ref.clone(),
        connection_ref: evidence.connection_ref.clone(),
        production_correlation: evidence.correlation.clone(),
    }
}

#[test]
fn registration_publishes_cas_and_separates_object_revision_content_location() {
    let temp = TempRoot::new();
    let evidence = seed_evidence(&temp.ledger());
    let mut store = ObjectStore::open(temp.ledger(), temp.cas(), test_clock())
        .expect("open object store");
    let result = store
        .register_object(b"immutable alpha bytes", registration_input(&evidence))
        .expect("register object");
    assert_ne!(result.object_ref.entity_id, result.revision_ref.entity_id);
    assert_ne!(result.revision_ref.entity_id, result.content_ref.entity_id);
    assert_ne!(result.content_ref.entity_id, result.location_ref.entity_id);
    assert!(!result.reused_content);
    assert!(!result.reused_location);
    let path = store
        .local_cas_path(result.location_ref.entity_id)
        .expect("CAS path");
    assert_eq!(fs::read(path).expect("read CAS bytes"), b"immutable alpha bytes");

    let content = store
        .required_schema(result.content_ref.entity_id, CONTENT_SCHEMA_ID)
        .expect("content");
    assert_eq!(
        field_string(content.document(), "deduplication_scope").expect("scope"),
        "workspace"
    );
    assert!(content.document().get("media_type_claim").is_none());
    let location = store
        .required_schema(result.location_ref.entity_id, LOCATION_SCHEMA_ID)
        .expect("location");
    assert_eq!(
        field_string(location.document(), "verification_state").expect("verification"),
        "unverified"
    );
}

#[test]
fn same_workspace_digest_reuses_content_and_local_location() {
    let temp = TempRoot::new();
    let evidence = seed_evidence(&temp.ledger());
    let mut store = ObjectStore::open(temp.ledger(), temp.cas(), test_clock())
        .expect("open object store");
    let first = store
        .register_object(b"same bytes", registration_input(&evidence))
        .expect("first registration");
    let second = store
        .register_object(b"same bytes", registration_input(&evidence))
        .expect("second registration");
    assert_eq!(first.content_ref, second.content_ref);
    assert_eq!(first.location_ref, second.location_ref);
    assert!(second.reused_content);
    assert!(second.reused_location);
    assert_ne!(first.object_ref, second.object_ref);
}

#[test]
fn verification_is_independent_from_availability_and_records_readback() {
    let temp = TempRoot::new();
    let evidence = seed_evidence(&temp.ledger());
    let mut store = ObjectStore::open(temp.ledger(), temp.cas(), test_clock())
        .expect("open object store");
    let registered = store
        .register_object(b"verified bytes", registration_input(&evidence))
        .expect("register object");
    let verification = store
        .verify_location(
            registered.location_ref.entity_id,
            VerifyLocation {
                authority_ref: evidence.authority_ref.clone(),
                verifier_ref: reference("proof.verifier"),
                verifier_version: "a07-verifier/1".to_owned(),
                production_correlation: evidence.correlation.clone(),
            },
        )
        .expect("verify location");
    assert_eq!(verification.outcome, "verified");
    let location = store
        .required_schema(registered.location_ref.entity_id, LOCATION_SCHEMA_ID)
        .expect("updated location");
    assert_eq!(
        field_string(location.document(), "verification_state").expect("verification"),
        "verified"
    );
    assert_eq!(field_string(location.document(), "health_state").expect("health"), "healthy");
}

#[test]
fn preexisting_wrong_bytes_at_digest_path_fail_closed() {
    let temp = TempRoot::new();
    let evidence = seed_evidence(&temp.ledger());
    let mut store = ObjectStore::open(temp.ledger(), temp.cas(), test_clock())
        .expect("open object store");
    let expected = b"expected bytes";
    let digest = sha256_hex(expected);
    let path = cas_path(&temp.cas(), &digest).expect("CAS path");
    fs::create_dir_all(path.parent().expect("CAS parent")).expect("create CAS parent");
    fs::write(&path, b"malicious bytes").expect("seed collision");
    let error = store
        .register_object(expected, registration_input(&evidence))
        .expect_err("collision must fail closed");
    assert!(matches!(error, ObjectStoreError::CasCollision(_)));
}

#[test]
fn receipt_from_different_attempt_is_rejected() {
    let temp = TempRoot::new();
    let evidence = seed_evidence(&temp.ledger());
    let mut input = registration_input(&evidence);
    input.production_correlation.attempt_ref = reference("core.attempt");
    let mut store = ObjectStore::open(temp.ledger(), temp.cas(), test_clock())
        .expect("open object store");
    assert!(matches!(
        store.register_object(b"bytes", input),
        Err(ObjectStoreError::ReceiptCorrelationMismatch)
    ));
}

#[test]
fn receipt_activity_from_different_workspace_is_rejected() {
    let temp = TempRoot::new();
    let evidence = seed_evidence(&temp.ledger());
    let mut input = registration_input(&evidence);
    input.workspace_ref = reference("core.workspace");
    let mut store = ObjectStore::open(temp.ledger(), temp.cas(), test_clock())
        .expect("open object store");
    assert!(matches!(
        store.register_object(b"bytes", input),
        Err(ObjectStoreError::ReceiptCorrelationMismatch)
    ));
}
