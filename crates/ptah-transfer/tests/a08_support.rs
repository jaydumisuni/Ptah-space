use ptah_activity_runtime::{
    ActivityRuntime, ActivitySpec, AttemptContext, IdempotencyClass, LedgerJournal, OperationSpec,
    RetryClass, SideEffectClass,
};
use ptah_events::EventBus;
use ptah_identifiers::{EntityId, EntityRef};
use ptah_ledger::{EntityRecordRepository, Ledger};
use ptah_receipts::{
    AuthorityClass, ProofLevel, ReceiptContext, ReceiptKind, ReceiptOutcome, ReceiptSpec,
};
use ptah_transfer::{
    DestinationDescriptor, DestinationIntent, DigestValue, ProviderAcknowledgement,
    ResumabilityPolicy, ResumeSpec, SourceDescriptor, SourceKind, StartTransferSpec, TransferClock,
    TransferConfig, TransferEngine, TransferError, TransferEvidence, TransferMode,
    TransferRequestSpec, UploadSink, ValidatorObservation, VerificationDomain,
};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
    process,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

const NOW: &str = "2026-08-19T20:00:00Z";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempRoot {
    root: PathBuf,
}

impl TempRoot {
    fn new() -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("ptah-a08-transfer-{}-{serial}", process::id()));
        fs::create_dir_all(&root).expect("create test root");
        Self { root }
    }

    fn ledger(&self) -> PathBuf {
        self.root.join("ptah.sqlite3")
    }

    fn staging(&self) -> PathBuf {
        self.root.join("staging")
    }

    fn destination(&self) -> PathBuf {
        self.root.join("destination")
    }

    fn source_root(&self) -> PathBuf {
        self.root.join("source")
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone)]
struct AttemptFixture {
    activity_id: EntityId,
    operation_id: EntityId,
    attempt_id: EntityId,
    context: AttemptContext,
    nonce: String,
}

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid reference")
}

fn fixed_clock() -> TransferClock {
    Arc::new(|| NOW.to_owned())
}

fn runtime(path: &Path) -> ActivityRuntime {
    let journal = Arc::new(LedgerJournal::open(path).expect("open A04 journal"));
    ActivityRuntime::new(8, journal, fixed_clock()).expect("create A04 runtime")
}

fn config() -> TransferConfig {
    static CONFIG: OnceLock<TransferConfig> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider_instance_ref = reference("runtime.provider_instance");
            TransferConfig {
                provider_ref: reference("runtime.provider"),
                provider_instance_ref: provider_instance_ref.clone(),
                provider_revision_ref: reference("runtime.provider_revision"),
                provider_generation: 3,
                connection_epoch: 5,
                protocol_ref: reference("core.protocol"),
                protocol_revision: "a08-local-1".to_owned(),
                producer_ref: provider_instance_ref,
                producer_version: "ptah-transfer-a08-test".to_owned(),
            }
        })
        .clone()
}

fn engine(temp: &TempRoot) -> TransferEngine {
    TransferEngine::open(
        temp.ledger(),
        temp.staging(),
        config(),
        EventBus::new(64),
        fixed_clock(),
    )
    .expect("open A08 engine")
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn source(bytes: &[u8]) -> SourceDescriptor {
    SourceDescriptor {
        source_kind: SourceKind::RemoteDescriptor,
        content_ref: None,
        object_revision_ref: None,
        location_ref: None,
        provider_instance_ref: Some(config().provider_instance_ref),
        remote_alias_ref: Some(reference("storage.alias")),
        stream_ref: None,
        expected_size: Some(bytes.len() as u64),
        expected_digests: vec![DigestValue::canonical_sha256(sha256(bytes))],
        validator_observations: vec![ValidatorObservation {
            validator_type: "etag".to_owned(),
            value: "source-etag-v1".to_owned(),
            observed_at: NOW.to_owned(),
        }],
    }
}

fn destination() -> DestinationDescriptor {
    DestinationDescriptor {
        destination_intent: DestinationIntent::StageForObjectAcceptance,
        provider_instance_ref: config().provider_instance_ref,
        existing_location_ref: None,
        namespace_or_alias_ref: Some(reference("storage.alias")),
        storage_class: "local_stage".to_owned(),
        expected_location_generation: None,
    }
}

fn request_spec(bytes: &[u8], mode: TransferMode) -> TransferRequestSpec {
    TransferRequestSpec {
        requestor_ref: reference("identity.principal"),
        workspace_ref: reference("core.workspace"),
        authority_ref: reference("identity.principal"),
        transfer_mode: mode,
        source: source(bytes),
        destination: destination(),
        resumability_policy: ResumabilityPolicy::Required,
        network_or_grant_refs: vec![reference("security.grant")],
        credential_refs: vec![reference("security.credential")],
        privacy_policy_ref: reference("policy.privacy"),
        retention_policy_ref: reference("policy.retention"),
        requested_verification_domains: vec![
            VerificationDomain::TransportCompleted,
            VerificationDomain::ByteCountMatched,
            VerificationDomain::ContentDigestMatched,
            VerificationDomain::DestinationReadbackMatched,
        ],
    }
}

fn start_spec() -> StartTransferSpec {
    StartTransferSpec {
        idempotency_key: "a08-transfer-key-0001".to_owned(),
        compression_mode: "none".to_owned(),
        encryption_mode: "none".to_owned(),
        chunk_size: 8,
    }
}

fn create_attempt(
    runtime: &ActivityRuntime,
    workspace: &EntityRef,
    authority: &EntityRef,
    target: EntityRef,
) -> AttemptFixture {
    let activity_id = runtime
        .create_activity(ActivitySpec {
            request_ref: reference("core.request"),
            workspace_ref: workspace.clone(),
            caller_ref: authority.clone(),
            authority_ref: authority.clone(),
            activity_kind: "transfer.a08_proof".to_owned(),
            intent_ref: reference("core.intent"),
            priority: 0,
            max_attempts: 4,
        })
        .expect("create Activity");
    assert_eq!(
        runtime.admit_next().expect("admit Activity"),
        Some(activity_id)
    );
    let operation_id = runtime
        .create_operation(
            activity_id,
            OperationSpec {
                operation_kind: "transfer.a08_operation".to_owned(),
                logical_target_refs: vec![target],
                command_or_action_ref: reference("core.command"),
                side_effect_class: SideEffectClass::IdempotentMutation,
                retry_class: RetryClass::RetrySafe,
                idempotency_class: IdempotencyClass::OperationIdentity,
                idempotency_key: None,
                required_authority_refs: vec![authority.clone()],
                precondition_refs: Vec::new(),
                desired_proof_refs: vec![reference("proof.claim")],
                compensating_operation_ref: None,
            },
        )
        .expect("create Operation");
    runtime
        .make_operation_ready(operation_id)
        .expect("ready Operation");
    create_physical_attempt(runtime, activity_id, operation_id, attempt_context())
}

fn create_physical_attempt(
    runtime: &ActivityRuntime,
    activity_id: EntityId,
    operation_id: EntityId,
    context: AttemptContext,
) -> AttemptFixture {
    let attempt_id = runtime
        .create_attempt(operation_id, context.clone())
        .expect("create Attempt");
    runtime
        .dispatch_attempt(attempt_id)
        .expect("dispatch Attempt");
    runtime.accept_attempt(attempt_id).expect("accept Attempt");
    runtime
        .begin_attempt_execution(attempt_id)
        .expect("execute Attempt");
    let nonce = runtime
        .attempt(attempt_id)
        .expect("read Attempt")
        .expect("Attempt retained")
        .correlation_nonce()
        .to_owned();
    AttemptFixture {
        activity_id,
        operation_id,
        attempt_id,
        context,
        nonce,
    }
}

fn attempt_context() -> AttemptContext {
    let cfg = config();
    AttemptContext {
        node_ref: reference("core.node"),
        node_generation: 7,
        provider_ref: cfg.provider_ref,
        provider_generation: cfg.provider_generation,
        workload_generation: 11,
        connection_epoch: cfg.connection_epoch,
        facility_ref: reference("runtime.facility"),
        producer_instance_ref: cfg.provider_instance_ref,
        producer_version: "a08-proof-provider".to_owned(),
    }
}

fn append_receipt(
    runtime: &ActivityRuntime,
    attempt: &AttemptFixture,
    kind: ReceiptKind,
    proof_levels: Vec<ProofLevel>,
) -> EntityRef {
    let id = runtime
        .append_receipt(ReceiptSpec {
            kind,
            outcome: ReceiptOutcome::Positive,
            authority_class: AuthorityClass::FacilityRuntime,
            context: ReceiptContext {
                activity_ref: EntityRef::from_id(attempt.activity_id, "core.activity")
                    .expect("Activity"),
                operation_ref: EntityRef::from_id(attempt.operation_id, "core.operation")
                    .expect("Operation"),
                attempt_ref: EntityRef::from_id(attempt.attempt_id, "core.attempt")
                    .expect("Attempt"),
                idempotency_key: None,
                correlation_nonce: attempt.nonce.clone(),
                node_ref: attempt.context.node_ref.clone(),
                node_generation: attempt.context.node_generation,
                provider_ref: attempt.context.provider_ref.clone(),
                provider_generation: attempt.context.provider_generation,
                workload_generation: attempt.context.workload_generation,
                connection_epoch: attempt.context.connection_epoch,
                facility_ref: attempt.context.facility_ref.clone(),
                producer_instance_ref: attempt.context.producer_instance_ref.clone(),
                producer_version: attempt.context.producer_version.clone(),
            },
            producer_identity_evidence_refs: vec![reference("proof.evidence")],
            proof_claim_refs: vec![reference("proof.claim")],
            proof_levels,
            previous_or_superseded_receipt_refs: Vec::new(),
            summary: format!("A08 {kind:?} proof"),
            limitations: Vec::new(),
            occurred_at: NOW.to_owned(),
        })
        .expect("append Receipt");
    EntityRef::from_id(id, "proof.receipt").expect("Receipt ref")
}

fn evidence(attempt: &AttemptFixture, receipts: Vec<EntityRef>) -> TransferEvidence {
    TransferEvidence {
        activity_ref: EntityRef::from_id(attempt.activity_id, "core.activity").expect("Activity"),
        operation_ref: EntityRef::from_id(attempt.operation_id, "core.operation")
            .expect("Operation"),
        attempt_ref: EntityRef::from_id(attempt.attempt_id, "core.attempt").expect("Attempt"),
        receipt_refs: receipts,
    }
}

fn start_evidence(runtime: &ActivityRuntime, attempt: &AttemptFixture) -> TransferEvidence {
    evidence(
        attempt,
        vec![
            append_receipt(
                runtime,
                attempt,
                ReceiptKind::RequestAcknowledgement,
                vec![ProofLevel::Accepted],
            ),
            append_receipt(
                runtime,
                attempt,
                ReceiptKind::WorkDispatch,
                vec![ProofLevel::Dispatched],
            ),
        ],
    )
}

fn readback_evidence(runtime: &ActivityRuntime, attempt: &AttemptFixture) -> TransferEvidence {
    evidence(
        attempt,
        vec![
            append_receipt(
                runtime,
                attempt,
                ReceiptKind::Readback,
                vec![ProofLevel::OutputReadBack],
            ),
            append_receipt(
                runtime,
                attempt,
                ReceiptKind::HashVerification,
                vec![ProofLevel::OutputHashVerified],
            ),
        ],
    )
}

fn output_evidence(runtime: &ActivityRuntime, attempt: &AttemptFixture) -> TransferEvidence {
    evidence(
        attempt,
        vec![append_receipt(
            runtime,
            attempt,
            ReceiptKind::OutputObservation,
            vec![ProofLevel::OutputCreated, ProofLevel::OperationCompleted],
        )],
    )
}

fn hash_evidence(runtime: &ActivityRuntime, attempt: &AttemptFixture) -> TransferEvidence {
    evidence(
        attempt,
        vec![append_receipt(
            runtime,
            attempt,
            ReceiptKind::HashVerification,
            vec![ProofLevel::OutputHashVerified],
        )],
    )
}

fn ledger_document(path: &Path, id: EntityId) -> serde_json::Value {
    Ledger::open(path)
        .expect("open ledger")
        .latest_record(id)
        .expect("read record")
        .expect("record retained")
        .document()
        .clone()
}

fn lifecycle_state(path: &Path, id: EntityId) -> String {
    ledger_document(path, id)
        .get("lifecycle")
        .and_then(|value| value.get("current_state"))
        .and_then(serde_json::Value::as_str)
        .expect("lifecycle state")
        .to_owned()
}

fn assert_resume_manifest_bindings(
    ledger_path: &Path,
    run_ref: &EntityRef,
    original_nonce: &str,
    resumed_nonce: &str,
) -> serde_json::Value {
    let run = ledger_document(ledger_path, run_ref.entity_id);
    let manifests = run
        .get("manifest_refs")
        .and_then(serde_json::Value::as_array)
        .expect("manifest refs");
    assert_eq!(manifests.len(), 2);
    let first_manifest_ref: EntityRef =
        serde_json::from_value(manifests[0].clone()).expect("first Manifest ref");
    let resumed_manifest_ref: EntityRef =
        serde_json::from_value(manifests[1].clone()).expect("resumed Manifest ref");
    let first_manifest = ledger_document(ledger_path, first_manifest_ref.entity_id);
    let resumed_manifest = ledger_document(ledger_path, resumed_manifest_ref.entity_id);
    assert_eq!(
        first_manifest
            .get("correlation_nonce")
            .and_then(serde_json::Value::as_str),
        Some(original_nonce)
    );
    assert_eq!(
        resumed_manifest
            .get("correlation_nonce")
            .and_then(serde_json::Value::as_str),
        Some(resumed_nonce)
    );
    assert_ne!(original_nonce, resumed_nonce);
    assert_eq!(
        resumed_manifest
            .get("credential_or_grant_refs")
            .and_then(serde_json::Value::as_array)
            .expect("credential/grant refs")
            .len(),
        2
    );
    assert_eq!(
        resumed_manifest
            .get("policy_refs")
            .and_then(serde_json::Value::as_array)
            .expect("policy refs")
            .len(),
        2
    );
    run
}

#[derive(Default)]
struct MemorySink {
    bytes: Vec<u8>,
    acknowledgement: Option<ProviderAcknowledgement>,
}

impl UploadSink for MemorySink {
    fn write_chunk(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let offset = usize::try_from(offset).map_err(|_| io::Error::other("offset overflow"))?;
        if offset != self.bytes.len() {
            return Err(io::Error::other("non-contiguous upload"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn finalize(&mut self) -> io::Result<ProviderAcknowledgement> {
        Ok(self
            .acknowledgement
            .unwrap_or(ProviderAcknowledgement::Acknowledged))
    }

    fn read_back_chunk(&mut self, offset: u64, max_len: usize) -> io::Result<Vec<u8>> {
        let offset = usize::try_from(offset).map_err(|_| io::Error::other("offset overflow"))?;
        if offset >= self.bytes.len() {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(max_len).min(self.bytes.len());
        Ok(self.bytes[offset..end].to_vec())
    }
}
