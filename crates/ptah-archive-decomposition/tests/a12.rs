//! A12 archive-decomposition acceptance tests.

use ptah_activity_runtime::{
    ActivityRuntime, ActivitySpec, AttemptContext, IdempotencyClass, LedgerJournal, OperationSpec,
    RetryClass, SideEffectClass,
};
use ptah_archive_decomposition::{
    ArchiveBackend, BackendIdentity, DecompositionBudget, DecompositionOutcome, DecompositionSpec,
    DecompositionStore, MemberKind, ParseReport, ParseTerminal, ParsedMember, decompose,
};
use ptah_identifiers::{EntityId, EntityRef};
use ptah_ledger::{EntityRecordRepository, Ledger};
use ptah_object_store::{
    ObjectStore, ObjectStoreConfig, OriginClass, ProductionEvidence, RegisterObjectSpec,
    RevisionRole, StoreClock,
};
use ptah_receipts::{
    AuthorityClass, ProofLevel, ReceiptContext, ReceiptKind, ReceiptOutcome, ReceiptSpec,
};
use rusqlite::Connection;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

const NOW: &str = "2026-08-20T13:00:00Z";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);
impl TempRoot {
    fn new() -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("ptah-a12-{}-{serial}", process::id()));
        fs::create_dir_all(&root).expect("create temp root");
        Self(root)
    }
    fn ledger(&self) -> PathBuf {
        self.0.join("ptah.sqlite3")
    }
    fn cas(&self) -> PathBuf {
        self.0.join("cas")
    }
}
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("reference")
}
fn clock() -> StoreClock {
    Arc::new(|| NOW.to_owned())
}
fn config() -> ObjectStoreConfig {
    ObjectStoreConfig {
        backend_ref: reference("storage.backend"),
        connection_ref: reference("storage.connection"),
        producer_ref: reference("runtime.provider_instance"),
        producer_version: "a12-test-1.0.0".to_owned(),
    }
}
fn runtime(path: &Path) -> ActivityRuntime {
    ActivityRuntime::new(
        8,
        Arc::new(LedgerJournal::open(path).expect("journal")),
        clock(),
    )
    .expect("runtime")
}

#[derive(Clone)]
struct EvidenceBundle {
    production: ProductionEvidence,
}

fn evidence_for_target(
    runtime: &ActivityRuntime,
    workspace: &EntityRef,
    authority: &EntityRef,
    target: EntityRef,
) -> EvidenceBundle {
    let activity = runtime
        .create_activity(ActivitySpec {
            request_ref: reference("core.request"),
            workspace_ref: workspace.clone(),
            caller_ref: authority.clone(),
            authority_ref: authority.clone(),
            activity_kind: "object.a12_proof".to_owned(),
            intent_ref: reference("core.intent"),
            priority: 0,
            max_attempts: 2,
        })
        .expect("activity");
    assert_eq!(runtime.admit_next().expect("admit"), Some(activity));
    let operation = runtime
        .create_operation(
            activity,
            OperationSpec {
                operation_kind: "object.archive_decomposition".to_owned(),
                logical_target_refs: vec![target],
                command_or_action_ref: reference("core.command"),
                side_effect_class: SideEffectClass::IdempotentMutation,
                retry_class: RetryClass::RetrySafe,
                idempotency_class: IdempotencyClass::NoneRequired,
                idempotency_key: None,
                required_authority_refs: vec![authority.clone()],
                precondition_refs: Vec::new(),
                desired_proof_refs: vec![reference("proof.claim")],
                compensating_operation_ref: None,
            },
        )
        .expect("operation");
    runtime.make_operation_ready(operation).expect("ready");
    let context = AttemptContext {
        node_ref: reference("core.node"),
        node_generation: 7,
        provider_ref: reference("runtime.provider"),
        provider_generation: 3,
        workload_generation: 11,
        connection_epoch: 5,
        facility_ref: reference("runtime.facility"),
        producer_instance_ref: reference("runtime.provider_instance"),
        producer_version: "a12-test-backend-1.0.0".to_owned(),
    };
    let attempt = runtime
        .create_attempt(operation, context.clone())
        .expect("attempt");
    runtime.dispatch_attempt(attempt).expect("dispatch");
    runtime.accept_attempt(attempt).expect("accept");
    runtime.begin_attempt_execution(attempt).expect("execute");
    let nonce = runtime
        .attempt(attempt)
        .expect("read")
        .expect("retained")
        .correlation_nonce()
        .to_owned();
    let output = append_receipt(
        runtime,
        activity,
        operation,
        attempt,
        &nonce,
        &context,
        ReceiptKind::OutputObservation,
        vec![ProofLevel::OutputCreated, ProofLevel::OperationCompleted],
    );
    let hash = append_receipt(
        runtime,
        activity,
        operation,
        attempt,
        &nonce,
        &context,
        ReceiptKind::HashVerification,
        vec![ProofLevel::OutputHashVerified],
    );
    EvidenceBundle {
        production: ProductionEvidence {
            activity_ref: EntityRef::from_id(activity, "core.activity").expect("activity ref"),
            operation_ref: EntityRef::from_id(operation, "core.operation").expect("operation ref"),
            attempt_ref: EntityRef::from_id(attempt, "core.attempt").expect("attempt ref"),
            receipt_refs: vec![
                EntityRef::from_id(output, "proof.receipt").expect("receipt"),
                EntityRef::from_id(hash, "proof.receipt").expect("receipt"),
            ],
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn append_receipt(
    runtime: &ActivityRuntime,
    activity: EntityId,
    operation: EntityId,
    attempt: EntityId,
    nonce: &str,
    context: &AttemptContext,
    kind: ReceiptKind,
    proof_levels: Vec<ProofLevel>,
) -> EntityId {
    runtime
        .append_receipt(ReceiptSpec {
            kind,
            outcome: ReceiptOutcome::Positive,
            authority_class: AuthorityClass::FacilityRuntime,
            context: ReceiptContext {
                activity_ref: EntityRef::from_id(activity, "core.activity").expect("activity"),
                operation_ref: EntityRef::from_id(operation, "core.operation").expect("operation"),
                attempt_ref: EntityRef::from_id(attempt, "core.attempt").expect("attempt"),
                idempotency_key: None,
                correlation_nonce: nonce.to_owned(),
                node_ref: context.node_ref.clone(),
                node_generation: context.node_generation,
                provider_ref: context.provider_ref.clone(),
                provider_generation: context.provider_generation,
                workload_generation: context.workload_generation,
                connection_epoch: context.connection_epoch,
                facility_ref: context.facility_ref.clone(),
                producer_instance_ref: context.producer_instance_ref.clone(),
                producer_version: context.producer_version.clone(),
            },
            producer_identity_evidence_refs: vec![reference("proof.evidence")],
            proof_claim_refs: vec![reference("proof.claim")],
            proof_levels,
            previous_or_superseded_receipt_refs: Vec::new(),
            summary: "A12 proof".to_owned(),
            limitations: Vec::new(),
            occurred_at: NOW.to_owned(),
        })
        .expect("receipt")
}

#[derive(Clone)]
struct FakeBackend {
    reports: HashMap<Vec<u8>, ParseReport>,
    identity: BackendIdentity,
}
impl ArchiveBackend for FakeBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity.clone()
    }
    fn parse(
        &self,
        bytes: &[u8],
    ) -> Result<ParseReport, ptah_archive_decomposition::DecompositionError> {
        Ok(self.reports.get(bytes).cloned().unwrap_or(ParseReport {
            format: None,
            members: Vec::new(),
            terminal: ParseTerminal::UnsupportedFormat,
            warnings: Vec::new(),
            limitations: Vec::new(),
        }))
    }
}
fn backend(reports: Vec<(&[u8], ParseReport)>) -> FakeBackend {
    FakeBackend {
        reports: reports.into_iter().map(|(k, v)| (k.to_vec(), v)).collect(),
        identity: BackendIdentity {
            provider_ref: reference("runtime.provider"),
            provider_generation: 4,
            implementation: "libarchive".to_owned(),
            implementation_version: "3.8.7".to_owned(),
            source_sha256: "a".repeat(64),
            executable_sha256: "b".repeat(64),
        },
    }
}
fn spec(source_revision_ref: EntityRef, production: ProductionEvidence) -> DecompositionSpec {
    DecompositionSpec {
        workspace_ref: reference("core.workspace"),
        authority_ref: reference("identity.principal"),
        source_revision_ref,
        production,
        budget: DecompositionBudget {
            max_depth: 3,
            max_members: 100,
            max_expanded_bytes: 1024 * 1024,
            max_member_bytes: 512 * 1024,
            max_path_chars: 8192,
        },
        requested_level: "L3_decomposed".to_owned(),
    }
}
fn report(members: Vec<ParsedMember>, terminal: ParseTerminal) -> ParseReport {
    ParseReport {
        format: Some("test".to_owned()),
        members,
        terminal,
        warnings: Vec::new(),
        limitations: Vec::new(),
    }
}
fn regular(path: &str, bytes: &[u8]) -> ParsedMember {
    ParsedMember {
        path: path.to_owned(),
        kind: MemberKind::Regular,
        bytes: bytes.to_vec(),
    }
}

#[test]
fn traversal_duplicate_and_links_fail_closed_without_escape() {
    for bad in ["../escape", "C:\\escape", "\\\\server\\share\\x"] {
        let root = b"root";
        let b = backend(vec![(
            root,
            report(
                vec![regular("ok.txt", b"ok"), regular(bad, b"bad")],
                ParseTerminal::Complete,
            ),
        )]);
        let s = spec(
            reference("object.revision"),
            ProductionEvidence {
                activity_ref: reference("core.activity"),
                operation_ref: reference("core.operation"),
                attempt_ref: reference("core.attempt"),
                receipt_refs: vec![reference("proof.receipt")],
            },
        );
        let plan = decompose(root, &s, &b).expect("bounded plan");
        assert!(!plan.outcome.is_complete());
        assert_eq!(plan.recovered_members.len(), 1);
        assert_eq!(plan.recovered_members[0].logical_path, "ok.txt");
    }
    let root = b"dup";
    let b = backend(vec![(
        root,
        report(
            vec![regular("a/./b", b"1"), regular("a/b", b"2")],
            ParseTerminal::Complete,
        ),
    )]);
    let s = spec(
        reference("object.revision"),
        ProductionEvidence {
            activity_ref: reference("core.activity"),
            operation_ref: reference("core.operation"),
            attempt_ref: reference("core.attempt"),
            receipt_refs: vec![reference("proof.receipt")],
        },
    );
    assert!(!decompose(root, &s, &b).expect("plan").outcome.is_complete());
    let link = ParsedMember {
        path: "link".to_owned(),
        kind: MemberKind::Symlink,
        bytes: Vec::new(),
    };
    let b = backend(vec![(
        b"linkroot",
        report(vec![link], ParseTerminal::Complete),
    )]);
    assert_eq!(
        decompose(b"linkroot", &s, &b).expect("plan").outcome,
        DecompositionOutcome::Failed
    );
}

#[test]
fn nested_members_bind_immediate_container_and_cumulative_budget() {
    let root = b"root";
    let nested = b"nested";
    let b = backend(vec![
        (
            root,
            report(vec![regular("nested.tar", nested)], ParseTerminal::Complete),
        ),
        (
            nested,
            report(
                vec![regular("child.bin", b"payload")],
                ParseTerminal::Complete,
            ),
        ),
    ]);
    let s = spec(
        reference("object.revision"),
        ProductionEvidence {
            activity_ref: reference("core.activity"),
            operation_ref: reference("core.operation"),
            attempt_ref: reference("core.attempt"),
            receipt_refs: vec![reference("proof.receipt")],
        },
    );
    let plan = decompose(root, &s, &b).expect("plan");
    assert_eq!(plan.outcome, DecompositionOutcome::Complete);
    assert_eq!(plan.recovered_members.len(), 2);
    assert_eq!(plan.recovered_members[1].parent_inventory_index, Some(0));
    assert_eq!(
        plan.recovered_members[1].logical_path,
        "nested.tar/child.bin"
    );
    assert_eq!(
        plan.processed_bytes,
        (nested.len() + b"payload".len()) as u64
    );
}

#[test]
fn malformed_prefix_outputs_are_retained_with_incomplete_coverage() {
    let root = b"broken";
    let b = backend(vec![(
        root,
        report(
            vec![regular("valid.bin", b"valid")],
            ParseTerminal::Malformed,
        ),
    )]);
    let s = spec(
        reference("object.revision"),
        ProductionEvidence {
            activity_ref: reference("core.activity"),
            operation_ref: reference("core.operation"),
            attempt_ref: reference("core.attempt"),
            receipt_refs: vec![reference("proof.receipt")],
        },
    );
    let plan = decompose(root, &s, &b).expect("plan");
    assert_eq!(plan.outcome, DecompositionOutcome::Malformed);
    assert_eq!(plan.recovered_members.len(), 1);
    assert!(!plan.unknown_gaps.is_empty());
}

#[test]
fn backend_replacement_does_not_change_decomposition_identity() {
    let root = b"root";
    let base = report(vec![regular("a", b"x")], ParseTerminal::Complete);
    let mut b1 = backend(vec![(root, base.clone())]);
    let mut b2 = backend(vec![(root, base)]);
    b1.identity.executable_sha256 = "1".repeat(64);
    b2.identity.executable_sha256 = "2".repeat(64);
    let s = spec(
        reference("object.revision"),
        ProductionEvidence {
            activity_ref: reference("core.activity"),
            operation_ref: reference("core.operation"),
            attempt_ref: reference("core.attempt"),
            receipt_refs: vec![reference("proof.receipt")],
        },
    );
    assert_eq!(
        decompose(root, &s, &b1)
            .expect("one")
            .decomposition_identity,
        decompose(root, &s, &b2)
            .expect("two")
            .decomposition_identity
    );
}

fn create_source(
    temp: &TempRoot,
    runtime: &ActivityRuntime,
    workspace: &EntityRef,
    authority: &EntityRef,
    bytes: &[u8],
) -> (ObjectStore, ptah_object_store::Registration) {
    let mut store = ObjectStore::open(temp.ledger(), temp.cas(), config(), clock()).expect("store");
    let ev = evidence_for_target(runtime, workspace, authority, reference("object.object"));
    let reg = store
        .register_bytes(
            bytes,
            RegisterObjectSpec {
                workspace_ref: workspace.clone(),
                authority_ref: authority.clone(),
                object_class: "archive_source".to_owned(),
                declared_name: Some("source.tar".to_owned()),
                source_refs: vec![reference("proof.evidence")],
                revision_role: RevisionRole::Original,
                origin_class: OriginClass::OriginalSource,
                created_reason: "A12 source".to_owned(),
                production: ev.production,
                expected_sha256: None,
            },
        )
        .expect("source register");
    (store, reg)
}

#[test]
fn persistence_registers_children_view_relationships_and_run_last() {
    let temp = TempRoot::new();
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let runtime = runtime(&temp.ledger());
    let source_bytes = b"root";
    let (mut store, source) = create_source(&temp, &runtime, &workspace, &authority, source_bytes);
    let ev = evidence_for_target(
        &runtime,
        &workspace,
        &authority,
        source.revision_ref.clone(),
    );
    let s = DecompositionSpec {
        workspace_ref: workspace.clone(),
        authority_ref: authority.clone(),
        source_revision_ref: source.revision_ref.clone(),
        production: ev.production,
        budget: DecompositionBudget::default(),
        requested_level: "L3_decomposed".to_owned(),
    };
    let b = backend(vec![(
        source_bytes,
        report(
            vec![regular("child.bin", b"child")],
            ParseTerminal::Complete,
        ),
    )]);
    let plan = decompose(source_bytes, &s, &b).expect("plan");
    let persisted = DecompositionStore::new(temp.ledger(), Arc::new(|| NOW.to_owned()))
        .persist(&mut store, source_bytes, s, plan)
        .expect("persist");
    assert_eq!(persisted.child_object_refs.len(), 1);
    assert_eq!(persisted.relationship_refs.len(), 1);
    let ledger = Ledger::open(temp.ledger()).expect("ledger");
    let run = ledger
        .latest_record(persisted.run_ref.entity_id)
        .expect("read")
        .expect("run");
    assert_eq!(
        run.schema_id(),
        "urn:ptah:schema:object:decomposition-run:0.1.0"
    );
    assert_eq!(run.document()["outcome"], "complete");
    assert_eq!(run.document()["coverage"]["complete_claim"], true);
    assert_eq!(
        run.document()["view_refs"].as_array().expect("views").len(),
        1
    );
    let source_after = ledger
        .latest_record(source.object_ref.entity_id)
        .expect("read source")
        .expect("source");
    assert!(
        source_after.document()["view_refs"]
            .as_array()
            .expect("views")
            .iter()
            .any(|v| v["entity_id"] == persisted.inventory_view_ref.entity_id.to_string())
    );
}

#[test]
fn partial_malformed_plan_persists_valid_child_without_complete_claim() {
    let temp = TempRoot::new();
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let runtime = runtime(&temp.ledger());
    let source_bytes = b"broken";
    let (mut store, source) = create_source(&temp, &runtime, &workspace, &authority, source_bytes);
    let ev = evidence_for_target(
        &runtime,
        &workspace,
        &authority,
        source.revision_ref.clone(),
    );
    let s = DecompositionSpec {
        workspace_ref: workspace,
        authority_ref: authority,
        source_revision_ref: source.revision_ref,
        production: ev.production,
        budget: DecompositionBudget::default(),
        requested_level: "L3_decomposed".to_owned(),
    };
    let b = backend(vec![(
        source_bytes,
        report(vec![regular("good.bin", b"good")], ParseTerminal::Malformed),
    )]);
    let plan = decompose(source_bytes, &s, &b).expect("plan");
    let persisted = DecompositionStore::new(temp.ledger(), Arc::new(|| NOW.to_owned()))
        .persist(&mut store, source_bytes, s, plan)
        .expect("persist");
    assert_eq!(persisted.child_object_refs.len(), 1);
    let run = Ledger::open(temp.ledger())
        .expect("ledger")
        .latest_record(persisted.run_ref.entity_id)
        .expect("read")
        .expect("run");
    assert_eq!(run.document()["outcome"], "malformed");
    assert_eq!(run.document()["coverage"]["complete_claim"], false);
    assert!(
        !run.document()["coverage"]["unknown_gaps"]
            .as_array()
            .expect("gaps")
            .is_empty()
    );
}

#[test]
fn source_bytes_and_operation_target_must_match_exact_revision() {
    let temp = TempRoot::new();
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let runtime = runtime(&temp.ledger());
    let source_bytes = b"root";
    let (mut store, source) = create_source(&temp, &runtime, &workspace, &authority, source_bytes);
    let wrong_target = reference("object.revision");
    let ev = evidence_for_target(&runtime, &workspace, &authority, wrong_target);
    let s = DecompositionSpec {
        workspace_ref: workspace,
        authority_ref: authority,
        source_revision_ref: source.revision_ref,
        production: ev.production,
        budget: DecompositionBudget::default(),
        requested_level: "L3_decomposed".to_owned(),
    };
    let b = backend(vec![(
        source_bytes,
        report(Vec::new(), ParseTerminal::Complete),
    )]);
    let plan = decompose(source_bytes, &s, &b).expect("plan");
    assert!(matches!(
        DecompositionStore::new(temp.ledger(), Arc::new(|| NOW.to_owned())).persist(
            &mut store,
            source_bytes,
            s,
            plan
        ),
        Err(ptah_archive_decomposition::DecompositionError::SourceMismatch)
    ));
}

#[test]
fn safe_materialization_never_writes_archive_paths_to_workspace() {
    let temp = TempRoot::new();
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let runtime = runtime(&temp.ledger());
    let source_bytes = b"root";
    let (mut store, source) = create_source(&temp, &runtime, &workspace, &authority, source_bytes);
    let ev = evidence_for_target(
        &runtime,
        &workspace,
        &authority,
        source.revision_ref.clone(),
    );
    let s = DecompositionSpec {
        workspace_ref: workspace,
        authority_ref: authority,
        source_revision_ref: source.revision_ref,
        production: ev.production,
        budget: DecompositionBudget::default(),
        requested_level: "L3_decomposed".to_owned(),
    };
    let b = backend(vec![(
        source_bytes,
        report(
            vec![regular("dir/child.bin", b"child")],
            ParseTerminal::Complete,
        ),
    )]);
    let plan = decompose(source_bytes, &s, &b).expect("plan");
    let _ = DecompositionStore::new(temp.ledger(), Arc::new(|| NOW.to_owned()))
        .persist(&mut store, source_bytes, s, plan)
        .expect("persist");
    assert!(!temp.0.join("dir").exists());
    assert_eq!(Connection::open(temp.ledger()).expect("db").query_row("SELECT COUNT(*) FROM ptah_entity_records WHERE schema_id='urn:ptah:schema:object:decomposition-run:0.1.0'",[],|r|r.get::<_,u64>(0)).expect("count"),1);
}

#[test]
fn decompression_budget_stops_before_overclaiming_complete_coverage() {
    let root = b"bomb";
    let b = backend(vec![(
        root,
        report(
            vec![regular("a", b"1234"), regular("b", b"5678")],
            ParseTerminal::Complete,
        ),
    )]);
    let mut s = spec(
        reference("object.revision"),
        ProductionEvidence {
            activity_ref: reference("core.activity"),
            operation_ref: reference("core.operation"),
            attempt_ref: reference("core.attempt"),
            receipt_refs: vec![reference("proof.receipt")],
        },
    );
    s.budget.max_expanded_bytes = 6;
    s.budget.max_member_bytes = 6;
    let plan = decompose(root, &s, &b).expect("bounded plan");
    assert_eq!(plan.outcome, DecompositionOutcome::BudgetExhausted);
    assert_eq!(plan.recovered_members.len(), 1);
    assert_eq!(plan.processed_bytes, 4);
    assert!(!plan.unknown_gaps.is_empty());
}

#[test]
fn source_revision_bytes_and_identity_remain_immutable_after_decomposition() {
    let temp = TempRoot::new();
    let workspace = reference("core.workspace");
    let authority = reference("identity.principal");
    let runtime = runtime(&temp.ledger());
    let source_bytes = b"immutable-root";
    let (mut store, source) = create_source(&temp, &runtime, &workspace, &authority, source_bytes);
    let before = Ledger::open(temp.ledger())
        .expect("ledger")
        .latest_record(source.revision_ref.entity_id)
        .expect("read")
        .expect("revision")
        .document()
        .clone();
    let ev = evidence_for_target(
        &runtime,
        &workspace,
        &authority,
        source.revision_ref.clone(),
    );
    let s = DecompositionSpec {
        workspace_ref: workspace,
        authority_ref: authority,
        source_revision_ref: source.revision_ref.clone(),
        production: ev.production,
        budget: DecompositionBudget::default(),
        requested_level: "L3_decomposed".to_owned(),
    };
    let b = backend(vec![(
        source_bytes,
        report(vec![regular("child", b"x")], ParseTerminal::Complete),
    )]);
    let plan = decompose(source_bytes, &s, &b).expect("plan");
    let _ = DecompositionStore::new(temp.ledger(), Arc::new(|| NOW.to_owned()))
        .persist(&mut store, source_bytes, s, plan)
        .expect("persist");
    let after = Ledger::open(temp.ledger())
        .expect("ledger")
        .latest_record(source.revision_ref.entity_id)
        .expect("read")
        .expect("revision")
        .document()
        .clone();
    assert_eq!(before, after);
}
