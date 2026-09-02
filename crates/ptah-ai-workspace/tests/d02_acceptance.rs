//! D02 AI Project Workspace runtime acceptance corpus.

use ptah_ai_workspace::{
    ActivityResultState, AvailabilityState, CallerRecord, D02Error, OperationEffectClass,
    RecordClass, RetrievalRequest, TimingMode, WorkspaceReader, ai_project_profile,
    archived_session_by_identity, artifact_library, decode_caller_record, encode_caller_record,
    operations_profile, project_session_threads,
};

use ptah_activity_runtime::{
    ActivityRuntime, ActivitySpec, AttemptContext, IdempotencyClass, LedgerJournal, OperationSpec,
    RetryClass, SideEffectClass,
};
use ptah_checkpoint::{SessionVaultManifest, SessionVaultSession};
use ptah_identifiers::{EntityId, EntityRef, RecordRevision};
use ptah_ledger::Ledger;
use ptah_object_store::{
    ArtifactPromotionSpec, ObjectStore, ObjectStoreConfig, OriginClass, ProductionEvidence,
    RegisterObjectSpec, RevisionRole,
};
use ptah_receipts::{
    AuthorityClass, ProofLevel, ReceiptContext, ReceiptKind, ReceiptOutcome, ReceiptSpec,
};
use ptah_workspace::{
    CreateSession, CreateWorkspace, ScopeProjection, SessionAuthority, SessionKind, WorkspaceStore,
};
use std::{fs, path::PathBuf, sync::Arc};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid reference")
}

fn ref_key(reference: &EntityRef) -> String {
    format!("{}:{}", reference.entity_kind, reference.entity_id)
}

fn db_path(label: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("ptah-d02-{label}-{}.sqlite3", EntityId::new_v7()));
    let _ = fs::remove_file(&path);
    path
}

fn clock() -> Arc<dyn Fn() -> String + Send + Sync> {
    Arc::new(|| "2026-09-02T01:30:00Z".to_owned())
}

fn activity_runtime(path: &std::path::Path) -> ActivityRuntime {
    let journal = Arc::new(LedgerJournal::open(path).expect("A04 journal"));
    ActivityRuntime::new(8, journal, clock()).expect("A04 runtime")
}

fn a07_config() -> ObjectStoreConfig {
    ObjectStoreConfig {
        backend_ref: reference("storage.backend"),
        connection_ref: reference("storage.connection"),
        producer_ref: reference("runtime.provider_instance"),
        producer_version: "d02-a07-test-1.0.0".to_owned(),
    }
}

fn production_evidence(
    runtime: &ActivityRuntime,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    logical_target_ref: EntityRef,
    registration: bool,
) -> ProductionEvidence {
    let activity_id = runtime
        .create_activity(ActivitySpec {
            request_ref: reference("core.request"),
            workspace_ref: workspace_ref.clone(),
            caller_ref: authority_ref.clone(),
            authority_ref: authority_ref.clone(),
            activity_kind: "workspace.d02_object_proof".to_owned(),
            intent_ref: reference("core.intent"),
            priority: 0,
            max_attempts: 2,
        })
        .expect("create Activity");
    assert_eq!(runtime.admit_next().expect("admit"), Some(activity_id));
    let operation_id = runtime
        .create_operation(
            activity_id,
            OperationSpec {
                operation_kind: "workspace.d02_object_operation".to_owned(),
                logical_target_refs: vec![logical_target_ref],
                command_or_action_ref: reference("core.command"),
                side_effect_class: SideEffectClass::IdempotentMutation,
                retry_class: RetryClass::RetrySafe,
                idempotency_class: IdempotencyClass::NoneRequired,
                idempotency_key: None,
                required_authority_refs: vec![authority_ref.clone()],
                precondition_refs: Vec::new(),
                desired_proof_refs: vec![reference("proof.claim")],
                compensating_operation_ref: None,
            },
        )
        .expect("create Operation");
    runtime.make_operation_ready(operation_id).expect("ready");
    let context = AttemptContext {
        node_ref: reference("core.node"),
        node_generation: 7,
        provider_ref: reference("runtime.provider"),
        provider_generation: 3,
        workload_generation: 11,
        connection_epoch: 5,
        facility_ref: reference("runtime.facility"),
        producer_instance_ref: reference("runtime.provider_instance"),
        producer_version: "d02-a07-proof-1.0.0".to_owned(),
    };
    let attempt_id = runtime
        .create_attempt(operation_id, context.clone())
        .expect("create Attempt");
    runtime.dispatch_attempt(attempt_id).expect("dispatch");
    runtime.accept_attempt(attempt_id).expect("accept");
    runtime.begin_attempt_execution(attempt_id).expect("begin");
    let nonce = runtime
        .attempt(attempt_id)
        .expect("attempt query")
        .expect("attempt")
        .correlation_nonce()
        .to_owned();

    let mut receipt_refs = Vec::new();
    let kinds: Vec<(ReceiptKind, Vec<ProofLevel>, &str)> = if registration {
        vec![
            (
                ReceiptKind::OutputObservation,
                vec![ProofLevel::OutputCreated, ProofLevel::OperationCompleted],
                "D02 caller bytes observed",
            ),
            (
                ReceiptKind::HashVerification,
                vec![ProofLevel::OutputHashVerified],
                "D02 caller bytes hash verified",
            ),
        ]
    } else {
        vec![(
            ReceiptKind::OutputObservation,
            vec![ProofLevel::OutputCreated, ProofLevel::OperationCompleted],
            "D02 Artifact promotion observed",
        )]
    };
    for (kind, levels, summary) in kinds {
        let receipt_id = runtime
            .append_receipt(ReceiptSpec {
                kind,
                outcome: ReceiptOutcome::Positive,
                authority_class: AuthorityClass::FacilityRuntime,
                context: ReceiptContext {
                    activity_ref: EntityRef::from_id(activity_id, "core.activity")
                        .expect("activity ref"),
                    operation_ref: EntityRef::from_id(operation_id, "core.operation")
                        .expect("operation ref"),
                    attempt_ref: EntityRef::from_id(attempt_id, "core.attempt")
                        .expect("attempt ref"),
                    idempotency_key: None,
                    correlation_nonce: nonce.clone(),
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
                proof_levels: levels,
                previous_or_superseded_receipt_refs: Vec::new(),
                summary: summary.to_owned(),
                limitations: Vec::new(),
                occurred_at: "2026-09-02T01:30:00Z".to_owned(),
            })
            .expect("append receipt");
        receipt_refs.push(EntityRef::from_id(receipt_id, "proof.receipt").expect("receipt ref"));
    }

    ProductionEvidence {
        activity_ref: EntityRef::from_id(activity_id, "core.activity").expect("activity ref"),
        operation_ref: EntityRef::from_id(operation_id, "core.operation").expect("operation ref"),
        attempt_ref: EntityRef::from_id(attempt_id, "core.attempt").expect("attempt ref"),
        receipt_refs,
    }
}

fn register_caller_bytes(
    store: &mut ObjectStore,
    runtime: &ActivityRuntime,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    bytes: &[u8],
) -> ptah_object_store::Registration {
    let production = production_evidence(
        runtime,
        workspace_ref,
        authority_ref,
        reference("object.object"),
        true,
    );
    store
        .register_bytes(
            bytes,
            RegisterObjectSpec {
                workspace_ref: workspace_ref.clone(),
                authority_ref: authority_ref.clone(),
                object_class: "caller_record".to_owned(),
                declared_name: Some("caller-record.json".to_owned()),
                source_refs: vec![reference("proof.evidence")],
                revision_role: RevisionRole::Generated,
                origin_class: OriginClass::Generated,
                created_reason: "D02 caller-authored record".to_owned(),
                production,
                expected_sha256: None,
            },
        )
        .expect("register caller bytes")
}

fn create_workspace(store: &mut WorkspaceStore, key: &str) -> ptah_workspace::WorkspaceProjection {
    store
        .create_workspace(CreateWorkspace {
            workspace_key: key.to_owned(),
            title: format!("Workspace {key}"),
            description: None,
            owner_ref: reference("identity.principal"),
            authority_ref: reference("authority.owner"),
            created_by_ref: reference("identity.principal"),
            policy_refs: vec![reference("policy.workspace")],
        })
        .expect("create workspace")
}

fn create_session(store: &mut WorkspaceStore, workspace_ref: EntityRef) -> EntityRef {
    store
        .create_session(CreateSession {
            workspace_ref,
            owner_ref: reference("identity.principal"),
            session_kind: SessionKind::Application,
            provider_instance_ref: reference("runtime.provider_instance"),
            authority: SessionAuthority::new(3, 7).expect("session authority"),
            node_ref: Some(reference("core.node")),
            node_generation: Some(4),
            remote_service_ref: None,
            subject_refs: vec![reference("core.activity")],
            policy_refs: vec![reference("policy.workspace")],
            authority_ref: reference("authority.owner"),
        })
        .expect("create session")
}

#[test]
fn d02_exposes_both_neutral_profile_ids_without_ptah_decision_authority() {
    let ai = ai_project_profile();
    let ops = operations_profile();

    assert_eq!(ai.profile_id, "ptah.workspace.ai_project.v1");
    assert_eq!(ops.profile_id, "ptah.workspace.operations.v2");
    assert!(!ai.decision_authority);
    assert!(!ai.context_selection_authority);
    assert!(!ai.review_authority);
    assert!(!ai.approval_authority);
    assert!(!ai.new_core_entity_required);
}

#[test]
fn operations_v2_vocabularies_match_adr0037() {
    use ActivityResultState::{Cancelled, Declined, Failed, NotRun, PartiallyCompleted, Succeeded};
    use AvailabilityState::{
        ExternalReference, GeneratedArtifact, IndexedReference, MaterializedCopy, MountedReadOnly,
    };
    use OperationEffectClass::{
        Destructive, Draft, ExternalSideEffect, Mutate, Observe, Publish, Simulate,
    };
    use TimingMode::{ConditionDependent, Exact, FlexibleWindow};

    let ops = operations_profile();
    assert_eq!(
        ops.effect_classes,
        vec![
            Observe,
            Draft,
            Simulate,
            Mutate,
            Publish,
            Destructive,
            ExternalSideEffect,
        ]
    );
    assert_eq!(
        ops.availability_states,
        vec![
            ExternalReference,
            IndexedReference,
            MountedReadOnly,
            MaterializedCopy,
            GeneratedArtifact,
        ]
    );
    assert_eq!(
        ops.result_states,
        vec![
            Succeeded,
            Failed,
            Declined,
            Cancelled,
            NotRun,
            PartiallyCompleted
        ]
    );
    assert_eq!(
        ops.timing_modes,
        vec![Exact, FlexibleWindow, ConditionDependent]
    );
    assert!(ops.provider_permission_separate_from_grant);
    assert!(ops.grant_separate_from_caller_approval);
}

#[test]
fn workspace_isolation() {
    let path = db_path("workspace-isolation");
    let (workspace_a, workspace_b, private_session) = {
        let mut store = WorkspaceStore::open(&path, clock()).expect("workspace store");
        let workspace_a = create_workspace(&mut store, "private.workspace");
        let workspace_b = create_workspace(&mut store, "public.workspace");
        let private_session = create_session(&mut store, workspace_a.workspace_ref.clone());
        (
            workspace_a.workspace_ref,
            workspace_b.workspace_ref,
            private_session,
        )
    };
    let actor = reference("identity.principal");
    let reader = WorkspaceReader::open(&path, clock()).expect("reader");

    let same_workspace = reader
        .retrieve(&RetrievalRequest {
            actor_ref: actor.clone(),
            source_workspace_ref: workspace_a.clone(),
            target_workspace_ref: workspace_a.clone(),
            record_class: RecordClass::Session,
            entity_ref: private_session.clone(),
            record_revision: Some(RecordRevision::new(1).expect("revision")),
            required_scope: "workspace.read".to_owned(),
            grant_ref: None,
        })
        .expect("same workspace exact retrieval");
    assert_eq!(same_workspace.entity_ref, private_session);
    assert_eq!(same_workspace.record_revision.value(), 1);

    let denied = reader.retrieve(&RetrievalRequest {
        actor_ref: actor,
        source_workspace_ref: workspace_b,
        target_workspace_ref: workspace_a,
        record_class: RecordClass::Session,
        entity_ref: private_session,
        record_revision: None,
        required_scope: "workspace.read".to_owned(),
        grant_ref: None,
    });
    assert!(matches!(denied, Err(D02Error::WorkspaceAccessDenied)));
}

#[test]
fn parallel_session_threads_are_non_authoritative() {
    let path = db_path("parallel-sessions");
    let mut store = WorkspaceStore::open(&path, clock()).expect("workspace store");
    let workspace = create_workspace(&mut store, "parallel.workspace");
    let first = create_session(&mut store, workspace.workspace_ref.clone());
    let second = create_session(&mut store, workspace.workspace_ref.clone());

    let projection = project_session_threads(&store, workspace.workspace_ref.entity_id)
        .expect("session projection");
    assert_eq!(projection.workspace_ref, workspace.workspace_ref);
    assert_eq!(projection.sessions.len(), 2);
    assert!(
        projection
            .sessions
            .iter()
            .any(|session| session.session_ref == first)
    );
    assert!(
        projection
            .sessions
            .iter()
            .any(|session| session.session_ref == second)
    );
    assert!(!projection.authoritative);
}

#[test]
fn archived_session_discoverability() {
    let archived_ref = reference("runtime.session");
    let workspace_ref = reference("core.workspace");
    let manifest = SessionVaultManifest {
        workspace_ref: ref_key(&workspace_ref),
        current_workspace_revision_ref: "workspace-revision:4".to_owned(),
        current_materialization_generation: 9,
        workspace_versions: Vec::new(),
        sessions: vec![SessionVaultSession {
            session_ref: ref_key(&archived_ref),
            workspace_ref: ref_key(&workspace_ref),
            workspace_revision_ref: "workspace-revision:4".to_owned(),
            provider_instance_ref: "provider:a".to_owned(),
            provider_generation: 7,
            connection_epoch: 4,
            node_ref: Some("node:a".to_owned()),
            node_generation: Some(3),
            attachment_refs: vec!["attachment:old".to_owned()],
            subject_refs: vec!["object:1".to_owned()],
        }],
        objects: Vec::new(),
        artifacts: Vec::new(),
        conflicts: Vec::new(),
        required_capability_refs: Vec::new(),
        checkpoint_bundle_ref: "checkpoint:1".to_owned(),
        checkpoint_manifest_sha256: "a".repeat(64),
        checkpoint_verified_at_export: true,
        export_evidence_refs: vec!["evidence:vault".to_owned()],
    };

    let found = archived_session_by_identity(&manifest, &archived_ref)
        .expect("archived Session by exact identity");
    assert_eq!(found.session_ref, ref_key(&archived_ref));

    let missing = archived_session_by_identity(&manifest, &reference("runtime.session"));
    assert!(matches!(missing, Err(D02Error::ArchivedSessionNotFound)));
}

#[test]
fn caller_label_roundtrip() {
    let hunter = reference("identity.principal");
    let reviewer = reference("identity.principal");
    let first = CallerRecord {
        format_version: "ptah.caller-record.v1".to_owned(),
        author_ref: hunter,
        labels: vec!["canonical".to_owned(), "temporary_context".to_owned()],
        payload_bytes: b"caller A exact bytes".to_vec(),
    };
    let second = CallerRecord {
        format_version: "ptah.caller-record.v1".to_owned(),
        author_ref: reviewer,
        labels: vec!["reference".to_owned(), "rejected".to_owned()],
        payload_bytes: b"caller B exact bytes".to_vec(),
    };

    let first_bytes = encode_caller_record(&first).expect("encode first");
    let second_bytes = encode_caller_record(&second).expect("encode second");
    assert_eq!(
        decode_caller_record(&first_bytes).expect("decode first"),
        first
    );
    assert_eq!(
        decode_caller_record(&second_bytes).expect("decode second"),
        second
    );

    let path = db_path("caller-label-roundtrip");
    let cas = path.with_extension("cas");
    let mut workspace_store = WorkspaceStore::open(&path, clock()).expect("workspace");
    let workspace = create_workspace(&mut workspace_store, "caller.labels");
    drop(workspace_store);
    let runtime = activity_runtime(&path);
    let authority = reference("identity.principal");
    let mut object_store = ObjectStore::open(&path, &cas, a07_config(), clock()).expect("A07");
    let first_registration = register_caller_bytes(
        &mut object_store,
        &runtime,
        &workspace.workspace_ref,
        &authority,
        &first_bytes,
    );
    let second_registration = register_caller_bytes(
        &mut object_store,
        &runtime,
        &workspace.workspace_ref,
        &authority,
        &second_bytes,
    );
    assert_ne!(first_registration.sha256, second_registration.sha256);
}

#[test]
fn conflicting_labels_no_ranking() {
    let first = CallerRecord {
        format_version: "ptah.caller-record.v1".to_owned(),
        author_ref: reference("identity.principal"),
        labels: vec!["canonical".to_owned()],
        payload_bytes: b"position one".to_vec(),
    };
    let second = CallerRecord {
        format_version: "ptah.caller-record.v1".to_owned(),
        author_ref: reference("identity.principal"),
        labels: vec!["canonical".to_owned()],
        payload_bytes: b"contradictory position two".to_vec(),
    };
    assert_eq!(
        decode_caller_record(&encode_caller_record(&first).expect("first")).expect("decode"),
        first
    );
    assert_eq!(
        decode_caller_record(&encode_caller_record(&second).expect("second")).expect("decode"),
        second
    );
}

#[test]
fn artifact_library_is_projection_only() {
    let path = db_path("artifact-library");
    let cas = path.with_extension("cas");
    let mut workspace_store = WorkspaceStore::open(&path, clock()).expect("workspace");
    let workspace = create_workspace(&mut workspace_store, "artifact.library");
    let runtime = activity_runtime(&path);
    let authority = reference("identity.principal");
    let mut object_store = ObjectStore::open(&path, &cas, a07_config(), clock()).expect("A07");
    let registration = register_caller_bytes(
        &mut object_store,
        &runtime,
        &workspace.workspace_ref,
        &authority,
        b"library object",
    );
    let promotion = production_evidence(
        &runtime,
        &workspace.workspace_ref,
        &authority,
        registration.revision_ref.clone(),
        false,
    );
    let artifact_ref = object_store
        .promote_artifact(
            registration.revision_ref.entity_id,
            ArtifactPromotionSpec {
                workspace_ref: workspace.workspace_ref.clone(),
                authority_ref: authority.clone(),
                artifact_type: "caller_record".to_owned(),
                artifact_version: "1.0.0".to_owned(),
                purpose: "D02 reusable Artifact Library fixture".to_owned(),
                subject_refs: Vec::new(),
                production: promotion,
            },
        )
        .expect("promote Artifact");
    workspace_store
        .record_scope_projection(
            workspace.workspace_ref.entity_id,
            reference("core.request"),
            &ScopeProjection {
                object_refs: vec![registration.object_ref.clone()],
                activity_refs: Vec::new(),
                terminal_refs: Vec::new(),
                policy_refs: Vec::new(),
            },
            &authority,
        )
        .expect("scope projection");
    let ledger = Ledger::open(&path).expect("ledger");
    let library = artifact_library(&workspace_store, &ledger, workspace.workspace_ref.entity_id)
        .expect("library projection");
    assert_eq!(library.workspace_ref, workspace.workspace_ref);
    assert_eq!(library.entries.len(), 1);
    assert_eq!(library.entries[0].artifact_ref, artifact_ref);
    assert_eq!(library.entries[0].object_ref, registration.object_ref);
    assert!(!library.authoritative);
    assert!(!library.exhaustive);
}
