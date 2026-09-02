//! D02 AI Project Workspace runtime acceptance corpus.

use ptah_ai_workspace::{
    ActivityInputEnvelope, ActivityResultState, AvailabilityState, CallerRecord, D02Error,
    HunterAdapter, OperationEffectClass, RecordClass, RetrievalRequest, SergeantAdapter,
    SergeantReviewPayload, TimingMode, WorkspaceReader, WorkspaceSearchDocument,
    WorkspaceSearchIndex, WorkspaceSearchLimits, WorkspaceSearchRequest, WorkspaceSearchSource,
    ai_project_profile, archived_session_by_identity, artifact_library, decode_caller_record,
    encode_caller_record, operations_profile, project_session_threads, query_workspace_index,
};

use ptah_activity_runtime::{
    ActivityRuntime, ActivitySpec, ActivityState, AttemptContext, IdempotencyClass, LedgerJournal,
    OperationSpec, RetryClass, SideEffectClass, WorkerFormationSpec, WorkerRole,
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
    AttachSession, AttachmentKind, CreateSession, CreateWorkspace, IssueGrant, ScopeProjection,
    SessionAuthority, SessionKind, WorkspaceStore,
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

#[test]
fn scheduled_exact_inputs() {
    let workspace_ref = reference("core.workspace");
    let request_ref = reference("core.request");
    let artifact_a = reference("object.artifact");
    let artifact_b = reference("object.artifact");
    let artifact_c = reference("object.artifact");
    let grant = reference("isolation.secure_grant");
    let other_grant = reference("isolation.secure_grant");
    let envelope = ActivityInputEnvelope {
        workspace_ref,
        request_ref,
        input_refs: vec![artifact_a.clone(), artifact_b],
        provider_refs: vec![reference("runtime.provider")],
        facility_refs: vec![reference("runtime.facility")],
        grant_refs: vec![grant.clone()],
        schedule_ref: Some(reference("core.schedule")),
    };

    envelope
        .ensure_declared_input(&artifact_a)
        .expect("declared input");
    assert!(matches!(
        envelope.ensure_declared_input(&artifact_c),
        Err(D02Error::InputNotDeclared)
    ));
    envelope
        .ensure_declared_grant(Some(&grant))
        .expect("declared Grant");
    assert!(matches!(
        envelope.ensure_declared_grant(Some(&other_grant)),
        Err(D02Error::GrantNotDeclared)
    ));
}

#[test]
fn search_is_source_bound_not_authority() {
    let path = db_path("search-authority");
    let (private_workspace, public_workspace) = {
        let mut store = WorkspaceStore::open(&path, clock()).expect("workspace store");
        let private_workspace = create_workspace(&mut store, "search.private");
        let public_workspace = create_workspace(&mut store, "search.public");
        (
            private_workspace.workspace_ref,
            public_workspace.workspace_ref,
        )
    };
    let source_ref = reference("object.artifact");
    let source = WorkspaceSearchSource {
        workspace_ref: private_workspace.clone(),
        source_ref: source_ref.clone(),
        source_record_revision: 4,
        object_revision_ref: None,
    };
    let mut index =
        WorkspaceSearchIndex::new(WorkspaceSearchLimits::default()).expect("search index");
    index
        .rebuild(&[WorkspaceSearchDocument::Artifact {
            source,
            values: vec!["generated candidate alpha".to_owned()],
        }])
        .expect("index rebuild");
    let reader = WorkspaceReader::open(&path, clock()).expect("reader");
    let actor = reference("identity.principal");

    let response = query_workspace_index(
        &reader,
        &index,
        &WorkspaceSearchRequest {
            actor_ref: actor.clone(),
            source_workspace_ref: private_workspace.clone(),
            target_workspace_ref: private_workspace.clone(),
            required_scope: "workspace.read".to_owned(),
            grant_ref: None,
            text: "candidate alpha".to_owned(),
            domains: Vec::new(),
            limit: 10,
        },
    )
    .expect("authorized search");
    assert!(!response.authoritative);
    assert_eq!(response.hits.len(), 1);
    assert_eq!(response.hits[0].source_ref, source_ref);
    assert_eq!(response.hits[0].source_record_revision, 4);

    let denied = query_workspace_index(
        &reader,
        &index,
        &WorkspaceSearchRequest {
            actor_ref: actor,
            source_workspace_ref: public_workspace,
            target_workspace_ref: private_workspace,
            required_scope: "workspace.read".to_owned(),
            grant_ref: None,
            text: "candidate".to_owned(),
            domains: Vec::new(),
            limit: 10,
        },
    );
    assert!(matches!(denied, Err(D02Error::WorkspaceAccessDenied)));
}

#[test]
fn model_independent_resume() {
    let path = db_path("model-independent-resume");
    let actor = reference("identity.principal");
    let (source_workspace, target_workspace, session_ref, grant_ref) = {
        let mut store = WorkspaceStore::open(&path, clock()).expect("workspace store");
        let source = create_workspace(&mut store, "model.source");
        let target = create_workspace(&mut store, "model.target");
        let session_ref = create_session(&mut store, target.workspace_ref.clone());
        let grant_ref = store
            .issue_grant(IssueGrant {
                subject_ref: target.workspace_ref.clone(),
                grantee_ref: actor.clone(),
                scopes: vec!["workspace.read".to_owned()],
                policy_ref: reference("policy.workspace"),
                provider_generation: 2,
                fence_token: 1,
                expires_at: "2026-09-03T01:30:00Z".to_owned(),
                authority_ref: reference("authority.owner"),
            })
            .expect("read Grant");
        let authority = SessionAuthority::new(3, 7).expect("session authority");
        let model_a = reference("runtime.service");
        let model_b = reference("runtime.service");
        store
            .attach_session(
                session_ref.entity_id,
                authority,
                AttachSession {
                    attacher_ref: actor.clone(),
                    client_or_service_ref: Some(model_a),
                    attachment_kind: AttachmentKind::Service,
                    capability_scope: vec!["workspace.read".to_owned()],
                    control_lease_ref: None,
                    authority_ref: reference("authority.owner"),
                },
            )
            .expect("attach model A");
        store
            .attach_session(
                session_ref.entity_id,
                authority,
                AttachSession {
                    attacher_ref: actor.clone(),
                    client_or_service_ref: Some(model_b),
                    attachment_kind: AttachmentKind::Service,
                    capability_scope: vec!["workspace.read".to_owned()],
                    control_lease_ref: None,
                    authority_ref: reference("authority.owner"),
                },
            )
            .expect("attach model B");
        let projected = store.session(session_ref.entity_id).expect("session");
        assert_eq!(projected.session_ref, session_ref);
        assert_eq!(projected.attachment_refs.len(), 2);
        (
            source.workspace_ref,
            target.workspace_ref,
            session_ref,
            grant_ref,
        )
    };

    let reader = WorkspaceReader::open(&path, clock()).expect("reader");
    let hunter = HunterAdapter::new(&reader);
    let retrieved = hunter
        .retrieve_exact(&RetrievalRequest {
            actor_ref: actor,
            source_workspace_ref: source_workspace,
            target_workspace_ref: target_workspace,
            record_class: RecordClass::Session,
            entity_ref: session_ref.clone(),
            record_revision: None,
            required_scope: "workspace.read".to_owned(),
            grant_ref: Some(grant_ref),
        })
        .expect("same pre-existing Grant after model replacement");
    assert_eq!(retrieved.entity_ref, session_ref);
}

#[test]
fn grant_survives_agent_change() {
    let path = db_path("grant-agent-change");
    let actor = reference("identity.principal");
    let (source_workspace, target_workspace, session_ref, grant_ref) = {
        let mut store = WorkspaceStore::open(&path, clock()).expect("workspace store");
        let source = create_workspace(&mut store, "grant.source");
        let target = create_workspace(&mut store, "grant.target");
        let session_ref = create_session(&mut store, target.workspace_ref.clone());
        let grant_ref = store
            .issue_grant(IssueGrant {
                subject_ref: target.workspace_ref.clone(),
                grantee_ref: actor.clone(),
                scopes: vec!["workspace.read".to_owned()],
                policy_ref: reference("policy.workspace"),
                provider_generation: 5,
                fence_token: 2,
                expires_at: "2026-09-03T01:30:00Z".to_owned(),
                authority_ref: reference("authority.owner"),
            })
            .expect("Grant");
        (
            source.workspace_ref,
            target.workspace_ref,
            session_ref,
            grant_ref,
        )
    };
    let reader = WorkspaceReader::open(&path, clock()).expect("reader");
    let hunter = HunterAdapter::new(&reader);
    for _replacement_model in 0..2 {
        hunter
            .retrieve_exact(&RetrievalRequest {
                actor_ref: actor.clone(),
                source_workspace_ref: source_workspace.clone(),
                target_workspace_ref: target_workspace.clone(),
                record_class: RecordClass::Session,
                entity_ref: session_ref.clone(),
                record_revision: None,
                required_scope: "workspace.read".to_owned(),
                grant_ref: Some(grant_ref.clone()),
            })
            .expect("existing Grant remains exact access boundary");
    }
}

#[test]
fn sergeant_review_no_ptah_verdict() {
    let path = db_path("sergeant-review");
    let cas = path.with_extension("cas");
    let mut workspace_store = WorkspaceStore::open(&path, clock()).expect("workspace");
    let workspace = create_workspace(&mut workspace_store, "sergeant.review");
    drop(workspace_store);
    let runtime = activity_runtime(&path);
    let authority = reference("identity.principal");
    let mut object_store = ObjectStore::open(&path, &cas, a07_config(), clock()).expect("A07");

    let candidate_registration = register_caller_bytes(
        &mut object_store,
        &runtime,
        &workspace.workspace_ref,
        &authority,
        b"frozen D02 candidate",
    );
    let candidate_promotion = production_evidence(
        &runtime,
        &workspace.workspace_ref,
        &authority,
        candidate_registration.revision_ref.clone(),
        false,
    );
    let candidate_artifact = object_store
        .promote_artifact(
            candidate_registration.revision_ref.entity_id,
            ArtifactPromotionSpec {
                workspace_ref: workspace.workspace_ref.clone(),
                authority_ref: authority.clone(),
                artifact_type: "candidate".to_owned(),
                artifact_version: "1.0.0".to_owned(),
                purpose: "frozen review candidate".to_owned(),
                subject_refs: Vec::new(),
                production: candidate_promotion,
            },
        )
        .expect("candidate Artifact");

    let reader = WorkspaceReader::open(&path, clock()).expect("reader");
    let sergeant = SergeantAdapter::new(&reader);
    let review = SergeantReviewPayload {
        candidate_ref: candidate_artifact.clone(),
        reviewer_ref: reference("identity.principal"),
        selected_evidence_refs: vec![reference("proof.evidence")],
        result_bytes: b"Sergeant independent result: findings retained".to_vec(),
    };
    let review_bytes = sergeant
        .encode_review(&review)
        .expect("Sergeant review bytes");
    let review_json: serde_json::Value =
        serde_json::from_slice(&review_bytes).expect("review JSON");
    assert!(review_json.get("approved").is_none());
    assert!(review_json.get("rejected").is_none());
    assert!(review_json.get("canonical_winner").is_none());
    assert!(review_json.get("promotion").is_none());

    let review_registration = register_caller_bytes(
        &mut object_store,
        &runtime,
        &workspace.workspace_ref,
        &authority,
        &review_bytes,
    );
    let review_promotion = production_evidence(
        &runtime,
        &workspace.workspace_ref,
        &authority,
        review_registration.revision_ref.clone(),
        false,
    );
    let review_artifact = object_store
        .promote_artifact(
            review_registration.revision_ref.entity_id,
            ArtifactPromotionSpec {
                workspace_ref: workspace.workspace_ref,
                authority_ref: authority,
                artifact_type: "sergeant_review".to_owned(),
                artifact_version: "1.0.0".to_owned(),
                purpose: "Sergeant-owned independent review result".to_owned(),
                subject_refs: vec![candidate_artifact.clone()],
                production: review_promotion,
            },
        )
        .expect("review Artifact");
    assert_ne!(candidate_artifact, review_artifact);
}

#[test]
fn private_hunter_public_workspace() {
    let path = db_path("private-hunter-public");
    let cas = path.with_extension("cas");
    let (private_workspace, public_workspace) = {
        let mut store = WorkspaceStore::open(&path, clock()).expect("workspace store");
        let private_workspace = create_workspace(&mut store, "hunter.private");
        let public_workspace = create_workspace(&mut store, "workspace.public");
        (
            private_workspace.workspace_ref,
            public_workspace.workspace_ref,
        )
    };
    let runtime = activity_runtime(&path);
    let authority = reference("identity.principal");
    let mut object_store = ObjectStore::open(&path, &cas, a07_config(), clock()).expect("A07");
    let private_record = CallerRecord {
        format_version: "ptah.caller-record.v1".to_owned(),
        author_ref: reference("identity.principal"),
        labels: vec!["private_hunter".to_owned()],
        payload_bytes: b"private Hunter context bytes".to_vec(),
    };
    let private_bytes = encode_caller_record(&private_record).expect("private caller bytes");
    let registration = register_caller_bytes(
        &mut object_store,
        &runtime,
        &private_workspace,
        &authority,
        &private_bytes,
    );
    let promotion = production_evidence(
        &runtime,
        &private_workspace,
        &authority,
        registration.revision_ref.clone(),
        false,
    );
    let private_artifact = object_store
        .promote_artifact(
            registration.revision_ref.entity_id,
            ArtifactPromotionSpec {
                workspace_ref: private_workspace.clone(),
                authority_ref: authority,
                artifact_type: "hunter_private_record".to_owned(),
                artifact_version: "1.0.0".to_owned(),
                purpose: "private Hunter record fixture".to_owned(),
                subject_refs: Vec::new(),
                production: promotion,
            },
        )
        .expect("private Hunter Artifact");

    let reader = WorkspaceReader::open(&path, clock()).expect("reader");
    let denied = reader.retrieve(&RetrievalRequest {
        actor_ref: reference("identity.principal"),
        source_workspace_ref: public_workspace,
        target_workspace_ref: private_workspace,
        record_class: RecordClass::Artifact,
        entity_ref: private_artifact,
        record_revision: None,
        required_scope: "workspace.read".to_owned(),
        grant_ref: None,
    });
    assert!(matches!(denied, Err(D02Error::WorkspaceAccessDenied)));
}

#[test]
fn failed_activity_visible() {
    let path = db_path("failed-activity-visible");
    let runtime = activity_runtime(&path);
    let workspace_ref = reference("core.workspace");
    let authority_ref = reference("identity.principal");
    let activity_id = runtime
        .create_activity(ActivitySpec {
            request_ref: reference("core.request"),
            workspace_ref: workspace_ref.clone(),
            caller_ref: authority_ref.clone(),
            authority_ref: authority_ref.clone(),
            activity_kind: "workspace.d02_failed_partial".to_owned(),
            intent_ref: reference("core.intent"),
            priority: 0,
            max_attempts: 1,
        })
        .expect("Activity");
    assert_eq!(runtime.admit_next().expect("admit"), Some(activity_id));

    let formation_id = runtime
        .create_worker_formation(
            activity_id,
            WorkerFormationSpec {
                recipe_or_plan_ref: reference("core.recipe"),
                roles: vec![WorkerRole::Primary],
                workers_per_role: 1,
                max_slots: 1,
                require_independent_verifier: false,
            },
        )
        .expect("worker formation");
    let worker_id = runtime
        .worker_formation(formation_id)
        .expect("formation query")
        .expect("formation")
        .slots[0]
        .id;
    let partial_ref = reference("object.artifact");
    runtime
        .record_worker_partial_result(formation_id, worker_id, partial_ref.clone())
        .expect("retain partial result");

    let operation_id = runtime
        .create_operation(
            activity_id,
            OperationSpec {
                operation_kind: "workspace.d02_failed_operation".to_owned(),
                logical_target_refs: vec![reference("object.object")],
                command_or_action_ref: reference("core.command"),
                side_effect_class: SideEffectClass::ObservationOnly,
                retry_class: RetryClass::NonRetryable,
                idempotency_class: IdempotencyClass::NoneRequired,
                idempotency_key: None,
                required_authority_refs: vec![authority_ref],
                precondition_refs: Vec::new(),
                desired_proof_refs: vec![reference("proof.claim")],
                compensating_operation_ref: None,
            },
        )
        .expect("Operation");
    runtime.make_operation_ready(operation_id).expect("ready");
    let attempt_id = runtime
        .create_attempt(
            operation_id,
            AttemptContext {
                node_ref: reference("core.node"),
                node_generation: 7,
                provider_ref: reference("runtime.provider"),
                provider_generation: 3,
                workload_generation: 11,
                connection_epoch: 5,
                facility_ref: reference("runtime.facility"),
                producer_instance_ref: reference("runtime.provider_instance"),
                producer_version: "d02-failure-proof-1.0.0".to_owned(),
            },
        )
        .expect("Attempt");
    runtime.dispatch_attempt(attempt_id).expect("dispatch");
    runtime.accept_attempt(attempt_id).expect("accept");
    runtime.begin_attempt_execution(attempt_id).expect("begin");
    runtime
        .fail_attempt(attempt_id, "D02_FIXTURE_FAILURE")
        .expect("failed Attempt retained");
    runtime
        .fail_activity(activity_id, "D02_ACTIVITY_FAILED")
        .expect("failed Activity retained");

    let activity = runtime
        .activity(activity_id)
        .expect("Activity query")
        .expect("Activity retained");
    assert_eq!(activity.state(), ActivityState::Failed);
    assert_eq!(activity.failure_code(), Some("D02_ACTIVITY_FAILED"));
    assert!(activity.result_refs().is_empty());
    let formation = runtime
        .worker_formation(formation_id)
        .expect("formation query")
        .expect("formation retained");
    assert_eq!(formation.activity_id, activity_id);
    assert_eq!(formation.slots[0].partial_result_refs, vec![partial_ref]);
}

#[test]
fn provider_grant_and_approval_are_separate() {
    let profile = operations_profile();
    assert!(profile.provider_permission_separate_from_grant);
    assert!(profile.grant_separate_from_caller_approval);
}

#[test]
fn external_reference_is_not_materialized_copy() {
    assert_ne!(
        AvailabilityState::ExternalReference,
        AvailabilityState::MaterializedCopy
    );
    assert_ne!(
        AvailabilityState::IndexedReference,
        AvailabilityState::MaterializedCopy
    );
}

#[test]
fn library_and_session_views_are_non_authoritative() {
    let path = db_path("non-authoritative-views");
    let mut store = WorkspaceStore::open(&path, clock()).expect("workspace store");
    let workspace = create_workspace(&mut store, "views.workspace");
    create_session(&mut store, workspace.workspace_ref.clone());
    let sessions = project_session_threads(&store, workspace.workspace_ref.entity_id)
        .expect("session projection");
    let ledger = Ledger::open(&path).expect("ledger");
    let library = artifact_library(&store, &ledger, workspace.workspace_ref.entity_id)
        .expect("empty library projection");
    assert!(!sessions.authoritative);
    assert!(!library.authoritative);
}
