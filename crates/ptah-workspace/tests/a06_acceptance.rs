//! A06 persistent Workspace, Session, authority and recovery acceptance tests.

use ptah_identifiers::{EntityId, EntityRef};
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger};
use ptah_workspace::{
    AddParticipant, AttachSession, AttachmentKind, CreateSession, CreateWorkspace, HandoffProjection,
    IssueGrant, RecoveryProjection, ScopeProjection, SessionAuthority, SessionKind, WorkerProjection,
    WorkspaceError, WorkspaceStore,
};
use serde_json::Value;
use std::{fs, path::PathBuf, sync::Arc};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid reference")
}

fn db_path(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "ptah-a06-{label}-{}.sqlite3",
        EntityId::new_v7()
    ));
    let _ = fs::remove_file(&path);
    path
}

fn clock() -> Arc<dyn Fn() -> String + Send + Sync> {
    Arc::new(|| "2026-08-17T03:00:00Z".to_owned())
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

fn create_session(
    store: &mut WorkspaceStore,
    workspace_ref: EntityRef,
    authority: SessionAuthority,
) -> EntityRef {
    store
        .create_session(CreateSession {
            workspace_ref,
            owner_ref: reference("identity.principal"),
            session_kind: SessionKind::Pty,
            provider_instance_ref: reference("runtime.provider_instance"),
            authority,
            node_ref: Some(reference("core.node")),
            node_generation: Some(7),
            remote_service_ref: None,
            subject_refs: vec![reference("runtime.terminal")],
            policy_refs: vec![reference("policy.workspace")],
            authority_ref: reference("authority.owner"),
        })
        .expect("create session")
}

#[test]
fn workspace_identity_survives_disconnect_and_runtime_restart() {
    let path = db_path("restart");
    let authority = SessionAuthority::new(3, 11).expect("authority");
    let (workspace_id, workspace_ref, first_session) = {
        let mut store = WorkspaceStore::open(&path, clock()).expect("open");
        let workspace = create_workspace(&mut store, "restart.workspace");
        let first_session = create_session(&mut store, workspace.workspace_ref.clone(), authority);
        (
            workspace.workspace_ref.entity_id,
            workspace.workspace_ref,
            first_session,
        )
    };

    let mut reopened = WorkspaceStore::open(&path, clock()).expect("reopen");
    let recovered = reopened.workspace(workspace_id).expect("workspace");
    assert_eq!(recovered.workspace_ref, workspace_ref);
    assert!(recovered.session_refs.contains(&first_session));

    let second_session = create_session(&mut reopened, workspace_ref.clone(), authority);
    assert_ne!(first_session, second_session);
    let after = reopened.workspace(workspace_id).expect("workspace after session");
    assert_eq!(after.workspace_ref, workspace_ref);
}

#[test]
fn stale_session_authority_fails_closed() {
    let path = db_path("stale-session");
    let mut store = WorkspaceStore::open(&path, clock()).expect("open");
    let workspace = create_workspace(&mut store, "stale.session");
    let current = SessionAuthority::new(4, 9).expect("authority");
    let session = create_session(&mut store, workspace.workspace_ref, current);

    let stale = SessionAuthority::new(3, 9).expect("stale authority");
    let result = store.attach_session(
        session.entity_id,
        stale,
        AttachSession {
            attacher_ref: reference("identity.principal"),
            client_or_service_ref: None,
            attachment_kind: AttachmentKind::Human,
            capability_scope: vec!["workspace.observe".to_owned()],
            control_lease_ref: None,
            authority_ref: reference("authority.owner"),
        },
    );
    assert!(matches!(result, Err(WorkspaceError::StaleSessionAuthority)));
}

#[test]
fn missing_session_attachment_is_explicit_after_reopen() {
    let path = db_path("missing-attachment");
    let authority = SessionAuthority::new(2, 5).expect("authority");
    let (workspace_id, session_id) = {
        let mut store = WorkspaceStore::open(&path, clock()).expect("open");
        let workspace = create_workspace(&mut store, "missing.attachment");
        let session = create_session(&mut store, workspace.workspace_ref, authority);
        (workspace.workspace_ref.entity_id, session.entity_id)
    };

    let missing = reference("runtime.session_attachment");
    {
        let mut ledger = Ledger::open(&path).expect("ledger");
        let retained = ledger
            .latest_record(session_id)
            .expect("query")
            .expect("session record");
        let mut document = retained.document().clone();
        let envelope = document
            .get_mut("envelope")
            .and_then(Value::as_object_mut)
            .expect("envelope");
        envelope.insert("record_revision".to_owned(), serde_json::json!(2));
        document
            .get_mut("attachment_refs")
            .and_then(Value::as_array_mut)
            .expect("attachment refs")
            .push(serde_json::to_value(&missing).expect("ref json"));
        let record = CanonicalRecord::from_document(document).expect("canonical record");
        let write = ledger.begin_write().expect("write");
        write.insert(&record).expect("insert");
        write.commit().expect("commit");
    }

    let reopened = WorkspaceStore::open(&path, clock()).expect("reopen");
    let recovery = reopened
        .recovery_projection(workspace_id)
        .expect("recovery projection");
    assert_eq!(recovery.missing_attachment_refs, vec![missing]);
}

#[test]
fn cross_workspace_retrieval_requires_membership_or_secure_grant() {
    let path = db_path("cross-workspace");
    let mut store = WorkspaceStore::open(&path, clock()).expect("open");
    let source = create_workspace(&mut store, "source.workspace");
    let target = create_workspace(&mut store, "target.workspace");
    let actor = reference("identity.principal");

    assert!(matches!(
        store.authorize_retrieval(
            &actor,
            source.workspace_ref.entity_id,
            target.workspace_ref.entity_id,
            "workspace.read",
            None,
        ),
        Err(WorkspaceError::CrossWorkspaceDenied)
    ));

    let grant = store
        .issue_grant(IssueGrant {
            subject_ref: target.workspace_ref.clone(),
            grantee_ref: actor.clone(),
            scopes: vec!["workspace.read".to_owned()],
            policy_ref: reference("policy.workspace"),
            provider_generation: 2,
            fence_token: 1,
            expires_at: "2026-08-18T03:00:00Z".to_owned(),
            authority_ref: reference("authority.owner"),
        })
        .expect("grant");
    store
        .authorize_retrieval(
            &actor,
            source.workspace_ref.entity_id,
            target.workspace_ref.entity_id,
            "workspace.read",
            Some(&grant),
        )
        .expect("grant allows access");

    let member = reference("identity.principal");
    store
        .add_participant(
            target.workspace_ref.entity_id,
            AddParticipant {
                member_ref: member.clone(),
                role_key: "workspace.reader".to_owned(),
                scopes: vec!["workspace.read".to_owned()],
                issued_by_ref: reference("identity.principal"),
                policy_ref: reference("policy.workspace"),
                authority_ref: reference("authority.owner"),
            },
        )
        .expect("membership");
    store
        .authorize_retrieval(
            &member,
            source.workspace_ref.entity_id,
            target.workspace_ref.entity_id,
            "workspace.read",
            None,
        )
        .expect("membership allows access");
}

#[test]
fn worker_formation_and_handoff_recover_without_collapsing_evidence() {
    let path = db_path("worker-handoff");
    let workspace_id = {
        let mut store = WorkspaceStore::open(&path, clock()).expect("open");
        let workspace = create_workspace(&mut store, "worker.handoff");
        let formation = reference("runtime.worker_formation");
        let worker_a = WorkerProjection {
            formation_ref: formation.clone(),
            worker_ref: reference("runtime.worker"),
            role: "primary".to_owned(),
            independence_key: "lane.primary".to_owned(),
            checkpoint_refs: vec![reference("proof.checkpoint")],
            partial_result_refs: vec![reference("proof.partial_result")],
            conflict_refs: vec![reference("proof.conflict")],
        };
        let worker_b = WorkerProjection {
            formation_ref: formation,
            worker_ref: reference("runtime.worker"),
            role: "verifier".to_owned(),
            independence_key: "lane.verifier".to_owned(),
            checkpoint_refs: vec![reference("proof.checkpoint")],
            partial_result_refs: vec![reference("proof.partial_result")],
            conflict_refs: vec![reference("proof.conflict")],
        };
        store
            .record_worker_projection(
                workspace.workspace_ref.entity_id,
                reference("runtime.activity"),
                &[worker_a.clone(), worker_b.clone()],
                &reference("authority.owner"),
            )
            .expect("worker projection");
        store
            .record_handoff(
                workspace.workspace_ref.entity_id,
                reference("runtime.activity"),
                &HandoffProjection {
                    from_ref: reference("identity.agent"),
                    to_ref: reference("identity.agent"),
                    authority_refs: vec![reference("isolation.secure_grant")],
                    subject_refs: vec![reference("runtime.activity")],
                    note: "replace agent without replacing Workspace authority".to_owned(),
                },
                &reference("authority.owner"),
            )
            .expect("handoff");
        workspace.workspace_ref.entity_id
    };

    let reopened = WorkspaceStore::open(&path, clock()).expect("reopen");
    let RecoveryProjection {
        workers, handoff, ..
    } = reopened
        .recovery_projection(workspace_id)
        .expect("recovery projection");
    assert_eq!(workers.len(), 2);
    assert_ne!(workers[0].independence_key, workers[1].independence_key);
    assert!(!workers[0].checkpoint_refs.is_empty());
    assert!(!workers[0].partial_result_refs.is_empty());
    assert!(!workers[0].conflict_refs.is_empty());
    let handoff = handoff.expect("handoff preserved");
    assert_eq!(handoff.authority_refs.len(), 1);
    assert_eq!(handoff.subject_refs.len(), 1);
}

#[test]
fn workspace_scope_projection_survives_restart_without_claiming_a07_materialization() {
    let path = db_path("scope");
    let workspace_id = {
        let mut store = WorkspaceStore::open(&path, clock()).expect("open");
        let workspace = create_workspace(&mut store, "scope.workspace");
        let projection = ScopeProjection {
            object_refs: vec![reference("core.object")],
            activity_refs: vec![reference("runtime.activity")],
            terminal_refs: vec![reference("runtime.terminal")],
            policy_refs: vec![reference("policy.workspace")],
        };
        store
            .record_scope_projection(
                workspace.workspace_ref.entity_id,
                reference("runtime.activity"),
                &projection,
                &reference("authority.owner"),
            )
            .expect("scope projection");
        workspace.workspace_ref.entity_id
    };

    let reopened = WorkspaceStore::open(&path, clock()).expect("reopen");
    let recovery = reopened
        .recovery_projection(workspace_id)
        .expect("recovery");
    assert_eq!(recovery.scope.object_refs.len(), 1);
    assert_eq!(recovery.scope.activity_refs.len(), 1);
    assert_eq!(recovery.scope.terminal_refs.len(), 1);
    assert_eq!(recovery.scope.policy_refs.len(), 1);
}
