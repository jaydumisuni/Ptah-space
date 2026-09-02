//! D02 AI Project Workspace runtime acceptance corpus.

use ptah_ai_workspace::{
    ActivityResultState, AvailabilityState, D02Error, OperationEffectClass, RecordClass,
    RetrievalRequest, TimingMode, WorkspaceReader, ai_project_profile, operations_profile,
};

use ptah_identifiers::{EntityId, EntityRef, RecordRevision};
use ptah_workspace::{
    CreateSession, CreateWorkspace, SessionAuthority, SessionKind, WorkspaceStore,
};
use std::{fs, path::PathBuf, sync::Arc};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid reference")
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
