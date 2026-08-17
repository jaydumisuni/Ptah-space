#![forbid(unsafe_code)]
//! A06 persistent Workspace, Session and authority projection runtime.
//!
//! The ledger remains the durable truth boundary. Workspace identity is never
//! replaced by Session, Provider, process or client identities. A06 projects
//! authority and recovery metadata only; A07 owns Object/CAS materialization and
//! A13 owns checkpoint/restore execution.

use ptah_identifiers::{EntityId, EntityRef, IdentifierError};
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger, LedgerError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{path::Path, sync::Arc};
use thiserror::Error;

/// Frozen Workspace schema identity.
pub const WORKSPACE_SCHEMA_ID: &str = "urn:ptah:schema:workspace:workspace:0.1.0";
/// Frozen Workspace Revision schema identity.
pub const WORKSPACE_REVISION_SCHEMA_ID: &str =
    "urn:ptah:schema:workspace:workspace-revision:0.1.0";
/// Frozen Workspace Membership schema identity.
pub const WORKSPACE_MEMBERSHIP_SCHEMA_ID: &str =
    "urn:ptah:schema:workspace:workspace-membership:0.1.0";
/// Frozen Workspace Provider Binding schema identity.
pub const WORKSPACE_PROVIDER_BINDING_SCHEMA_ID: &str =
    "urn:ptah:schema:workspace:workspace-provider-binding:0.1.0";
/// Frozen Session schema identity.
pub const SESSION_SCHEMA_ID: &str = "urn:ptah:schema:workspace:session:0.1.0";
/// Frozen Session Attachment schema identity.
pub const SESSION_ATTACHMENT_SCHEMA_ID: &str =
    "urn:ptah:schema:workspace:session-attachment:0.1.0";
/// Frozen Workspace Journal Entry schema identity.
pub const WORKSPACE_JOURNAL_SCHEMA_ID: &str =
    "urn:ptah:schema:workspace:workspace-journal-entry:0.1.0";
/// Frozen Secure Grant schema identity used for cross-Workspace authority.
pub const SECURE_GRANT_SCHEMA_ID: &str = "urn:ptah:schema:isolation:secure-grant:0.1.0";
const SCHEMA_VERSION: &str = "0.1.0";

/// A06 Workspace runtime failures.
#[derive(Debug, Error)]
pub enum WorkspaceError {
    /// Durable ledger failure.
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    /// Canonical identity failure.
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
    /// JSON serialization/deserialization failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Referenced canonical entity is absent.
    #[error("entity not found: {0}")]
    NotFound(EntityId),
    /// Entity exists but is not the required schema/kind.
    #[error("entity type mismatch")]
    TypeMismatch,
    /// Workspace key does not satisfy the frozen key vocabulary.
    #[error("invalid workspace key")]
    InvalidWorkspaceKey,
    /// Required user-facing text is empty.
    #[error("required field is empty: {0}")]
    EmptyField(&'static str),
    /// Session authority is older than the durable Session projection.
    #[error("stale session authority")]
    StaleSessionAuthority,
    /// Attachment is missing or no longer active.
    #[error("stale session attachment")]
    StaleAttachment,
    /// Cross-Workspace retrieval is not authorized.
    #[error("cross-workspace access denied")]
    CrossWorkspaceDenied,
    /// Grant is absent, stale, revoked, mismatched, or lacks the required scope.
    #[error("invalid secure grant")]
    InvalidGrant,
    /// Membership is absent or inactive.
    #[error("workspace membership denied")]
    MembershipDenied,
    /// A positive generation/fence value was required.
    #[error("positive generation/fence required")]
    InvalidGeneration,
    /// Record revision arithmetic overflowed.
    #[error("record revision overflow")]
    RevisionOverflow,
    /// Journal sequence arithmetic overflowed.
    #[error("journal sequence overflow")]
    JournalSequenceOverflow,
}

/// Session kinds frozen by the Workspace contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    /// Workspace control Session.
    Workspace,
    /// Native process Session.
    Process,
    /// PTY Session.
    Pty,
    /// Shell Session.
    Shell,
    /// Browser Session.
    Browser,
    /// Application Session.
    Application,
    /// Device Session.
    Device,
    /// Display Session.
    Display,
    /// Semantic UI Session.
    SemanticUi,
    /// Filesystem mount Session.
    FilesystemMount,
    /// Service Session.
    Service,
    /// Registered extension Session kind.
    OtherRegistered,
}

/// Session attachment kinds frozen by the Workspace contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentKind {
    /// Human client attachment.
    Human,
    /// Automation attachment.
    Automation,
    /// Service attachment.
    Service,
    /// Shell client attachment.
    ShellClient,
    /// Observer attachment.
    Observer,
    /// Registered extension attachment.
    OtherRegistered,
}

/// Input for creating a durable Workspace and first revision.
#[derive(Debug, Clone)]
pub struct CreateWorkspace {
    /// Stable Workspace key.
    pub workspace_key: String,
    /// Human-facing title.
    pub title: String,
    /// Optional description.
    pub description: Option<String>,
    /// Workspace owner.
    pub owner_ref: EntityRef,
    /// Authority/provenance reference retained in ledger envelopes.
    pub authority_ref: EntityRef,
    /// Principal that created the first revision.
    pub created_by_ref: EntityRef,
    /// Initial Policy references.
    pub policy_refs: Vec<EntityRef>,
}

/// Durable Workspace identity projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceProjection {
    /// Canonical Workspace reference.
    pub workspace_ref: EntityRef,
    /// Stable Workspace key.
    pub workspace_key: String,
    /// Human-facing title.
    pub title: String,
    /// Workspace owner.
    pub owner_ref: EntityRef,
    /// Current Workspace Revision.
    pub current_revision_ref: EntityRef,
    /// Durable revision references.
    pub revision_refs: Vec<EntityRef>,
    /// Durable membership references.
    pub membership_refs: Vec<EntityRef>,
    /// Durable Provider-binding references.
    pub provider_binding_refs: Vec<EntityRef>,
    /// Durable Session references.
    pub session_refs: Vec<EntityRef>,
    /// Durable journal-entry references.
    pub journal_refs: Vec<EntityRef>,
    /// Workspace Policy references.
    pub policy_refs: Vec<EntityRef>,
    /// Current canonical record revision.
    pub record_revision: u64,
}

/// Exact Session authority fence presented by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAuthority {
    /// Provider generation observed by the caller.
    pub provider_generation: u64,
    /// Provider connection epoch observed by the caller.
    pub connection_epoch: u64,
}

impl SessionAuthority {
    /// Construct a positive Session authority fence.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::InvalidGeneration`] when either value is zero.
    pub fn new(provider_generation: u64, connection_epoch: u64) -> Result<Self, WorkspaceError> {
        if provider_generation == 0 || connection_epoch == 0 {
            return Err(WorkspaceError::InvalidGeneration);
        }
        Ok(Self {
            provider_generation,
            connection_epoch,
        })
    }
}

/// Input for opening a durable Session within one Workspace.
#[derive(Debug, Clone)]
pub struct CreateSession {
    /// Workspace that owns this Session.
    pub workspace_ref: EntityRef,
    /// Session owner.
    pub owner_ref: EntityRef,
    /// Session kind.
    pub session_kind: SessionKind,
    /// Exact Provider Instance.
    pub provider_instance_ref: EntityRef,
    /// Exact Provider generation/connection fence.
    pub authority: SessionAuthority,
    /// Local Node identity where applicable.
    pub node_ref: Option<EntityRef>,
    /// Local Node generation where applicable.
    pub node_generation: Option<u64>,
    /// Remote service identity when this Session is remote.
    pub remote_service_ref: Option<EntityRef>,
    /// Workspace-scoped subject references.
    pub subject_refs: Vec<EntityRef>,
    /// Policy references.
    pub policy_refs: Vec<EntityRef>,
    /// Envelope authority/provenance reference.
    pub authority_ref: EntityRef,
}

/// Durable Session projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionProjection {
    /// Canonical Session reference.
    pub session_ref: EntityRef,
    /// Owning Workspace.
    pub workspace_ref: EntityRef,
    /// Session kind.
    pub session_kind: SessionKind,
    /// Provider instance.
    pub provider_instance_ref: EntityRef,
    /// Provider generation and connection epoch.
    pub authority: SessionAuthority,
    /// Durable Attachment references, including detached history.
    pub attachment_refs: Vec<EntityRef>,
    /// Workspace-scoped subjects.
    pub subject_refs: Vec<EntityRef>,
    /// Current lifecycle state.
    pub state: String,
    /// Current canonical record revision.
    pub record_revision: u64,
}

/// Input for attaching a client/service to a Session.
#[derive(Debug, Clone)]
pub struct AttachSession {
    /// Attaching principal/agent.
    pub attacher_ref: EntityRef,
    /// Optional concrete client/service identity.
    pub client_or_service_ref: Option<EntityRef>,
    /// Attachment kind.
    pub attachment_kind: AttachmentKind,
    /// Capability scope projected into the attachment.
    pub capability_scope: Vec<String>,
    /// Optional control lease.
    pub control_lease_ref: Option<EntityRef>,
    /// Envelope authority/provenance reference.
    pub authority_ref: EntityRef,
}

/// Durable Session Attachment projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttachmentProjection {
    /// Canonical attachment reference.
    pub attachment_ref: EntityRef,
    /// Session reference.
    pub session_ref: EntityRef,
    /// Attacher principal/agent.
    pub attacher_ref: EntityRef,
    /// Session connection epoch to which the attachment is fenced.
    pub connection_epoch: u64,
    /// Capability scope.
    pub capability_scope: Vec<String>,
    /// Current lifecycle state.
    pub state: String,
    /// Canonical record revision.
    pub record_revision: u64,
}

/// Workspace participant projection backed by frozen Workspace Membership.
#[derive(Debug, Clone)]
pub struct AddParticipant {
    /// Workspace participant.
    pub member_ref: EntityRef,
    /// Stable role key.
    pub role_key: String,
    /// Permission/capability scope.
    pub scopes: Vec<String>,
    /// Principal that issued the membership.
    pub issued_by_ref: EntityRef,
    /// Policy authorizing the membership.
    pub policy_ref: EntityRef,
    /// Envelope authority/provenance reference.
    pub authority_ref: EntityRef,
}

/// Provider-binding input projected into a frozen Workspace Provider Binding.
#[derive(Debug, Clone)]
pub struct BindProvider {
    /// Facility revision required by the Workspace revision.
    pub facility_revision_ref: EntityRef,
    /// Optional logical Provider.
    pub provider_ref: Option<EntityRef>,
    /// Optional exact Provider Revision.
    pub provider_revision_ref: Option<EntityRef>,
    /// Preferred Provider Instances.
    pub provider_instance_preference_refs: Vec<EntityRef>,
    /// Policy references.
    pub policy_refs: Vec<EntityRef>,
    /// Envelope authority/provenance reference.
    pub authority_ref: EntityRef,
}

/// A Workspace-scoped reference projection. A06 does not materialize Objects.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ScopeProjection {
    /// Object references known to the Workspace.
    pub object_refs: Vec<EntityRef>,
    /// Activity references known to the Workspace.
    pub activity_refs: Vec<EntityRef>,
    /// terminal references known to the Workspace.
    pub terminal_refs: Vec<EntityRef>,
    /// Policy references known to the Workspace.
    pub policy_refs: Vec<EntityRef>,
}

/// Worker recovery projection retained by A06 without executing checkpoint restore.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkerProjection {
    /// Formation identity from A04.
    pub formation_ref: EntityRef,
    /// Worker identity.
    pub worker_ref: EntityRef,
    /// Caller-defined role.
    pub role: String,
    /// Independence lane/group key.
    pub independence_key: String,
    /// Checkpoint evidence references.
    pub checkpoint_refs: Vec<EntityRef>,
    /// Partial-result references.
    pub partial_result_refs: Vec<EntityRef>,
    /// Conflict evidence references.
    pub conflict_refs: Vec<EntityRef>,
}

/// Basic durable handoff record projected through the Workspace journal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HandoffProjection {
    /// Agent/principal being replaced.
    pub from_ref: EntityRef,
    /// Replacement agent/principal.
    pub to_ref: EntityRef,
    /// Authority/Grant references transferred as references, not recreated.
    pub authority_refs: Vec<EntityRef>,
    /// Subject/work references retained across replacement.
    pub subject_refs: Vec<EntityRef>,
    /// Human-readable bounded handoff note.
    pub note: String,
}

/// Recovery state derived only from durable Workspace/Session/journal records.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryProjection {
    /// Stable Workspace identity recovered after reopen/restart.
    pub workspace: WorkspaceProjection,
    /// Durable Session projections.
    pub sessions: Vec<SessionProjection>,
    /// Attachment references named by Sessions but absent from the ledger.
    pub missing_attachment_refs: Vec<EntityRef>,
    /// Last durable Workspace scope projection.
    pub scope: ScopeProjection,
    /// Durable worker/formation recovery projections.
    pub workers: Vec<WorkerProjection>,
    /// Latest durable handoff projection when present.
    pub handoff: Option<HandoffProjection>,
}

/// Input for a frozen Secure Grant used by A06 cross-Workspace authority.
#[derive(Debug, Clone)]
pub struct IssueGrant {
    /// Workspace/resource subject protected by this Grant.
    pub subject_ref: EntityRef,
    /// Grantee principal/agent.
    pub grantee_ref: EntityRef,
    /// Required grant scopes.
    pub scopes: Vec<String>,
    /// Policy authority.
    pub policy_ref: EntityRef,
    /// Provider generation fence.
    pub provider_generation: u64,
    /// Monotonic fence token.
    pub fence_token: u64,
    /// Expiry timestamp.
    pub expires_at: String,
    /// Envelope authority/provenance reference.
    pub authority_ref: EntityRef,
}

/// Persistent A06 Workspace repository backed by the proven A03 ledger.
pub struct WorkspaceStore {
    ledger: Ledger,
    clock: Arc<dyn Fn() -> String + Send + Sync>,
}

impl WorkspaceStore {
    /// Open/create the durable Workspace repository.
    ///
    /// # Errors
    ///
    /// Returns a ledger error if the durable repository cannot be opened.
    pub fn open(
        path: impl AsRef<Path>,
        clock: Arc<dyn Fn() -> String + Send + Sync>,
    ) -> Result<Self, WorkspaceError> {
        Ok(Self {
            ledger: Ledger::open(path)?,
            clock,
        })
    }

    /// Create a persistent Workspace and first immutable Workspace Revision.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, identity failure, or durable write failure.
    pub fn create_workspace(
        &mut self,
        input: CreateWorkspace,
    ) -> Result<WorkspaceProjection, WorkspaceError> {
        validate_workspace_key(&input.workspace_key)?;
        require_text(&input.title, "title")?;
        let now = (self.clock)();
        let workspace_ref = EntityRef::new("core.workspace")?;
        let revision_ref = EntityRef::new("core.workspace_revision")?;
        let revision = json!({
            "envelope": envelope(&revision_ref, WORKSPACE_REVISION_SCHEMA_ID, 1, &input.authority_ref),
            "workspace_ref": workspace_ref,
            "revision_number": 1,
            "parent_revision_refs": [],
            "configuration_schema_refs": [],
            "source_or_object_refs": [],
            "facility_requirement_refs": [],
            "provider_requirement_refs": [],
            "policy_refs": input.policy_refs,
            "created_by_ref": input.created_by_ref,
            "created_at": now,
            "extensions": {}
        });
        let workspace = json!({
            "envelope": envelope(&workspace_ref, WORKSPACE_SCHEMA_ID, 1, &input.authority_ref),
            "lifecycle": lifecycle("workspace.lifecycle", "active", 1, &now),
            "workspace_key": input.workspace_key,
            "title": input.title,
            "description": input.description,
            "owner_ref": input.owner_ref,
            "current_revision_ref": revision_ref,
            "revision_refs": [revision_ref],
            "membership_refs": [],
            "policy_refs": input.policy_refs,
            "provider_binding_refs": [],
            "materialization_refs": [],
            "session_refs": [],
            "journal_cursor_refs": [],
            "created_at": now,
            "limitations": ["A06 projects workspace-scoped Object references but does not materialize A07 Object/CAS content", "A06 recovery is metadata projection; A13 owns checkpoint/restore execution"],
            "extensions": {}
        });
        self.write_documents(&[revision, workspace])?;
        self.workspace(workspace_ref.entity_id)
    }

    /// Read the latest durable Workspace projection.
    ///
    /// # Errors
    ///
    /// Returns an error when the Workspace is missing, malformed, or the ledger fails.
    pub fn workspace(&self, workspace_id: EntityId) -> Result<WorkspaceProjection, WorkspaceError> {
        let record = self.latest(workspace_id)?;
        if record.schema_id() != WORKSPACE_SCHEMA_ID {
            return Err(WorkspaceError::TypeMismatch);
        }
        workspace_projection(record.document(), record.record_revision().value())
    }

    /// Add a durable participant/membership projection to a Workspace.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed membership input or durable write failure.
    pub fn add_participant(
        &mut self,
        workspace_id: EntityId,
        input: AddParticipant,
    ) -> Result<EntityRef, WorkspaceError> {
        require_key(&input.role_key, "role_key")?;
        for scope in &input.scopes {
            require_scope(scope)?;
        }
        let mut workspace = self.latest_document(workspace_id, WORKSPACE_SCHEMA_ID)?;
        let workspace_ref = document_ref(&workspace)?;
        let membership_ref = EntityRef::new("core.workspace_membership")?;
        let now = (self.clock)();
        let membership = json!({
            "envelope": envelope(&membership_ref, WORKSPACE_MEMBERSHIP_SCHEMA_ID, 1, &input.authority_ref),
            "lifecycle": lifecycle("workspace.membership.lifecycle", "active", 1, &now),
            "workspace_ref": workspace_ref,
            "member_ref": input.member_ref,
            "role_key": input.role_key,
            "permission_or_capability_scope": input.scopes,
            "issued_by_ref": input.issued_by_ref,
            "issued_at": now,
            "policy_ref": input.policy_ref,
            "control_lease_refs": [],
            "decision_receipt_refs": [],
            "limitations": [],
            "extensions": {}
        });
        append_ref(&mut workspace, "membership_refs", membership_ref.clone())?;
        bump_document_revision(&mut workspace)?;
        self.write_documents(&[membership, workspace])?;
        Ok(membership_ref)
    }

    /// Bind Provider/facility intent to the current Workspace revision.
    ///
    /// # Errors
    ///
    /// Returns an error when Workspace state is malformed or persistence fails.
    pub fn bind_provider(
        &mut self,
        workspace_id: EntityId,
        input: BindProvider,
    ) -> Result<EntityRef, WorkspaceError> {
        let mut workspace = self.latest_document(workspace_id, WORKSPACE_SCHEMA_ID)?;
        let workspace_ref = document_ref(&workspace)?;
        let current_revision_ref: EntityRef = field_ref(&workspace, "current_revision_ref")?;
        let binding_ref = EntityRef::new("core.workspace_provider_binding")?;
        let now = (self.clock)();
        let binding = json!({
            "envelope": envelope(&binding_ref, WORKSPACE_PROVIDER_BINDING_SCHEMA_ID, 1, &input.authority_ref),
            "lifecycle": lifecycle("workspace.provider_binding.lifecycle", "active", 1, &now),
            "workspace_ref": workspace_ref,
            "workspace_revision_ref": current_revision_ref,
            "facility_revision_ref": input.facility_revision_ref,
            "provider_ref": input.provider_ref,
            "provider_revision_ref": input.provider_revision_ref,
            "provider_instance_preference_refs": input.provider_instance_preference_refs,
            "compatibility_requirement_refs": [],
            "policy_refs": input.policy_refs,
            "created_at": now,
            "limitations": [],
            "extensions": {}
        });
        append_ref(&mut workspace, "provider_binding_refs", binding_ref.clone())?;
        bump_document_revision(&mut workspace)?;
        self.write_documents(&[binding, workspace])?;
        Ok(binding_ref)
    }

    /// Create a durable Session without replacing Workspace identity.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid local/remote binding, stale Workspace state,
    /// or durable write failure.
    pub fn create_session(&mut self, input: CreateSession) -> Result<EntityRef, WorkspaceError> {
        if input.authority.provider_generation == 0 || input.authority.connection_epoch == 0 {
            return Err(WorkspaceError::InvalidGeneration);
        }
        match (&input.node_ref, input.node_generation, &input.remote_service_ref) {
            (Some(_), Some(generation), None) if generation > 0 => {}
            (None, None, Some(_)) => {}
            _ => return Err(WorkspaceError::InvalidGeneration),
        }
        let workspace_id = input.workspace_ref.entity_id;
        let mut workspace = self.latest_document(workspace_id, WORKSPACE_SCHEMA_ID)?;
        let stored_workspace_ref = document_ref(&workspace)?;
        if stored_workspace_ref != input.workspace_ref {
            return Err(WorkspaceError::TypeMismatch);
        }
        let session_ref = EntityRef::new("runtime.session")?;
        let now = (self.clock)();
        let session = json!({
            "envelope": envelope(&session_ref, SESSION_SCHEMA_ID, 1, &input.authority_ref),
            "lifecycle": lifecycle("session.lifecycle", "active", 1, &now),
            "session_kind": input.session_kind,
            "workspace_ref": input.workspace_ref,
            "owner_ref": input.owner_ref,
            "policy_refs": input.policy_refs,
            "provider_instance_ref": input.provider_instance_ref,
            "provider_generation": input.authority.provider_generation,
            "connection_epoch": input.authority.connection_epoch,
            "node_ref": input.node_ref,
            "node_generation": input.node_generation,
            "remote_service_ref": input.remote_service_ref,
            "subject_refs": input.subject_refs,
            "specialist_session_refs": [],
            "attachment_refs": [],
            "control_lease_refs": [],
            "backend_alias_refs": [],
            "stream_refs": [],
            "checkpoint_capability_refs": [],
            "created_at": now,
            "last_observed_at": now,
            "limitations": [],
            "extensions": {}
        });
        append_ref(&mut workspace, "session_refs", session_ref.clone())?;
        bump_document_revision(&mut workspace)?;
        self.write_documents(&[session, workspace])?;
        Ok(session_ref)
    }

    /// Read a durable Session projection.
    ///
    /// # Errors
    ///
    /// Returns an error when the Session is absent, malformed, or wrong-schema.
    pub fn session(&self, session_id: EntityId) -> Result<SessionProjection, WorkspaceError> {
        let record = self.latest(session_id)?;
        if record.schema_id() != SESSION_SCHEMA_ID {
            return Err(WorkspaceError::TypeMismatch);
        }
        session_projection(record.document(), record.record_revision().value())
    }

    /// Attach a client/service to a Session under an exact Session authority fence.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::StaleSessionAuthority`] for stale Provider
    /// generation/connection epoch or a persistence error otherwise.
    pub fn attach_session(
        &mut self,
        session_id: EntityId,
        authority: SessionAuthority,
        input: AttachSession,
    ) -> Result<EntityRef, WorkspaceError> {
        for scope in &input.capability_scope {
            require_scope(scope)?;
        }
        let mut session = self.latest_document(session_id, SESSION_SCHEMA_ID)?;
        ensure_session_authority(&session, authority)?;
        let session_ref = document_ref(&session)?;
        let attachment_ref = EntityRef::new("runtime.session_attachment")?;
        let now = (self.clock)();
        let attachment = json!({
            "envelope": envelope(&attachment_ref, SESSION_ATTACHMENT_SCHEMA_ID, 1, &input.authority_ref),
            "lifecycle": lifecycle("session.attachment.lifecycle", "attached", 1, &now),
            "session_ref": session_ref,
            "attachment_kind": input.attachment_kind,
            "attacher_ref": input.attacher_ref,
            "client_or_service_ref": input.client_or_service_ref,
            "connection_epoch": authority.connection_epoch,
            "capability_scope": input.capability_scope,
            "control_lease_ref": input.control_lease_ref,
            "attached_at": now,
            "last_seen_at": now,
            "receipt_refs": [],
            "limitations": [],
            "extensions": {}
        });
        append_ref(&mut session, "attachment_refs", attachment_ref.clone())?;
        set_string(&mut session, "last_observed_at", now)?;
        bump_document_revision(&mut session)?;
        self.write_documents(&[attachment, session])?;
        Ok(attachment_ref)
    }

    /// Detach one durable Session attachment without replacing Session/Workspace identity.
    ///
    /// # Errors
    ///
    /// Returns a stale-authority/attachment error or durable write failure.
    pub fn detach_session(
        &mut self,
        session_id: EntityId,
        attachment_id: EntityId,
        authority: SessionAuthority,
    ) -> Result<(), WorkspaceError> {
        let mut session = self.latest_document(session_id, SESSION_SCHEMA_ID)?;
        ensure_session_authority(&session, authority)?;
        let attachment_ref = ref_with_kind(attachment_id, "runtime.session_attachment")?;
        let refs = field_refs(&session, "attachment_refs")?;
        if !refs.contains(&attachment_ref) {
            return Err(WorkspaceError::StaleAttachment);
        }
        let mut attachment = self.latest_document(attachment_id, SESSION_ATTACHMENT_SCHEMA_ID)?;
        let state = lifecycle_state(&attachment)?;
        if state != "attached" {
            return Err(WorkspaceError::StaleAttachment);
        }
        let now = (self.clock)();
        set_lifecycle(&mut attachment, "session.attachment.lifecycle", "detached", &now)?;
        set_string(&mut attachment, "detached_at", now.clone())?;
        bump_document_revision(&mut attachment)?;
        set_string(&mut session, "last_observed_at", now)?;
        bump_document_revision(&mut session)?;
        self.write_documents(&[attachment, session])
    }

    /// Persist one Workspace-scoped Object/Activity/terminal/Policy projection.
    ///
    /// A06 stores references only; Object bytes/revisions remain A07-owned.
    ///
    /// # Errors
    ///
    /// Returns an error for missing Workspace state or persistence failure.
    pub fn record_scope_projection(
        &mut self,
        workspace_id: EntityId,
        source_ref: EntityRef,
        projection: &ScopeProjection,
        authority_ref: &EntityRef,
    ) -> Result<EntityRef, WorkspaceError> {
        self.append_journal(
            workspace_id,
            "workspace.scope_projection",
            source_ref,
            collect_scope_subjects(projection),
            authority_ref,
            json!({"scope_projection": projection}),
        )
    }

    /// Persist worker formation/role/checkpoint/partial/conflict recovery state.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid Workspace state or persistence failure.
    pub fn record_worker_projection(
        &mut self,
        workspace_id: EntityId,
        source_ref: EntityRef,
        workers: &[WorkerProjection],
        authority_ref: &EntityRef,
    ) -> Result<EntityRef, WorkspaceError> {
        for worker in workers {
            require_text(&worker.role, "worker role")?;
            require_text(&worker.independence_key, "independence_key")?;
        }
        let subjects = workers
            .iter()
            .flat_map(|worker| [worker.formation_ref.clone(), worker.worker_ref.clone()])
            .collect();
        self.append_journal(
            workspace_id,
            "workspace.worker_projection",
            source_ref,
            subjects,
            authority_ref,
            json!({"workers": workers}),
        )
    }

    /// Persist a basic handoff while preserving existing authority references.
    ///
    /// # Errors
    ///
    /// Returns an error for empty notes, missing Workspace state, or persistence failure.
    pub fn record_handoff(
        &mut self,
        workspace_id: EntityId,
        source_ref: EntityRef,
        handoff: &HandoffProjection,
        authority_ref: &EntityRef,
    ) -> Result<EntityRef, WorkspaceError> {
        require_text(&handoff.note, "handoff note")?;
        let mut subjects = vec![handoff.from_ref.clone(), handoff.to_ref.clone()];
        subjects.extend(handoff.subject_refs.clone());
        subjects.extend(handoff.authority_refs.clone());
        self.append_journal(
            workspace_id,
            "workspace.handoff",
            source_ref,
            subjects,
            authority_ref,
            json!({"handoff": handoff}),
        )
    }

    /// Issue a frozen Secure Grant that may authorize cross-Workspace retrieval.
    ///
    /// # Errors
    ///
    /// Returns an error for empty scopes, non-positive fences, or persistence failure.
    pub fn issue_grant(&mut self, input: IssueGrant) -> Result<EntityRef, WorkspaceError> {
        if input.scopes.is_empty() || input.provider_generation == 0 || input.fence_token == 0 {
            return Err(WorkspaceError::InvalidGeneration);
        }
        for scope in &input.scopes {
            require_scope(scope)?;
        }
        let grant_ref = EntityRef::new("isolation.secure_grant")?;
        let now = (self.clock)();
        let grant = json!({
            "envelope": envelope(&grant_ref, SECURE_GRANT_SCHEMA_ID, 1, &input.authority_ref),
            "lifecycle": lifecycle("isolation.secure_grant.lifecycle", "active", 1, &now),
            "subject_ref": input.subject_ref,
            "grantee_ref": input.grantee_ref,
            "grant_type": "control",
            "scopes": input.scopes,
            "policy_ref": input.policy_ref,
            "provider_generation": input.provider_generation,
            "fence_token": input.fence_token,
            "issued_at": now,
            "expires_at": input.expires_at,
            "extensions": {}
        });
        self.write_documents(&[grant])?;
        Ok(grant_ref)
    }

    /// Authorize/reject retrieval across Workspace authority boundaries.
    ///
    /// Same-Workspace retrieval succeeds. Cross-Workspace retrieval requires an
    /// active membership containing the requested scope or an exact Secure Grant.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceError::CrossWorkspaceDenied`] when no accepted
    /// membership/Grant exists, or another repository/shape error.
    pub fn authorize_retrieval(
        &self,
        actor_ref: &EntityRef,
        source_workspace_id: EntityId,
        target_workspace_id: EntityId,
        required_scope: &str,
        grant_ref: Option<&EntityRef>,
    ) -> Result<(), WorkspaceError> {
        require_scope(required_scope)?;
        if source_workspace_id == target_workspace_id {
            return Ok(());
        }
        let target = self.workspace(target_workspace_id)?;
        for membership_ref in &target.membership_refs {
            let record = self.latest(membership_ref.entity_id)?;
            if record.schema_id() != WORKSPACE_MEMBERSHIP_SCHEMA_ID {
                continue;
            }
            let doc = record.document();
            if field_ref(doc, "member_ref")? == *actor_ref
                && lifecycle_state(doc)? == "active"
                && field_strings(doc, "permission_or_capability_scope")?
                    .iter()
                    .any(|scope| scope == required_scope)
            {
                return Ok(());
            }
        }
        if let Some(grant_ref) = grant_ref {
            let record = self.latest(grant_ref.entity_id)?;
            if record.schema_id() == SECURE_GRANT_SCHEMA_ID {
                let doc = record.document();
                let target_ref = ref_with_kind(target_workspace_id, "core.workspace")?;
                let valid = field_ref(doc, "subject_ref")? == target_ref
                    && field_ref(doc, "grantee_ref")? == *actor_ref
                    && lifecycle_state(doc)? == "active"
                    && doc.get("revoked_at").is_none()
                    && field_strings(doc, "scopes")?
                        .iter()
                        .any(|scope| scope == required_scope);
                if valid {
                    return Ok(());
                }
                return Err(WorkspaceError::InvalidGrant);
            }
        }
        Err(WorkspaceError::CrossWorkspaceDenied)
    }

    /// Reconstruct A06 recovery/handoff state after process/runtime restart.
    ///
    /// This is metadata projection only. It does not execute A13 checkpoint restore.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed durable records or ledger failure.
    pub fn recovery_projection(
        &self,
        workspace_id: EntityId,
    ) -> Result<RecoveryProjection, WorkspaceError> {
        let workspace = self.workspace(workspace_id)?;
        let mut sessions = Vec::new();
        let mut missing_attachment_refs = Vec::new();
        for session_ref in &workspace.session_refs {
            let session = self.session(session_ref.entity_id)?;
            for attachment_ref in &session.attachment_refs {
                match self.ledger.latest_record(attachment_ref.entity_id)? {
                    Some(record) if record.schema_id() == SESSION_ATTACHMENT_SCHEMA_ID => {}
                    _ => missing_attachment_refs.push(attachment_ref.clone()),
                }
            }
            sessions.push(session);
        }
        let mut scope = ScopeProjection::default();
        let mut workers = Vec::new();
        let mut handoff = None;
        for journal_ref in &workspace.journal_refs {
            let record = self.latest(journal_ref.entity_id)?;
            if record.schema_id() != WORKSPACE_JOURNAL_SCHEMA_ID {
                continue;
            }
            let document = record.document();
            let Some(a06) = document
                .get("extensions")
                .and_then(|value| value.get("a06"))
            else {
                continue;
            };
            if let Some(value) = a06.get("scope_projection") {
                scope = serde_json::from_value(value.clone())?;
            }
            if let Some(value) = a06.get("workers") {
                workers = serde_json::from_value(value.clone())?;
            }
            if let Some(value) = a06.get("handoff") {
                handoff = Some(serde_json::from_value(value.clone())?);
            }
        }
        Ok(RecoveryProjection {
            workspace,
            sessions,
            missing_attachment_refs,
            scope,
            workers,
            handoff,
        })
    }

    fn append_journal(
        &mut self,
        workspace_id: EntityId,
        entry_type: &str,
        source_ref: EntityRef,
        subject_refs: Vec<EntityRef>,
        authority_ref: &EntityRef,
        a06_extension: Value,
    ) -> Result<EntityRef, WorkspaceError> {
        require_key(entry_type, "entry_type")?;
        let mut workspace = self.latest_document(workspace_id, WORKSPACE_SCHEMA_ID)?;
        let workspace_ref = document_ref(&workspace)?;
        let sequence = field_refs(&workspace, "journal_cursor_refs")?
            .len()
            .checked_add(1)
            .ok_or(WorkspaceError::JournalSequenceOverflow)?;
        let journal_ref = EntityRef::new("core.workspace_journal_entry")?;
        let now = (self.clock)();
        let current_revision_ref: EntityRef = field_ref(&workspace, "current_revision_ref")?;
        let journal = json!({
            "envelope": envelope(&journal_ref, WORKSPACE_JOURNAL_SCHEMA_ID, 1, authority_ref),
            "workspace_ref": workspace_ref,
            "journal_sequence": sequence,
            "entry_type": entry_type,
            "source_ref": source_ref,
            "subject_refs": unique_refs(subject_refs),
            "workspace_revision_ref": current_revision_ref,
            "occurred_at": now,
            "recorded_at": now,
            "event_or_receipt_refs": [],
            "limitations": [],
            "extensions": {"a06": a06_extension}
        });
        append_ref(&mut workspace, "journal_cursor_refs", journal_ref.clone())?;
        bump_document_revision(&mut workspace)?;
        self.write_documents(&[journal, workspace])?;
        Ok(journal_ref)
    }

    fn latest(&self, entity_id: EntityId) -> Result<CanonicalRecord, WorkspaceError> {
        self.ledger
            .latest_record(entity_id)?
            .ok_or(WorkspaceError::NotFound(entity_id))
    }

    fn latest_document(
        &self,
        entity_id: EntityId,
        expected_schema: &str,
    ) -> Result<Value, WorkspaceError> {
        let record = self.latest(entity_id)?;
        if record.schema_id() != expected_schema {
            return Err(WorkspaceError::TypeMismatch);
        }
        Ok(record.document().clone())
    }

    fn write_documents(&mut self, documents: &[Value]) -> Result<(), WorkspaceError> {
        let records = documents
            .iter()
            .cloned()
            .map(CanonicalRecord::from_document)
            .collect::<Result<Vec<_>, _>>()?;
        let write = self.ledger.begin_write()?;
        for record in &records {
            write.insert(record)?;
        }
        write.commit()?;
        Ok(())
    }
}

fn envelope(
    entity_ref: &EntityRef,
    schema_id: &str,
    revision: u64,
    authority_ref: &EntityRef,
) -> Value {
    json!({
        "entity_id": entity_ref.entity_id,
        "entity_kind": entity_ref.entity_kind,
        "schema_id": schema_id,
        "schema_version": SCHEMA_VERSION,
        "record_revision": revision,
        "authority_ref": authority_ref
    })
}

fn lifecycle(machine: &str, state: &str, sequence: u64, entered_at: &str) -> Value {
    json!({
        "state_machine_name": machine,
        "state_machine_version": SCHEMA_VERSION,
        "current_state": state,
        "state_sequence": sequence,
        "entered_at": entered_at,
        "transition_receipt_refs": []
    })
}

fn set_lifecycle(
    document: &mut Value,
    machine: &str,
    state: &str,
    entered_at: &str,
) -> Result<(), WorkspaceError> {
    let old_sequence = document
        .get("lifecycle")
        .and_then(|value| value.get("state_sequence"))
        .and_then(Value::as_u64)
        .ok_or(WorkspaceError::TypeMismatch)?;
    let sequence = old_sequence
        .checked_add(1)
        .ok_or(WorkspaceError::RevisionOverflow)?;
    document_object_mut(document)?.insert(
        "lifecycle".to_owned(),
        lifecycle(machine, state, sequence, entered_at),
    );
    Ok(())
}

fn lifecycle_state(document: &Value) -> Result<&str, WorkspaceError> {
    document
        .get("lifecycle")
        .and_then(|value| value.get("current_state"))
        .and_then(Value::as_str)
        .ok_or(WorkspaceError::TypeMismatch)
}

fn bump_document_revision(document: &mut Value) -> Result<u64, WorkspaceError> {
    let envelope = document
        .get_mut("envelope")
        .and_then(Value::as_object_mut)
        .ok_or(WorkspaceError::TypeMismatch)?;
    let current = envelope
        .get("record_revision")
        .and_then(Value::as_u64)
        .ok_or(WorkspaceError::TypeMismatch)?;
    let next = current
        .checked_add(1)
        .ok_or(WorkspaceError::RevisionOverflow)?;
    envelope.insert("record_revision".to_owned(), json!(next));
    Ok(next)
}

fn ensure_session_authority(
    session: &Value,
    authority: SessionAuthority,
) -> Result<(), WorkspaceError> {
    let provider_generation = session
        .get("provider_generation")
        .and_then(Value::as_u64)
        .ok_or(WorkspaceError::TypeMismatch)?;
    let connection_epoch = session
        .get("connection_epoch")
        .and_then(Value::as_u64)
        .ok_or(WorkspaceError::TypeMismatch)?;
    if provider_generation != authority.provider_generation
        || connection_epoch != authority.connection_epoch
    {
        return Err(WorkspaceError::StaleSessionAuthority);
    }
    Ok(())
}

fn workspace_projection(document: &Value, revision: u64) -> Result<WorkspaceProjection, WorkspaceError> {
    Ok(WorkspaceProjection {
        workspace_ref: document_ref(document)?,
        workspace_key: field_string(document, "workspace_key")?.to_owned(),
        title: field_string(document, "title")?.to_owned(),
        owner_ref: field_ref(document, "owner_ref")?,
        current_revision_ref: field_ref(document, "current_revision_ref")?,
        revision_refs: field_refs(document, "revision_refs")?,
        membership_refs: field_refs(document, "membership_refs")?,
        provider_binding_refs: field_refs(document, "provider_binding_refs")?,
        session_refs: field_refs(document, "session_refs")?,
        journal_refs: field_refs(document, "journal_cursor_refs")?,
        policy_refs: field_refs(document, "policy_refs")?,
        record_revision: revision,
    })
}

fn session_projection(document: &Value, revision: u64) -> Result<SessionProjection, WorkspaceError> {
    Ok(SessionProjection {
        session_ref: document_ref(document)?,
        workspace_ref: field_ref(document, "workspace_ref")?,
        session_kind: serde_json::from_value(
            document
                .get("session_kind")
                .cloned()
                .ok_or(WorkspaceError::TypeMismatch)?,
        )?,
        provider_instance_ref: field_ref(document, "provider_instance_ref")?,
        authority: SessionAuthority {
            provider_generation: field_u64(document, "provider_generation")?,
            connection_epoch: field_u64(document, "connection_epoch")?,
        },
        attachment_refs: field_refs(document, "attachment_refs")?,
        subject_refs: field_refs(document, "subject_refs")?,
        state: lifecycle_state(document)?.to_owned(),
        record_revision: revision,
    })
}

fn document_ref(document: &Value) -> Result<EntityRef, WorkspaceError> {
    let envelope = document.get("envelope").ok_or(WorkspaceError::TypeMismatch)?;
    let entity_id: EntityId = serde_json::from_value(
        envelope
            .get("entity_id")
            .cloned()
            .ok_or(WorkspaceError::TypeMismatch)?,
    )?;
    let entity_kind = envelope
        .get("entity_kind")
        .and_then(Value::as_str)
        .ok_or(WorkspaceError::TypeMismatch)?;
    EntityRef::from_id(entity_id, entity_kind).map_err(WorkspaceError::from)
}

fn field_ref(document: &Value, field: &'static str) -> Result<EntityRef, WorkspaceError> {
    serde_json::from_value(
        document
            .get(field)
            .cloned()
            .ok_or(WorkspaceError::EmptyField(field))?,
    )
    .map_err(WorkspaceError::from)
}

fn field_refs(document: &Value, field: &'static str) -> Result<Vec<EntityRef>, WorkspaceError> {
    serde_json::from_value(
        document
            .get(field)
            .cloned()
            .ok_or(WorkspaceError::EmptyField(field))?,
    )
    .map_err(WorkspaceError::from)
}

fn field_strings(document: &Value, field: &'static str) -> Result<Vec<String>, WorkspaceError> {
    serde_json::from_value(
        document
            .get(field)
            .cloned()
            .ok_or(WorkspaceError::EmptyField(field))?,
    )
    .map_err(WorkspaceError::from)
}

fn field_string<'a>(document: &'a Value, field: &'static str) -> Result<&'a str, WorkspaceError> {
    document
        .get(field)
        .and_then(Value::as_str)
        .ok_or(WorkspaceError::EmptyField(field))
}

fn field_u64(document: &Value, field: &'static str) -> Result<u64, WorkspaceError> {
    document
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(WorkspaceError::EmptyField(field))
}

fn append_ref(
    document: &mut Value,
    field: &'static str,
    entity_ref: EntityRef,
) -> Result<(), WorkspaceError> {
    let values = document_object_mut(document)?
        .get_mut(field)
        .and_then(Value::as_array_mut)
        .ok_or(WorkspaceError::EmptyField(field))?;
    let value = serde_json::to_value(entity_ref)?;
    if !values.contains(&value) {
        values.push(value);
    }
    Ok(())
}

fn set_string(document: &mut Value, field: &'static str, value: String) -> Result<(), WorkspaceError> {
    document_object_mut(document)?.insert(field.to_owned(), Value::String(value));
    Ok(())
}

fn document_object_mut(document: &mut Value) -> Result<&mut Map<String, Value>, WorkspaceError> {
    document.as_object_mut().ok_or(WorkspaceError::TypeMismatch)
}

fn collect_scope_subjects(projection: &ScopeProjection) -> Vec<EntityRef> {
    unique_refs(
        projection
            .object_refs
            .iter()
            .chain(&projection.activity_refs)
            .chain(&projection.terminal_refs)
            .chain(&projection.policy_refs)
            .cloned()
            .collect(),
    )
}

fn unique_refs(values: Vec<EntityRef>) -> Vec<EntityRef> {
    let mut output = Vec::new();
    for value in values {
        if !output.contains(&value) {
            output.push(value);
        }
    }
    output
}

fn ref_with_kind(entity_id: EntityId, kind: &str) -> Result<EntityRef, WorkspaceError> {
    EntityRef::from_id(entity_id, kind).map_err(WorkspaceError::from)
}

fn validate_workspace_key(value: &str) -> Result<(), WorkspaceError> {
    if value.len() < 3 || value.len() > 128 {
        return Err(WorkspaceError::InvalidWorkspaceKey);
    }
    let mut chars = value.chars();
    if !chars.next().is_some_and(|ch| ch.is_ascii_lowercase())
        || !chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '.' | '-'))
    {
        return Err(WorkspaceError::InvalidWorkspaceKey);
    }
    Ok(())
}

fn require_text(value: &str, field: &'static str) -> Result<(), WorkspaceError> {
    if value.trim().is_empty() {
        return Err(WorkspaceError::EmptyField(field));
    }
    Ok(())
}

fn require_key(value: &str, field: &'static str) -> Result<(), WorkspaceError> {
    if value.len() < 3
        || value.len() > 128
        || !value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_lowercase())
        || !value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '.' | '-'))
    {
        return Err(WorkspaceError::EmptyField(field));
    }
    Ok(())
}

fn require_scope(value: &str) -> Result<(), WorkspaceError> {
    if value.len() < 3
        || value.len() > 255
        || !value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_lowercase())
        || !value.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '.' | '-' | ':')
        })
    {
        return Err(WorkspaceError::EmptyField("scope"));
    }
    Ok(())
}
