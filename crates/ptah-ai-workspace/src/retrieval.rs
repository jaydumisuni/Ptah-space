//! Exact authority-gated D02 canonical record retrieval.

use crate::D02Error;
use ptah_activity_runtime::ACTIVITY_SCHEMA_ID;
use ptah_identifiers::{EntityRef, RecordRevision};
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger};
use ptah_object_store::{ARTIFACT_SCHEMA_ID, OBJECT_SCHEMA_ID};
use ptah_workspace::{SESSION_SCHEMA_ID, WORKSPACE_SCHEMA_ID, WorkspaceError, WorkspaceStore};
use serde_json::Value;
use std::{path::Path, sync::Arc};

/// Caller-supplied UTC clock authority reused from A06.
pub type WorkspaceClock = Arc<dyn Fn() -> String + Send + Sync>;

/// D02 canonical record classes exposed by exact retrieval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordClass {
    /// Canonical Workspace record.
    Workspace,
    /// Canonical Session record.
    Session,
    /// Canonical Activity record.
    Activity,
    /// Canonical Object record.
    Object,
    /// Canonical Artifact record.
    Artifact,
}

/// Exact authority-gated D02 retrieval request.
#[derive(Debug, Clone)]
pub struct RetrievalRequest {
    /// Caller identity.
    pub actor_ref: EntityRef,
    /// Workspace from which the caller is operating.
    pub source_workspace_ref: EntityRef,
    /// Workspace owning the requested record.
    pub target_workspace_ref: EntityRef,
    /// Exact supported record class.
    pub record_class: RecordClass,
    /// Exact canonical record identity.
    pub entity_ref: EntityRef,
    /// Optional exact canonical record revision.
    pub record_revision: Option<RecordRevision>,
    /// Configured scope A06 must authorize.
    pub required_scope: String,
    /// Optional exact Secure Grant reference.
    pub grant_ref: Option<EntityRef>,
}

/// Canonical record returned after exact authority and Workspace ownership checks.
#[derive(Debug, Clone, PartialEq)]
pub struct RetrievedRecord {
    /// Canonical record identity without inferred semantic labels.
    pub entity_ref: EntityRef,
    /// Exact canonical record revision returned.
    pub record_revision: RecordRevision,
    /// Frozen canonical schema identifier.
    pub schema_id: String,
    /// Exact preserved canonical JSON document.
    pub document: Value,
}

/// D02 exact-read façade over A06 authority and A03 canonical records.
pub struct WorkspaceReader {
    workspace: WorkspaceStore,
    ledger: Ledger,
}

impl WorkspaceReader {
    /// Open D02 read composition over one existing Ptah ledger.
    ///
    /// # Errors
    /// Returns the underlying A06/A03 open failure.
    pub fn open(path: impl AsRef<Path>, clock: WorkspaceClock) -> Result<Self, D02Error> {
        let path = path.as_ref();
        Ok(Self {
            workspace: WorkspaceStore::open(path, clock)?,
            ledger: Ledger::open(path)?,
        })
    }

    /// Enforce configured A06 access without reading the target canonical document.
    ///
    /// # Errors
    /// Fails closed when Workspace authority denies access.
    pub fn authorize_workspace_access(&self, request: &RetrievalRequest) -> Result<(), D02Error> {
        match self.workspace.authorize_retrieval(
            &request.actor_ref,
            request.source_workspace_ref.entity_id,
            request.target_workspace_ref.entity_id,
            &request.required_scope,
            request.grant_ref.as_ref(),
        ) {
            Ok(()) => Ok(()),
            Err(WorkspaceError::CrossWorkspaceDenied | WorkspaceError::InvalidGrant) => {
                Err(D02Error::WorkspaceAccessDenied)
            }
            Err(error) => Err(D02Error::Workspace(error)),
        }
    }

    /// Retrieve one exact/latest canonical record after A06 authority validation.
    ///
    /// # Errors
    /// Fails closed for denied access, missing/mismatched record class, or Workspace mismatch.
    pub fn retrieve(&self, request: &RetrievalRequest) -> Result<RetrievedRecord, D02Error> {
        self.authorize_workspace_access(request)?;
        let record = match request.record_revision {
            Some(revision) => self.ledger.record(request.entity_ref.entity_id, revision)?,
            None => self.ledger.latest_record(request.entity_ref.entity_id)?,
        }
        .ok_or(D02Error::RecordNotFound)?;
        validate_record_class(&record, request.record_class)?;
        validate_workspace_ownership(&record, request)?;
        Ok(RetrievedRecord {
            entity_ref: EntityRef::from_id(record.entity_id(), record.entity_kind().as_str())?,
            record_revision: record.record_revision(),
            schema_id: record.schema_id().to_owned(),
            document: record.document().clone(),
        })
    }
}

fn validate_record_class(record: &CanonicalRecord, class: RecordClass) -> Result<(), D02Error> {
    let expected = match class {
        RecordClass::Workspace => WORKSPACE_SCHEMA_ID,
        RecordClass::Session => SESSION_SCHEMA_ID,
        RecordClass::Activity => ACTIVITY_SCHEMA_ID,
        RecordClass::Object => OBJECT_SCHEMA_ID,
        RecordClass::Artifact => ARTIFACT_SCHEMA_ID,
    };
    if record.schema_id() == expected {
        Ok(())
    } else {
        Err(D02Error::RecordClassMismatch)
    }
}

fn validate_workspace_ownership(
    record: &CanonicalRecord,
    request: &RetrievalRequest,
) -> Result<(), D02Error> {
    if request.record_class == RecordClass::Workspace {
        return if record.entity_id() == request.target_workspace_ref.entity_id {
            Ok(())
        } else {
            Err(D02Error::WorkspaceMismatch)
        };
    }
    let workspace_value = match request.record_class {
        RecordClass::Session | RecordClass::Activity => record.document().get("workspace_ref"),
        RecordClass::Object | RecordClass::Artifact => record
            .document()
            .get("envelope")
            .and_then(|value| value.get("workspace_ref")),
        RecordClass::Workspace => unreachable!("handled above"),
    }
    .ok_or(D02Error::WorkspaceMismatch)?;
    let workspace_ref: EntityRef =
        serde_json::from_value(workspace_value.clone()).map_err(|_| D02Error::WorkspaceMismatch)?;
    if workspace_ref == request.target_workspace_ref {
        Ok(())
    } else {
        Err(D02Error::WorkspaceMismatch)
    }
}
