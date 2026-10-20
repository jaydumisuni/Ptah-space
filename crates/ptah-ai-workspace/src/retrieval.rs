//! Exact canonical record retrieval; caller access is admitted by Knights ingress.

use crate::D02Error;
use ptah_activity_runtime::ACTIVITY_SCHEMA_ID;
use ptah_identifiers::{EntityRef, RecordRevision};
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger};
use ptah_object_store::{ARTIFACT_SCHEMA_ID, OBJECT_SCHEMA_ID};
use ptah_workspace::{SESSION_SCHEMA_ID, WORKSPACE_SCHEMA_ID, WorkspaceStore};
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
    /// Caller-origin operation scope retained as provenance (not Ptah permission).
    pub required_scope: String,
    /// Optional historical Secure Grant metadata, not a new access requirement.
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

    /// Check chosen Workspace identity before retrieving a canonical document.
    ///
    /// # Errors
    /// Returns a record/integrity error for missing/mismatched Workspaces.
    pub fn authorize_workspace_access(&self, request: &RetrievalRequest) -> Result<(), D02Error> {
        self.authorize_workspace_scope(
            &request.actor_ref,
            &request.source_workspace_ref,
            &request.target_workspace_ref,
            &request.required_scope,
            request.grant_ref.as_ref(),
        )
    }

    /// Check Workspace references for caller-selected operations such as search.
    ///
    /// # Errors
    /// Returns a technical error when the selected Workspace does not exist.
    pub fn authorize_workspace_scope(
        &self,
        actor_ref: &EntityRef,
        source_workspace_ref: &EntityRef,
        target_workspace_ref: &EntityRef,
        required_scope: &str,
        grant_ref: Option<&EntityRef>,
    ) -> Result<(), D02Error> {
        // Upstream Knights decides admission once. Ptah does not recheck
        // actor, Grant or scope; those legacy fields are provenance only.
        let _ = (actor_ref, required_scope, grant_ref);
        for reference in [source_workspace_ref, target_workspace_ref] {
            if reference.entity_kind.as_str() != "core.workspace" {
                return Err(D02Error::WorkspaceMismatch);
            }
            let record = self.workspace.workspace(reference.entity_id)?;
            if record.workspace_ref != *reference {
                return Err(D02Error::WorkspaceMismatch);
            }
        }
        Ok(())
    }

    /// Retrieve exact canonical records after integrity and Workspace routing checks.
    ///
    /// # Errors
    /// Fails closed for missing/mismatched record class or wrong Workspace routing.
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
