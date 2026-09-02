//! Non-authoritative D02 Artifact Library projection over A06 scope and A07 canonical truth.

use crate::D02Error;
use ptah_identifiers::{EntityId, EntityRef};
use ptah_ledger::{EntityRecordRepository, Ledger};
use ptah_object_store::{ARTIFACT_SCHEMA_ID, OBJECT_SCHEMA_ID};
use ptah_workspace::WorkspaceStore;
use serde_json::Value;

/// One reusable canonical Artifact entry projected from the current A06 scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactLibraryEntry {
    /// Canonical Artifact identity.
    pub artifact_ref: EntityRef,
    /// Canonical Object identity from whose projection this Artifact was discovered.
    pub object_ref: EntityRef,
    /// Exact promoted Object Revision references retained by A07.
    pub promoted_revision_refs: Vec<EntityRef>,
    /// Caller/A07 Artifact type metadata.
    pub artifact_type: String,
    /// Caller/A07 human-readable purpose.
    pub purpose: String,
    /// Current mechanical A07 Artifact lifecycle state.
    pub lifecycle_state: String,
}

/// Read-only Artifact Library view. It is not canonical state or a ranking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactLibraryProjection {
    /// Stable Workspace identity.
    pub workspace_ref: EntityRef,
    /// Deterministically ordered Artifact entries.
    pub entries: Vec<ArtifactLibraryEntry>,
    /// False in D02 v1 because A06 scope projection is not asserted exhaustive Object discovery.
    pub exhaustive: bool,
    /// Visible projection limitations.
    pub limitations: Vec<String>,
    /// Always false: library presentation cannot promote, rank, accept, or delete Artifacts.
    pub authoritative: bool,
}

/// Build a D02 Artifact Library from the current A06 scope projection and exact A07 records.
///
/// # Errors
/// Fails for malformed/missing canonical Object or Artifact records and underlying A06/A03 errors.
pub fn artifact_library(
    workspace: &WorkspaceStore,
    ledger: &Ledger,
    workspace_id: EntityId,
) -> Result<ArtifactLibraryProjection, D02Error> {
    let recovery = workspace.recovery_projection(workspace_id)?;
    let workspace_ref = recovery.workspace.workspace_ref;
    let mut entries = Vec::new();

    for object_ref in &recovery.scope.object_refs {
        let object = ledger
            .latest_record(object_ref.entity_id)?
            .ok_or(D02Error::RecordNotFound)?;
        if object.schema_id() != OBJECT_SCHEMA_ID {
            return Err(D02Error::RecordClassMismatch);
        }
        ensure_workspace(object.document(), &workspace_ref)?;
        for artifact_ref in field_refs(object.document(), "artifact_refs")? {
            let artifact = ledger
                .latest_record(artifact_ref.entity_id)?
                .ok_or(D02Error::RecordNotFound)?;
            if artifact.schema_id() != ARTIFACT_SCHEMA_ID {
                return Err(D02Error::RecordClassMismatch);
            }
            ensure_workspace(artifact.document(), &workspace_ref)?;
            entries.push(ArtifactLibraryEntry {
                artifact_ref,
                object_ref: object_ref.clone(),
                promoted_revision_refs: field_refs(artifact.document(), "promoted_revision_refs")?,
                artifact_type: field_string(artifact.document(), "artifact_type")?.to_owned(),
                purpose: field_string(artifact.document(), "purpose")?.to_owned(),
                lifecycle_state: artifact
                    .document()
                    .get("lifecycle")
                    .and_then(|value| value.get("current_state"))
                    .and_then(Value::as_str)
                    .ok_or(D02Error::RecordClassMismatch)?
                    .to_owned(),
            });
        }
    }

    entries.sort_by_key(|entry| entry.artifact_ref.entity_id.to_string());
    Ok(ArtifactLibraryProjection {
        workspace_ref,
        entries,
        exhaustive: false,
        limitations: vec![String::from(
            "D02 Artifact Library reflects the current A06 scope projection; it does not claim exhaustive Workspace Object discovery",
        )],
        authoritative: false,
    })
}

fn field_refs(document: &Value, field: &'static str) -> Result<Vec<EntityRef>, D02Error> {
    document
        .get(field)
        .and_then(Value::as_array)
        .ok_or(D02Error::RecordClassMismatch)?
        .iter()
        .map(|value| {
            serde_json::from_value(value.clone()).map_err(|_| D02Error::RecordClassMismatch)
        })
        .collect()
}

fn field_string<'a>(document: &'a Value, field: &'static str) -> Result<&'a str, D02Error> {
    document
        .get(field)
        .and_then(Value::as_str)
        .ok_or(D02Error::RecordClassMismatch)
}

fn ensure_workspace(document: &Value, expected: &EntityRef) -> Result<(), D02Error> {
    let value = document
        .get("envelope")
        .and_then(|envelope| envelope.get("workspace_ref"))
        .ok_or(D02Error::WorkspaceMismatch)?;
    let observed: EntityRef =
        serde_json::from_value(value.clone()).map_err(|_| D02Error::WorkspaceMismatch)?;
    if &observed == expected {
        Ok(())
    } else {
        Err(D02Error::WorkspaceMismatch)
    }
}
