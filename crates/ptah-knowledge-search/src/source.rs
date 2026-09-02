use crate::D03Error;
use ptah_contracts::generated::{SchemaBinding, schema_by_id};
use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};

/// Source families normalized by D03.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeSourceClass {
    /// Anchored document/structured-text source.
    Document,
    /// Source-code symbol projection over an exact source revision.
    SourceSymbol,
    /// Firmware/container/package manifest evidence.
    FirmwareManifest,
    /// Exact partition/layout evidence.
    PartitionData,
    /// Structured dataset/table snapshot.
    Dataset,
    /// Exact database snapshot/query source.
    Database,
}

/// Exact D03 source revision binding. Index/query state never replaces this source truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeSourceRevision {
    /// Workspace that owns/admitted the source.
    pub workspace_ref: EntityRef,
    /// Canonical source entity.
    pub source_ref: EntityRef,
    /// Exact canonical source-record revision.
    pub source_record_revision: u64,
    /// Exact A07 Object Revision for byte-backed sources.
    pub object_revision_ref: Option<EntityRef>,
    /// Exact lowercase SHA-256 of source bytes/snapshot evidence.
    pub content_sha256: String,
    /// Mechanical D03 source class.
    pub class: KnowledgeSourceClass,
    /// Evidence/provenance reference for this binding.
    pub provenance_ref: EntityRef,
    /// Frozen schema identity associated with this source record.
    pub schema_id: String,
}

/// Owned construction request for one exact D03 source revision.
#[derive(Debug, Clone)]
pub struct KnowledgeSourceRevisionInput {
    /// Workspace that owns/admitted the source.
    pub workspace_ref: EntityRef,
    /// Canonical source entity.
    pub source_ref: EntityRef,
    /// Exact canonical source-record revision.
    pub source_record_revision: u64,
    /// Exact A07 Object Revision for byte-backed sources.
    pub object_revision_ref: Option<EntityRef>,
    /// Exact lowercase SHA-256 of source bytes/snapshot evidence.
    pub content_sha256: String,
    /// Mechanical D03 source class.
    pub class: KnowledgeSourceClass,
    /// Evidence/provenance reference for this binding.
    pub provenance_ref: EntityRef,
    /// Frozen schema identity associated with this source record.
    pub schema_id: String,
}

impl KnowledgeSourceRevision {
    /// Construct an exact source revision after mechanical validation.
    ///
    /// # Errors
    /// Returns [`D03Error::InvalidSourceBinding`] for malformed identifiers, revision or digest,
    /// and [`D03Error::UnknownKnowledgeSchema`] for an unavailable frozen schema identity.
    pub fn new(input: KnowledgeSourceRevisionInput) -> Result<Self, D03Error> {
        if input.workspace_ref.entity_kind.as_str() != "core.workspace" {
            return Err(D03Error::InvalidSourceBinding("workspace_ref"));
        }
        if input.source_record_revision == 0 {
            return Err(D03Error::InvalidSourceBinding("source_record_revision"));
        }
        if let Some(reference) = &input.object_revision_ref
            && reference.entity_kind.as_str() != "object.revision"
        {
            return Err(D03Error::InvalidSourceBinding("object_revision_ref"));
        }
        if !is_sha256(&input.content_sha256) {
            return Err(D03Error::InvalidSourceBinding("content_sha256"));
        }
        require_knowledge_schema(&input.schema_id)?;
        Ok(Self {
            workspace_ref: input.workspace_ref,
            source_ref: input.source_ref,
            source_record_revision: input.source_record_revision,
            object_revision_ref: input.object_revision_ref,
            content_sha256: input.content_sha256,
            class: input.class,
            provenance_ref: input.provenance_ref,
            schema_id: input.schema_id,
        })
    }
}

/// Resolve one existing frozen knowledge schema binding.
///
/// # Errors
/// Returns [`D03Error::UnknownKnowledgeSchema`] when the exact schema ID is not frozen.
pub fn require_knowledge_schema(schema_id: &str) -> Result<&'static SchemaBinding, D03Error> {
    if !schema_id.starts_with("urn:ptah:schema:") {
        return Err(D03Error::UnknownKnowledgeSchema(schema_id.to_owned()));
    }
    schema_by_id(schema_id).ok_or_else(|| D03Error::UnknownKnowledgeSchema(schema_id.to_owned()))
}

/// Revalidate that a previously cited source revision still names the same exact revision/digest.
///
/// # Errors
/// Returns stale-revision/digest errors rather than silently refreshing citation truth.
pub fn validate_current_source(
    expected: &KnowledgeSourceRevision,
    actual_record_revision: u64,
    actual_sha256: &str,
) -> Result<(), D03Error> {
    if actual_record_revision != expected.source_record_revision {
        return Err(D03Error::StaleSourceRevision);
    }
    if actual_sha256 != expected.content_sha256 {
        return Err(D03Error::SourceDigestMismatch);
    }
    Ok(())
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
