use super::*;
use super::documents_support::*;

pub(super) struct MaterializeInput<'a> {
    pub(super) workspace_ref: &'a EntityRef,
    pub(super) authority_ref: &'a EntityRef,
    pub(super) deduplication_scope: DeduplicationScope,
    pub(super) deduplication_scope_ref: Option<&'a EntityRef>,
    pub(super) media_type_claim: Option<&'a str>,
    pub(super) producer_ref: &'a EntityRef,
    pub(super) producer_version: &'a str,
    pub(super) backend_ref: &'a EntityRef,
    pub(super) connection_ref: &'a EntityRef,
    pub(super) production_correlation: &'a ProductionCorrelation,
    pub(super) now: &'a str,
}

pub(super) struct MaterializedContent {
    pub(super) content_ref: EntityRef,
    pub(super) location_ref: EntityRef,
    pub(super) reused_content: bool,
    pub(super) reused_location: bool,
    pub(super) documents: Vec<Value>,
}

pub(super) fn validate_register_input(input: &RegisterObject) -> Result<(), ObjectStoreError> {
    if input.revision_role == RevisionRole::Tombstone {
        return Err(ObjectStoreError::InvalidInput(
            "first Object Revision cannot be a tombstone",
        ));
    }
    require_key(&input.object_class, "object_class")?;
    require_text(&input.created_reason, "created_reason")?;
    require_text(&input.producer_version, "producer_version")?;
    if input.source_refs.is_empty() {
        return Err(ObjectStoreError::InvalidInput("source_refs must not be empty"));
    }
    for name in &input.declared_names {
        require_text(&name.name, "declared name")?;
    }
    validate_scope(input.deduplication_scope, input.deduplication_scope_ref.as_ref())
}

pub(super) fn validate_append_input(input: &AppendRevision) -> Result<(), ObjectStoreError> {
    if input.revision_role == RevisionRole::Tombstone {
        return Err(ObjectStoreError::InvalidInput(
            "tombstone Revision requires the dedicated Object lifecycle operation",
        ));
    }
    require_text(&input.created_reason, "created_reason")?;
    require_text(&input.producer_version, "producer_version")?;
    if input.source_refs.is_empty() {
        return Err(ObjectStoreError::InvalidInput("source_refs must not be empty"));
    }
    validate_scope(input.deduplication_scope, input.deduplication_scope_ref.as_ref())
}

pub(super) fn validate_scope(
    scope: DeduplicationScope,
    supplied: Option<&EntityRef>,
) -> Result<(), ObjectStoreError> {
    if matches!(
        scope,
        DeduplicationScope::OrganizationTrustDomain | DeduplicationScope::DeploymentTrustDomain
    ) && supplied.is_none()
    {
        return Err(ObjectStoreError::InvalidInput(
            "trust-domain deduplication requires deduplication_scope_ref",
        ));
    }
    Ok(())
}

pub(super) fn dedup_scope_ref(
    scope: DeduplicationScope,
    workspace_ref: &EntityRef,
    object_ref: &EntityRef,
    supplied: Option<&EntityRef>,
) -> Result<Option<EntityRef>, ObjectStoreError> {
    validate_scope(scope, supplied)?;
    Ok(match scope {
        DeduplicationScope::ObjectOnly => Some(object_ref.clone()),
        DeduplicationScope::Workspace => Some(workspace_ref.clone()),
        DeduplicationScope::OrganizationTrustDomain
        | DeduplicationScope::DeploymentTrustDomain => supplied.cloned(),
        DeduplicationScope::PublicContent => None,
    })
}

pub(super) fn envelope(
    entity_ref: &EntityRef,
    schema_id: &str,
    record_revision: u64,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    created_at: &str,
    updated_at: &str,
) -> Value {
    json!({
        "entity_id": entity_ref.entity_id,
        "entity_kind": entity_ref.entity_kind,
        "schema_id": schema_id,
        "schema_version": SCHEMA_VERSION,
        "record_revision": record_revision,
        "created_at": created_at,
        "updated_at": updated_at,
        "workspace_ref": workspace_ref,
        "authority_ref": authority_ref,
        "privacy_class": "internal",
        "audience": "workspace",
        "redaction_policy": "none",
        "retention_policy": {
            "policy_id": "ptah.a07.object_store",
            "policy_version": SCHEMA_VERSION,
            "retention_class": "historical"
        },
        "extensions": {}
    })
}

pub(super) fn state_projection(machine: &str, state: &str, sequence: u64) -> Value {
    json!({
        "state_machine_name": machine,
        "state_machine_version": SCHEMA_VERSION,
        "current_state": state,
        "state_sequence": sequence
    })
}

pub(super) fn production_correlation(correlation: &ProductionCorrelation) -> Value {
    json!({
        "activity_ref": correlation.activity_ref,
        "operation_ref": correlation.operation_ref,
        "attempt_ref": correlation.attempt_ref,
        "receipt_refs": unique_refs(correlation.receipt_refs.clone())
    })
}

pub(super) fn content_document(
    content_ref: &EntityRef,
    observation_ref: &EntityRef,
    digest: &Value,
    byte_size: u64,
    input: &MaterializeInput<'_>,
    verification_receipts: &[EntityRef],
) -> Value {
    let mut value = json!({
        "envelope": envelope(
            content_ref,
            CONTENT_SCHEMA_ID,
            1,
            input.workspace_ref,
            input.authority_ref,
            input.now,
            input.now,
        ),
        "content_contract_version": SCHEMA_VERSION,
        "canonical_digest": digest,
        "additional_digests": [],
        "byte_size": byte_size,
        "content_encoding": "raw",
        "deduplication_scope": input.deduplication_scope,
        "hash_observation_refs": [observation_ref],
        "verification_receipt_refs": verification_receipts,
        "limitations": [],
        "extensions": {}
    });
    let object = value.as_object_mut().expect("Content document must be object");
    if let Some(reference) = input.deduplication_scope_ref {
        object.insert("deduplication_scope_ref".to_owned(), json!(reference));
    }
    if let Some(media_type) = input.media_type_claim {
        object.insert("media_type_claim".to_owned(), json!(media_type));
    }
    value
}

pub(super) fn hash_observation_document(
    observation_ref: &EntityRef,
    content_ref: &EntityRef,
    digest: &Value,
    byte_size: u64,
    producer_ref: &EntityRef,
    producer_version: &str,
    correlation: &ProductionCorrelation,
    authority_ref: &EntityRef,
    workspace_ref: &EntityRef,
    now: &str,
) -> Value {
    json!({
        "envelope": envelope(
            observation_ref,
            HASH_OBSERVATION_SCHEMA_ID,
            1,
            workspace_ref,
            authority_ref,
            now,
            now,
        ),
        "observation_contract_version": SCHEMA_VERSION,
        "subject_ref": content_ref,
        "qualified_digest": digest,
        "observed_size": byte_size,
        "outcome": "verified",
        "producer_ref": producer_ref,
        "producer_version": producer_version,
        "observed_at": now,
        "production_correlation": production_correlation(correlation),
        "receipt_refs": unique_refs(correlation.receipt_refs.clone()),
        "limitations": [],
        "extensions": {}
    })
}
