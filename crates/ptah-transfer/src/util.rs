use crate::{A08_SCHEMA_VERSION, TransferConfig, TransferError, TransferEvidence};
use ptah_identifiers::{EntityId, EntityRef};
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger};
use serde_json::{Value, json};
use std::collections::HashSet;

pub(crate) const ACTIVITY_SCHEMA_ID: &str = "urn:ptah:schema:activity:activity:0.1.0";
pub(crate) const OPERATION_SCHEMA_ID: &str = "urn:ptah:schema:activity:operation:0.1.0";
pub(crate) const ATTEMPT_SCHEMA_ID: &str = "urn:ptah:schema:activity:attempt:0.1.0";
pub(crate) const RECEIPT_SCHEMA_ID: &str = "urn:ptah:schema:activity:receipt:0.1.0";
pub(crate) const CONTENT_SCHEMA_ID: &str = "urn:ptah:schema:object:content:0.1.0";
pub(crate) const REVISION_SCHEMA_ID: &str = "urn:ptah:schema:object:revision:0.1.0";
pub(crate) const LOCATION_SCHEMA_ID: &str = "urn:ptah:schema:storage:location:0.1.0";

const ACTIVITY_KIND: &str = "core.activity";
const OPERATION_KIND: &str = "core.operation";
const ATTEMPT_KIND: &str = "core.attempt";
const RECEIPT_KIND: &str = "proof.receipt";

#[derive(Debug, Clone)]
pub(crate) struct ValidatedExecution {
    pub(crate) activity_ref: EntityRef,
    pub(crate) operation_ref: EntityRef,
    pub(crate) attempt_ref: EntityRef,
    pub(crate) receipt_refs: Vec<EntityRef>,
    pub(crate) correlation_nonce: String,
    pub(crate) provider_ref: EntityRef,
    pub(crate) provider_instance_ref: EntityRef,
    pub(crate) provider_generation: u64,
    pub(crate) connection_epoch: u64,
}

pub(crate) fn latest_document(
    ledger: &Ledger,
    entity_id: EntityId,
    expected_schema: &str,
) -> Result<Value, TransferError> {
    let record = ledger
        .latest_record(entity_id)?
        .ok_or(TransferError::NotFound(entity_id))?;
    if record.schema_id() != expected_schema {
        return Err(TransferError::TypeMismatch);
    }
    Ok(record.document().clone())
}

pub(crate) fn write_documents(
    ledger: &mut Ledger,
    documents: &[Value],
) -> Result<(), TransferError> {
    let records = documents
        .iter()
        .cloned()
        .map(CanonicalRecord::from_document)
        .collect::<Result<Vec<_>, _>>()?;
    let write = ledger.begin_write()?;
    for record in &records {
        write.insert(record)?;
    }
    write.commit()?;
    Ok(())
}

pub(crate) fn envelope(
    reference: &EntityRef,
    schema_id: &str,
    revision: u64,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    now: &str,
) -> Value {
    json!({
        "entity_id": reference.entity_id,
        "entity_kind": reference.entity_kind,
        "schema_id": schema_id,
        "schema_version": A08_SCHEMA_VERSION,
        "record_revision": revision,
        "created_at": now,
        "updated_at": now,
        "workspace_ref": workspace_ref,
        "authority_ref": authority_ref,
        "privacy_class": "internal",
        "audience": "workspace",
        "redaction_policy": "none",
        "retention_policy": {
            "policy_id": "ptah.a08.transfer",
            "policy_version": A08_SCHEMA_VERSION,
            "retention_class": "historical",
            "delete_bytes_when_unreferenced": false
        },
        "extensions": {}
    })
}

pub(crate) fn state_projection(name: &str, state: &str, sequence: u64) -> Value {
    json!({
        "state_machine_name": name,
        "state_machine_version": A08_SCHEMA_VERSION,
        "current_state": state,
        "state_sequence": sequence
    })
}

pub(crate) fn document_ref(document: &Value) -> Result<EntityRef, TransferError> {
    let envelope = document
        .get("envelope")
        .ok_or(TransferError::TypeMismatch)?;
    Ok(serde_json::from_value(json!({
        "entity_id": envelope.get("entity_id").ok_or(TransferError::TypeMismatch)?,
        "entity_kind": envelope.get("entity_kind").ok_or(TransferError::TypeMismatch)?
    }))?)
}

pub(crate) fn field_ref(document: &Value, field: &str) -> Result<EntityRef, TransferError> {
    Ok(serde_json::from_value(
        document
            .get(field)
            .cloned()
            .ok_or(TransferError::TypeMismatch)?,
    )?)
}

pub(crate) fn field_refs(document: &Value, field: &str) -> Result<Vec<EntityRef>, TransferError> {
    Ok(serde_json::from_value(
        document
            .get(field)
            .cloned()
            .ok_or(TransferError::TypeMismatch)?,
    )?)
}

pub(crate) fn field_string<'a>(document: &'a Value, field: &str) -> Result<&'a str, TransferError> {
    document
        .get(field)
        .and_then(Value::as_str)
        .ok_or(TransferError::TypeMismatch)
}

pub(crate) fn field_u64(document: &Value, field: &str) -> Result<u64, TransferError> {
    document
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(TransferError::TypeMismatch)
}

pub(crate) fn ensure_workspace(
    document: &Value,
    expected: &EntityRef,
) -> Result<(), TransferError> {
    let envelope = document
        .get("envelope")
        .ok_or(TransferError::TypeMismatch)?;
    let workspace: EntityRef = serde_json::from_value(
        envelope
            .get("workspace_ref")
            .cloned()
            .ok_or(TransferError::WorkspaceMismatch)?,
    )?;
    if !same_ref(&workspace, expected) {
        return Err(TransferError::WorkspaceMismatch);
    }
    Ok(())
}

pub(crate) fn envelope_authority(document: &Value) -> Result<EntityRef, TransferError> {
    let envelope = document
        .get("envelope")
        .ok_or(TransferError::TypeMismatch)?;
    Ok(serde_json::from_value(
        envelope
            .get("authority_ref")
            .cloned()
            .ok_or(TransferError::AuthorityMismatch)?,
    )?)
}

pub(crate) fn same_ref(left: &EntityRef, right: &EntityRef) -> bool {
    left.entity_id == right.entity_id && left.entity_kind == right.entity_kind
}

pub(crate) fn unique_refs(refs: impl IntoIterator<Item = EntityRef>) -> Vec<EntityRef> {
    let mut seen = HashSet::new();
    refs.into_iter()
        .filter(|reference| seen.insert((reference.entity_id, reference.entity_kind.clone())))
        .collect()
}

pub(crate) fn append_ref(
    document: &mut Value,
    field: &str,
    reference: EntityRef,
) -> Result<(), TransferError> {
    let array = document
        .get_mut(field)
        .and_then(Value::as_array_mut)
        .ok_or(TransferError::TypeMismatch)?;
    let existing: Vec<EntityRef> = serde_json::from_value(Value::Array(array.clone()))?;
    if !existing.iter().any(|item| same_ref(item, &reference)) {
        array.push(serde_json::to_value(reference)?);
    }
    Ok(())
}

pub(crate) fn bump(document: &mut Value, now: &str) -> Result<u64, TransferError> {
    let envelope = document
        .get_mut("envelope")
        .and_then(Value::as_object_mut)
        .ok_or(TransferError::TypeMismatch)?;
    let current = envelope
        .get("record_revision")
        .and_then(Value::as_u64)
        .ok_or(TransferError::TypeMismatch)?;
    let next = current
        .checked_add(1)
        .ok_or(TransferError::AccountingOverflow)?;
    envelope.insert("record_revision".to_owned(), json!(next));
    envelope.insert("updated_at".to_owned(), json!(now));
    Ok(next)
}

pub(crate) fn set_lifecycle(
    document: &mut Value,
    state: &str,
    now: &str,
) -> Result<(), TransferError> {
    let lifecycle = document
        .get_mut("lifecycle")
        .and_then(Value::as_object_mut)
        .ok_or(TransferError::TypeMismatch)?;
    let sequence = lifecycle
        .get("state_sequence")
        .and_then(Value::as_u64)
        .ok_or(TransferError::TypeMismatch)?
        .checked_add(1)
        .ok_or(TransferError::AccountingOverflow)?;
    lifecycle.insert("current_state".to_owned(), json!(state));
    lifecycle.insert("state_sequence".to_owned(), json!(sequence));
    bump(document, now)?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn validate_execution(
    ledger: &Ledger,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    evidence: &TransferEvidence,
    required_receipt_kinds: &[&'static str],
    required_target: Option<&EntityRef>,
) -> Result<ValidatedExecution, TransferError> {
    require_kind(&evidence.activity_ref, ACTIVITY_KIND)?;
    require_kind(&evidence.operation_ref, OPERATION_KIND)?;
    require_kind(&evidence.attempt_ref, ATTEMPT_KIND)?;
    if evidence.receipt_refs.is_empty() {
        return Err(TransferError::ExecutionEvidenceMismatch);
    }
    if evidence
        .receipt_refs
        .iter()
        .any(|reference| reference.entity_kind.as_str() != RECEIPT_KIND)
    {
        return Err(TransferError::ExecutionEvidenceMismatch);
    }

    let activity = latest_document(ledger, evidence.activity_ref.entity_id, ACTIVITY_SCHEMA_ID)?;
    let operation = latest_document(
        ledger,
        evidence.operation_ref.entity_id,
        OPERATION_SCHEMA_ID,
    )?;
    let attempt = latest_document(ledger, evidence.attempt_ref.entity_id, ATTEMPT_SCHEMA_ID)?;
    ensure_workspace(&activity, workspace_ref)?;
    ensure_workspace(&operation, workspace_ref)?;
    ensure_workspace(&attempt, workspace_ref)?;
    if !same_ref(&envelope_authority(&activity)?, authority_ref)
        || !same_ref(&envelope_authority(&operation)?, authority_ref)
        || !same_ref(&envelope_authority(&attempt)?, authority_ref)
    {
        return Err(TransferError::AuthorityMismatch);
    }
    if !same_ref(
        &field_ref(&operation, "activity_ref")?,
        &evidence.activity_ref,
    ) || !same_ref(
        &field_ref(&attempt, "operation_ref")?,
        &evidence.operation_ref,
    ) {
        return Err(TransferError::ExecutionEvidenceMismatch);
    }
    if let Some(target) = required_target {
        let targets = field_refs(&operation, "logical_target_refs")?;
        if !targets.iter().any(|reference| same_ref(reference, target)) {
            return Err(TransferError::ExecutionEvidenceMismatch);
        }
    }
    let state = attempt
        .get("lifecycle")
        .and_then(|value| value.get("current_state"))
        .and_then(Value::as_str)
        .ok_or(TransferError::ExecutionEvidenceMismatch)?;
    if !matches!(
        state,
        "dispatched" | "accepted" | "executing" | "waiting" | "completed"
    ) {
        return Err(TransferError::ExecutionEvidenceMismatch);
    }

    let attached = field_refs(&attempt, "receipt_refs")?;
    let mut found = HashSet::new();
    let context_fields = [
        "correlation_nonce",
        "node_ref",
        "node_generation",
        "provider_ref",
        "provider_generation",
        "workload_generation",
        "connection_epoch",
        "facility_ref",
        "producer_instance_ref",
        "producer_version",
    ];
    for receipt_ref in &evidence.receipt_refs {
        if !attached
            .iter()
            .any(|reference| same_ref(reference, receipt_ref))
        {
            return Err(TransferError::ExecutionEvidenceMismatch);
        }
        let receipt = latest_document(ledger, receipt_ref.entity_id, RECEIPT_SCHEMA_ID)?;
        if field_string(&receipt, "receipt_outcome")? != "positive"
            || !same_ref(
                &field_ref(&receipt, "activity_ref")?,
                &evidence.activity_ref,
            )
            || !same_ref(
                &field_ref(&receipt, "operation_ref")?,
                &evidence.operation_ref,
            )
            || !same_ref(&field_ref(&receipt, "attempt_ref")?, &evidence.attempt_ref)
        {
            return Err(TransferError::ExecutionEvidenceMismatch);
        }
        for field in context_fields {
            let Some(receipt_value) = receipt.get(field) else {
                return Err(TransferError::ExecutionEvidenceMismatch);
            };
            let Some(attempt_value) = attempt.get(field) else {
                return Err(TransferError::ExecutionEvidenceMismatch);
            };
            if receipt_value != attempt_value {
                return Err(TransferError::ExecutionEvidenceMismatch);
            }
        }
        found.insert(field_string(&receipt, "receipt_kind")?.to_owned());
    }
    for required in required_receipt_kinds {
        if !found.contains(*required) {
            return Err(TransferError::MissingReceiptKind(required));
        }
    }

    Ok(ValidatedExecution {
        activity_ref: evidence.activity_ref.clone(),
        operation_ref: evidence.operation_ref.clone(),
        attempt_ref: evidence.attempt_ref.clone(),
        receipt_refs: unique_refs(evidence.receipt_refs.clone()),
        correlation_nonce: field_string(&attempt, "correlation_nonce")?.to_owned(),
        provider_ref: field_ref(&attempt, "provider_ref")?,
        provider_instance_ref: field_ref(&attempt, "producer_instance_ref")?,
        provider_generation: field_u64(&attempt, "provider_generation")?,
        connection_epoch: field_u64(&attempt, "connection_epoch")?,
    })
}

fn require_kind(reference: &EntityRef, expected: &str) -> Result<(), TransferError> {
    if reference.entity_kind.as_str() != expected {
        return Err(TransferError::ExecutionEvidenceMismatch);
    }
    Ok(())
}

pub(crate) fn validate_config(config: &TransferConfig) -> Result<(), TransferError> {
    validate_key_token(&config.protocol_revision, "protocol_revision", 1, 256)?;
    validate_key_token(&config.producer_version, "producer_version", 1, 256)
}

pub(crate) fn validate_idempotency_key(value: &str) -> Result<(), TransferError> {
    if !(8..=512).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(TransferError::InvalidField("idempotency_key"));
    }
    Ok(())
}

pub(crate) fn validate_storage_class(value: &str) -> Result<(), TransferError> {
    if !(3..=128).contains(&value.len()) {
        return Err(TransferError::InvalidField("storage_class"));
    }
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
    {
        return Err(TransferError::InvalidField("storage_class"));
    }
    Ok(())
}

fn validate_key_token(
    value: &str,
    field: &'static str,
    min: usize,
    max: usize,
) -> Result<(), TransferError> {
    if !(min..=max).contains(&value.len()) || value.trim().is_empty() {
        return Err(TransferError::InvalidField(field));
    }
    Ok(())
}

mod path;
pub(crate) use path::*;
