use crate::{
    DecompositionClock, DecompositionError, DecompositionPlan, DecompositionSpec,
    PersistedDecomposition,
};
use ptah_identifiers::EntityRef;
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger};
use ptah_object_store::{
    CONTENT_SCHEMA_ID, ObjectStore, OriginClass, REVISION_SCHEMA_ID, RegisterObjectSpec,
    Registration, RelationshipSpec, RevisionRole, ViewSpec,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

/// Frozen A12 Decomposition Run schema.
pub const DECOMPOSITION_RUN_SCHEMA_ID: &str = "urn:ptah:schema:object:decomposition-run:0.1.0";
const DECOMPOSITION_RUN_KIND: &str = "object.decomposition_run";
const OPERATION_SCHEMA_ID: &str = "urn:ptah:schema:activity:operation:0.1.0";
const ATTEMPT_SCHEMA_ID: &str = "urn:ptah:schema:activity:attempt:0.1.0";
const A12_VERSION: &str = "0.1.0";

/// A12 canonical-persistence boundary over one A03 ledger.
pub struct DecompositionStore {
    ledger_path: PathBuf,
    clock: DecompositionClock,
}

impl DecompositionStore {
    /// Create an A12 persistence boundary over the same A03 ledger used by A07.
    #[must_use]
    pub fn new(ledger_path: impl AsRef<Path>, clock: DecompositionClock) -> Self {
        Self {
            ledger_path: ledger_path.as_ref().to_path_buf(),
            clock,
        }
    }

    /// Persist one already-reviewed decomposition plan through A07 and A03.
    ///
    /// Child Objects, immediate-container Relationships, and the inventory View
    /// are retained before the Decomposition Run. The Run is always the final
    /// canonical write so an interrupted persistence sequence cannot leave a
    /// false complete-run claim.
    ///
    /// # Errors
    /// Fails when source bytes no longer match the exact source Revision,
    /// production evidence does not target that Revision, A07 refuses child/View
    /// registration, or the final canonical Run cannot be retained.
    #[allow(clippy::needless_pass_by_value)]
    pub fn persist(
        &self,
        object_store: &mut ObjectStore,
        source_bytes: &[u8],
        spec: DecompositionSpec,
        plan: DecompositionPlan,
    ) -> Result<PersistedDecomposition, DecompositionError> {
        if plan.source_revision_ref != spec.source_revision_ref {
            return Err(DecompositionError::SourceMismatch);
        }
        let ledger = Ledger::open(&self.ledger_path)?;
        let source = validate_source(&ledger, source_bytes, &spec)?;
        ensure_operation_targets_source(&ledger, &spec)?;

        let mut registered_by_inventory: HashMap<usize, Registration> = HashMap::new();
        let mut child_object_refs = Vec::new();
        let mut relationship_refs = Vec::new();

        for member in &plan.recovered_members {
            let (parent_object_ref, source_ref) = match member.parent_inventory_index {
                Some(parent_index) => {
                    let parent = registered_by_inventory
                        .get(&parent_index)
                        .ok_or(DecompositionError::SourceMismatch)?;
                    (parent.object_ref.clone(), parent.revision_ref.clone())
                }
                None => (source.object_ref.clone(), spec.source_revision_ref.clone()),
            };
            let registration = object_store.register_bytes(
                &member.bytes,
                RegisterObjectSpec {
                    workspace_ref: spec.workspace_ref.clone(),
                    authority_ref: spec.authority_ref.clone(),
                    object_class: "archive_member".to_owned(),
                    declared_name: Some(member.logical_path.clone()),
                    source_refs: vec![source_ref],
                    revision_role: RevisionRole::Recovered,
                    origin_class: OriginClass::RecoveredEmbeddedSource,
                    created_reason: format!("A12 recovered archive member {}", member.logical_path),
                    production: spec.production.clone(),
                    expected_sha256: Some(member.member_sha256.clone()),
                },
            )?;
            let relationship_ref = object_store.create_relationship(RelationshipSpec {
                workspace_ref: spec.workspace_ref.clone(),
                authority_ref: spec.authority_ref.clone(),
                subject_refs: vec![parent_object_ref],
                relationship_type: "contains_archive_member".to_owned(),
                object_refs: vec![registration.object_ref.clone()],
                production: spec.production.clone(),
            })?;
            child_object_refs.push(registration.object_ref.clone());
            relationship_refs.push(relationship_ref);
            registered_by_inventory.insert(member.inventory_index, registration);
        }

        let inventory_view_ref = object_store.create_view(ViewSpec {
            workspace_ref: spec.workspace_ref.clone(),
            authority_ref: spec.authority_ref.clone(),
            view_kind: "archive_inventory".to_owned(),
            view_schema_id: DECOMPOSITION_RUN_SCHEMA_ID.to_owned(),
            view_schema_version: A12_VERSION.to_owned(),
            source_revision_refs: vec![spec.source_revision_ref.clone()],
            origin_class: OriginClass::Generated,
            production: spec.production.clone(),
        })?;

        let run_ref = EntityRef::new(DECOMPOSITION_RUN_KIND)?;
        let now = self.now()?;
        let attempt = ledger
            .latest_record(spec.production.attempt_ref.entity_id)?
            .ok_or(DecompositionError::SourceMismatch)?;
        if attempt.schema_id() != ATTEMPT_SCHEMA_ID {
            return Err(DecompositionError::SourceMismatch);
        }
        let document = run_document(
            &run_ref,
            &spec,
            &plan,
            &inventory_view_ref,
            &child_object_refs,
            &relationship_refs,
            attempt.document(),
            &now,
        )?;
        let record = CanonicalRecord::from_document(document)?;
        let mut run_ledger = Ledger::open(&self.ledger_path)?;
        let write = run_ledger.begin_write()?;
        write.insert(&record)?;
        write.commit()?;

        Ok(PersistedDecomposition {
            run_ref,
            inventory_view_ref,
            child_object_refs,
            relationship_refs,
        })
    }

    fn now(&self) -> Result<String, DecompositionError> {
        let value = (self.clock)();
        require_utc_datetime(&value)?;
        Ok(value)
    }
}

struct SourceBinding {
    object_ref: EntityRef,
}

fn validate_source(
    ledger: &Ledger,
    source_bytes: &[u8],
    spec: &DecompositionSpec,
) -> Result<SourceBinding, DecompositionError> {
    if spec.source_revision_ref.entity_kind.as_str() != "object.revision" {
        return Err(DecompositionError::SourceMismatch);
    }
    let revision = ledger
        .latest_record(spec.source_revision_ref.entity_id)?
        .ok_or(DecompositionError::SourceMismatch)?;
    if revision.schema_id() != REVISION_SCHEMA_ID
        || !document_in_workspace(revision.document(), &spec.workspace_ref)?
    {
        return Err(DecompositionError::SourceMismatch);
    }
    let content_ref = field_ref(revision.document(), "content_ref")?;
    let object_ref = field_ref(revision.document(), "object_ref")?;
    let content = ledger
        .latest_record(content_ref.entity_id)?
        .ok_or(DecompositionError::SourceMismatch)?;
    if content.schema_id() != CONTENT_SCHEMA_ID
        || !document_in_workspace(content.document(), &spec.workspace_ref)?
    {
        return Err(DecompositionError::SourceMismatch);
    }
    let expected_digest = content
        .document()
        .get("canonical_digest")
        .and_then(|value| value.get("digest"))
        .and_then(Value::as_str)
        .ok_or(DecompositionError::TypeMismatch)?;
    let expected_size = content
        .document()
        .get("byte_size")
        .and_then(Value::as_u64)
        .ok_or(DecompositionError::TypeMismatch)?;
    let observed_size =
        u64::try_from(source_bytes.len()).map_err(|_| DecompositionError::AccountingOverflow)?;
    if expected_size != observed_size || expected_digest != sha256(source_bytes) {
        return Err(DecompositionError::SourceMismatch);
    }
    Ok(SourceBinding { object_ref })
}

fn ensure_operation_targets_source(
    ledger: &Ledger,
    spec: &DecompositionSpec,
) -> Result<(), DecompositionError> {
    let operation = ledger
        .latest_record(spec.production.operation_ref.entity_id)?
        .ok_or(DecompositionError::SourceMismatch)?;
    if operation.schema_id() != OPERATION_SCHEMA_ID
        || !document_in_workspace(operation.document(), &spec.workspace_ref)?
        || envelope_authority(operation.document())? != spec.authority_ref
    {
        return Err(DecompositionError::SourceMismatch);
    }
    let targets: Vec<EntityRef> = serde_json::from_value(
        operation
            .document()
            .get("logical_target_refs")
            .cloned()
            .ok_or(DecompositionError::TypeMismatch)?,
    )?;
    if !targets
        .iter()
        .any(|reference| reference == &spec.source_revision_ref)
    {
        return Err(DecompositionError::SourceMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_document(
    run_ref: &EntityRef,
    spec: &DecompositionSpec,
    plan: &DecompositionPlan,
    inventory_view_ref: &EntityRef,
    child_object_refs: &[EntityRef],
    relationship_refs: &[EntityRef],
    attempt: &Value,
    now: &str,
) -> Result<Value, DecompositionError> {
    let complete = plan.outcome.is_complete();
    let coverage_class = if complete {
        "complete"
    } else if plan.processed_members > 0 {
        "partial"
    } else {
        "none"
    };
    let unknown_locators = plan
        .unknown_gaps
        .iter()
        .map(|gap| json!({"locator_kind":"unknown","identifier": bounded(gap, 4096)}))
        .collect::<Vec<_>>();
    let inventory = plan
        .inventory
        .iter()
        .map(|entry| {
            json!({
                "logical_path": entry.logical_path,
                "kind": entry.kind.as_str(),
                "depth": entry.depth,
                "container_sha256": entry.container_sha256,
                "member_sha256": entry.member_sha256,
                "byte_size": entry.byte_size
            })
        })
        .collect::<Vec<_>>();
    let correlation = json!({
        "activity_ref": spec.production.activity_ref,
        "operation_ref": spec.production.operation_ref,
        "attempt_ref": spec.production.attempt_ref,
        "receipt_refs": unique_refs(&spec.production.receipt_refs),
        "facility_ref": field_ref(attempt, "facility_ref")?,
        "provider_ref": field_ref(attempt, "provider_ref")?,
        "node_ref": field_ref(attempt, "node_ref")?
    });
    Ok(json!({
        "envelope": envelope(run_ref, &spec.workspace_ref, &spec.authority_ref, now),
        "run_contract_version": A12_VERSION,
        "source_revision_ref": spec.source_revision_ref,
        "requested_level": spec.requested_level,
        "achieved_level": plan.achieved_level,
        "outcome": plan.outcome.as_str(),
        "production_correlation": correlation,
        "coverage": {
            "coverage_class": coverage_class,
            "complete_claim": complete,
            "processed_units": plan.processed_members,
            "processed_bytes": plan.processed_bytes,
            "skipped_scope": [],
            "unknown_gaps": unknown_locators,
            "limitations": bounded_list(&plan.limitations)
        },
        "budget_request": {
            "max_depth": plan.budget_request.max_depth,
            "max_members": plan.budget_request.max_members,
            "max_expanded_bytes": plan.budget_request.max_expanded_bytes,
            "max_member_bytes": plan.budget_request.max_member_bytes,
            "max_path_chars": plan.budget_request.max_path_chars
        },
        "budget_usage": {
            "processed_members": plan.processed_members,
            "processed_bytes": plan.processed_bytes,
            "maximum_depth_observed": plan.inventory.iter().map(|entry| entry.depth).max().unwrap_or(0)
        },
        "child_object_refs": unique_refs(child_object_refs),
        "view_refs": [inventory_view_ref],
        "preview_refs": [],
        "derivative_refs": [],
        "relationship_refs": unique_refs(relationship_refs),
        "unknown_gap_locators": unknown_locators,
        "warnings": bounded_list(&plan.warnings),
        "limitations": bounded_list(&plan.limitations),
        "extensions": {
            "ptah.a12.archive": {
                "schema_id": "urn:ptah:extension:a12:archive-decomposition",
                "schema_version": A12_VERSION,
                "value": {
                    "decomposition_identity": plan.decomposition_identity,
                    "backend": {
                        "provider_ref": plan.backend.provider_ref,
                        "provider_generation": plan.backend.provider_generation,
                        "implementation": plan.backend.implementation,
                        "implementation_version": plan.backend.implementation_version,
                        "source_sha256": plan.backend.source_sha256,
                        "executable_sha256": plan.backend.executable_sha256
                    },
                    "inventory": inventory,
                    "safe_materialization": "a07_local_cas_only"
                }
            }
        }
    }))
}

fn envelope(
    run_ref: &EntityRef,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    now: &str,
) -> Value {
    json!({
        "entity_id": run_ref.entity_id,
        "entity_kind": run_ref.entity_kind,
        "schema_id": DECOMPOSITION_RUN_SCHEMA_ID,
        "schema_version": A12_VERSION,
        "record_revision": 1,
        "created_at": now,
        "updated_at": now,
        "workspace_ref": workspace_ref,
        "authority_ref": authority_ref,
        "privacy_class": "internal",
        "audience": "workspace",
        "redaction_policy": "none",
        "retention_policy": {
            "policy_id": "ptah.a12.decomposition",
            "policy_version": A12_VERSION,
            "retention_class": "historical",
            "delete_bytes_when_unreferenced": false
        },
        "extensions": {}
    })
}

fn field_ref(document: &Value, field: &'static str) -> Result<EntityRef, DecompositionError> {
    Ok(serde_json::from_value(
        document
            .get(field)
            .cloned()
            .ok_or(DecompositionError::TypeMismatch)?,
    )?)
}

fn document_in_workspace(
    document: &Value,
    workspace_ref: &EntityRef,
) -> Result<bool, DecompositionError> {
    let envelope = document
        .get("envelope")
        .and_then(Value::as_object)
        .ok_or(DecompositionError::TypeMismatch)?;
    let retained: EntityRef = serde_json::from_value(
        envelope
            .get("workspace_ref")
            .cloned()
            .ok_or(DecompositionError::TypeMismatch)?,
    )?;
    Ok(retained == *workspace_ref)
}

fn envelope_authority(document: &Value) -> Result<EntityRef, DecompositionError> {
    let envelope = document
        .get("envelope")
        .and_then(Value::as_object)
        .ok_or(DecompositionError::TypeMismatch)?;
    Ok(serde_json::from_value(
        envelope
            .get("authority_ref")
            .cloned()
            .ok_or(DecompositionError::TypeMismatch)?,
    )?)
}

fn unique_refs(refs: &[EntityRef]) -> Vec<EntityRef> {
    let mut result = Vec::new();
    for reference in refs {
        if !result.iter().any(|item| item == reference) {
            result.push(reference.clone());
        }
    }
    result
}

fn bounded_list(values: &[String]) -> Vec<String> {
    values.iter().map(|value| bounded(value, 4096)).collect()
}

fn bounded(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn require_utc_datetime(value: &str) -> Result<(), DecompositionError> {
    let Some(without_z) = value.strip_suffix('Z') else {
        return Err(DecompositionError::InvalidTimestamp);
    };
    let Some(separator) = without_z.find(['T', 't']) else {
        return Err(DecompositionError::InvalidTimestamp);
    };
    let (date, time_with_separator) = without_z.split_at(separator);
    let time = &time_with_separator[1..];
    if date.len() != 10
        || date.as_bytes().get(4) != Some(&b'-')
        || date.as_bytes().get(7) != Some(&b'-')
        || time.len() < 8
        || time.as_bytes().get(2) != Some(&b':')
        || time.as_bytes().get(5) != Some(&b':')
    {
        return Err(DecompositionError::InvalidTimestamp);
    }
    let year = parse_decimal(&date[0..4])?;
    let month = parse_decimal(&date[5..7])?;
    let day = parse_decimal(&date[8..10])?;
    let clock = time
        .split('.')
        .next()
        .ok_or(DecompositionError::InvalidTimestamp)?;
    if clock.len() != 8 {
        return Err(DecompositionError::InvalidTimestamp);
    }
    let hour = parse_decimal(&clock[0..2])?;
    let minute = parse_decimal(&clock[3..5])?;
    let second = parse_decimal(&clock[6..8])?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(DecompositionError::InvalidTimestamp);
    }
    Ok(())
}

fn parse_decimal(value: &str) -> Result<u32, DecompositionError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DecompositionError::InvalidTimestamp);
    }
    value
        .parse()
        .map_err(|_| DecompositionError::InvalidTimestamp)
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}
