use super::*;
use super::documents_model::*;
use super::documents_support::*;

pub(super) fn location_document(
    location_ref: &EntityRef,
    content_ref: &EntityRef,
    observation_ref: &EntityRef,
    relative_path: &str,
    byte_size: u64,
    input: &MaterializeInput<'_>,
) -> Value {
    json!({
        "envelope": envelope(
            location_ref,
            LOCATION_SCHEMA_ID,
            1,
            input.workspace_ref,
            input.authority_ref,
            input.now,
            input.now,
        ),
        "location_contract_version": SCHEMA_VERSION,
        "content_ref": content_ref,
        "location_kind": "local_cas",
        "replica_role": "primary",
        "backend_ref": input.backend_ref,
        "connection_ref": input.connection_ref,
        "backend_aliases": [{"alias_kind": CAS_BACKEND_ALIAS_KIND, "alias_value": relative_path}],
        "stored_size_claim": byte_size,
        "provider_digest_claims": [],
        "lifecycle": state_projection("storage.location.lifecycle", "available", 1),
        "health_state": "healthy",
        "verification_state": "unverified",
        "last_observed_at": input.now,
        "observation_refs": [observation_ref],
        "verification_refs": [],
        "receipt_refs": unique_refs(input.production_correlation.receipt_refs.clone()),
        "limitations": [],
        "extensions": {}
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn location_observation_document(
    observation_ref: &EntityRef,
    location_ref: &EntityRef,
    lifecycle: &str,
    health: &str,
    observed_size: Option<u64>,
    observed_digest: Option<&Value>,
    observer_ref: &EntityRef,
    observer_version: &str,
    receipt_refs: &[EntityRef],
    authority_ref: &EntityRef,
    workspace_ref: &EntityRef,
    now: &str,
) -> Value {
    let provider_digest_claims =
        observed_digest.map_or_else(Vec::new, |digest| vec![digest.clone()]);
    json!({
        "envelope": envelope(
            observation_ref,
            LOCATION_OBSERVATION_SCHEMA_ID,
            1,
            workspace_ref,
            authority_ref,
            now,
            now,
        ),
        "observation_contract_version": SCHEMA_VERSION,
        "location_ref": location_ref,
        "observed_lifecycle_state": lifecycle,
        "observed_health_state": health,
        "provider_aliases": [],
        "observed_size": observed_size,
        "provider_digest_claims": provider_digest_claims,
        "observer_ref": observer_ref,
        "observer_version": observer_version,
        "observed_at": now,
        "receipt_refs": unique_refs(receipt_refs.to_vec()),
        "limitations": [],
        "extensions": {}
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn revision_document(
    revision_ref: &EntityRef,
    object_ref: &EntityRef,
    revision_number: u64,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    revision_role: RevisionRole,
    origin_class: OriginClass,
    source_refs: &[EntityRef],
    content_ref: &EntityRef,
    correlation: &ProductionCorrelation,
    created_reason: &str,
    verification_receipt_refs: &[EntityRef],
    now: &str,
) -> Value {
    json!({
        "envelope": envelope(
            revision_ref,
            REVISION_SCHEMA_ID,
            1,
            workspace_ref,
            authority_ref,
            now,
            now,
        ),
        "revision_contract_version": SCHEMA_VERSION,
        "object_ref": object_ref,
        "revision_number": revision_number,
        "revision_role": revision_role,
        "origin_class": origin_class,
        "parent_revision_refs": [],
        "content_ref": content_ref,
        "source_refs": unique_refs(source_refs.to_vec()),
        "production_correlation": production_correlation(correlation),
        "created_reason": created_reason,
        "verification_receipt_refs": unique_refs(verification_receipt_refs.to_vec()),
        "limitations": [],
        "extensions": {}
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn object_document(
    object_ref: &EntityRef,
    revision_ref: &EntityRef,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    object_class: &str,
    declared_names: &[DeclaredName],
    source_refs: &[EntityRef],
    now: &str,
) -> Value {
    json!({
        "envelope": envelope(
            object_ref,
            OBJECT_SCHEMA_ID,
            1,
            workspace_ref,
            authority_ref,
            now,
            now,
        ),
        "object_contract_version": SCHEMA_VERSION,
        "object_class": object_class,
        "declared_names": declared_names,
        "source_refs": unique_refs(source_refs.to_vec()),
        "current_revision_ref": revision_ref,
        "revision_refs": [revision_ref],
        "relationship_refs": [],
        "view_refs": [],
        "artifact_refs": [],
        "lifecycle": state_projection("object.lifecycle", "active", 0),
        "limitations": [],
        "extensions": {}
    })
}

pub(super) fn relationship_document(
    relationship_ref: &EntityRef,
    revision_ref: &EntityRef,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    now: &str,
) -> Value {
    json!({
        "envelope": envelope(
            relationship_ref,
            RELATIONSHIP_SCHEMA_ID,
            1,
            workspace_ref,
            authority_ref,
            now,
            now,
        ),
        "relationship_contract_version": SCHEMA_VERSION,
        "current_revision_ref": revision_ref,
        "revision_refs": [revision_ref],
        "lifecycle": state_projection("relationship.lifecycle", "active", 0),
        "limitations": [],
        "extensions": {}
    })
}

pub(super) fn relationship_revision_document(
    revision_ref: &EntityRef,
    relationship_ref: &EntityRef,
    input: &CreateRelationship,
    now: &str,
) -> Value {
    let mut value = json!({
        "envelope": envelope(
            revision_ref,
            RELATIONSHIP_REVISION_SCHEMA_ID,
            1,
            &input.workspace_ref,
            &input.authority_ref,
            now,
            now,
        ),
        "relationship_revision_contract_version": SCHEMA_VERSION,
        "relationship_ref": relationship_ref,
        "revision_number": 1,
        "subject_refs": unique_refs(input.subject_refs.clone()),
        "relationship_type": input.relationship_type,
        "object_refs": unique_refs(input.object_refs.clone()),
        "locators": input.locators,
        "coverage": input.coverage,
        "production_correlation": production_correlation(&input.production_correlation),
        "confidence_class": input.confidence_class,
        "limitations": [],
        "extensions": {}
    });
    if let Some(direction) = &input.direction_class {
        value
            .as_object_mut()
            .expect("Relationship Revision document must be object")
            .insert("direction_class".to_owned(), json!(direction));
    }
    value
}

pub(super) fn artifact_document(
    artifact_ref: &EntityRef,
    input: &PromoteArtifact,
    now: &str,
) -> Value {
    json!({
        "envelope": envelope(
            artifact_ref,
            ARTIFACT_SCHEMA_ID,
            1,
            &input.workspace_ref,
            &input.authority_ref,
            now,
            now,
        ),
        "artifact_contract_version": SCHEMA_VERSION,
        "artifact_type": input.artifact_type,
        "artifact_version": input.artifact_version,
        "purpose": input.purpose,
        "subject_refs": unique_refs(input.subject_refs.clone()),
        "promoted_revision_refs": unique_refs(input.promoted_revision_refs.clone()),
        "production_correlation": production_correlation(&input.production_correlation),
        "promotion_receipt_refs": unique_refs(input.production_correlation.receipt_refs.clone()),
        "lifecycle": state_projection("artifact.lifecycle", "promoted", 1),
        "verification_projection": "not_requested",
        "review_projection": "not_requested",
        "acceptance_projection": "not_requested",
        "provenance_refs": unique_refs(input.provenance_refs.clone()),
        "sbom_refs": [],
        "signature_or_attestation_refs": [],
        "reproduction_refs": [],
        "release_refs": [],
        "limitations": [],
        "extensions": {}
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn storage_verification_document(
    verification_ref: &EntityRef,
    content_ref: &EntityRef,
    location_ref: &EntityRef,
    expected_digest: &Value,
    expected_size: u64,
    observed_digest: Option<&Value>,
    observed_size: Option<u64>,
    outcome: &str,
    input: &VerifyLocation,
    workspace_ref: &EntityRef,
    now: &str,
) -> Value {
    json!({
        "envelope": envelope(
            verification_ref,
            STORAGE_VERIFICATION_SCHEMA_ID,
            1,
            workspace_ref,
            &input.authority_ref,
            now,
            now,
        ),
        "verification_contract_version": SCHEMA_VERSION,
        "content_ref": content_ref,
        "location_ref": location_ref,
        "expected_digest": expected_digest,
        "expected_size": expected_size,
        "observed_digest": observed_digest,
        "observed_size": observed_size,
        "outcome": outcome,
        "verifier_ref": input.verifier_ref,
        "verifier_version": input.verifier_version,
        "verified_at": now,
        "production_correlation": production_correlation(&input.production_correlation),
        "receipt_refs": unique_refs(input.production_correlation.receipt_refs.clone()),
        "limitations": [],
        "extensions": {}
    })
}
