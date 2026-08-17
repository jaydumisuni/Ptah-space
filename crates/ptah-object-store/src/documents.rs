fn hash_observation_document(
    observation_ref: &EntityRef,
    content_ref: &EntityRef,
    byte_size: usize,
    digest: &str,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    config: &ObjectStoreConfig,
    evidence: &ValidatedProduction,
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
        ),
        "observation_contract_version": A07_SCHEMA_VERSION,
        "subject_ref": content_ref,
        "qualified_digest": qualified_digest(digest, "whole_content"),
        "observed_size": byte_size,
        "outcome": "verified",
        "producer_ref": config.producer_ref,
        "producer_version": config.producer_version,
        "observed_at": now,
        "production_correlation": evidence.correlation,
        "receipt_refs": evidence.hash_receipt_refs,
        "limitations": [],
        "extensions": {}
    })
}

fn content_document(
    content_ref: &EntityRef,
    hash_observation_ref: &EntityRef,
    byte_size: usize,
    digest: &str,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    verification_receipt_refs: &[EntityRef],
    now: &str,
) -> Value {
    json!({
        "envelope": envelope(
            content_ref,
            CONTENT_SCHEMA_ID,
            1,
            workspace_ref,
            authority_ref,
            now,
        ),
        "content_contract_version": A07_SCHEMA_VERSION,
        "canonical_digest": qualified_digest(digest, "whole_content"),
        "additional_digests": [],
        "byte_size": byte_size,
        "content_encoding": "raw",
        "deduplication_scope": "workspace",
        "hash_observation_refs": [hash_observation_ref],
        "verification_receipt_refs": verification_receipt_refs,
        "collision_or_ambiguity_notes": [],
        "limitations": [],
        "extensions": {}
    })
}

fn revision_document(
    revision_ref: &EntityRef,
    object_ref: &EntityRef,
    content_ref: &EntityRef,
    spec: &RegisterObjectSpec,
    evidence: &ValidatedProduction,
    now: &str,
) -> Value {
    json!({
        "envelope": envelope(
            revision_ref,
            REVISION_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
        ),
        "revision_contract_version": A07_SCHEMA_VERSION,
        "object_ref": object_ref,
        "revision_number": 1,
        "revision_role": spec.revision_role.as_str(),
        "origin_class": spec.origin_class.as_str(),
        "parent_revision_refs": [],
        "content_ref": content_ref,
        "source_refs": unique_refs(spec.source_refs.clone()),
        "captured_metadata": {},
        "production_correlation": evidence.correlation,
        "created_reason": spec.created_reason,
        "verification_receipt_refs": evidence.hash_receipt_refs,
        "limitations": [],
        "extensions": {}
    })
}

fn object_document(
    object_ref: &EntityRef,
    revision_ref: &EntityRef,
    spec: &RegisterObjectSpec,
    now: &str,
) -> Value {
    let declared_names = spec.declared_name.as_ref().map_or_else(Vec::new, |name| {
        vec![json!({
            "name": name,
            "name_role": "original",
            "source_class": "caller"
        })]
    });
    json!({
        "envelope": envelope(
            object_ref,
            OBJECT_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
        ),
        "object_contract_version": A07_SCHEMA_VERSION,
        "object_class": spec.object_class,
        "declared_names": declared_names,
        "source_refs": unique_refs(spec.source_refs.clone()),
        "current_revision_ref": revision_ref,
        "revision_refs": [revision_ref],
        "relationship_refs": [],
        "view_refs": [],
        "artifact_refs": [],
        "lifecycle": lifecycle("object.lifecycle", "active", 1),
        "limitations": [],
        "extensions": {}
    })
}

#[allow(clippy::too_many_arguments)]
fn location_observation_document(
    observation_ref: &EntityRef,
    location_ref: &EntityRef,
    byte_size: usize,
    digest: &str,
    object_key: &str,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    config: &ObjectStoreConfig,
    receipt_refs: &[EntityRef],
    now: &str,
) -> Value {
    json!({
        "envelope": envelope(
            observation_ref,
            LOCATION_OBSERVATION_SCHEMA_ID,
            1,
            workspace_ref,
            authority_ref,
            now,
        ),
        "observation_contract_version": A07_SCHEMA_VERSION,
        "location_ref": location_ref,
        "observed_lifecycle_state": "available",
        "observed_health_state": "healthy",
        "provider_aliases": [{
            "alias_kind": "object_key",
            "alias_value": object_key
        }],
        "observed_size": byte_size,
        "provider_digest_claims": [qualified_digest(digest, "stored_representation")],
        "observer_ref": config.producer_ref,
        "observer_version": config.producer_version,
        "observed_at": now,
        "receipt_refs": receipt_refs,
        "limitations": [],
        "extensions": {}
    })
}

#[allow(clippy::too_many_arguments)]
fn location_document(
    location_ref: &EntityRef,
    content_ref: &EntityRef,
    observation_ref: &EntityRef,
    byte_size: usize,
    digest: &str,
    object_key: &str,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    config: &ObjectStoreConfig,
    receipt_refs: &[EntityRef],
    now: &str,
) -> Value {
    json!({
        "envelope": envelope(
            location_ref,
            LOCATION_SCHEMA_ID,
            1,
            workspace_ref,
            authority_ref,
            now,
        ),
        "location_contract_version": A07_SCHEMA_VERSION,
        "content_ref": content_ref,
        "location_kind": "local_cas",
        "replica_role": "primary",
        "backend_ref": config.backend_ref,
        "connection_ref": config.connection_ref,
        "backend_aliases": [{
            "alias_kind": "object_key",
            "alias_value": object_key
        }],
        "stored_size_claim": byte_size,
        "provider_digest_claims": [qualified_digest(digest, "stored_representation")],
        "lifecycle": lifecycle("storage.location.lifecycle", "available", 3),
        "health_state": "healthy",
        "verification_state": "unverified",
        "last_observed_at": now,
        "observation_refs": [observation_ref],
        "verification_refs": [],
        "repair_refs": [],
        "receipt_refs": receipt_refs,
        "limitations": [],
        "extensions": {}
    })
}

#[allow(clippy::too_many_arguments)]
fn artifact_document(
    artifact_ref: &EntityRef,
    revision_id: EntityId,
    subject_refs: &[EntityRef],
    spec: &ArtifactPromotionSpec,
    evidence: &ValidatedProduction,
    state: &str,
    state_sequence: u64,
    record_revision: u64,
    now: &str,
) -> Result<Value, ObjectStoreError> {
    let revision_ref = EntityRef::from_id(revision_id, REVISION_KIND)?;
    Ok(json!({
        "envelope": envelope(
            artifact_ref,
            ARTIFACT_SCHEMA_ID,
            record_revision,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
        ),
        "artifact_contract_version": A07_SCHEMA_VERSION,
        "artifact_type": spec.artifact_type,
        "artifact_version": spec.artifact_version,
        "purpose": spec.purpose,
        "subject_refs": unique_refs(subject_refs.to_vec()),
        "promoted_revision_refs": [revision_ref],
        "production_correlation": evidence.correlation,
        "promotion_receipt_refs": evidence.receipt_refs,
        "lifecycle": lifecycle("artifact.lifecycle", state, state_sequence),
        "verification_projection": "not_requested",
        "review_projection": "not_requested",
        "acceptance_projection": "not_requested",
        "release_eligibility": "not_evaluated",
        "provenance_refs": [],
        "sbom_refs": [],
        "signature_or_attestation_refs": [],
        "reproduction_refs": [],
        "release_refs": [],
        "limitations": [],
        "extensions": {}
    }))
}

#[allow(clippy::too_many_arguments)]
fn storage_verification_document(
    verification_ref: &EntityRef,
    content_ref: &EntityRef,
    location_ref: &EntityRef,
    expected_digest: &str,
    expected_size: u64,
    observed_digest: Option<&str>,
    observed_size: Option<u64>,
    outcome: &str,
    spec: &VerificationSpec,
    config: &ObjectStoreConfig,
    evidence: &ValidatedProduction,
    now: &str,
) -> Value {
    json!({
        "envelope": envelope(
            verification_ref,
            STORAGE_VERIFICATION_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
        ),
        "verification_contract_version": A07_SCHEMA_VERSION,
        "content_ref": content_ref,
        "location_ref": location_ref,
        "expected_digest": qualified_digest(expected_digest, "whole_content"),
        "expected_size": expected_size,
        "observed_digest": observed_digest.map(|digest| qualified_digest(digest, "whole_content")),
        "observed_size": observed_size,
        "outcome": outcome,
        "verifier_ref": config.producer_ref,
        "verifier_version": config.producer_version,
        "verified_at": now,
        "production_correlation": evidence.correlation,
        "receipt_refs": evidence.receipt_refs,
        "limitations": [],
        "extensions": {}
    })
}

#[allow(clippy::too_many_arguments)]
fn verification_location_observation_document(
    observation_ref: &EntityRef,
    location_ref: &EntityRef,
    observed_size: Option<u64>,
    observed_digest: Option<&str>,
    object_key: &str,
    health: &str,
    spec: &VerificationSpec,
    config: &ObjectStoreConfig,
    evidence: &ValidatedProduction,
    now: &str,
) -> Value {
    let digest_claims = observed_digest.map_or_else(Vec::new, |digest| {
        vec![qualified_digest(digest, "stored_representation")]
    });
    json!({
        "envelope": envelope(
            observation_ref,
            LOCATION_OBSERVATION_SCHEMA_ID,
            1,
            &spec.workspace_ref,
            &spec.authority_ref,
            now,
        ),
        "observation_contract_version": A07_SCHEMA_VERSION,
        "location_ref": location_ref,
        "observed_lifecycle_state": "available",
        "observed_health_state": health,
        "provider_aliases": [{
            "alias_kind": "object_key",
            "alias_value": object_key
        }],
        "observed_size": observed_size,
        "provider_digest_claims": digest_claims,
        "observer_ref": config.producer_ref,
        "observer_version": config.producer_version,
        "observed_at": now,
        "receipt_refs": evidence.receipt_refs,
        "limitations": [],
        "extensions": {}
    })
}
