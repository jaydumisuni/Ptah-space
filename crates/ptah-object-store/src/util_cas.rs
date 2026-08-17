fn envelope(
    entity_ref: &EntityRef,
    schema_id: &str,
    record_revision: u64,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
    now: &str,
) -> Value {
    json!({
        "entity_id": entity_ref.entity_id,
        "entity_kind": entity_ref.entity_kind,
        "schema_id": schema_id,
        "schema_version": A07_SCHEMA_VERSION,
        "record_revision": record_revision,
        "created_at": now,
        "updated_at": now,
        "workspace_ref": workspace_ref,
        "authority_ref": authority_ref,
        "privacy_class": "internal",
        "audience": "workspace",
        "redaction_policy": "none",
        "retention_policy": {
            "policy_id": "ptah.a07.canonical",
            "policy_version": A07_SCHEMA_VERSION,
            "retention_class": "historical",
            "delete_bytes_when_unreferenced": false
        },
        "extensions": {}
    })
}

fn lifecycle(machine: &str, state: &str, sequence: u64) -> Value {
    json!({
        "state_machine_name": machine,
        "state_machine_version": A07_SCHEMA_VERSION,
        "current_state": state,
        "state_sequence": sequence
    })
}

fn qualified_digest(digest: &str, byte_scope: &str) -> Value {
    json!({
        "algorithm": "sha256",
        "algorithm_profile": "sha2-0.10",
        "digest": digest,
        "byte_scope": byte_scope
    })
}

fn production_correlation(
    evidence: &ProductionEvidence,
    attempt: &Value,
) -> Result<Value, ObjectStoreError> {
    Ok(json!({
        "activity_ref": evidence.activity_ref,
        "operation_ref": evidence.operation_ref,
        "attempt_ref": evidence.attempt_ref,
        "receipt_refs": unique_refs(evidence.receipt_refs.clone()),
        "facility_ref": field_ref(attempt, "facility_ref")?,
        "provider_ref": field_ref(attempt, "provider_ref")?,
        "node_ref": field_ref(attempt, "node_ref")?
    }))
}

fn same_production_identity(left: &Value, right: &Value) -> Result<bool, ObjectStoreError> {
    for field in ["activity_ref", "operation_ref", "attempt_ref"] {
        if !same_ref(&field_ref(left, field)?, &field_ref(right, field)?) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn receipt_attempt_context_matches(receipt: &Value, attempt: &Value) -> bool {
    for field in [
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
    ] {
        if receipt.get(field) != attempt.get(field) {
            return false;
        }
    }
    true
}

fn ensure_regular_cas_file(target: &Path) -> Result<(), ObjectStoreError> {
    let metadata = fs::symlink_metadata(target)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ObjectStoreError::CasIntegrityMismatch);
    }
    Ok(())
}

fn ensure_location_binding(
    document: &Value,
    config: &ObjectStoreConfig,
) -> Result<(), ObjectStoreError> {
    if !same_ref(&field_ref(document, "backend_ref")?, &config.backend_ref)
        || !same_ref(
            &field_ref(document, "connection_ref")?,
            &config.connection_ref,
        )
    {
        return Err(ObjectStoreError::TypeMismatch);
    }
    Ok(())
}

fn sync_cas_directory(path: &Path) -> Result<(), ObjectStoreError> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn verify_cas_target(
    target: &Path,
    expected_bytes: &[u8],
    expected_digest: &str,
) -> Result<(), ObjectStoreError> {
    ensure_regular_cas_file(target)?;
    let retained = fs::read(target)?;
    let observed_digest = format!("{:x}", Sha256::digest(&retained));
    if retained.len() != expected_bytes.len()
        || observed_digest != expected_digest
        || retained != expected_bytes
    {
        return Err(ObjectStoreError::CasIntegrityMismatch);
    }
    Ok(())
}

fn cas_object_key(digest: &str) -> Result<String, ObjectStoreError> {
    validate_digest_text(digest)?;
    Ok(format!("sha256/{}/{digest}", &digest[..2]))
}

fn validate_digest_text(value: &str) -> Result<(), ObjectStoreError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ObjectStoreError::InvalidExpectedDigest);
    }
    Ok(())
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), ObjectStoreError> {
    if value.trim().is_empty() {
        return Err(ObjectStoreError::EmptyField(field));
    }
    Ok(())
}

fn require_kind(
    reference: &EntityRef,
    expected: &str,
    field: &'static str,
) -> Result<(), ObjectStoreError> {
    if reference.entity_kind.as_str() != expected {
        return Err(ObjectStoreError::InvalidProductionKind(field));
    }
    Ok(())
}

fn same_ref(left: &EntityRef, right: &EntityRef) -> bool {
    left.entity_id == right.entity_id && left.entity_kind == right.entity_kind
}

fn unique_refs(refs: Vec<EntityRef>) -> Vec<EntityRef> {
    let mut seen = HashSet::new();
    refs.into_iter()
        .filter(|reference| seen.insert((reference.entity_id, reference.entity_kind.clone())))
        .collect()
}

fn append_unique_ref(refs: &mut Vec<EntityRef>, reference: EntityRef) {
    if !refs.iter().any(|item| same_ref(item, &reference)) {
        refs.push(reference);
    }
}
