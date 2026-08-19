const CAS_IO_BUFFER_SIZE: usize = 64 * 1024;

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
        let (Some(observed), Some(expected)) = (receipt.get(field), attempt.get(field)) else {
            return false;
        };
        if observed != expected {
            return false;
        }
    }
    true
}

fn ensure_real_directory(path: &Path) -> Result<(), ObjectStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ObjectStoreError::CasIntegrityMismatch);
    }
    Ok(())
}

fn ensure_or_create_real_directory(path: &Path) -> Result<(), ObjectStoreError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    ensure_real_directory(path)
}

fn cas_parent_hierarchy_exists_and_is_safe(
    cas_root: &Path,
    target: &Path,
) -> Result<bool, ObjectStoreError> {
    ensure_real_directory(cas_root)?;
    let prefix_dir = target.parent().ok_or(ObjectStoreError::InvalidCasKey)?;
    let algorithm_dir = prefix_dir.parent().ok_or(ObjectStoreError::InvalidCasKey)?;
    if algorithm_dir.parent() != Some(cas_root) {
        return Err(ObjectStoreError::InvalidCasKey);
    }
    for directory in [algorithm_dir, prefix_dir] {
        match fs::symlink_metadata(directory) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(ObjectStoreError::CasIntegrityMismatch);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(true)
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
    let mut file = fs::File::open(target)?;
    let mut hasher = Sha256::new();
    let mut offset = 0usize;
    let mut buffer = [0u8; CAS_IO_BUFFER_SIZE];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)?;
        if read == 0 {
            break;
        }
        let end = offset
            .checked_add(read)
            .ok_or(ObjectStoreError::CasIntegrityMismatch)?;
        if expected_bytes.get(offset..end) != Some(&buffer[..read]) {
            return Err(ObjectStoreError::CasIntegrityMismatch);
        }
        hasher.update(&buffer[..read]);
        offset = end;
    }
    let observed_digest = format!("{:x}", hasher.finalize());
    if offset != expected_bytes.len() || observed_digest != expected_digest {
        return Err(ObjectStoreError::CasIntegrityMismatch);
    }
    Ok(())
}

fn hash_cas_file(target: &Path) -> Result<(String, u64), io::Error> {
    let mut file = fs::File::open(target)?;
    let mut hasher = Sha256::new();
    let mut observed_size = 0u64;
    let mut buffer = [0u8; CAS_IO_BUFFER_SIZE];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        let read_u64 = u64::try_from(read).map_err(|_| io::Error::other("CAS read size overflow"))?;
        observed_size = observed_size
            .checked_add(read_u64)
            .ok_or_else(|| io::Error::other("CAS observed size overflow"))?;
    }
    Ok((format!("{:x}", hasher.finalize()), observed_size))
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

fn require_bounded_text(
    value: &str,
    max_chars: usize,
    field: &'static str,
) -> Result<(), ObjectStoreError> {
    require_non_empty(value, field)?;
    if value.chars().count() > max_chars {
        return Err(ObjectStoreError::TypeMismatch);
    }
    Ok(())
}

fn require_family_key(value: &str, field: &'static str) -> Result<(), ObjectStoreError> {
    require_non_empty(value, field)?;
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(ObjectStoreError::TypeMismatch);
    }
    Ok(())
}

fn require_semver(value: &str, field: &'static str) -> Result<(), ObjectStoreError> {
    require_non_empty(value, field)?;
    if !is_semver(value) {
        return Err(ObjectStoreError::TypeMismatch);
    }
    Ok(())
}

fn require_schema_id(value: &str, field: &'static str) -> Result<(), ObjectStoreError> {
    require_non_empty(value, field)?;
    let Some(rest) = value.strip_prefix("urn:ptah:schema:") else {
        return Err(ObjectStoreError::TypeMismatch);
    };
    let Some((path, version)) = rest.rsplit_once(':') else {
        return Err(ObjectStoreError::TypeMismatch);
    };
    let mut segments = path.split(':');
    let Some(first) = segments.next() else {
        return Err(ObjectStoreError::TypeMismatch);
    };
    let Some(second) = segments.next() else {
        return Err(ObjectStoreError::TypeMismatch);
    };
    if !is_schema_segment(first)
        || !is_schema_segment(second)
        || !segments.all(is_schema_segment)
        || !is_schema_version(version)
    {
        return Err(ObjectStoreError::TypeMismatch);
    }
    Ok(())
}

fn is_schema_segment(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn is_schema_version(value: &str) -> bool {
    let (without_build, build) = value
        .split_once('+')
        .map_or((value, None), |(core, build)| (core, Some(build)));
    if build.is_some_and(|part| !valid_schema_suffix(part)) {
        return false;
    }
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(core, pre)| (core, Some(pre)));
    if prerelease.is_some_and(|part| !valid_schema_suffix(part)) {
        return false;
    }
    let mut numbers = core.split('.');
    let Some(major) = numbers.next() else {
        return false;
    };
    let Some(minor) = numbers.next() else {
        return false;
    };
    let Some(patch) = numbers.next() else {
        return false;
    };
    numbers.next().is_none()
        && valid_numeric_identifier(major)
        && valid_numeric_identifier(minor)
        && valid_numeric_identifier(patch)
}

fn valid_schema_suffix(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn is_semver(value: &str) -> bool {
    let (without_build, build) = value
        .split_once('+')
        .map_or((value, None), |(core, build)| (core, Some(build)));
    if build.is_some_and(|part| !valid_semver_identifiers(part, false)) {
        return false;
    }
    if without_build.contains('+') {
        return false;
    }
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(core, pre)| (core, Some(pre)));
    if prerelease.is_some_and(|part| !valid_semver_identifiers(part, true)) {
        return false;
    }
    let mut numbers = core.split('.');
    let Some(major) = numbers.next() else {
        return false;
    };
    let Some(minor) = numbers.next() else {
        return false;
    };
    let Some(patch) = numbers.next() else {
        return false;
    };
    numbers.next().is_none()
        && valid_numeric_identifier(major)
        && valid_numeric_identifier(minor)
        && valid_numeric_identifier(patch)
}

fn valid_semver_identifiers(value: &str, reject_numeric_leading_zero: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!reject_numeric_leading_zero
                    || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || valid_numeric_identifier(identifier))
        })
}

fn valid_numeric_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
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
