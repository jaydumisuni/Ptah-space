use super::*;

pub(super) fn qualified_sha256(bytes: &[u8]) -> Value {
    json!({
        "algorithm": "sha256",
        "digest": sha256_hex(bytes),
        "byte_scope": "whole_content"
    })
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn digest_text(value: &Value) -> Result<String, ObjectStoreError> {
    let algorithm = value
        .get("algorithm")
        .and_then(Value::as_str)
        .ok_or(ObjectStoreError::TypeMismatch)?;
    if algorithm != "sha256" {
        return Err(ObjectStoreError::InvalidInput("unsupported canonical digest"));
    }
    value
        .get("digest")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(ObjectStoreError::TypeMismatch)
}

pub(super) fn cas_path(root: &Path, digest: &str) -> Result<PathBuf, ObjectStoreError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ObjectStoreError::InvalidInput("invalid SHA-256 digest"));
    }
    Ok(root.join("sha256").join(&digest[..2]).join(digest))
}

pub(super) fn readback(path: &Path) -> io::Result<Vec<u8>> {
    fs::read(path)
}

pub(super) fn sync_cas_publication(_leaf_directory: &Path, _cas_root: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut current = Some(_leaf_directory);
        while let Some(directory) = current {
            fs::File::open(directory)?.sync_all()?;
            if directory == _cas_root {
                break;
            }
            current = directory.parent();
        }
    }
    Ok(())
}

pub(super) fn document_ref(document: &Value) -> Result<EntityRef, ObjectStoreError> {
    let envelope = document
        .get("envelope")
        .ok_or(ObjectStoreError::TypeMismatch)?;
    let entity_id: EntityId = serde_json::from_value(
        envelope
            .get("entity_id")
            .cloned()
            .ok_or(ObjectStoreError::TypeMismatch)?,
    )?;
    let entity_kind = envelope
        .get("entity_kind")
        .and_then(Value::as_str)
        .ok_or(ObjectStoreError::TypeMismatch)?;
    Ok(EntityRef::from_id(entity_id, entity_kind)?)
}

pub(super) fn envelope_ref(
    document: &Value,
    field: &'static str,
) -> Result<EntityRef, ObjectStoreError> {
    let envelope = document
        .get("envelope")
        .ok_or(ObjectStoreError::TypeMismatch)?;
    field_ref(envelope, field)
}

pub(super) fn field_value<'a>(
    document: &'a Value,
    field: &'static str,
) -> Result<&'a Value, ObjectStoreError> {
    document.get(field).ok_or(ObjectStoreError::TypeMismatch)
}

pub(super) fn field_string<'a>(
    document: &'a Value,
    field: &'static str,
) -> Result<&'a str, ObjectStoreError> {
    document
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ObjectStoreError::TypeMismatch)
}

pub(super) fn field_u64(document: &Value, field: &'static str) -> Result<u64, ObjectStoreError> {
    document
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(ObjectStoreError::TypeMismatch)
}

pub(super) fn field_ref(
    document: &Value,
    field: &'static str,
) -> Result<EntityRef, ObjectStoreError> {
    serde_json::from_value(
        document
            .get(field)
            .cloned()
            .ok_or(ObjectStoreError::TypeMismatch)?,
    )
    .map_err(ObjectStoreError::from)
}

pub(super) fn field_refs(
    document: &Value,
    field: &'static str,
) -> Result<Vec<EntityRef>, ObjectStoreError> {
    serde_json::from_value(
        document
            .get(field)
            .cloned()
            .ok_or(ObjectStoreError::TypeMismatch)?,
    )
    .map_err(ObjectStoreError::from)
}

pub(super) fn optional_ref(
    document: &Value,
    field: &'static str,
) -> Result<Option<EntityRef>, ObjectStoreError> {
    document
        .get(field)
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(ObjectStoreError::from)
}

pub(super) fn lifecycle_state(document: &Value) -> Result<&str, ObjectStoreError> {
    document
        .get("lifecycle")
        .and_then(|value| value.get("current_state"))
        .and_then(Value::as_str)
        .ok_or(ObjectStoreError::TypeMismatch)
}

pub(super) fn append_ref(
    document: &mut Value,
    field: &'static str,
    reference: EntityRef,
) -> Result<(), ObjectStoreError> {
    let array = document
        .get_mut(field)
        .and_then(Value::as_array_mut)
        .ok_or(ObjectStoreError::TypeMismatch)?;
    let candidate = json!(reference);
    if !array.contains(&candidate) {
        array.push(candidate);
    }
    Ok(())
}

pub(super) fn append_refs(
    document: &mut Value,
    field: &'static str,
    refs: &[EntityRef],
) -> Result<(), ObjectStoreError> {
    for reference in refs {
        append_ref(document, field, reference.clone())?;
    }
    Ok(())
}

pub(super) fn set_ref(
    document: &mut Value,
    field: &'static str,
    reference: EntityRef,
) -> Result<(), ObjectStoreError> {
    document_object_mut(document)?.insert(field.to_owned(), json!(reference));
    Ok(())
}

pub(super) fn set_string(
    document: &mut Value,
    field: &'static str,
    value: &str,
) -> Result<(), ObjectStoreError> {
    document_object_mut(document)?.insert(field.to_owned(), json!(value));
    Ok(())
}

pub(super) fn bump_envelope(
    document: &mut Value,
    authority_ref: &EntityRef,
    now: &str,
) -> Result<(), ObjectStoreError> {
    let envelope = document
        .get_mut("envelope")
        .and_then(Value::as_object_mut)
        .ok_or(ObjectStoreError::TypeMismatch)?;
    let current = envelope
        .get("record_revision")
        .and_then(Value::as_u64)
        .ok_or(ObjectStoreError::TypeMismatch)?;
    let next = current
        .checked_add(1)
        .ok_or(ObjectStoreError::RevisionOverflow)?;
    envelope.insert("record_revision".to_owned(), json!(next));
    envelope.insert("updated_at".to_owned(), json!(now));
    envelope.insert("authority_ref".to_owned(), json!(authority_ref));
    Ok(())
}

pub(super) fn document_object_mut(
    document: &mut Value,
) -> Result<&mut Map<String, Value>, ObjectStoreError> {
    document.as_object_mut().ok_or(ObjectStoreError::TypeMismatch)
}

pub(super) fn unique_refs(refs: Vec<EntityRef>) -> Vec<EntityRef> {
    let mut seen = BTreeSet::new();
    refs.into_iter()
        .filter(|reference| {
            seen.insert(format!(
                "{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}",
                reference.entity_id,
                reference.entity_kind.as_str(),
                reference.record_revision,
                reference.node_generation,
                reference.provider_generation,
                reference.workload_generation,
                reference.connection_epoch,
            ))
        })
        .collect()
}

pub(super) fn require_text(value: &str, field: &'static str) -> Result<(), ObjectStoreError> {
    if value.trim().is_empty() {
        return Err(ObjectStoreError::InvalidInput(field));
    }
    Ok(())
}

pub(super) fn require_key(value: &str, field: &'static str) -> Result<(), ObjectStoreError> {
    if value.is_empty()
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || (index > 0 && (byte.is_ascii_digit() || byte == b'_'))
            })
    {
        return Err(ObjectStoreError::InvalidInput(field));
    }
    Ok(())
}
