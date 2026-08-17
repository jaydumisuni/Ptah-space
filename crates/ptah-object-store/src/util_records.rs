fn document_ref(document: &Value) -> Result<EntityRef, ObjectStoreError> {
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

fn envelope_workspace(document: &Value) -> Result<EntityRef, ObjectStoreError> {
    let envelope = document
        .get("envelope")
        .ok_or(ObjectStoreError::TypeMismatch)?;
    Ok(serde_json::from_value(
        envelope
            .get("workspace_ref")
            .cloned()
            .ok_or(ObjectStoreError::WorkspaceMismatch)?,
    )?)
}

fn document_in_workspace(
    document: &Value,
    workspace_ref: &EntityRef,
) -> Result<bool, ObjectStoreError> {
    Ok(same_ref(&envelope_workspace(document)?, workspace_ref))
}

fn ensure_workspace(
    document: &Value,
    workspace_ref: &EntityRef,
) -> Result<(), ObjectStoreError> {
    if !document_in_workspace(document, workspace_ref)? {
        return Err(ObjectStoreError::WorkspaceMismatch);
    }
    Ok(())
}

fn field_ref(document: &Value, field: &'static str) -> Result<EntityRef, ObjectStoreError> {
    Ok(serde_json::from_value(
        document
            .get(field)
            .cloned()
            .ok_or(ObjectStoreError::TypeMismatch)?,
    )?)
}

fn field_refs(document: &Value, field: &'static str) -> Result<Vec<EntityRef>, ObjectStoreError> {
    Ok(serde_json::from_value(
        document
            .get(field)
            .cloned()
            .ok_or(ObjectStoreError::TypeMismatch)?,
    )?)
}

fn field_string<'a>(
    document: &'a Value,
    field: &'static str,
) -> Result<&'a str, ObjectStoreError> {
    document
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ObjectStoreError::TypeMismatch)
}

fn field_u64(document: &Value, field: &'static str) -> Result<u64, ObjectStoreError> {
    document
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(ObjectStoreError::TypeMismatch)
}

fn append_document_ref(
    document: &mut Value,
    field: &'static str,
    reference: EntityRef,
) -> Result<(), ObjectStoreError> {
    let array = document
        .get_mut(field)
        .and_then(Value::as_array_mut)
        .ok_or(ObjectStoreError::TypeMismatch)?;
    let existing: Vec<EntityRef> = serde_json::from_value(Value::Array(array.clone()))?;
    if !existing.iter().any(|item| same_ref(item, &reference)) {
        array.push(serde_json::to_value(reference)?);
    }
    Ok(())
}

fn append_document_refs(
    document: &mut Value,
    field: &'static str,
    references: &[EntityRef],
) -> Result<(), ObjectStoreError> {
    for reference in references {
        append_document_ref(document, field, reference.clone())?;
    }
    Ok(())
}

fn bump_document(document: &mut Value, now: &str) -> Result<u64, ObjectStoreError> {
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
    Ok(next)
}

fn set_string(
    document: &mut Value,
    field: &'static str,
    value: &str,
) -> Result<(), ObjectStoreError> {
    document
        .as_object_mut()
        .ok_or(ObjectStoreError::TypeMismatch)?
        .insert(field.to_owned(), json!(value));
    Ok(())
}

fn location_object_key(document: &Value) -> Result<String, ObjectStoreError> {
    let aliases = document
        .get("backend_aliases")
        .and_then(Value::as_array)
        .ok_or(ObjectStoreError::TypeMismatch)?;
    aliases
        .iter()
        .find_map(|alias| {
            (alias.get("alias_kind").and_then(Value::as_str) == Some("object_key"))
                .then(|| alias.get("alias_value").and_then(Value::as_str))
                .flatten()
                .map(str::to_owned)
        })
        .ok_or(ObjectStoreError::TypeMismatch)
}
