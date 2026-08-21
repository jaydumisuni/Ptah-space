impl ObjectStore {
    fn now(&self) -> Result<String, ObjectStoreError> {
        let now = (self.clock)();
        require_utc_datetime(&now)?;
        Ok(now)
    }
}

fn require_utc_datetime(value: &str) -> Result<(), ObjectStoreError> {
    let Some(without_z) = value.strip_suffix('Z') else {
        return Err(ObjectStoreError::TypeMismatch);
    };
    let separator = without_z.find(['T', 't']).ok_or(ObjectStoreError::TypeMismatch)?;
    let (date, time_with_separator) = without_z.split_at(separator);
    let time = &time_with_separator[1..];
    if date.len() != 10
        || date.as_bytes().get(4) != Some(&b'-')
        || date.as_bytes().get(7) != Some(&b'-')
    {
        return Err(ObjectStoreError::TypeMismatch);
    }
    let year = parse_fixed_decimal(&date[0..4])?;
    let month = parse_fixed_decimal(&date[5..7])?;
    let day = parse_fixed_decimal(&date[8..10])?;
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return Err(ObjectStoreError::TypeMismatch);
    }

    let (clock, fraction) = time
        .split_once('.')
        .map_or((time, None), |(clock, fraction)| (clock, Some(fraction)));
    if clock.len() != 8
        || clock.as_bytes().get(2) != Some(&b':')
        || clock.as_bytes().get(5) != Some(&b':')
        || fraction.is_some_and(|part| {
            part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(ObjectStoreError::TypeMismatch);
    }
    let hour = parse_fixed_decimal(&clock[0..2])?;
    let minute = parse_fixed_decimal(&clock[3..5])?;
    let second = parse_fixed_decimal(&clock[6..8])?;
    if hour > 23 || minute > 59 || second > 60 {
        return Err(ObjectStoreError::TypeMismatch);
    }
    Ok(())
}

fn parse_fixed_decimal(value: &str) -> Result<u32, ObjectStoreError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ObjectStoreError::TypeMismatch);
    }
    value.parse().map_err(|_| ObjectStoreError::TypeMismatch)
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

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

fn envelope_authority(document: &Value) -> Result<EntityRef, ObjectStoreError> {
    let envelope = document
        .get("envelope")
        .ok_or(ObjectStoreError::TypeMismatch)?;
    Ok(serde_json::from_value(
        envelope
            .get("authority_ref")
            .cloned()
            .ok_or(ObjectStoreError::AuthorityMismatch)?,
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
