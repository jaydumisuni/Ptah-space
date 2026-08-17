use super::*;
use super::documents_support::*;

impl ObjectStore {
    pub(super) fn publish_cas(
        &self,
        bytes: &[u8],
        digest: &str,
    ) -> Result<PathBuf, ObjectStoreError> {
        let destination = cas_path(&self.cas_root, digest)?;
        let parent = destination
            .parent()
            .ok_or(ObjectStoreError::InvalidInput("CAS path has no parent"))?;
        fs::create_dir_all(parent)?;
        if destination.exists() {
            self.verify_existing_cas(&destination, digest, bytes.len())?;
            sync_cas_publication(parent, &self.cas_root)?;
            return Ok(destination);
        }

        let temp = parent.join(format!(".a07-{}.tmp", EntityId::new_v7()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        match fs::hard_link(&temp, &destination) {
            Ok(()) => {
                fs::remove_file(&temp)?;
                sync_cas_publication(parent, &self.cas_root)?;
                self.verify_existing_cas(&destination, digest, bytes.len())?;
                Ok(destination)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&temp);
                self.verify_existing_cas(&destination, digest, bytes.len())?;
                sync_cas_publication(parent, &self.cas_root)?;
                Ok(destination)
            }
            Err(error) => {
                let _ = fs::remove_file(&temp);
                Err(ObjectStoreError::Io(error))
            }
        }
    }

    pub(super) fn verify_existing_cas(
        &self,
        path: &Path,
        expected_digest: &str,
        expected_len: usize,
    ) -> Result<(), ObjectStoreError> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ObjectStoreError::CasCollision(expected_digest.to_owned()));
        }
        let expected_len = u64::try_from(expected_len)
            .map_err(|_| ObjectStoreError::InvalidInput("content size overflow"))?;
        if metadata.len() != expected_len {
            return Err(ObjectStoreError::CasCollision(expected_digest.to_owned()));
        }
        let bytes = fs::read(path)?;
        let observed = sha256_hex(&bytes);
        if observed != expected_digest {
            return Err(ObjectStoreError::CasCollision(expected_digest.to_owned()));
        }
        Ok(())
    }

    pub(super) fn find_content(
        &self,
        digest: &str,
        byte_size: u64,
        scope: DeduplicationScope,
        scope_ref: Option<&EntityRef>,
    ) -> Result<Option<EntityRef>, ObjectStoreError> {
        let documents = self.latest_documents_by_kind(CONTENT_KIND)?;
        for document in documents {
            if field_u64(&document, "byte_size")? != byte_size
                || field_string(&document, "deduplication_scope")? != scope.as_str()
            {
                continue;
            }
            if digest_text(field_value(&document, "canonical_digest")?)? != digest {
                continue;
            }
            let retained_scope_ref = optional_ref(&document, "deduplication_scope_ref")?;
            if retained_scope_ref.as_ref() != scope_ref {
                continue;
            }
            return Ok(Some(document_ref(&document)?));
        }
        Ok(None)
    }

    pub(super) fn find_local_location(
        &self,
        content_ref: &EntityRef,
        digest: &str,
    ) -> Result<Option<EntityRef>, ObjectStoreError> {
        let expected_path = cas_path(&self.cas_root, digest)?;
        let expected_relative = expected_path
            .strip_prefix(&self.cas_root)
            .unwrap_or(&expected_path)
            .to_string_lossy()
            .replace('\\', "/");
        for document in self.latest_documents_by_kind(LOCATION_KIND)? {
            if field_string(&document, "location_kind")? != "local_cas"
                || field_ref(&document, "content_ref")? != *content_ref
                || lifecycle_state(&document)? != "available"
                || field_string(&document, "health_state")? != "healthy"
            {
                continue;
            }
            let aliases = document
                .get("backend_aliases")
                .and_then(Value::as_array)
                .ok_or(ObjectStoreError::TypeMismatch)?;
            let same_path = aliases.iter().any(|alias| {
                alias.get("alias_kind").and_then(Value::as_str) == Some(CAS_BACKEND_ALIAS_KIND)
                    && alias.get("alias_value").and_then(Value::as_str)
                        == Some(expected_relative.as_str())
            });
            if same_path {
                return Ok(Some(document_ref(&document)?));
            }
        }
        Ok(None)
    }

    pub(super) fn latest_documents_by_kind(
        &self,
        kind: &str,
    ) -> Result<Vec<Value>, ObjectStoreError> {
        let connection = Connection::open_with_flags(
            &self.ledger_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let mut statement = connection.prepare(
            "SELECT records.document_json \
             FROM ptah_entity_records AS records \
             INNER JOIN (\
                 SELECT entity_id, MAX(record_revision) AS max_revision \
                 FROM ptah_entity_records WHERE entity_kind = ?1 GROUP BY entity_id\
             ) AS latest \
             ON records.entity_id = latest.entity_id \
             AND records.record_revision = latest.max_revision \
             WHERE records.entity_kind = ?1 ORDER BY records.entity_id",
        )?;
        let rows = statement.query_map([kind], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let json = row?;
            Ok(serde_json::from_str(&json)?)
        })
        .collect()
    }

    pub(super) fn require_receipt_kinds(
        &self,
        workspace_ref: &EntityRef,
        correlation: &ProductionCorrelation,
        required: &[&'static str],
    ) -> Result<(), ObjectStoreError> {
        if correlation.receipt_refs.is_empty() {
            return Err(ObjectStoreError::InvalidInput("receipt_refs must not be empty"));
        }
        let mut observed = BTreeSet::new();
        for receipt_ref in &correlation.receipt_refs {
            if receipt_ref.entity_kind.as_str() != "proof.receipt" {
                return Err(ObjectStoreError::TypeMismatch);
            }
            let record = self.required_schema(receipt_ref.entity_id, RECEIPT_SCHEMA_ID)?;
            let document = record.document();
            if field_string(document, "receipt_outcome")? != "positive" {
                return Err(ObjectStoreError::ReceiptNotPositive);
            }
            if field_ref(document, "activity_ref")? != correlation.activity_ref
                || field_ref(document, "operation_ref")? != correlation.operation_ref
                || field_ref(document, "attempt_ref")? != correlation.attempt_ref
            {
                return Err(ObjectStoreError::ReceiptCorrelationMismatch);
            }
            observed.insert(field_string(document, "receipt_kind")?.to_owned());
        }
        let activity =
            self.required_schema(correlation.activity_ref.entity_id, ACTIVITY_SCHEMA_ID)?;
        if envelope_ref(activity.document(), "workspace_ref")? != *workspace_ref {
            return Err(ObjectStoreError::ReceiptCorrelationMismatch);
        }
        let operation =
            self.required_schema(correlation.operation_ref.entity_id, OPERATION_SCHEMA_ID)?;
        if field_ref(operation.document(), "activity_ref")? != correlation.activity_ref {
            return Err(ObjectStoreError::ReceiptCorrelationMismatch);
        }
        let attempt = self.required_schema(correlation.attempt_ref.entity_id, ATTEMPT_SCHEMA_ID)?;
        if field_ref(attempt.document(), "operation_ref")? != correlation.operation_ref {
            return Err(ObjectStoreError::ReceiptCorrelationMismatch);
        }
        for kind in required {
            if !observed.contains(*kind) {
                return Err(ObjectStoreError::MissingReceiptKind(kind));
            }
        }
        Ok(())
    }

    pub(super) fn receipt_refs_for_kind(
        &self,
        correlation: &ProductionCorrelation,
        kind: &str,
    ) -> Result<Vec<EntityRef>, ObjectStoreError> {
        let mut refs = Vec::new();
        for receipt_ref in &correlation.receipt_refs {
            let record = self.required_schema(receipt_ref.entity_id, RECEIPT_SCHEMA_ID)?;
            if field_string(record.document(), "receipt_kind")? == kind
                && field_string(record.document(), "receipt_outcome")? == "positive"
            {
                refs.push(receipt_ref.clone());
            }
        }
        Ok(unique_refs(refs))
    }

    pub(super) fn required_schema(
        &self,
        entity_id: EntityId,
        schema_id: &str,
    ) -> Result<CanonicalRecord, ObjectStoreError> {
        let record = self
            .ledger
            .latest_record(entity_id)?
            .ok_or(ObjectStoreError::NotFound(entity_id))?;
        if record.schema_id() != schema_id {
            return Err(ObjectStoreError::TypeMismatch);
        }
        Ok(record)
    }

    pub(super) fn location_path(&self, location: &Value) -> Result<PathBuf, ObjectStoreError> {
        let content_ref = field_ref(location, "content_ref")?;
        let content = self.required_schema(content_ref.entity_id, CONTENT_SCHEMA_ID)?;
        let digest = digest_text(field_value(content.document(), "canonical_digest")?)?;
        let expected = cas_path(&self.cas_root, &digest)?;
        let expected_relative = expected
            .strip_prefix(&self.cas_root)
            .map_err(|_| ObjectStoreError::TypeMismatch)?
            .to_string_lossy()
            .replace('\\', "/");
        let aliases = location
            .get("backend_aliases")
            .and_then(Value::as_array)
            .ok_or(ObjectStoreError::TypeMismatch)?;
        let relative = aliases
            .iter()
            .find(|alias| {
                alias.get("alias_kind").and_then(Value::as_str) == Some(CAS_BACKEND_ALIAS_KIND)
            })
            .and_then(|alias| alias.get("alias_value"))
            .and_then(Value::as_str)
            .ok_or(ObjectStoreError::TypeMismatch)?;
        if relative != expected_relative {
            return Err(ObjectStoreError::InvalidInput(
                "CAS backend alias does not match Content digest",
            ));
        }
        Ok(expected)
    }

    pub(super) fn write_documents(&mut self, documents: &[Value]) -> Result<(), ObjectStoreError> {
        let records = documents
            .iter()
            .cloned()
            .map(CanonicalRecord::from_document)
            .collect::<Result<Vec<_>, _>>()?;
        let write = self.ledger.begin_write()?;
        for record in &records {
            write.insert(record)?;
        }
        write.commit()?;
        Ok(())
    }
}
