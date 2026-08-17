impl ObjectStore {
    fn latest_document(
        &self,
        entity_id: EntityId,
        expected_schema: &str,
    ) -> Result<Value, ObjectStoreError> {
        let record = self
            .ledger
            .latest_record(entity_id)?
            .ok_or(ObjectStoreError::NotFound(entity_id))?;
        if record.schema_id() != expected_schema {
            return Err(ObjectStoreError::TypeMismatch);
        }
        Ok(record.document().clone())
    }

    fn write_documents(&mut self, documents: &[Value]) -> Result<(), ObjectStoreError> {
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

    fn validate_production(
        &self,
        workspace_ref: &EntityRef,
        evidence: &ProductionEvidence,
        required_receipt_kinds: &[&'static str],
    ) -> Result<ValidatedProduction, ObjectStoreError> {
        require_kind(&evidence.activity_ref, ACTIVITY_KIND, "activity_ref")?;
        require_kind(&evidence.operation_ref, OPERATION_KIND, "operation_ref")?;
        require_kind(&evidence.attempt_ref, ATTEMPT_KIND, "attempt_ref")?;
        if evidence.receipt_refs.is_empty() {
            return Err(ObjectStoreError::EmptyField("receipt_refs"));
        }
        if evidence
            .receipt_refs
            .iter()
            .any(|reference| reference.entity_kind.as_str() != RECEIPT_KIND)
        {
            return Err(ObjectStoreError::InvalidProductionKind("receipt_ref"));
        }

        let activity =
            self.latest_document(evidence.activity_ref.entity_id, ACTIVITY_SCHEMA_ID)?;
        let operation =
            self.latest_document(evidence.operation_ref.entity_id, OPERATION_SCHEMA_ID)?;
        let attempt =
            self.latest_document(evidence.attempt_ref.entity_id, ATTEMPT_SCHEMA_ID)?;
        ensure_workspace(&activity, workspace_ref)?;
        if !same_ref(&field_ref(&operation, "activity_ref")?, &evidence.activity_ref)
            || !same_ref(&field_ref(&attempt, "operation_ref")?, &evidence.operation_ref)
        {
            return Err(ObjectStoreError::ProductionEvidenceMismatch);
        }
        let state = attempt
            .get("lifecycle")
            .and_then(|value| value.get("current_state"))
            .and_then(Value::as_str)
            .ok_or(ObjectStoreError::ProductionEvidenceMismatch)?;
        if !matches!(state, "executing" | "waiting" | "completed") {
            return Err(ObjectStoreError::ProductionEvidenceMismatch);
        }
        let attached_receipts: Vec<EntityRef> = field_refs(&attempt, "receipt_refs")?;
        let mut found: HashMap<&'static str, Vec<EntityRef>> = required_receipt_kinds
            .iter()
            .copied()
            .map(|kind| (kind, Vec::new()))
            .collect();

        for receipt_ref in &evidence.receipt_refs {
            if !attached_receipts.iter().any(|item| same_ref(item, receipt_ref)) {
                return Err(ObjectStoreError::ProductionEvidenceMismatch);
            }
            let receipt = self.latest_document(receipt_ref.entity_id, RECEIPT_SCHEMA_ID)?;
            if field_string(&receipt, "receipt_outcome")? != "positive"
                || !same_ref(&field_ref(&receipt, "activity_ref")?, &evidence.activity_ref)
                || !same_ref(&field_ref(&receipt, "operation_ref")?, &evidence.operation_ref)
                || !same_ref(&field_ref(&receipt, "attempt_ref")?, &evidence.attempt_ref)
                || !receipt_attempt_context_matches(&receipt, &attempt)?
            {
                return Err(ObjectStoreError::ProductionEvidenceMismatch);
            }
            let kind = field_string(&receipt, "receipt_kind")?;
            if let Some(refs) = found.get_mut(kind) {
                refs.push(receipt_ref.clone());
            }
        }
        for required in required_receipt_kinds {
            if found.get(required).is_none_or(Vec::is_empty) {
                return Err(ObjectStoreError::MissingReceiptKind(required));
            }
        }

        let correlation = production_correlation(evidence, &attempt)?;
        Ok(ValidatedProduction {
            correlation,
            receipt_refs: unique_refs(evidence.receipt_refs.clone()),
            hash_receipt_refs: found.remove("hash_verification").unwrap_or_default(),
        })
    }

    fn find_content(
        &self,
        workspace_ref: &EntityRef,
        digest: &str,
    ) -> Result<Option<EntityRef>, ObjectStoreError> {
        for document in self.latest_documents_by_kind(CONTENT_KIND)? {
            if !document_in_workspace(&document, workspace_ref)? {
                continue;
            }
            let algorithm = document
                .get("canonical_digest")
                .and_then(|value| value.get("algorithm"))
                .and_then(Value::as_str);
            let observed = document
                .get("canonical_digest")
                .and_then(|value| value.get("digest"))
                .and_then(Value::as_str);
            if algorithm == Some("sha256")
                && observed == Some(digest)
                && field_string(&document, "deduplication_scope")? == "workspace"
            {
                return Ok(Some(document_ref(&document)?));
            }
        }
        Ok(None)
    }

    fn find_local_cas_location(
        &self,
        workspace_ref: &EntityRef,
        content_ref: &EntityRef,
        object_key: &str,
    ) -> Result<Option<EntityRef>, ObjectStoreError> {
        for document in self.latest_documents_by_kind(LOCATION_KIND)? {
            if !document_in_workspace(&document, workspace_ref)?
                || field_string(&document, "location_kind")? != "local_cas"
                || !same_ref(&field_ref(&document, "content_ref")?, content_ref)
            {
                continue;
            }
            if location_object_key(&document).is_ok_and(|key| key == object_key) {
                return Ok(Some(document_ref(&document)?));
            }
        }
        Ok(None)
    }

    fn latest_documents_by_kind(&self, kind: &str) -> Result<Vec<Value>, ObjectStoreError> {
        // A03 owns this database. A07 uses a read-only projection over the same
        // canonical rows only because A03's public repository trait has no
        // kind-scan yet. No writes or secondary metadata authority occur here.
        let connection = Connection::open_with_flags(
            &self.ledger_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(READ_ONLY_BUSY_TIMEOUT)?;
        let mut statement = connection.prepare(
            "SELECT r.document_json
             FROM ptah_entity_records AS r
             WHERE r.entity_kind = ?1
               AND r.record_revision = (
                   SELECT MAX(r2.record_revision)
                   FROM ptah_entity_records AS r2
                   WHERE r2.entity_id = r.entity_id
               )
             ORDER BY r.entity_id",
        )?;
        let rows = statement.query_map([kind], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let document_json = row?;
            serde_json::from_str(&document_json).map_err(ObjectStoreError::from)
        })
        .collect()
    }

    fn publish_cas(
        &self,
        bytes: &[u8],
        digest: &str,
        object_key: &str,
    ) -> Result<(), ObjectStoreError> {
        let target = self.cas_path(object_key)?;
        let parent = target.parent().ok_or(ObjectStoreError::InvalidCasKey)?;
        fs::create_dir_all(parent)?;
        if target.exists() {
            return verify_cas_target(&target, bytes, digest);
        }

        let temp = parent.join(format!(".{digest}.{}.tmp", EntityId::new_v7()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&temp);
            return Err(error.into());
        }
        drop(file);

        match fs::hard_link(&temp, &target) {
            Ok(()) => {
                fs::remove_file(&temp)?;
                verify_cas_target(&target, bytes, digest)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&temp);
                verify_cas_target(&target, bytes, digest)
            }
            Err(error) => {
                let _ = fs::remove_file(&temp);
                Err(error.into())
            }
        }
    }

    fn cas_path(&self, object_key: &str) -> Result<PathBuf, ObjectStoreError> {
        let mut parts = object_key.split('/');
        let Some(algorithm) = parts.next() else {
            return Err(ObjectStoreError::InvalidCasKey);
        };
        let Some(prefix) = parts.next() else {
            return Err(ObjectStoreError::InvalidCasKey);
        };
        let Some(digest) = parts.next() else {
            return Err(ObjectStoreError::InvalidCasKey);
        };
        if parts.next().is_some()
            || algorithm != "sha256"
            || prefix.len() != 2
            || digest.len() != 64
            || &digest[..2] != prefix
            || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ObjectStoreError::InvalidCasKey);
        }
        Ok(self.cas_root.join(algorithm).join(prefix).join(digest))
    }
}
