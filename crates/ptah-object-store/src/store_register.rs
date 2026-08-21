impl ObjectStore {
    /// Open the canonical A03 ledger and the local digest-addressed byte root.
    ///
    /// # Errors
    /// Fails if the A03 ledger or local CAS root cannot be opened.
    pub fn open(
        ledger_path: impl AsRef<Path>,
        cas_root: impl AsRef<Path>,
        config: ObjectStoreConfig,
        clock: StoreClock,
    ) -> Result<Self, ObjectStoreError> {
        require_bounded_text(&config.producer_version, 256, "producer_version")?;
        let ledger_path = ledger_path.as_ref().to_path_buf();
        let requested_cas_root = cas_root.as_ref().to_path_buf();
        fs::create_dir_all(&requested_cas_root)?;
        let cas_root = fs::canonicalize(&requested_cas_root)?;
        ensure_real_directory(&cas_root)?;
        let ledger = Ledger::open(&ledger_path)?;
        Ok(Self {
            ledger_path,
            ledger,
            cas_root,
            config,
            clock,
        })
    }

    /// Compute the canonical lowercase SHA-256 digest used by A07.
    #[must_use]
    pub fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    /// Register bytes as Content plus a fresh logical Object and first immutable Revision.
    ///
    /// Content may deduplicate inside the same Workspace, but logical Object
    /// identity is always newly allocated. The command specification is consumed
    /// deliberately: registration is a one-shot authority request, not retained
    /// mutable caller state.
    ///
    /// # Errors
    /// Fails closed for digest mismatch, invalid/mismatched A04 evidence, corrupt
    /// pre-existing CAS bytes, or canonical-ledger failure.
    #[allow(clippy::needless_pass_by_value)]
    pub fn register_bytes(
        &mut self,
        bytes: &[u8],
        spec: RegisterObjectSpec,
    ) -> Result<Registration, ObjectStoreError> {
        let digest = registration_digest(bytes, &spec)?;
        let validated = self.validate_production(
            &spec.workspace_ref,
            &spec.authority_ref,
            &spec.production,
            &["output_observation", "hash_verification"],
        )?;
        let now = self.now()?;
        let object_key = cas_object_key(&digest)?;
        self.publish_cas(bytes, &digest, &object_key)?;

        let existing_content = self.find_content(&spec.workspace_ref, &digest)?;
        let content_deduplicated = existing_content.is_some();
        let content_ref = existing_content.unwrap_or(EntityRef::new(CONTENT_KIND)?);
        let object_ref = EntityRef::new(OBJECT_KIND)?;
        let revision_ref = EntityRef::new(REVISION_KIND)?;
        let mut documents = Vec::new();

        if !content_deduplicated {
            let hash_observation_ref = EntityRef::new(HASH_OBSERVATION_KIND)?;
            documents.push(hash_observation_document(
                &hash_observation_ref,
                &content_ref,
                bytes.len(),
                &digest,
                &spec.workspace_ref,
                &spec.authority_ref,
                &self.config,
                &validated,
                &now,
            ));
            documents.push(content_document(
                &content_ref,
                &hash_observation_ref,
                bytes.len(),
                &digest,
                &spec.workspace_ref,
                &spec.authority_ref,
                &validated.hash_receipt_refs,
                &now,
            ));
        }

        let location_ref = self.stage_local_cas_location(
            &content_ref,
            bytes.len(),
            &digest,
            &object_key,
            &spec,
            &validated,
            &now,
            &mut documents,
        )?;
        documents.push(revision_document(
            &revision_ref,
            &object_ref,
            &content_ref,
            &spec,
            &validated,
            &now,
        ));
        documents.push(object_document(
            &object_ref,
            &revision_ref,
            &spec,
            &now,
        ));
        self.write_documents(&documents)?;

        Ok(Registration {
            content_ref,
            object_ref,
            revision_ref,
            location_ref,
            sha256: digest,
            byte_size: u64::try_from(bytes.len()).map_err(|_| ObjectStoreError::RevisionOverflow)?,
            cas_object_key: object_key,
            content_deduplicated,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn stage_local_cas_location(
        &self,
        content_ref: &EntityRef,
        byte_size: usize,
        digest: &str,
        object_key: &str,
        spec: &RegisterObjectSpec,
        validated: &ValidatedProduction,
        now: &str,
        documents: &mut Vec<Value>,
    ) -> Result<EntityRef, ObjectStoreError> {
        if let Some(existing) =
            self.find_local_cas_location(&spec.workspace_ref, content_ref, object_key)?
        {
            let mut location = self.latest_document(existing.entity_id, LOCATION_SCHEMA_ID)?;
            let lifecycle_state = location
                .get("lifecycle")
                .and_then(|value| value.get("current_state"))
                .and_then(Value::as_str)
                .ok_or(ObjectStoreError::TypeMismatch)?;
            if lifecycle_state != "available" {
                return Err(ObjectStoreError::VerificationFailed);
            }
            let health_state = field_string(&location, "health_state")?;
            let verification_state = field_string(&location, "verification_state")?;
            if health_state != "healthy"
                || matches!(verification_state, "failed" | "stale")
            {
                let observation_ref = EntityRef::new(LOCATION_OBSERVATION_KIND)?;
                documents.push(location_observation_document(
                    &observation_ref,
                    &existing,
                    byte_size,
                    digest,
                    object_key,
                    &spec.workspace_ref,
                    &spec.authority_ref,
                    &self.config,
                    &validated.receipt_refs,
                    now,
                ));
                append_document_ref(&mut location, "observation_refs", observation_ref)?;
                append_document_refs(
                    &mut location,
                    "receipt_refs",
                    &validated.receipt_refs,
                )?;
                set_string(&mut location, "health_state", "healthy")?;
                set_string(&mut location, "verification_state", "unverified")?;
                set_string(&mut location, "last_observed_at", now)?;
                bump_document(&mut location, now)?;
                documents.push(location);
            }
            return Ok(existing);
        }
        let location_ref = EntityRef::new(LOCATION_KIND)?;
        let observation_ref = EntityRef::new(LOCATION_OBSERVATION_KIND)?;
        documents.push(location_observation_document(
            &observation_ref,
            &location_ref,
            byte_size,
            digest,
            object_key,
            &spec.workspace_ref,
            &spec.authority_ref,
            &self.config,
            &validated.receipt_refs,
            now,
        ));
        documents.push(location_document(
            &location_ref,
            content_ref,
            &observation_ref,
            byte_size,
            digest,
            object_key,
            &spec.workspace_ref,
            &spec.authority_ref,
            &self.config,
            &validated.receipt_refs,
            now,
        ));
        Ok(location_ref)
    }
}

fn registration_digest(
    bytes: &[u8],
    spec: &RegisterObjectSpec,
) -> Result<String, ObjectStoreError> {
    require_family_key(&spec.object_class, "object_class")?;
    require_bounded_text(&spec.created_reason, 4096, "created_reason")?;
    if spec.source_refs.is_empty() {
        return Err(ObjectStoreError::MissingSourceRefs);
    }
    if let Some(name) = &spec.declared_name {
        require_bounded_text(name, 8192, "declared_name")?;
    }
    let digest = ObjectStore::sha256(bytes);
    if let Some(expected) = &spec.expected_sha256 {
        validate_digest_text(expected)?;
        if expected != &digest {
            return Err(ObjectStoreError::ExpectedDigestMismatch {
                expected: expected.clone(),
                observed: digest,
            });
        }
    }
    Ok(digest)
}
