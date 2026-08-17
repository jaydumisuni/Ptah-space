use super::*;
use super::documents_entities::*;
use super::documents_model::*;
use super::documents_support::*;

impl ObjectStore {
    /// Open A07 over one proven A03 ledger and one local CAS root.
    ///
    /// # Errors
    ///
    /// Returns an error if the ledger cannot open or the local CAS root cannot
    /// be created.
    pub fn open(
        ledger_path: impl AsRef<Path>,
        cas_root: impl AsRef<Path>,
        clock: Arc<dyn Fn() -> String + Send + Sync>,
    ) -> Result<Self, ObjectStoreError> {
        let ledger_path = ledger_path.as_ref().to_path_buf();
        let cas_root = cas_root.as_ref().to_path_buf();
        fs::create_dir_all(&cas_root)?;
        Ok(Self {
            ledger: Ledger::open(&ledger_path)?,
            ledger_path,
            cas_root,
            clock,
        })
    }

    /// Register bytes as a new logical Object and immutable first Revision.
    ///
    /// Positive `output_observation`, `hash_verification` and
    /// `operation_observation` Receipts bound to one exact A04 Attempt are
    /// required before A07 creates canonical success projections.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input/evidence, local CAS corruption, or
    /// durable ledger failure.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "A07 write commands are owned durable-boundary requests"
    )]
    pub fn register_object(
        &mut self,
        bytes: &[u8],
        input: RegisterObject,
    ) -> Result<Registration, ObjectStoreError> {
        validate_register_input(&input)?;
        self.require_receipt_kinds(
            &input.workspace_ref,
            &input.production_correlation,
            &["output_observation", "hash_verification", "operation_observation"],
        )?;

        let now = (self.clock)();
        let object_ref = EntityRef::new(OBJECT_KIND)?;
        let revision_ref = EntityRef::new(REVISION_KIND)?;
        let scope_ref = dedup_scope_ref(
            input.deduplication_scope,
            &input.workspace_ref,
            &object_ref,
            input.deduplication_scope_ref.as_ref(),
        )?;
        let materialized = self.materialize_content(
            bytes,
            MaterializeInput {
                workspace_ref: &input.workspace_ref,
                authority_ref: &input.authority_ref,
                deduplication_scope: input.deduplication_scope,
                deduplication_scope_ref: scope_ref.as_ref(),
                media_type_claim: input.media_type_claim.as_deref(),
                producer_ref: &input.producer_ref,
                producer_version: &input.producer_version,
                backend_ref: &input.backend_ref,
                connection_ref: &input.connection_ref,
                production_correlation: &input.production_correlation,
                now: &now,
            },
        )?;

        let revision = revision_document(
            &revision_ref,
            &object_ref,
            1,
            &input.workspace_ref,
            &input.authority_ref,
            input.revision_role,
            input.origin_class,
            &input.source_refs,
            &materialized.content_ref,
            &input.production_correlation,
            &input.created_reason,
            &self.receipt_refs_for_kind(&input.production_correlation, "hash_verification")?,
            &now,
        );
        let object = object_document(
            &object_ref,
            &revision_ref,
            &input.workspace_ref,
            &input.authority_ref,
            &input.object_class,
            &input.declared_names,
            &input.source_refs,
            &now,
        );
        let mut documents = materialized.documents;
        documents.push(revision);
        documents.push(object);
        self.write_documents(&documents)?;

        Ok(Registration {
            object_ref,
            revision_ref,
            content_ref: materialized.content_ref,
            location_ref: materialized.location_ref,
            reused_content: materialized.reused_content,
            reused_location: materialized.reused_location,
        })
    }

    /// Append one immutable Revision to an active logical Object.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid evidence, inactive/type-mismatched Objects,
    /// local CAS corruption, revision overflow, or durable write failure.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "A07 write commands are owned durable-boundary requests"
    )]
    pub fn append_revision(
        &mut self,
        object_id: EntityId,
        bytes: &[u8],
        input: AppendRevision,
    ) -> Result<Registration, ObjectStoreError> {
        validate_append_input(&input)?;
        let object_record = self.required_schema(object_id, OBJECT_SCHEMA_ID)?;
        let mut object = object_record.document().clone();
        if lifecycle_state(&object)? != "active" {
            return Err(ObjectStoreError::InvalidInput("Object is not active"));
        }
        let object_ref = document_ref(&object)?;
        let workspace_ref = envelope_ref(&object, "workspace_ref")?;
        self.require_receipt_kinds(
            &workspace_ref,
            &input.production_correlation,
            &["output_observation", "hash_verification", "operation_observation"],
        )?;
        let current_revision_refs = field_refs(&object, "revision_refs")?;
        let revision_number = u64::try_from(current_revision_refs.len())
            .map_err(|_| ObjectStoreError::RevisionOverflow)?
            .checked_add(1)
            .ok_or(ObjectStoreError::RevisionOverflow)?;
        let revision_ref = EntityRef::new(REVISION_KIND)?;
        let scope_ref = dedup_scope_ref(
            input.deduplication_scope,
            &workspace_ref,
            &object_ref,
            input.deduplication_scope_ref.as_ref(),
        )?;
        let now = (self.clock)();
        let materialized = self.materialize_content(
            bytes,
            MaterializeInput {
                workspace_ref: &workspace_ref,
                authority_ref: &input.authority_ref,
                deduplication_scope: input.deduplication_scope,
                deduplication_scope_ref: scope_ref.as_ref(),
                media_type_claim: input.media_type_claim.as_deref(),
                producer_ref: &input.producer_ref,
                producer_version: &input.producer_version,
                backend_ref: &input.backend_ref,
                connection_ref: &input.connection_ref,
                production_correlation: &input.production_correlation,
                now: &now,
            },
        )?;
        let parent_refs = vec![field_ref(&object, "current_revision_ref")?];
        let mut revision = revision_document(
            &revision_ref,
            &object_ref,
            revision_number,
            &workspace_ref,
            &input.authority_ref,
            input.revision_role,
            input.origin_class,
            &input.source_refs,
            &materialized.content_ref,
            &input.production_correlation,
            &input.created_reason,
            &self.receipt_refs_for_kind(&input.production_correlation, "hash_verification")?,
            &now,
        );
        revision
            .as_object_mut()
            .ok_or(ObjectStoreError::TypeMismatch)?
            .insert("parent_revision_refs".to_owned(), json!(parent_refs));
        append_ref(&mut object, "revision_refs", revision_ref.clone())?;
        set_ref(&mut object, "current_revision_ref", revision_ref.clone())?;
        bump_envelope(&mut object, &input.authority_ref, &now)?;

        let mut documents = materialized.documents;
        documents.push(revision);
        documents.push(object);
        self.write_documents(&documents)?;

        Ok(Registration {
            object_ref,
            revision_ref,
            content_ref: materialized.content_ref,
            location_ref: materialized.location_ref,
            reused_content: materialized.reused_content,
            reused_location: materialized.reused_location,
        })
    }

    /// Verify one local CAS Location by independent byte readback and SHA-256.
    ///
    /// Verification is a separate dimension from Location availability. A07
    /// retains an immutable `storage.verification` record and then advances the
    /// mutable Location projection to `verified` or `failed`.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid evidence, non-CAS locations, malformed
    /// canonical records, or durable write failure.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "A07 write commands are owned durable-boundary requests"
    )]
    pub fn verify_location(
        &mut self,
        location_id: EntityId,
        input: VerifyLocation,
    ) -> Result<VerificationResult, ObjectStoreError> {
        require_text(&input.verifier_version, "verifier_version")?;
        let location_record = self.required_schema(location_id, LOCATION_SCHEMA_ID)?;
        let mut location = location_record.document().clone();
        if field_string(&location, "location_kind")? != "local_cas" {
            return Err(ObjectStoreError::UnsupportedLocation);
        }
        let workspace_ref = envelope_ref(&location, "workspace_ref")?;
        self.require_receipt_kinds(
            &workspace_ref,
            &input.production_correlation,
            &["readback", "hash_verification", "operation_observation"],
        )?;
        let content_ref = field_ref(&location, "content_ref")?;
        let content = self.required_schema(content_ref.entity_id, CONTENT_SCHEMA_ID)?;
        let expected_digest = field_value(content.document(), "canonical_digest")?.clone();
        let expected_digest_text = digest_text(&expected_digest)?;
        let expected_size = field_u64(content.document(), "byte_size")?;
        let path = self.location_path(&location)?;
        let readback = readback(&path);
        let (outcome, observed_digest, observed_size, health_state, verification_state) =
            match readback {
                Ok(bytes) => {
                    let observed_size = u64::try_from(bytes.len())
                        .map_err(|_| ObjectStoreError::InvalidInput("content size overflow"))?;
                    let observed = qualified_sha256(&bytes);
                    if observed_size != expected_size {
                        (
                            "size_mismatch",
                            Some(observed),
                            Some(observed_size),
                            "corrupt",
                            "failed",
                        )
                    } else if digest_text(&observed)? != expected_digest_text {
                        (
                            "digest_mismatch",
                            Some(observed),
                            Some(observed_size),
                            "corrupt",
                            "failed",
                        )
                    } else {
                        (
                            "verified",
                            Some(observed),
                            Some(observed_size),
                            "healthy",
                            "verified",
                        )
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    ("missing", None, None, "missing", "failed")
                }
                Err(_) => ("unreadable", None, None, "degraded", "failed"),
            };
        let now = (self.clock)();
        let verification_ref = EntityRef::new(STORAGE_VERIFICATION_KIND)?;
        let location_ref = document_ref(&location)?;
        let verification = storage_verification_document(
            &verification_ref,
            &content_ref,
            &location_ref,
            &expected_digest,
            expected_size,
            observed_digest.as_ref(),
            observed_size,
            outcome,
            &input,
            &workspace_ref,
            &now,
        );
        let observation_ref = EntityRef::new(LOCATION_OBSERVATION_KIND)?;
        let observation = location_observation_document(
            &observation_ref,
            &location_ref,
            lifecycle_state(&location)?,
            health_state,
            observed_size,
            observed_digest.as_ref(),
            &input.verifier_ref,
            &input.verifier_version,
            &input.production_correlation.receipt_refs,
            &input.authority_ref,
            &workspace_ref,
            &now,
        );
        append_ref(&mut location, "verification_refs", verification_ref.clone())?;
        append_ref(&mut location, "observation_refs", observation_ref)?;
        append_refs(
            &mut location,
            "receipt_refs",
            &input.production_correlation.receipt_refs,
        )?;
        set_string(&mut location, "health_state", health_state)?;
        set_string(&mut location, "verification_state", verification_state)?;
        set_string(&mut location, "last_observed_at", &now)?;
        if verification_state == "verified" {
            set_string(&mut location, "last_verified_at", &now)?;
        }
        bump_envelope(&mut location, &input.authority_ref, &now)?;
        self.write_documents(&[verification, observation, location])?;
        Ok(VerificationResult {
            verification_ref,
            outcome: outcome.to_owned(),
            location_verification_state: verification_state.to_owned(),
        })
    }
}
