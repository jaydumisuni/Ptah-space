struct CasObservation {
    outcome: &'static str,
    observed_digest: Option<String>,
    observed_size: Option<u64>,
    health: &'static str,
}

impl ObjectStore {
    /// Independently re-read and verify one local CAS Location, retaining a
    /// Storage Verification and fresh Location Observation.
    ///
    /// The command specification is consumed as one bounded verification request.
    ///
    /// # Errors
    /// Fails for invalid evidence/workspace, a Location bound to a different
    /// configured backend/connection, or ledger/I/O errors. Integrity mismatch
    /// is returned as a negative report rather than manufactured success.
    #[allow(clippy::needless_pass_by_value)]
    pub fn verify_location(
        &mut self,
        location_id: EntityId,
        spec: VerificationSpec,
    ) -> Result<VerificationReport, ObjectStoreError> {
        let validated = self.validate_production(
            &spec.workspace_ref,
            &spec.authority_ref,
            &spec.production,
            &["readback"],
        )?;
        let mut location = self.latest_document(location_id, LOCATION_SCHEMA_ID)?;
        ensure_workspace(&location, &spec.workspace_ref)?;
        if field_string(&location, "location_kind")? != "local_cas" {
            return Err(ObjectStoreError::TypeMismatch);
        }
        let location_ref = document_ref(&location)?;
        if !validated
            .logical_target_refs
            .iter()
            .any(|reference| same_ref(reference, &location_ref))
        {
            return Err(ObjectStoreError::ProductionEvidenceMismatch);
        }
        ensure_location_binding(&location, &self.config)?;
        let content_ref = field_ref(&location, "content_ref")?;
        let content = self.latest_document(content_ref.entity_id, CONTENT_SCHEMA_ID)?;
        ensure_workspace(&content, &spec.workspace_ref)?;
        let expected_digest = content
            .get("canonical_digest")
            .and_then(|value| value.get("digest"))
            .and_then(Value::as_str)
            .ok_or(ObjectStoreError::TypeMismatch)?
            .to_owned();
        let expected_size = field_u64(&content, "byte_size")?;
        let object_key = location_object_key(&location)?;
        let target = self.cas_path(&object_key)?;
        let observed = observe_cas(&self.cas_root, &target, &expected_digest, expected_size)?;

        let now = self.now()?;
        let verification_ref = EntityRef::new(STORAGE_VERIFICATION_KIND)?;
        let observation_ref = EntityRef::new(LOCATION_OBSERVATION_KIND)?;
        let verification = storage_verification_document(
            &verification_ref,
            &content_ref,
            &location_ref,
            &expected_digest,
            expected_size,
            observed.observed_digest.as_deref(),
            observed.observed_size,
            observed.outcome,
            &spec,
            &self.config,
            &validated,
            &now,
        );
        let observation = verification_location_observation_document(
            &observation_ref,
            &location_ref,
            observed.observed_size,
            observed.observed_digest.as_deref(),
            &object_key,
            observed.health,
            &spec,
            &self.config,
            &validated,
            &now,
        );

        append_document_ref(&mut location, "verification_refs", verification_ref.clone())?;
        append_document_ref(&mut location, "observation_refs", observation_ref)?;
        append_document_refs(&mut location, "receipt_refs", &validated.receipt_refs)?;
        set_string(
            &mut location,
            "verification_state",
            if observed.outcome == "verified" {
                "verified"
            } else {
                "failed"
            },
        )?;
        set_string(&mut location, "health_state", observed.health)?;
        set_string(&mut location, "last_verified_at", &now)?;
        set_string(&mut location, "last_observed_at", &now)?;
        bump_document(&mut location, &now)?;
        self.write_documents(&[verification, observation, location])?;

        Ok(VerificationReport {
            verification_ref,
            location_ref,
            outcome: observed.outcome.to_owned(),
            expected_sha256: expected_digest,
            observed_sha256: observed.observed_digest,
            expected_size,
            observed_size: observed.observed_size,
        })
    }
}

fn observe_cas(
    cas_root: &Path,
    target: &Path,
    expected_digest: &str,
    expected_size: u64,
) -> Result<CasObservation, ObjectStoreError> {
    if !cas_parent_hierarchy_exists_and_is_safe(cas_root, target)? {
        return Ok(CasObservation {
            outcome: "missing",
            observed_digest: None,
            observed_size: None,
            health: "missing",
        });
    }
    match fs::symlink_metadata(target) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Ok(CasObservation {
                outcome: "unreadable",
                observed_digest: None,
                observed_size: None,
                health: "corrupt",
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(CasObservation {
                outcome: "missing",
                observed_digest: None,
                observed_size: None,
                health: "missing",
            });
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return Ok(CasObservation {
                outcome: "permission_denied",
                observed_digest: None,
                observed_size: None,
                health: "degraded",
            });
        }
        Err(error) => return Err(error.into()),
    }

    match fs::read(target) {
        Ok(bytes) => {
            let observed_digest = ObjectStore::sha256(&bytes);
            let observed_size =
                u64::try_from(bytes.len()).map_err(|_| ObjectStoreError::RevisionOverflow)?;
            let (outcome, health) = if observed_digest != expected_digest {
                ("digest_mismatch", "corrupt")
            } else if observed_size != expected_size {
                ("size_mismatch", "corrupt")
            } else {
                ("verified", "healthy")
            };
            Ok(CasObservation {
                outcome,
                observed_digest: Some(observed_digest),
                observed_size: Some(observed_size),
                health,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(CasObservation {
            outcome: "missing",
            observed_digest: None,
            observed_size: None,
            health: "missing",
        }),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(CasObservation {
            outcome: "permission_denied",
            observed_digest: None,
            observed_size: None,
            health: "degraded",
        }),
        Err(error) => Err(error.into()),
    }
}
