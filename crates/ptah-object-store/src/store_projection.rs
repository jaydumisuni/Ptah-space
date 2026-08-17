use super::*;
use super::documents_entities::*;
use super::documents_model::*;
use super::documents_support::*;

impl ObjectStore {
    /// Create a first-class Relationship and immutable Relationship Revision.
    /// Participating logical Objects are updated only by adding the Relationship
    /// reference; endpoints/type remain immutable in the Relationship Revision.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid evidence/input, missing Objects, or durable
    /// write failure.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "A07 write commands are owned durable-boundary requests"
    )]
    pub fn create_relationship(
        &mut self,
        input: CreateRelationship,
    ) -> Result<EntityRef, ObjectStoreError> {
        require_key(&input.relationship_type, "relationship_type")?;
        if input.subject_refs.is_empty() || input.object_refs.is_empty() {
            return Err(ObjectStoreError::InvalidInput(
                "relationship subjects/objects must not be empty",
            ));
        }
        self.require_receipt_kinds(
            &input.workspace_ref,
            &input.production_correlation,
            &["output_observation", "operation_observation"],
        )?;
        let now = (self.clock)();
        let relationship_ref = EntityRef::new(RELATIONSHIP_KIND)?;
        let revision_ref = EntityRef::new(RELATIONSHIP_REVISION_KIND)?;
        let revision = relationship_revision_document(
            &revision_ref,
            &relationship_ref,
            &input,
            &now,
        );
        let relationship = relationship_document(
            &relationship_ref,
            &revision_ref,
            &input.workspace_ref,
            &input.authority_ref,
            &now,
        );
        let mut documents = vec![revision, relationship];
        let mut seen = BTreeSet::new();
        for object_ref in &input.object_refs {
            if !seen.insert(object_ref.entity_id.to_string()) {
                continue;
            }
            let record = self.required_schema(object_ref.entity_id, OBJECT_SCHEMA_ID)?;
            if envelope_ref(record.document(), "workspace_ref")? != input.workspace_ref {
                return Err(ObjectStoreError::InvalidInput(
                    "Relationship Object belongs to another Workspace",
                ));
            }
            let mut object = record.document().clone();
            append_ref(&mut object, "relationship_refs", relationship_ref.clone())?;
            bump_envelope(&mut object, &input.authority_ref, &now)?;
            documents.push(object);
        }
        self.write_documents(&documents)?;
        Ok(relationship_ref)
    }

    /// Promote exact immutable Object Revisions into one durable Artifact role.
    /// Artifact promotion does not imply independent verification, review,
    /// acceptance or release eligibility.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid evidence/input, missing revisions, or durable
    /// write failure.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "A07 write commands are owned durable-boundary requests"
    )]
    pub fn promote_artifact(
        &mut self,
        input: PromoteArtifact,
    ) -> Result<EntityRef, ObjectStoreError> {
        require_key(&input.artifact_type, "artifact_type")?;
        require_text(&input.artifact_version, "artifact_version")?;
        require_text(&input.purpose, "purpose")?;
        if input.promoted_revision_refs.is_empty() {
            return Err(ObjectStoreError::InvalidInput(
                "promoted_revision_refs must not be empty",
            ));
        }
        self.require_receipt_kinds(
            &input.workspace_ref,
            &input.production_correlation,
            &["output_observation", "operation_observation"],
        )?;
        let now = (self.clock)();
        let artifact_ref = EntityRef::new(ARTIFACT_KIND)?;
        let artifact = artifact_document(&artifact_ref, &input, &now);
        let mut documents = vec![artifact];
        let mut object_ids = BTreeSet::new();
        for revision_ref in &input.promoted_revision_refs {
            let record = self.required_schema(revision_ref.entity_id, REVISION_SCHEMA_ID)?;
            if envelope_ref(record.document(), "workspace_ref")? != input.workspace_ref {
                return Err(ObjectStoreError::InvalidInput(
                    "promoted Revision belongs to another Workspace",
                ));
            }
            let object_ref = field_ref(record.document(), "object_ref")?;
            object_ids.insert(object_ref.entity_id.to_string());
        }
        for object_id in object_ids {
            let object_id = object_id
                .parse::<EntityId>()
                .map_err(ObjectStoreError::Identifier)?;
            let record = self.required_schema(object_id, OBJECT_SCHEMA_ID)?;
            let mut object = record.document().clone();
            append_ref(&mut object, "artifact_refs", artifact_ref.clone())?;
            bump_envelope(&mut object, &input.authority_ref, &now)?;
            documents.push(object);
        }
        self.write_documents(&documents)?;
        Ok(artifact_ref)
    }

    /// Read one exact local CAS path for a registered Location.
    ///
    /// # Errors
    ///
    /// Returns an error when the Location is absent, malformed, or not local CAS.
    pub fn local_cas_path(&self, location_id: EntityId) -> Result<PathBuf, ObjectStoreError> {
        let location = self.required_schema(location_id, LOCATION_SCHEMA_ID)?;
        if field_string(location.document(), "location_kind")? != "local_cas" {
            return Err(ObjectStoreError::UnsupportedLocation);
        }
        self.location_path(location.document())
    }

    pub(super) fn materialize_content(
        &self,
        bytes: &[u8],
        input: MaterializeInput<'_>,
    ) -> Result<MaterializedContent, ObjectStoreError> {
        let digest = qualified_sha256(bytes);
        let digest_text = digest_text(&digest)?;
        let byte_size = u64::try_from(bytes.len())
            .map_err(|_| ObjectStoreError::InvalidInput("content size overflow"))?;
        let cas_path = self.publish_cas(bytes, &digest_text)?;
        let existing_content = self.find_content(
            &digest_text,
            byte_size,
            input.deduplication_scope,
            input.deduplication_scope_ref,
        )?;
        let (content_ref, reused_content, mut documents) = match existing_content {
            Some(reference) => (reference, true, Vec::new()),
            None => {
                let content_ref = EntityRef::new(CONTENT_KIND)?;
                let observation_ref = EntityRef::new(HASH_OBSERVATION_KIND)?;
                let verification_receipts = self.receipt_refs_for_kind(
                    input.production_correlation,
                    "hash_verification",
                )?;
                let observation = hash_observation_document(
                    &observation_ref,
                    &content_ref,
                    &digest,
                    byte_size,
                    input.producer_ref,
                    input.producer_version,
                    input.production_correlation,
                    input.authority_ref,
                    input.workspace_ref,
                    input.now,
                );
                let content = content_document(
                    &content_ref,
                    &observation_ref,
                    &digest,
                    byte_size,
                    &input,
                    &verification_receipts,
                );
                (content_ref, false, vec![observation, content])
            }
        };
        let existing_location = self.find_local_location(&content_ref, &digest_text)?;
        let (location_ref, reused_location) = match existing_location {
            Some(reference) => (reference, true),
            None => {
                let location_ref = EntityRef::new(LOCATION_KIND)?;
                let observation_ref = EntityRef::new(LOCATION_OBSERVATION_KIND)?;
                let relative = cas_path
                    .strip_prefix(&self.cas_root)
                    .unwrap_or(&cas_path)
                    .to_string_lossy()
                    .replace('\\', "/");
                let observation = location_observation_document(
                    &observation_ref,
                    &location_ref,
                    "available",
                    "healthy",
                    Some(byte_size),
                    None,
                    input.producer_ref,
                    input.producer_version,
                    &input.production_correlation.receipt_refs,
                    input.authority_ref,
                    input.workspace_ref,
                    input.now,
                );
                let location = location_document(
                    &location_ref,
                    &content_ref,
                    &observation_ref,
                    &relative,
                    byte_size,
                    &input,
                );
                documents.push(observation);
                documents.push(location);
                (location_ref, false)
            }
        };
        Ok(MaterializedContent {
            content_ref,
            location_ref,
            reused_content,
            reused_location,
            documents,
        })
    }
}
