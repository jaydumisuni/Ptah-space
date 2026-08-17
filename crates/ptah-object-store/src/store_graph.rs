impl ObjectStore {
    /// Explicitly promote one exact Object Revision into an Artifact role.
    ///
    /// Registration never calls this method implicitly.
    ///
    /// # Errors
    /// Fails if the Revision/evidence/workspace does not match canonical truth.
    pub fn promote_artifact(
        &mut self,
        revision_id: EntityId,
        spec: ArtifactPromotionSpec,
    ) -> Result<EntityRef, ObjectStoreError> {
        require_non_empty(&spec.artifact_type, "artifact_type")?;
        require_non_empty(&spec.artifact_version, "artifact_version")?;
        require_non_empty(&spec.purpose, "purpose")?;
        let validated = self.validate_production(
            &spec.workspace_ref,
            &spec.production,
            &["output_observation"],
        )?;
        let revision = self.latest_document(revision_id, REVISION_SCHEMA_ID)?;
        ensure_workspace(&revision, &spec.workspace_ref)?;
        let revision_correlation = revision
            .get("production_correlation")
            .ok_or(ObjectStoreError::ProductionEvidenceMismatch)?;
        if !same_production_identity(revision_correlation, &validated.correlation)? {
            return Err(ObjectStoreError::ProductionEvidenceMismatch);
        }
        let object_ref = field_ref(&revision, "object_ref")?;
        let mut object = self.latest_document(object_ref.entity_id, OBJECT_SCHEMA_ID)?;
        ensure_workspace(&object, &spec.workspace_ref)?;

        let artifact_ref = EntityRef::new(ARTIFACT_KIND)?;
        let now = (self.clock)();
        let mut subjects = spec.subject_refs.clone();
        append_unique_ref(&mut subjects, object_ref.clone());

        let draft = artifact_document(
            &artifact_ref,
            revision_id,
            &subjects,
            &spec,
            &validated,
            "draft",
            1,
            1,
            &now,
        )?;
        let promoted = artifact_document(
            &artifact_ref,
            revision_id,
            &subjects,
            &spec,
            &validated,
            "promoted",
            2,
            2,
            &now,
        )?;
        append_document_ref(&mut object, "artifact_refs", artifact_ref.clone())?;
        bump_document(&mut object, &now)?;

        self.write_documents(&[draft, promoted, object])?;
        Ok(artifact_ref)
    }

    /// Create the A07 Relationship identity plus immutable first Relationship Revision.
    ///
    /// # Errors
    /// Fails for invalid evidence, empty endpoints/type or projection-update conflicts.
    pub fn create_relationship(
        &mut self,
        spec: RelationshipSpec,
    ) -> Result<EntityRef, ObjectStoreError> {
        require_non_empty(&spec.relationship_type, "relationship_type")?;
        if spec.subject_refs.is_empty() {
            return Err(ObjectStoreError::EmptyField("subject_refs"));
        }
        if spec.object_refs.is_empty() {
            return Err(ObjectStoreError::EmptyField("object_refs"));
        }
        let validated = self.validate_production(
            &spec.workspace_ref,
            &spec.production,
            &["output_observation"],
        )?;
        let relationship_ref = EntityRef::new(RELATIONSHIP_KIND)?;
        let relationship_revision_ref = EntityRef::new(RELATIONSHIP_REVISION_KIND)?;
        let now = (self.clock)();

        let relationship_revision = json!({
            "envelope": envelope(
                &relationship_revision_ref,
                RELATIONSHIP_REVISION_SCHEMA_ID,
                1,
                &spec.workspace_ref,
                &spec.authority_ref,
                &now,
            ),
            "relationship_revision_contract_version": A07_SCHEMA_VERSION,
            "relationship_ref": relationship_ref,
            "revision_number": 1,
            "subject_refs": unique_refs(spec.subject_refs.clone()),
            "relationship_type": spec.relationship_type,
            "object_refs": unique_refs(spec.object_refs.clone()),
            "locators": [],
            "coverage": {
                "coverage_class": "unknown",
                "complete_claim": false,
                "skipped_scope": [],
                "unknown_gaps": [],
                "limitations": []
            },
            "production_correlation": validated.correlation,
            "confidence_class": "not_applicable",
            "limitations": [],
            "extensions": {}
        });
        let relationship = json!({
            "envelope": envelope(
                &relationship_ref,
                RELATIONSHIP_SCHEMA_ID,
                1,
                &spec.workspace_ref,
                &spec.authority_ref,
                &now,
            ),
            "relationship_contract_version": A07_SCHEMA_VERSION,
            "current_revision_ref": relationship_revision_ref,
            "revision_refs": [relationship_revision_ref],
            "lifecycle": lifecycle("relationship.lifecycle", "active", 1),
            "limitations": [],
            "extensions": {}
        });

        let mut documents = vec![relationship_revision, relationship];
        let mut object_ids = HashSet::new();
        for reference in spec.subject_refs.iter().chain(spec.object_refs.iter()) {
            if reference.entity_kind.as_str() == OBJECT_KIND && object_ids.insert(reference.entity_id) {
                let mut object = self.latest_document(reference.entity_id, OBJECT_SCHEMA_ID)?;
                ensure_workspace(&object, &spec.workspace_ref)?;
                append_document_ref(&mut object, "relationship_refs", relationship_ref.clone())?;
                bump_document(&mut object, &now)?;
                documents.push(object);
            }
        }
        self.write_documents(&documents)?;
        Ok(relationship_ref)
    }

    /// Create one structured View over exact Object Revisions.
    ///
    /// # Errors
    /// Fails for invalid source Revision/evidence/workspace or projection update.
    pub fn create_view(&mut self, spec: ViewSpec) -> Result<EntityRef, ObjectStoreError> {
        require_non_empty(&spec.view_kind, "view_kind")?;
        require_non_empty(&spec.view_schema_id, "view_schema_id")?;
        require_non_empty(&spec.view_schema_version, "view_schema_version")?;
        if spec.source_revision_refs.is_empty() {
            return Err(ObjectStoreError::EmptyField("source_revision_refs"));
        }
        let validated = self.validate_production(
            &spec.workspace_ref,
            &spec.production,
            &["output_observation"],
        )?;
        let view_ref = EntityRef::new(VIEW_KIND)?;
        let now = (self.clock)();
        let view = json!({
            "envelope": envelope(
                &view_ref,
                VIEW_SCHEMA_ID,
                1,
                &spec.workspace_ref,
                &spec.authority_ref,
                &now,
            ),
            "view_contract_version": A07_SCHEMA_VERSION,
            "view_kind": spec.view_kind,
            "view_schema_id": spec.view_schema_id,
            "view_schema_version": spec.view_schema_version,
            "source_revision_refs": unique_refs(spec.source_revision_refs.clone()),
            "producer_ref": self.config.producer_ref,
            "producer_version": self.config.producer_version,
            "configuration_refs": [],
            "production_correlation": validated.correlation,
            "coverage": {
                "coverage_class": "unknown",
                "complete_claim": false,
                "skipped_scope": [],
                "unknown_gaps": [],
                "limitations": []
            },
            "serialized_revision_ref": Value::Null,
            "origin_class": spec.origin_class.as_str(),
            "warnings": [],
            "disagreement_refs": [],
            "limitations": [],
            "extensions": {}
        });

        let mut documents = vec![view];
        let mut object_ids = HashSet::new();
        for revision_ref in &spec.source_revision_refs {
            if revision_ref.entity_kind.as_str() != REVISION_KIND {
                return Err(ObjectStoreError::TypeMismatch);
            }
            let revision = self.latest_document(revision_ref.entity_id, REVISION_SCHEMA_ID)?;
            ensure_workspace(&revision, &spec.workspace_ref)?;
            let object_ref = field_ref(&revision, "object_ref")?;
            if object_ids.insert(object_ref.entity_id) {
                let mut object = self.latest_document(object_ref.entity_id, OBJECT_SCHEMA_ID)?;
                ensure_workspace(&object, &spec.workspace_ref)?;
                append_document_ref(&mut object, "view_refs", view_ref.clone())?;
                bump_document(&mut object, &now)?;
                documents.push(object);
            }
        }
        self.write_documents(&documents)?;
        Ok(view_ref)
    }
}
