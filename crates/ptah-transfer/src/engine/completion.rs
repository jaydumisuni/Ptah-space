use super::{
    AcceptedOutputRefs, CONTENT_SCHEMA_ID, DigestValue, DomainResultState, EntityId, EntityRef,
    File, Path, ProviderAcknowledgement, TRANSFER_RUN_SCHEMA_ID, TransferEngine, TransferError,
    TransferEvidence, TransferMode, TransferVerificationReport, Value, VerificationDomain,
    VerificationDomainResult, append_ref, bump, canonicalize_root, copy_synced, document_ref,
    ensure_mode, ensure_run_state, expected_canonical_sha256, field_ref, fs, is_current_attempt,
    json, latest_document, partial_path, report_from_verification, safe_relative_path, same_ref,
    scope_from_document, set_lifecycle, sha256_reader, sync_directory, unique_refs,
    validate_execution, verification_document, verification_state_for_request,
    verified_transfer_domains, write_documents,
};

impl TransferEngine {
    /// Record provider transport acknowledgement without promoting it to completion.
    ///
    /// Positive acknowledgement moves the Run to `verifying`; uncertain provider
    /// finalize state moves it to `uncertain`. Neither path creates accepted output.
    ///
    /// # Errors
    /// Rejects unrelated A04 evidence or invalid lifecycle state.
    #[allow(clippy::needless_pass_by_value)]
    pub fn acknowledge_transport(
        &mut self,
        run_id: EntityId,
        acknowledgement: ProviderAcknowledgement,
        evidence: TransferEvidence,
    ) -> Result<(), TransferError> {
        let mut run = latest_document(&self.ledger, run_id, TRANSFER_RUN_SCHEMA_ID)?;
        ensure_run_state(&run, &["transferring"])?;
        let request_ref = field_ref(&run, "request_ref")?;
        let (workspace_ref, authority_ref) = scope_from_document(&run)?;
        let execution = validate_execution(
            &self.ledger,
            &workspace_ref,
            &authority_ref,
            &evidence,
            &["output_observation"],
            Some(&request_ref),
        )?;
        if !same_ref(&execution.operation_ref, &field_ref(&run, "operation_ref")?)
            || !is_current_attempt(&run, &execution.attempt_ref)?
        {
            return Err(TransferError::ExecutionEvidenceMismatch);
        }
        for receipt in execution.receipt_refs {
            append_ref(&mut run, "receipt_refs", receipt)?;
        }
        let now = self.now()?;
        match acknowledgement {
            ProviderAcknowledgement::Acknowledged => set_lifecycle(&mut run, "verifying", &now)?,
            ProviderAcknowledgement::Uncertain => set_lifecycle(&mut run, "uncertain", &now)?,
        }
        write_documents(&mut self.ledger, &[run])?;
        Ok(())
    }

    /// Verify a download partial, materialize it under a caller-declared safe root,
    /// and read the materialized destination back before atomic promotion.
    ///
    /// This method never registers A07 Content/Object/Location truth. The Run stays
    /// `verifying` after success until independently accepted A07 output references
    /// are bound through [`Self::complete_with_accepted_output`].
    ///
    /// # Errors
    /// Digest/size/read-back failure is retained as a negative Transfer Verification
    /// and leaves partial/quarantined bytes rather than manufacturing success.
    #[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
    pub fn verify_and_materialize_download(
        &mut self,
        run_id: EntityId,
        destination_root: impl AsRef<Path>,
        relative_path: impl AsRef<Path>,
        evidence: TransferEvidence,
    ) -> Result<TransferVerificationReport, TransferError> {
        let mut run = latest_document(&self.ledger, run_id, TRANSFER_RUN_SCHEMA_ID)?;
        ensure_run_state(&run, &["verifying", "uncertain"])?;
        ensure_mode(&run, TransferMode::Download)?;
        let run_ref = document_ref(&run)?;
        let (workspace_ref, authority_ref) = scope_from_document(&run)?;
        let execution = validate_execution(
            &self.ledger,
            &workspace_ref,
            &authority_ref,
            &evidence,
            &["readback", "hash_verification"],
            Some(&run_ref),
        )?;
        let request = self.request_from_run(&run)?;
        let ranges = self.latest_ranges(&run)?;
        let verified_ranges = self.verify_partial_ranges(&run_ref, &ranges)?;
        let partial = partial_path(&self.staging_root, &run_ref);
        let (partial_digest, partial_size) = sha256_reader(File::open(&partial)?)?;
        if verified_ranges != partial_size {
            return self.retain_failed_verification(
                run,
                run_ref,
                workspace_ref,
                authority_ref,
                execution,
                &request,
                partial_digest,
                partial_size,
                None,
            );
        }

        let expected_sha = expected_canonical_sha256(&request.source)?;
        let size_ok = request
            .source
            .expected_size
            .is_none_or(|size| size == partial_size);
        let digest_ok = expected_sha
            .as_deref()
            .is_none_or(|digest| digest == partial_digest);
        if !size_ok || !digest_ok {
            return self.retain_failed_verification(
                run,
                run_ref,
                workspace_ref,
                authority_ref,
                execution,
                &request,
                partial_digest,
                partial_size,
                None,
            );
        }

        let destination_root = canonicalize_root(destination_root.as_ref())?;
        let target = safe_relative_path(&destination_root, relative_path.as_ref())?;
        if target.exists() {
            return Err(TransferError::UnsafeDestination);
        }
        let parent = target.parent().ok_or(TransferError::UnsafeDestination)?;
        let temp = parent.join(format!(".ptah-{}.staging", run_ref.entity_id));
        if temp.exists() {
            return Err(TransferError::UnsafeDestination);
        }
        copy_synced(&partial, &temp)?;
        let (staged_digest, staged_size) = sha256_reader(File::open(&temp)?)?;
        if staged_digest != partial_digest || staged_size != partial_size {
            return self.retain_failed_verification(
                run,
                run_ref,
                workspace_ref,
                authority_ref,
                execution,
                &request,
                staged_digest,
                staged_size,
                Some(temp),
            );
        }
        fs::rename(&temp, &target)?;
        sync_directory(parent)?;
        let (destination_digest, destination_size) = sha256_reader(File::open(&target)?)?;
        if destination_digest != partial_digest || destination_size != partial_size {
            let quarantine = parent.join(format!(".ptah-{}.quarantine", run_ref.entity_id));
            let _ = fs::rename(&target, &quarantine);
            return self.retain_failed_verification(
                run,
                run_ref,
                workspace_ref,
                authority_ref,
                execution,
                &request,
                destination_digest,
                destination_size,
                Some(quarantine),
            );
        }

        let domain_results = verified_transfer_domains(
            &request,
            &execution,
            expected_sha.clone(),
            &destination_digest,
            destination_size,
            true,
        );
        let verification_state = verification_state_for_request(&request, &domain_results);
        let verification_ref = EntityRef::new("transfer.verification")?;
        let now = self.now()?;
        let verification = verification_document(
            &verification_ref,
            &run_ref,
            &workspace_ref,
            &authority_ref,
            &self.config,
            &execution,
            verification_state,
            &domain_results,
            None,
            &[],
            &now,
        );
        append_ref(&mut run, "verification_refs", verification_ref.clone())?;
        for receipt in &execution.receipt_refs {
            append_ref(&mut run, "receipt_refs", receipt.clone())?;
        }
        bump(&mut run, &now)?;
        write_documents(&mut self.ledger, &[verification, run])?;
        Ok(report_from_verification(
            run_ref,
            verification_ref,
            verification_state.to_owned(),
            expected_sha,
            destination_digest,
            destination_size,
            Some(target),
        ))
    }

    /// Bind independently accepted A07 output references and complete a verified Run.
    ///
    /// A08 validates that Content, Revision and Location exist in the same Workspace,
    /// name the same Content, and that the Location is already `verified`. It does not
    /// create or repair those A07 records.
    ///
    /// # Errors
    /// Rejects missing/unverified A07 truth, incomplete requested verification domains,
    /// unrelated A04 completion evidence, or invalid lifecycle state.
    #[allow(clippy::needless_pass_by_value)]
    pub fn complete_with_accepted_output(
        &mut self,
        run_id: EntityId,
        accepted: AcceptedOutputRefs,
        evidence: TransferEvidence,
    ) -> Result<(), TransferError> {
        let mut run = latest_document(&self.ledger, run_id, TRANSFER_RUN_SCHEMA_ID)?;
        ensure_run_state(&run, &["verifying"])?;
        let run_ref = document_ref(&run)?;
        let (workspace_ref, authority_ref) = scope_from_document(&run)?;
        let execution = validate_execution(
            &self.ledger,
            &workspace_ref,
            &authority_ref,
            &evidence,
            &["output_observation"],
            Some(&run_ref),
        )?;
        self.validate_accepted_output(&workspace_ref, &accepted)?;

        let content = latest_document(
            &self.ledger,
            accepted.content_ref.entity_id,
            CONTENT_SCHEMA_ID,
        )?;
        let canonical_digest = content
            .get("canonical_digest")
            .and_then(|value| value.get("digest"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut domains = vec![
            VerificationDomainResult {
                domain: VerificationDomain::LocationRegistered,
                result: DomainResultState::Passed,
                observed_size: None,
                observed_digests: canonical_digest
                    .clone()
                    .map(DigestValue::canonical_sha256)
                    .into_iter()
                    .collect(),
                evidence_refs: vec![accepted.location_ref.clone()],
                limitations: Vec::new(),
            },
            VerificationDomainResult {
                domain: VerificationDomain::ObjectAcceptanceCompleted,
                result: DomainResultState::Passed,
                observed_size: None,
                observed_digests: canonical_digest
                    .map(DigestValue::canonical_sha256)
                    .into_iter()
                    .collect(),
                evidence_refs: vec![accepted.object_revision_ref.clone()],
                limitations: Vec::new(),
            },
        ];
        let request = self.request_from_run(&run)?;
        let mut aggregate = self.aggregate_domain_results(&run)?;
        for domain in &domains {
            aggregate.insert(domain.domain, domain.result);
        }
        if !request
            .requested_verification_domains
            .iter()
            .all(|domain| aggregate.get(domain) == Some(&DomainResultState::Passed))
        {
            return Err(TransferError::VerificationFailed);
        }

        for domain in &mut domains {
            domain.evidence_refs.extend(execution.receipt_refs.clone());
            domain.evidence_refs = unique_refs(domain.evidence_refs.clone());
        }
        let verification_ref = EntityRef::new("transfer.verification")?;
        let now = self.now()?;
        let verification = verification_document(
            &verification_ref,
            &run_ref,
            &workspace_ref,
            &authority_ref,
            &self.config,
            &execution,
            "verified",
            &domains,
            Some(&accepted),
            &[],
            &now,
        );
        append_ref(&mut run, "verification_refs", verification_ref)?;
        for receipt in &execution.receipt_refs {
            append_ref(&mut run, "receipt_refs", receipt.clone())?;
        }
        run["accepted_content_ref"] = serde_json::to_value(&accepted.content_ref)?;
        run["accepted_object_revision_ref"] = serde_json::to_value(&accepted.object_revision_ref)?;
        run["accepted_location_ref"] = serde_json::to_value(&accepted.location_ref)?;
        run["completed_at"] = json!(now);
        set_lifecycle(&mut run, "completed", &now)?;
        write_documents(&mut self.ledger, &[verification, run])
    }
}
