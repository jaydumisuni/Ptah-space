use super::{
    ATTEMPT_SCHEMA_ID, AcceptedOutputRefs, CONTENT_SCHEMA_ID, DomainResultState, EVENT_ENTITY_KIND,
    EntityId, EntityRef, EventClass, EventPayload, EventSpec, File, HashMap, LOCATION_SCHEMA_ID,
    OpenOptions, PathBuf, ProgressReport, REVISION_SCHEMA_ID, RangeRecord, Read, Seek, SeekFrom,
    StartTransferSpec, TRANSFER_MANIFEST_SCHEMA_ID, TRANSFER_REQUEST_SCHEMA_ID,
    TRANSFER_VERIFICATION_SCHEMA_ID, TransferEngine, TransferError, TransferEvidence, TransferMode,
    TransferRequestSpec, TransferRunHandle, TransferVerificationReport, ValidatedExecution, Value,
    VerificationDomain, append_ref, bump, document_ref, ensure_request_state, ensure_workspace,
    expected_canonical_sha256, failed_transfer_domains, field_ref, field_refs, field_string, fs,
    latest_document, manifest_document, partial_path, progress_document, range_from_value,
    request_accepted_document, request_spec_from_document, same_ref, scope_from_document,
    set_lifecycle, sha256_bytes, transfer_run_document, utc_shape, validate_execution,
    validate_start_spec, verification_document, write_documents,
};

impl TransferEngine {
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn start_run(
        &mut self,
        request_id: EntityId,
        evidence: TransferEvidence,
        spec: StartTransferSpec,
        expected_mode: TransferMode,
        create_partial: bool,
    ) -> Result<TransferRunHandle, TransferError> {
        validate_start_spec(&spec)?;
        let request_document =
            latest_document(&self.ledger, request_id, TRANSFER_REQUEST_SCHEMA_ID)?;
        ensure_request_state(&request_document, &["submitted", "validating"])?;
        let request_ref = document_ref(&request_document)?;
        let request = request_spec_from_document(&request_document)?;
        if request.transfer_mode != expected_mode
            || !same_ref(
                &request.destination.provider_instance_ref,
                &self.config.provider_instance_ref,
            )
        {
            return Err(TransferError::TypeMismatch);
        }
        let execution = validate_execution(
            &self.ledger,
            &request.workspace_ref,
            &request.authority_ref,
            &evidence,
            &["request_acknowledgement", "work_dispatch"],
            Some(&request_ref),
        )?;
        if !same_ref(&execution.provider_ref, &self.config.provider_ref)
            || !same_ref(
                &execution.provider_instance_ref,
                &self.config.provider_instance_ref,
            )
            || execution.provider_generation != self.config.provider_generation
            || execution.connection_epoch != self.config.connection_epoch
        {
            return Err(TransferError::ResumeMismatch);
        }

        let run_ref = EntityRef::new("transfer.run")?;
        let manifest_ref = EntityRef::new("transfer.manifest")?;
        let now = self.now()?;
        let accepted_request = request_accepted_document(&request_document, &execution, &now)?;
        let partial = partial_path(&self.staging_root, &run_ref);
        if create_partial {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&partial)?;
            file.sync_all()?;
        }
        let manifest = manifest_document(
            &manifest_ref,
            &run_ref,
            &request,
            &self.config,
            &execution,
            &spec.idempotency_key,
            &spec.compression_mode,
            &spec.encryption_mode,
            spec.chunk_size,
            &now,
        );
        let queued = transfer_run_document(
            &run_ref,
            &request_ref,
            &request,
            &execution,
            &spec.idempotency_key,
            &manifest_ref,
            "queued",
            1,
            &now,
        );
        let mut preparing = queued.clone();
        set_lifecycle(&mut preparing, "preparing", &now)?;
        let mut transferring = preparing.clone();
        set_lifecycle(&mut transferring, "transferring", &now)?;
        if let Err(error) = write_documents(
            &mut self.ledger,
            &[accepted_request, manifest, queued, preparing, transferring],
        ) {
            if create_partial {
                let _ = fs::remove_file(&partial);
            }
            return Err(error);
        }
        Ok(TransferRunHandle {
            run_ref,
            manifest_ref,
            partial_path: partial,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn write_progress(
        &mut self,
        run: &mut Value,
        run_ref: &EntityRef,
        workspace_ref: &EntityRef,
        authority_ref: &EntityRef,
        execution: &ValidatedExecution,
        expected_size: Option<u64>,
        bytes_received: u64,
        bytes_verified: u64,
        bytes_acknowledged: u64,
        ranges: &[RangeRecord],
    ) -> Result<ProgressReport, TransferError> {
        let now = self.now()?;
        let snapshot_ref = EntityRef::new("transfer.progress_snapshot")?;
        let event = self.event_bus.emit(EventSpec {
            event_type: "transfer.progress_snapshot".to_owned(),
            event_class: EventClass::LedgerDerived,
            source_ref: self.config.producer_ref.clone(),
            subject_ref: snapshot_ref.clone(),
            activity_ref: Some(execution.activity_ref.clone()),
            operation_ref: Some(execution.operation_ref.clone()),
            attempt_ref: Some(execution.attempt_ref.clone()),
            sequence_scope_ref: run_ref.clone(),
            occurred_at: now.clone(),
            payload: EventPayload::none(),
            receipt_ref: None,
        })?;
        let event_ref = EntityRef::from_id(event.id(), EVENT_ENTITY_KIND)?;
        let bytes_received_unverified = bytes_received
            .checked_sub(bytes_verified)
            .ok_or(TransferError::AccountingOverflow)?;
        let snapshot = progress_document(
            &snapshot_ref,
            run_ref,
            workspace_ref,
            authority_ref,
            execution,
            expected_size,
            bytes_received_unverified,
            bytes_verified,
            ranges,
            bytes_acknowledged,
            std::slice::from_ref(&event_ref),
            &now,
            &now,
        );
        append_ref(run, "progress_snapshot_refs", snapshot_ref.clone())?;
        bump(run, &now)?;
        let event_document = event.canonical_document();
        write_documents(&mut self.ledger, &[event_document, snapshot, run.clone()])?;
        Ok(ProgressReport {
            snapshot_ref,
            bytes_received_unverified,
            bytes_verified,
        })
    }

    pub(super) fn execution_from_run(
        &self,
        run: &Value,
    ) -> Result<ValidatedExecution, TransferError> {
        let request_ref = field_ref(run, "request_ref")?;
        let (workspace_ref, authority_ref) = scope_from_document(run)?;
        let attempt_refs = field_refs(run, "attempt_refs")?;
        let attempt_ref = attempt_refs
            .last()
            .cloned()
            .ok_or(TransferError::ExecutionEvidenceMismatch)?;
        let attempt = latest_document(&self.ledger, attempt_ref.entity_id, ATTEMPT_SCHEMA_ID)?;
        let mut positive_receipts = Vec::new();
        for receipt_ref in field_refs(&attempt, "receipt_refs")? {
            let receipt = latest_document(
                &self.ledger,
                receipt_ref.entity_id,
                crate::util::RECEIPT_SCHEMA_ID,
            )?;
            if field_string(&receipt, "receipt_outcome")? == "positive" {
                positive_receipts.push(receipt_ref);
            }
        }
        let evidence = TransferEvidence {
            activity_ref: field_ref(run, "activity_ref")?,
            operation_ref: field_ref(run, "operation_ref")?,
            attempt_ref,
            receipt_refs: positive_receipts,
        };
        validate_execution(
            &self.ledger,
            &workspace_ref,
            &authority_ref,
            &evidence,
            &[],
            Some(&request_ref),
        )
    }

    pub(super) fn request_from_run(
        &self,
        run: &Value,
    ) -> Result<TransferRequestSpec, TransferError> {
        let request_ref = field_ref(run, "request_ref")?;
        let request = latest_document(
            &self.ledger,
            request_ref.entity_id,
            TRANSFER_REQUEST_SCHEMA_ID,
        )?;
        request_spec_from_document(&request)
    }

    pub(super) fn manifest_from_run(&self, run: &Value) -> Result<Value, TransferError> {
        let refs = field_refs(run, "manifest_refs")?;
        let reference = refs.last().ok_or(TransferError::TypeMismatch)?;
        latest_document(
            &self.ledger,
            reference.entity_id,
            TRANSFER_MANIFEST_SCHEMA_ID,
        )
    }

    pub(super) fn latest_ranges(&self, run: &Value) -> Result<Vec<RangeRecord>, TransferError> {
        let refs = field_refs(run, "progress_snapshot_refs")?;
        let Some(reference) = refs.last() else {
            return Ok(Vec::new());
        };
        let snapshot = latest_document(
            &self.ledger,
            reference.entity_id,
            crate::TRANSFER_PROGRESS_SCHEMA_ID,
        )?;
        let values = snapshot
            .get("ranges")
            .and_then(Value::as_array)
            .ok_or(TransferError::TypeMismatch)?;
        values.iter().map(range_from_value).collect()
    }

    pub(super) fn verify_partial_ranges(
        &self,
        run_ref: &EntityRef,
        ranges: &[RangeRecord],
    ) -> Result<u64, TransferError> {
        let mut file = File::open(partial_path(&self.staging_root, run_ref))?;
        let mut total = 0u64;
        for range in ranges {
            if range.state != "verified" {
                continue;
            }
            if range.length == 0 || range.offset != total {
                return Err(TransferError::PartialStateCorrupt);
            }
            let length =
                usize::try_from(range.length).map_err(|_| TransferError::AccountingOverflow)?;
            let mut bytes = vec![0u8; length];
            file.seek(SeekFrom::Start(range.offset))?;
            file.read_exact(&mut bytes)?;
            if sha256_bytes(&bytes) != range.digest {
                return Err(TransferError::PartialStateCorrupt);
            }
            total = total
                .checked_add(range.length)
                .ok_or(TransferError::AccountingOverflow)?;
        }
        Ok(total)
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn retain_failed_verification(
        &mut self,
        mut run: Value,
        run_ref: EntityRef,
        workspace_ref: EntityRef,
        authority_ref: EntityRef,
        execution: ValidatedExecution,
        request: &TransferRequestSpec,
        observed_digest: String,
        observed_size: u64,
        _quarantine_path: Option<PathBuf>,
    ) -> Result<TransferVerificationReport, TransferError> {
        let expected = expected_canonical_sha256(&request.source)?;
        let domains = failed_transfer_domains(
            request,
            &execution,
            expected.clone(),
            &observed_digest,
            observed_size,
        );
        let verification_ref = EntityRef::new("transfer.verification")?;
        let now = self.now()?;
        let verification = verification_document(
            &verification_ref,
            &run_ref,
            &workspace_ref,
            &authority_ref,
            &self.config,
            &execution,
            "failed",
            &domains,
            None,
            &[],
            &now,
        );
        append_ref(&mut run, "verification_refs", verification_ref.clone())?;
        for receipt in &execution.receipt_refs {
            append_ref(&mut run, "receipt_refs", receipt.clone())?;
        }
        set_lifecycle(&mut run, "failed", &now)?;
        write_documents(&mut self.ledger, &[verification, run])?;
        Err(TransferError::VerificationFailed)
    }

    pub(super) fn validate_accepted_output(
        &self,
        workspace_ref: &EntityRef,
        accepted: &AcceptedOutputRefs,
    ) -> Result<(), TransferError> {
        let content = latest_document(
            &self.ledger,
            accepted.content_ref.entity_id,
            CONTENT_SCHEMA_ID,
        )?;
        let revision = latest_document(
            &self.ledger,
            accepted.object_revision_ref.entity_id,
            REVISION_SCHEMA_ID,
        )?;
        let location = latest_document(
            &self.ledger,
            accepted.location_ref.entity_id,
            LOCATION_SCHEMA_ID,
        )?;
        ensure_workspace(&content, workspace_ref)?;
        ensure_workspace(&revision, workspace_ref)?;
        ensure_workspace(&location, workspace_ref)?;
        if !same_ref(&field_ref(&revision, "content_ref")?, &accepted.content_ref)
            || !same_ref(&field_ref(&location, "content_ref")?, &accepted.content_ref)
            || field_string(&location, "verification_state")? != "verified"
        {
            return Err(TransferError::VerificationFailed);
        }
        Ok(())
    }

    pub(super) fn aggregate_domain_results(
        &self,
        run: &Value,
    ) -> Result<HashMap<VerificationDomain, DomainResultState>, TransferError> {
        let mut aggregate = HashMap::new();
        for reference in field_refs(run, "verification_refs")? {
            let verification = latest_document(
                &self.ledger,
                reference.entity_id,
                TRANSFER_VERIFICATION_SCHEMA_ID,
            )?;
            let results = verification
                .get("domain_results")
                .and_then(Value::as_array)
                .ok_or(TransferError::TypeMismatch)?;
            for result in results {
                let domain: VerificationDomain = serde_json::from_value(
                    result
                        .get("domain")
                        .cloned()
                        .ok_or(TransferError::TypeMismatch)?,
                )?;
                let state: DomainResultState = serde_json::from_value(
                    result
                        .get("result")
                        .cloned()
                        .ok_or(TransferError::TypeMismatch)?,
                )?;
                aggregate.insert(domain, state);
            }
        }
        Ok(aggregate)
    }

    pub(super) fn now(&self) -> Result<String, TransferError> {
        let now = (self.clock)();
        if !utc_shape(&now) {
            return Err(TransferError::InvalidField("clock"));
        }
        Ok(now)
    }
}
