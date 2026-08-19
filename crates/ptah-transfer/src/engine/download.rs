use super::{
    EntityId, EntityRef, OpenOptions, ProgressReport, RangeRecord, Read, ResumeSpec, Seek,
    SeekFrom, StartTransferSpec, TRANSFER_RUN_SCHEMA_ID, TransferEngine, TransferError,
    TransferEvidence, TransferMode, TransferRunHandle, Write, append_ref, document_ref,
    ensure_mode, ensure_run_state, field_ref, field_refs, field_string, field_u64, fs,
    latest_document, manifest_document, manifest_matches_request, manifest_provider_matches,
    partial_path, same_ref, scope_from_document, set_lifecycle, sha256_bytes,
    start_spec_from_manifest, validate_execution, write_documents,
};

impl TransferEngine {
    /// Start one resumable download Run from an exact A04 work-dispatch Attempt.
    ///
    /// The logical Operation targets the Transfer Request. Provider generation,
    /// connection epoch, idempotency key, protocol revision and source/destination
    /// descriptors are frozen into the Run/Manifest.
    ///
    /// # Errors
    /// Rejects stale/mismatched execution evidence, invalid request state, or unsafe partial state.
    pub fn start_download(
        &mut self,
        request_id: EntityId,
        evidence: TransferEvidence,
        spec: StartTransferSpec,
    ) -> Result<TransferRunHandle, TransferError> {
        self.start_run(request_id, evidence, spec, TransferMode::Download, true)
    }

    /// Append one contiguous provider byte chunk to a download partial.
    ///
    /// The chunk is flushed and independently re-read before its range is marked
    /// verified. A durable Progress Snapshot and replayable Event are retained.
    ///
    /// # Errors
    /// Rejects non-contiguous writes, stale run state, partial-file drift or ledger/event failure.
    pub fn append_download_chunk(
        &mut self,
        run_id: EntityId,
        offset: u64,
        bytes: &[u8],
    ) -> Result<ProgressReport, TransferError> {
        if bytes.is_empty() {
            return Err(TransferError::InvalidField("chunk"));
        }
        let mut run = latest_document(&self.ledger, run_id, TRANSFER_RUN_SCHEMA_ID)?;
        ensure_run_state(&run, &["transferring"])?;
        ensure_mode(&run, TransferMode::Download)?;
        let run_ref = document_ref(&run)?;
        let (workspace_ref, authority_ref) = scope_from_document(&run)?;
        let execution = self.execution_from_run(&run)?;
        let request = self.request_from_run(&run)?;
        if let Some(expected_size) = request.source.expected_size {
            let end = offset
                .checked_add(
                    u64::try_from(bytes.len()).map_err(|_| TransferError::AccountingOverflow)?,
                )
                .ok_or(TransferError::AccountingOverflow)?;
            if end > expected_size {
                return Err(TransferError::VerificationFailed);
            }
        }

        let path = partial_path(&self.staging_root, &run_ref);
        let metadata = fs::metadata(&path)?;
        if metadata.len() != offset {
            return Err(TransferError::NonContiguousChunk);
        }
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        file.seek(SeekFrom::Start(offset))?;
        let write_and_readback = (|| -> Result<Vec<u8>, TransferError> {
            file.write_all(bytes)?;
            file.sync_data()?;
            let mut readback = vec![0u8; bytes.len()];
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut readback)?;
            if readback != bytes {
                return Err(TransferError::PartialStateCorrupt);
            }
            Ok(readback)
        })();
        let readback = match write_and_readback {
            Ok(readback) => readback,
            Err(error) => {
                if file.set_len(offset).and_then(|()| file.sync_all()).is_err() {
                    return Err(TransferError::PartialStateCorrupt);
                }
                return Err(error);
            }
        };
        let digest = sha256_bytes(&readback);
        let length = u64::try_from(bytes.len()).map_err(|_| TransferError::AccountingOverflow)?;
        let total = offset
            .checked_add(length)
            .ok_or(TransferError::AccountingOverflow)?;
        let ranges = [RangeRecord {
            offset,
            length,
            state: "verified",
            digest,
            attempt_ref: execution.attempt_ref.clone(),
        }];
        self.write_progress(
            &mut run,
            &run_ref,
            &workspace_ref,
            &authority_ref,
            &execution,
            request.source.expected_size,
            total,
            total,
            0,
            &ranges,
        )
    }

    /// Pause a download after flushing retained partial bytes.
    ///
    /// # Errors
    /// Rejects invalid lifecycle state or filesystem/ledger failure.
    pub fn pause_download(&mut self, run_id: EntityId) -> Result<(), TransferError> {
        let mut run = latest_document(&self.ledger, run_id, TRANSFER_RUN_SCHEMA_ID)?;
        ensure_run_state(&run, &["transferring", "waiting"])?;
        ensure_mode(&run, TransferMode::Download)?;
        let run_ref = document_ref(&run)?;
        let path = partial_path(&self.staging_root, &run_ref);
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?
            .sync_all()?;
        let now = self.now()?;
        set_lifecycle(&mut run, "paused", &now)?;
        write_documents(&mut self.ledger, &[run])
    }

    /// Resume a paused download under the same logical Operation and a new A04 Attempt.
    ///
    /// Every retained resume dimension and verified byte range is revalidated.
    /// Source/provider/protocol/destination drift rejects resume while preserving partial evidence.
    ///
    /// # Errors
    /// Returns [`TransferError::ResumeMismatch`] or [`TransferError::PartialStateCorrupt`]
    /// rather than restarting silently.
    #[allow(clippy::needless_pass_by_value)]
    pub fn resume_download(
        &mut self,
        run_id: EntityId,
        resume: ResumeSpec,
    ) -> Result<ProgressReport, TransferError> {
        let mut run = latest_document(&self.ledger, run_id, TRANSFER_RUN_SCHEMA_ID)?;
        ensure_run_state(&run, &["paused", "waiting"])?;
        ensure_mode(&run, TransferMode::Download)?;
        let run_ref = document_ref(&run)?;
        let request_ref = field_ref(&run, "request_ref")?;
        let request = self.request_from_run(&run)?;
        if matches!(
            request.resumability_policy,
            crate::ResumabilityPolicy::Disabled
        ) {
            return Err(TransferError::ResumeMismatch);
        }
        if resume.source != request.source || resume.destination != request.destination {
            return Err(TransferError::ResumeMismatch);
        }
        let (workspace_ref, authority_ref) = scope_from_document(&run)?;
        let execution = validate_execution(
            &self.ledger,
            &workspace_ref,
            &authority_ref,
            &resume.evidence,
            &["work_dispatch"],
            Some(&request_ref),
        )?;
        if !same_ref(&execution.operation_ref, &field_ref(&run, "operation_ref")?)
            || execution.provider_generation != field_u64(&run, "destination_provider_generation")?
            || execution.connection_epoch != self.config.connection_epoch
            || !same_ref(&execution.provider_ref, &self.config.provider_ref)
            || !same_ref(
                &execution.provider_instance_ref,
                &self.config.provider_instance_ref,
            )
            || execution.provider_generation != self.config.provider_generation
        {
            return Err(TransferError::ResumeMismatch);
        }
        let attempts = field_refs(&run, "attempt_refs")?;
        if attempts
            .iter()
            .any(|reference| same_ref(reference, &execution.attempt_ref))
        {
            return Err(TransferError::ResumeMismatch);
        }
        let manifest = self.manifest_from_run(&run)?;
        if field_string(&manifest, "protocol_revision")? != self.config.protocol_revision
            || !manifest_provider_matches(&manifest, &self.config.provider_revision_ref)?
            || !manifest_matches_request(&manifest, &request)?
            || field_string(&manifest, "idempotency_key")? != field_string(&run, "idempotency_key")?
        {
            return Err(TransferError::ResumeMismatch);
        }
        let resume_start = start_spec_from_manifest(&manifest)?;

        let ranges = self.latest_ranges(&run)?;
        let bytes_verified = self.verify_partial_ranges(&run_ref, &ranges)?;
        let partial_len = fs::metadata(partial_path(&self.staging_root, &run_ref))?.len();
        if partial_len != bytes_verified {
            return Err(TransferError::PartialStateCorrupt);
        }

        append_ref(&mut run, "attempt_refs", execution.attempt_ref.clone())?;
        for receipt in &execution.receipt_refs {
            append_ref(&mut run, "receipt_refs", receipt.clone())?;
        }
        let now = self.now()?;
        let resume_manifest_ref = EntityRef::new("transfer.manifest")?;
        let resume_manifest = manifest_document(
            &resume_manifest_ref,
            &run_ref,
            &request,
            &self.config,
            &execution,
            &resume_start.idempotency_key,
            &resume_start.compression_mode,
            &resume_start.encryption_mode,
            resume_start.chunk_size,
            &now,
        );
        append_ref(&mut run, "manifest_refs", resume_manifest_ref)?;
        let mut preparing = run.clone();
        set_lifecycle(&mut preparing, "preparing", &now)?;
        let mut transferring = preparing.clone();
        set_lifecycle(&mut transferring, "transferring", &now)?;
        write_documents(
            &mut self.ledger,
            &[resume_manifest, preparing, transferring.clone()],
        )?;
        run = transferring;

        self.write_progress(
            &mut run,
            &run_ref,
            &workspace_ref,
            &authority_ref,
            &execution,
            request.source.expected_size,
            partial_len,
            bytes_verified,
            0,
            &ranges,
        )
    }
}
