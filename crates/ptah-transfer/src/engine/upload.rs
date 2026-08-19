use super::helpers::run_state;
use super::{
    Digest, DigestValue, EntityId, EntityRef, File, Path, ProviderAcknowledgement, RangeRecord,
    Read, Sha256, StartTransferSpec, TRANSFER_MANIFEST_SCHEMA_ID, TRANSFER_RUN_SCHEMA_ID,
    TransferEngine, TransferError, TransferEvidence, TransferMode, TransferRunHandle,
    TransferVerificationReport, UploadSink, UploadTransportReport, Value, append_ref, bump,
    canonicalize_root, document_ref, ensure_mode, ensure_run_state, expected_canonical_sha256,
    field_ref, field_refs, is_current_attempt, json, latest_document, report_from_verification,
    safe_existing_path, same_ref, scope_from_document, set_lifecycle, sha256_bytes,
    upload_source_failure_domains, upload_verification_domains, validate_execution,
    verification_document, verification_state_for_request, write_documents,
};

const UPLOAD_PROGRESS_BATCH_RANGES: usize = 64;
const SOURCE_VERIFICATION_MANIFEST_KEY: &str = "ptah.a08.upload_source_verification_manifest_ref";

fn set_source_verification_manifest(
    run: &mut Value,
    manifest_ref: &EntityRef,
) -> Result<(), TransferError> {
    let extensions = run
        .get_mut("extensions")
        .and_then(Value::as_object_mut)
        .ok_or(TransferError::TypeMismatch)?;
    extensions.insert(
        SOURCE_VERIFICATION_MANIFEST_KEY.to_owned(),
        serde_json::to_value(manifest_ref)?,
    );
    Ok(())
}

fn source_verification_manifest(run: &Value) -> Result<EntityRef, TransferError> {
    serde_json::from_value(
        run.get("extensions")
            .and_then(Value::as_object)
            .and_then(|extensions| extensions.get(SOURCE_VERIFICATION_MANIFEST_KEY))
            .cloned()
            .ok_or(TransferError::SourceVerificationMissing)?,
    )
    .map_err(TransferError::from)
}

impl TransferEngine {
    /// Start one upload Run from an exact A04 Request/dispatch Attempt.
    ///
    /// # Errors
    /// Rejects invalid Request mode or stale execution evidence.
    pub fn start_upload(
        &mut self,
        request_id: EntityId,
        evidence: TransferEvidence,
        spec: StartTransferSpec,
    ) -> Result<TransferRunHandle, TransferError> {
        self.start_run(request_id, evidence, spec, TransferMode::Upload, false)
    }

    /// Stream a safe local source file into a provider-neutral sink without
    /// finalizing the provider effect. The returned source observation must be
    /// independently bound to A04 hash evidence before provider finalization.
    ///
    /// # Errors
    /// Rejects unsafe source paths, invalid run state, provider failure, or ledger failure.
    pub fn stream_upload_file(
        &mut self,
        run_id: EntityId,
        source_root: impl AsRef<Path>,
        relative_source: impl AsRef<Path>,
        sink: &mut impl UploadSink,
        chunk_size: usize,
    ) -> Result<UploadTransportReport, TransferError> {
        if chunk_size == 0 || chunk_size > 16 * 1024 * 1024 {
            return Err(TransferError::InvalidField("chunk_size"));
        }
        let source_root = canonicalize_root(source_root.as_ref())?;
        let source_path = safe_existing_path(&source_root, relative_source.as_ref())?;
        let mut run = latest_document(&self.ledger, run_id, TRANSFER_RUN_SCHEMA_ID)?;
        ensure_run_state(&run, &["transferring"])?;
        ensure_mode(&run, TransferMode::Upload)?;
        let run_ref = document_ref(&run)?;
        let request = self.request_from_run(&run)?;
        let (workspace_ref, authority_ref) = scope_from_document(&run)?;
        let execution = self.execution_from_run(&run)?;
        let mut source = File::open(source_path)?;
        let mut hasher = Sha256::new();
        let mut pending_ranges = Vec::new();
        let mut offset = 0u64;
        let mut buffer = vec![0u8; chunk_size];
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            let chunk = &buffer[..read];
            sink.write_chunk(offset, chunk)?;
            hasher.update(chunk);
            let length = u64::try_from(read).map_err(|_| TransferError::AccountingOverflow)?;
            pending_ranges.push(RangeRecord {
                offset,
                length,
                state: "received_unverified",
                digest: sha256_bytes(chunk),
                attempt_ref: execution.attempt_ref.clone(),
            });
            offset = offset
                .checked_add(length)
                .ok_or(TransferError::AccountingOverflow)?;
            if pending_ranges.len() >= UPLOAD_PROGRESS_BATCH_RANGES {
                let _ = self.write_progress(
                    &mut run,
                    &run_ref,
                    &workspace_ref,
                    &authority_ref,
                    &execution,
                    request.source.expected_size,
                    offset,
                    0,
                    0,
                    &pending_ranges,
                )?;
                pending_ranges.clear();
                run = latest_document(&self.ledger, run_id, TRANSFER_RUN_SCHEMA_ID)?;
            }
        }
        let _ = self.write_progress(
            &mut run,
            &run_ref,
            &workspace_ref,
            &authority_ref,
            &execution,
            request.source.expected_size,
            offset,
            0,
            0,
            &pending_ranges,
        )?;
        Ok(UploadTransportReport {
            run_ref,
            source_sha256: format!("{:x}", hasher.finalize()),
            source_size: offset,
        })
    }

    /// Validate the streamed upload source against the Request and retain a
    /// manifest bound to the observed size/digest only after A04 hash evidence
    /// exists. A mismatch is retained as negative Transfer Verification and
    /// fails the Run before provider finalization.
    ///
    /// # Errors
    /// Rejects unrelated A04 evidence, source expectation mismatch, or stale Run state.
    #[allow(clippy::needless_pass_by_value)]
    pub fn verify_upload_source(
        &mut self,
        run_id: EntityId,
        observation: &UploadTransportReport,
        evidence: TransferEvidence,
    ) -> Result<EntityRef, TransferError> {
        let mut run = latest_document(&self.ledger, run_id, TRANSFER_RUN_SCHEMA_ID)?;
        ensure_run_state(&run, &["transferring"])?;
        ensure_mode(&run, TransferMode::Upload)?;
        let run_ref = document_ref(&run)?;
        if !same_ref(&run_ref, &observation.run_ref) {
            return Err(TransferError::ExecutionEvidenceMismatch);
        }
        let request = self.request_from_run(&run)?;
        let (workspace_ref, authority_ref) = scope_from_document(&run)?;
        let execution = validate_execution(
            &self.ledger,
            &workspace_ref,
            &authority_ref,
            &evidence,
            &["hash_verification"],
            Some(&field_ref(&run, "request_ref")?),
        )?;
        if !same_ref(&execution.operation_ref, &field_ref(&run, "operation_ref")?)
            || !is_current_attempt(&run, &execution.attempt_ref)?
        {
            return Err(TransferError::ExecutionEvidenceMismatch);
        }

        let expected_sha = expected_canonical_sha256(&request.source)?;
        let size_matches = request
            .source
            .expected_size
            .is_none_or(|size| size == observation.source_size);
        let digest_matches = expected_sha
            .as_deref()
            .is_none_or(|digest| digest == observation.source_sha256);
        if !size_matches || !digest_matches {
            let domains = upload_source_failure_domains(
                &request,
                &execution,
                expected_sha.clone(),
                &observation.source_sha256,
                observation.source_size,
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
            append_ref(&mut run, "verification_refs", verification_ref)?;
            for receipt in &execution.receipt_refs {
                append_ref(&mut run, "receipt_refs", receipt.clone())?;
            }
            set_lifecycle(&mut run, "failed", &now)?;
            write_documents(&mut self.ledger, &[verification, run])?;
            return Err(TransferError::VerificationFailed);
        }

        let original_manifest = self.manifest_from_run(&run)?;
        let manifest_ref = EntityRef::new("transfer.manifest")?;
        let now = self.now()?;
        let mut observed_manifest = original_manifest;
        observed_manifest["envelope"] = crate::util::envelope(
            &manifest_ref,
            TRANSFER_MANIFEST_SCHEMA_ID,
            1,
            &workspace_ref,
            &authority_ref,
            &now,
        );
        observed_manifest["expected_size"] = json!(observation.source_size);
        observed_manifest["expected_digests"] =
            json!([DigestValue::canonical_sha256(&observation.source_sha256)]);
        observed_manifest["created_at"] = json!(now);
        append_ref(&mut run, "manifest_refs", manifest_ref.clone())?;
        set_source_verification_manifest(&mut run, &manifest_ref)?;
        for receipt in &execution.receipt_refs {
            append_ref(&mut run, "receipt_refs", receipt.clone())?;
        }
        bump(&mut run, &now)?;
        write_documents(&mut self.ledger, &[observed_manifest, run])?;
        Ok(manifest_ref)
    }

    /// Finalize the provider transport effect after source verification. The
    /// returned acknowledgement is still not completion proof.
    ///
    /// # Errors
    /// Rejects stale lifecycle state or provider finalization failure.
    pub fn finalize_upload_transport(
        &self,
        run_id: EntityId,
        sink: &mut impl UploadSink,
    ) -> Result<ProviderAcknowledgement, TransferError> {
        let run = latest_document(&self.ledger, run_id, TRANSFER_RUN_SCHEMA_ID)?;
        ensure_run_state(&run, &["transferring"])?;
        ensure_mode(&run, TransferMode::Upload)?;
        let verified_manifest_ref = source_verification_manifest(&run)?;
        let manifest_refs = field_refs(&run, "manifest_refs")?;
        if !manifest_refs
            .last()
            .is_some_and(|reference| same_ref(reference, &verified_manifest_ref))
        {
            return Err(TransferError::SourceVerificationMissing);
        }
        let manifest = latest_document(
            &self.ledger,
            verified_manifest_ref.entity_id,
            TRANSFER_MANIFEST_SCHEMA_ID,
        )?;
        let has_size = manifest
            .get("expected_size")
            .and_then(Value::as_u64)
            .is_some();
        let has_digest = manifest
            .get("expected_digests")
            .and_then(Value::as_array)
            .is_some_and(|digests| !digests.is_empty());
        if !has_size || !has_digest {
            return Err(TransferError::SourceVerificationMissing);
        }
        Ok(sink.finalize()?)
    }

    /// Read an acknowledged upload back from the provider and retain Transfer
    /// Verification. Provider acknowledgement alone cannot call this proof `verified`.
    ///
    /// # Errors
    /// Rejects missing readback/hash A04 evidence, digest/size mismatch, or invalid lifecycle state.
    #[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
    pub fn verify_upload_sink(
        &mut self,
        run_id: EntityId,
        sink: &mut impl UploadSink,
        evidence: TransferEvidence,
        chunk_size: usize,
    ) -> Result<TransferVerificationReport, TransferError> {
        if chunk_size == 0 || chunk_size > 16 * 1024 * 1024 {
            return Err(TransferError::InvalidField("chunk_size"));
        }
        let mut run = latest_document(&self.ledger, run_id, TRANSFER_RUN_SCHEMA_ID)?;
        ensure_run_state(&run, &["verifying", "uncertain"])?;
        ensure_mode(&run, TransferMode::Upload)?;
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
        let manifest = self.manifest_from_run(&run)?;
        let expected_size = manifest
            .get("expected_size")
            .and_then(Value::as_u64)
            .ok_or(TransferError::TypeMismatch)?;
        let expected_sha = manifest
            .get("expected_digests")
            .and_then(Value::as_array)
            .and_then(|digests| {
                digests.iter().find_map(|digest| {
                    (digest.get("algorithm").and_then(Value::as_str) == Some("sha256")
                        && digest.get("digest_domain").and_then(Value::as_str)
                            == Some("canonical_content"))
                    .then(|| digest.get("value").and_then(Value::as_str))
                    .flatten()
                })
            })
            .ok_or(TransferError::TypeMismatch)?
            .to_owned();

        let mut destination_hasher = Sha256::new();
        let mut destination_size = 0u64;
        while destination_size < expected_size {
            let remaining = expected_size
                .checked_sub(destination_size)
                .ok_or(TransferError::AccountingOverflow)?;
            let requested = usize::try_from(remaining.min(chunk_size as u64))
                .map_err(|_| TransferError::AccountingOverflow)?;
            let chunk = sink.read_back_chunk(destination_size, requested)?;
            if chunk.is_empty() {
                break;
            }
            if chunk.len() > requested {
                return Err(TransferError::VerificationFailed);
            }
            destination_hasher.update(&chunk);
            destination_size = destination_size
                .checked_add(
                    u64::try_from(chunk.len()).map_err(|_| TransferError::AccountingOverflow)?,
                )
                .ok_or(TransferError::AccountingOverflow)?;
        }
        if destination_size == expected_size {
            let trailing = sink.read_back_chunk(destination_size, 1)?;
            if !trailing.is_empty() {
                destination_hasher.update(&trailing);
                destination_size = destination_size
                    .checked_add(
                        u64::try_from(trailing.len())
                            .map_err(|_| TransferError::AccountingOverflow)?,
                    )
                    .ok_or(TransferError::AccountingOverflow)?;
            }
        }
        let destination_sha = format!("{:x}", destination_hasher.finalize());
        let passed = destination_size == expected_size && destination_sha == expected_sha;
        let domains = upload_verification_domains(
            &execution,
            &expected_sha,
            &destination_sha,
            destination_size,
            passed,
        );
        let verification_state = if passed {
            verification_state_for_request(&request, &domains)
        } else {
            "failed"
        };
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
            &domains,
            None,
            &[],
            &now,
        );
        append_ref(&mut run, "verification_refs", verification_ref.clone())?;
        for receipt in &execution.receipt_refs {
            append_ref(&mut run, "receipt_refs", receipt.clone())?;
        }
        if passed {
            if run_state(&run)? == "uncertain" {
                set_lifecycle(&mut run, "verifying", &now)?;
            } else {
                bump(&mut run, &now)?;
            }
        } else {
            set_lifecycle(&mut run, "failed", &now)?;
        }
        write_documents(&mut self.ledger, &[verification, run])?;
        if !passed {
            return Err(TransferError::VerificationFailed);
        }
        Ok(report_from_verification(
            run_ref,
            verification_ref,
            verification_state.to_owned(),
            Some(expected_sha),
            destination_sha,
            destination_size,
            None,
        ))
    }
}
