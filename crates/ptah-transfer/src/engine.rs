use crate::records::{
    RangeRecord, VerificationDomainResult, manifest_document, progress_document,
    report_from_verification, request_accepted_document, request_submitted_document,
    transfer_run_document, verification_document,
};
use crate::util::{
    ATTEMPT_SCHEMA_ID, CONTENT_SCHEMA_ID, LOCATION_SCHEMA_ID, REVISION_SCHEMA_ID,
    ValidatedExecution, append_ref, bump, canonicalize_root, document_ref, ensure_workspace,
    field_ref, field_refs, field_string, field_u64, latest_document, partial_path,
    safe_existing_path, safe_relative_path, same_ref, set_lifecycle, sha256_bytes, sha256_reader,
    unique_refs, utc_shape, validate_config, validate_execution, validate_idempotency_key,
    validate_storage_class, write_documents,
};
use crate::{
    AcceptedOutputRefs, DigestDomain, DigestValue, DomainResultState, ProgressReport,
    ProviderAcknowledgement, ResumeSpec, SourceDescriptor, SourceKind, StartTransferSpec,
    TRANSFER_MANIFEST_SCHEMA_ID, TRANSFER_REQUEST_SCHEMA_ID, TRANSFER_RUN_SCHEMA_ID,
    TRANSFER_VERIFICATION_SCHEMA_ID, TransferConfig, TransferError, TransferEvidence, TransferMode,
    TransferRequestSpec, TransferRunHandle, TransferVerificationReport, UploadTransportReport,
    VerificationDomain,
};
use ptah_events::{EVENT_ENTITY_KIND, EventBus, EventClass, EventPayload, EventSpec};
use ptah_identifiers::{EntityId, EntityRef};
use ptah_ledger::Ledger;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

/// Caller-supplied UTC clock authority used to stamp A08 records.
pub type TransferClock = Arc<dyn Fn() -> String + Send + Sync>;

/// Provider-neutral upload destination. Provider acknowledgement is explicitly
/// separate from read-back verification.
pub trait UploadSink {
    /// Write one exact byte range at the given offset.
    ///
    /// # Errors
    /// Returns I/O/provider failure without manufacturing transfer completion.
    fn write_chunk(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()>;

    /// Ask the provider to finalize the upload transport effect.
    ///
    /// # Errors
    /// Returns provider/transport failure. An acknowledged result is still not
    /// transfer completion until read-back verification succeeds.
    fn finalize(&mut self) -> std::io::Result<ProviderAcknowledgement>;

    /// Read back one destination range. Empty bytes signal EOF.
    ///
    /// # Errors
    /// Returns provider/read-back failure.
    fn read_back_chunk(&mut self, offset: u64, max_len: usize) -> std::io::Result<Vec<u8>>;
}

/// A08 transfer runtime over the A03 canonical ledger and one private staging root.
pub struct TransferEngine {
    ledger: Ledger,
    staging_root: PathBuf,
    config: TransferConfig,
    event_bus: EventBus,
    clock: TransferClock,
}

impl TransferEngine {
    /// Open the A08 runtime against an existing A03 ledger and private partial-byte root.
    ///
    /// # Errors
    /// Fails for invalid configuration, ledger failure, or unsafe staging root.
    pub fn open(
        ledger_path: impl AsRef<Path>,
        staging_root: impl AsRef<Path>,
        config: TransferConfig,
        event_bus: EventBus,
        clock: TransferClock,
    ) -> Result<Self, TransferError> {
        validate_config(&config)?;
        let staging_root = canonicalize_root(staging_root.as_ref())?;
        let ledger = Ledger::open(ledger_path)?;
        Ok(Self {
            ledger,
            staging_root,
            config,
            event_bus,
            clock,
        })
    }

    /// Create one durable Transfer Request. This is intent only: no Activity,
    /// Run, provider acknowledgement, byte movement, or accepted output is implied.
    ///
    /// # Errors
    /// Rejects schema-invalid source/destination intent or canonical persistence failure.
    #[allow(clippy::needless_pass_by_value)]
    pub fn create_request(
        &mut self,
        spec: TransferRequestSpec,
    ) -> Result<EntityRef, TransferError> {
        validate_request(&spec)?;
        let now = self.now()?;
        let request_ref = EntityRef::new("transfer.request")?;
        let document = request_submitted_document(&request_ref, &spec, &now);
        write_documents(&mut self.ledger, &[document])?;
        Ok(request_ref)
    }
}

mod completion;
mod download;
mod helpers;
mod internal;
mod upload;

use helpers::{
    copy_synced, ensure_mode, ensure_request_state, ensure_run_state, expected_canonical_sha256,
    failed_transfer_domains, is_current_attempt, manifest_matches_request,
    manifest_provider_matches, range_from_value, request_spec_from_document, scope_from_document,
    start_spec_from_manifest, sync_directory, upload_source_failure_domains,
    upload_verification_domains, validate_request, validate_start_spec,
    verification_state_for_request, verified_transfer_domains,
};
