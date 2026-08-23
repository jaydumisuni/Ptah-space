#!/usr/bin/env python3
from pathlib import Path
import re


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def sub_once(text: str, pattern: str, replacement: str, label: str) -> str:
    result, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return result


path = Path("crates/ptah-transfer/src/b01.rs")
text = path.read_text(encoding="utf-8")

text = replace_once(
    text,
    "    /// Enqueue one job. Duplicate IDs are rejected so queue identity cannot silently alias.\n    pub fn enqueue(",
    """    /// Enqueue one job. Duplicate IDs are rejected so queue identity cannot silently alias.\n    ///\n    /// # Errors\n    /// Returns [`B01Error::DuplicateQueueId`] when the caller reuses a pending job identity.\n    pub fn enqueue(""",
    "enqueue errors docs",
)
text = replace_once(
    text,
    "    /// Select one bounded execution batch while preserving local capacity.\n    pub fn schedule(",
    """    /// Select one bounded execution batch while preserving local capacity.\n    ///\n    /// # Errors\n    /// Returns [`B01Error::InvalidQueuePolicy`] when the requested batch cannot satisfy the\n    /// bounded local-capacity policy.\n    pub fn schedule(""",
    "schedule errors docs",
)

upload_block = r"/// Minimal provider contract needed for offset-safe upload resume\.[\s\S]*?\n/// One exact verified download range\."
new_upload_block = '''/// Minimal provider contract needed for offset-safe upload resume.
pub trait ResumableUploadSink {
    /// Number of bytes the provider says are durably accepted for this upload identity.
    ///
    /// # Errors
    /// Returns an adapter-defined error when durable provider state cannot be read.
    fn accepted_len(&self) -> Result<u64, String>;
    /// Write exact bytes at the current accepted offset.
    ///
    /// # Errors
    /// Returns an adapter-defined error when the provider rejects or cannot persist the write.
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), String>;
    /// Finalize the provider object only after all source bytes are accepted.
    ///
    /// # Errors
    /// Returns an adapter-defined error when provider finalization fails.
    fn finalize(&mut self) -> Result<(), String>;
}

/// Stream a local source into a provider sink, optionally stopping after a byte budget.
///
/// The sink's durable offset must exactly match the caller cursor. A mismatch fails closed rather
/// than overwriting or skipping provider bytes.
///
/// # Errors
/// Returns a [`B01Error`] when source/provider identity disagrees, source bytes mutate during the
/// pass, transfer accounting cannot be represented, provider I/O fails, or local file I/O fails.
pub fn resumable_upload_file(
    source: &Path,
    sink: &mut dyn ResumableUploadSink,
    cursor: &UploadCursor,
    chunk_size: usize,
    byte_budget: Option<u64>,
) -> Result<ResumableUploadReport, B01Error> {
    if chunk_size == 0 {
        return Err(B01Error::InvalidChunkSize);
    }
    let source_size = fs::metadata(source)?.len();
    let source_sha256 = sha256_file(source)?;
    if cursor
        .source_size
        .is_some_and(|expected| expected != source_size)
        || cursor
            .source_sha256
            .as_deref()
            .is_some_and(|expected| expected != source_sha256.as_str())
    {
        return Err(B01Error::ResumeSourceIdentityMismatch);
    }
    if cursor.accepted_offset > source_size {
        return Err(B01Error::ResumeOffsetOutOfRange {
            offset: cursor.accepted_offset,
            size: source_size,
        });
    }
    let sink_len = sink.accepted_len().map_err(B01Error::Adapter)?;
    if sink_len != cursor.accepted_offset {
        return Err(B01Error::ResumeSinkMismatch {
            cursor: cursor.accepted_offset,
            sink: sink_len,
        });
    }

    let starting_offset = cursor.accepted_offset;
    let mut accepted_offset = starting_offset;
    let mut remaining_budget = byte_budget.unwrap_or(u64::MAX);
    let chunk_size_u64 = u64::try_from(chunk_size).map_err(|_| B01Error::AccountingOverflow)?;
    let mut file = File::open(source)?;
    let mut sent_prefix_hasher = Sha256::new();
    let mut prefix_remaining = starting_offset;
    let mut prefix_buffer = vec![0_u8; 64 * 1024];
    let prefix_capacity_u64 =
        u64::try_from(prefix_buffer.len()).map_err(|_| B01Error::AccountingOverflow)?;
    while prefix_remaining > 0 {
        let request = usize::try_from(prefix_remaining.min(prefix_capacity_u64))
            .map_err(|_| B01Error::AccountingOverflow)?;
        let read = file.read(&mut prefix_buffer[..request])?;
        if read == 0 {
            return Err(B01Error::UnexpectedSourceEof);
        }
        sent_prefix_hasher.update(&prefix_buffer[..read]);
        prefix_remaining -= u64::try_from(read).map_err(|_| B01Error::AccountingOverflow)?;
    }
    file.seek(SeekFrom::Start(starting_offset))?;
    let mut buffer = vec![0_u8; chunk_size];

    while accepted_offset < source_size && remaining_budget > 0 {
        let remaining_source = source_size - accepted_offset;
        let request = usize::try_from(
            remaining_source
                .min(remaining_budget)
                .min(chunk_size_u64),
        )
        .map_err(|_| B01Error::AccountingOverflow)?;
        let read = file.read(&mut buffer[..request])?;
        if read == 0 {
            return Err(B01Error::UnexpectedSourceEof);
        }
        sent_prefix_hasher.update(&buffer[..read]);
        sink.write_at(accepted_offset, &buffer[..read])
            .map_err(B01Error::Adapter)?;
        let read_u64 = u64::try_from(read).map_err(|_| B01Error::AccountingOverflow)?;
        accepted_offset = accepted_offset
            .checked_add(read_u64)
            .ok_or(B01Error::AccountingOverflow)?;
        remaining_budget = remaining_budget.saturating_sub(read_u64);
    }

    let sent_prefix_sha256 = format!("{:x}", sent_prefix_hasher.finalize());
    let retained_prefix_sha256 = sha256_prefix(source, accepted_offset)?;
    if sent_prefix_sha256 != retained_prefix_sha256 {
        return Err(B01Error::SourceChangedDuringUpload {
            expected: retained_prefix_sha256,
            observed: sent_prefix_sha256,
        });
    }
    let post_source_size = fs::metadata(source)?.len();
    let post_source_sha256 = sha256_file(source)?;
    if post_source_size != source_size || post_source_sha256 != source_sha256 {
        return Err(B01Error::ResumeSourceIdentityMismatch);
    }

    let complete = accepted_offset == source_size;
    if complete {
        sink.finalize().map_err(B01Error::Adapter)?;
    }
    Ok(ResumableUploadReport {
        cursor: UploadCursor {
            accepted_offset,
            source_size: Some(source_size),
            source_sha256: Some(source_sha256.clone()),
        },
        starting_offset,
        accepted_offset,
        source_size,
        source_sha256,
        complete,
    })
}

/// One exact verified download range.'''
text = sub_once(text, upload_block, new_upload_block, "upload block")

text = replace_once(
    text,
    "    /// Return exactly the requested range or an adapter error.\n    fn read_range(&mut self, start: u64, len: usize) -> Result<Vec<u8>, String>;",
    """    /// Return exactly the requested range or an adapter error.\n    ///\n    /// # Errors\n    /// Returns an adapter-defined error when the requested range cannot be served exactly.\n    fn read_range(&mut self, start: u64, len: usize) -> Result<Vec<u8>, String>;""",
    "range source errors docs",
)

segmented_block = r"/// Download fixed-size segments from multiple sources with fallback and exact-range resume\.[\s\S]*?\n/// Export boundary implemented by Node-to-Node, object-store and Drive adapters\."
new_segmented_block = '''fn verify_retained_segment(
    output: &mut File,
    verified: &VerifiedRange,
    start: u64,
    len: usize,
) -> Result<(), B01Error> {
    let mut retained = vec![0_u8; len];
    output.seek(SeekFrom::Start(start))?;
    output.read_exact(&mut retained)?;
    let observed = sha256_bytes(&retained);
    if observed != verified.sha256 {
        return Err(B01Error::ResumeRangeDigestMismatch {
            start,
            expected: verified.sha256.clone(),
            observed,
        });
    }
    Ok(())
}

fn fetch_segment(
    sources: &mut [&mut dyn RangeSource],
    start: u64,
    len: usize,
    preferred: usize,
    successful_sources: &mut Vec<String>,
    successful_source_set: &mut HashSet<String>,
    failures: &mut Vec<SourceFailure>,
) -> Option<Vec<u8>> {
    for attempt in 0..sources.len() {
        let source_index = (preferred + attempt) % sources.len();
        let source = &mut sources[source_index];
        match source.read_range(start, len) {
            Ok(bytes) if bytes.len() == len => {
                let source_id = source.source_id().to_owned();
                if successful_source_set.insert(source_id.clone()) {
                    successful_sources.push(source_id);
                }
                return Some(bytes);
            }
            Ok(bytes) => failures.push(SourceFailure {
                source_id: source.source_id().to_owned(),
                start,
                error: format!(
                    "short range: expected {len} bytes, observed {}",
                    bytes.len()
                ),
            }),
            Err(error) => failures.push(SourceFailure {
                source_id: source.source_id().to_owned(),
                start,
                error,
            }),
        }
    }
    None
}

fn completed_download_digest(
    destination: &Path,
    complete: bool,
    expected_sha256: Option<&str>,
) -> Result<Option<String>, B01Error> {
    if !complete {
        return Ok(None);
    }
    let digest = sha256_file(destination)?;
    if let Some(expected) = expected_sha256
        && digest != expected
    {
        return Err(B01Error::DigestMismatch {
            expected: expected.to_owned(),
            observed: digest,
        });
    }
    Ok(Some(digest))
}

/// Download fixed-size segments from multiple sources with fallback and exact-range resume.
///
/// # Errors
/// Returns a [`B01Error`] when source configuration or cursor geometry is invalid, retained bytes
/// fail digest verification, transfer accounting cannot be represented, local I/O fails, or the
/// completed destination does not match the expected whole-file digest.
pub fn segmented_download(
    sources: &mut [&mut dyn RangeSource],
    destination: &Path,
    expected_size: u64,
    segment_size: usize,
    mut cursor: DownloadCursor,
    max_new_segments: Option<usize>,
    expected_sha256: Option<&str>,
) -> Result<SegmentedDownloadReport, B01Error> {
    if sources.is_empty() {
        return Err(B01Error::NoRangeSource);
    }
    if segment_size == 0 {
        return Err(B01Error::InvalidChunkSize);
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut output = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(destination)?;
    output.set_len(expected_size)?;

    let segment_size_u64 = u64::try_from(segment_size).map_err(|_| B01Error::AccountingOverflow)?;
    let source_count_u64 = u64::try_from(sources.len()).map_err(|_| B01Error::AccountingOverflow)?;
    cursor.validate_for(expected_size, segment_size_u64)?;
    let segment_count = if expected_size == 0 {
        0
    } else {
        expected_size.div_ceil(segment_size_u64)
    };
    let mut resumed_ranges = 0_usize;
    let mut downloaded_ranges = 0_usize;
    let mut failures = Vec::new();
    let mut successful_sources = Vec::new();
    let mut successful_source_set = HashSet::new();

    for segment_index in 0..segment_count {
        let start = segment_index * segment_size_u64;
        let len_u64 = (expected_size - start).min(segment_size_u64);
        let len = usize::try_from(len_u64).map_err(|_| B01Error::AccountingOverflow)?;
        if let Some(verified) = cursor.get(start, len_u64) {
            verify_retained_segment(&mut output, verified, start, len)?;
            resumed_ranges += 1;
            continue;
        }
        if max_new_segments.is_some_and(|limit| downloaded_ranges >= limit) {
            break;
        }

        let preferred = usize::try_from(segment_index % source_count_u64)
            .map_err(|_| B01Error::AccountingOverflow)?;
        let Some(bytes) = fetch_segment(
            sources,
            start,
            len,
            preferred,
            &mut successful_sources,
            &mut successful_source_set,
            &mut failures,
        ) else {
            return Ok(SegmentedDownloadReport {
                cursor,
                resumed_ranges,
                downloaded_ranges,
                successful_sources,
                failures,
                blocked_segment: Some(BlockedSegment { start, len }),
                complete: false,
                destination_sha256: None,
            });
        };
        output.seek(SeekFrom::Start(start))?;
        output.write_all(&bytes)?;
        output.flush()?;
        output.sync_data()?;
        cursor.mark_verified(VerifiedRange {
            start,
            len: len_u64,
            sha256: sha256_bytes(&bytes),
        });
        downloaded_ranges += 1;
    }

    let complete = (0..segment_count).all(|segment_index| {
        let start = segment_index * segment_size_u64;
        let len = (expected_size - start).min(segment_size_u64);
        cursor.get(start, len).is_some()
    });
    let destination_sha256 = completed_download_digest(destination, complete, expected_sha256)?;
    Ok(SegmentedDownloadReport {
        cursor,
        resumed_ranges,
        downloaded_ranges,
        successful_sources,
        failures,
        blocked_segment: None,
        complete,
        destination_sha256,
    })
}

/// Export boundary implemented by Node-to-Node, object-store and Drive adapters.'''
text = sub_once(text, segmented_block, new_segmented_block, "segmented block")

text = replace_once(
    text,
    "    /// Export exact bytes under the adapter's own authorization boundary.\n    fn export(&mut self, bytes: &[u8], sha256: &str) -> Result<ExportReceipt, String>;",
    """    /// Export exact bytes under the adapter's own authorization boundary.\n    ///\n    /// # Errors\n    /// Returns an adapter-defined error when the target cannot accept the exact export.\n    fn export(&mut self, bytes: &[u8], sha256: &str) -> Result<ExportReceipt, String>;""",
    "export trait errors docs",
)
text = replace_once(
    text,
    """/// Remote failure is observable but cannot roll back or hide the completed primary result.\npub fn export_with_optional_remote(""",
    """/// Remote failure is observable but cannot roll back or hide the completed primary result.\n///\n/// # Errors\n/// Returns [`B01Error::Adapter`] when the mandatory primary export fails. Optional remote failures\n/// are retained in [`ExportOutcome::remote_failure`] instead of rewriting primary success.\npub fn export_with_optional_remote(""",
    "export function errors docs",
)
text = replace_once(
    text,
    "    /// Commit a previously observed non-conflicting synchronization result.\n    pub fn reconcile_pending(",
    """    /// Commit a previously observed non-conflicting synchronization result.\n    ///\n    /// # Errors\n    /// Returns [`B01Error::NoPendingSync`] unless a non-conflicting observation is pending.\n    pub fn reconcile_pending(""",
    "reconcile errors docs",
)
text = replace_once(
    text,
    "    /// Resolve only an explicit conflict using a caller-selected policy.\n    pub fn resolve(",
    """    /// Resolve only an explicit conflict using a caller-selected policy.\n    ///\n    /// # Errors\n    /// Returns [`B01Error::NoSyncConflict`] unless the relationship is currently conflicted.\n    pub fn resolve(""",
    "resolve errors docs",
)
text = replace_once(
    text,
    "    /// Create one immutable byte snapshot. Duplicate logical paths are rejected.\n    pub fn create_snapshot(",
    """    /// Create one immutable byte snapshot. Duplicate logical paths are rejected.\n    ///\n    /// # Errors\n    /// Returns a [`B01Error`] for duplicate snapshot identities, duplicate logical paths, or an\n    /// internal repository invariant failure.\n    pub fn create_snapshot(""",
    "create snapshot errors docs",
)
text = replace_once(
    text,
    """        self.next_sequence = self.next_sequence.saturating_add(1);\n        self.snapshots.push(snapshot);\n        Ok(self.snapshots.last().expect(\"snapshot was just pushed\"))""",
    """        self.next_sequence = self.next_sequence.saturating_add(1);\n        self.snapshots.push(snapshot);\n        self.snapshots\n            .last()\n            .ok_or(B01Error::InternalInvariant(\"snapshot push produced no retained snapshot\"))""",
    "snapshot panic removal",
)
text = replace_once(
    text,
    "    /// Rehash every retained entry before marking a snapshot verified.\n    pub fn verify_snapshot(",
    """    /// Rehash every retained entry before marking a snapshot verified.\n    ///\n    /// # Errors\n    /// Returns [`B01Error::SnapshotNotFound`] when the snapshot is absent or\n    /// [`B01Error::DigestMismatch`] when retained bytes no longer match their recorded digest.\n    pub fn verify_snapshot(""",
    "verify snapshot errors docs",
)
text = replace_once(
    text,
    "    /// Restore exact bytes only from an independently verified snapshot.\n    pub fn restore(",
    """    /// Restore exact bytes only from an independently verified snapshot.\n    ///\n    /// # Errors\n    /// Returns [`B01Error::SnapshotNotFound`] for an unknown snapshot or\n    /// [`B01Error::SnapshotUnverified`] until independent verification has succeeded.\n    pub fn restore(""",
    "restore errors docs",
)

text = replace_once(
    text,
    "    /// Zero-sized transfer chunks are invalid.\n    #[error(\"chunk or segment size must be greater than zero\")]\n    InvalidChunkSize,",
    """    /// Zero-sized transfer chunks are invalid.\n    #[error(\"chunk or segment size must be greater than zero\")]\n    InvalidChunkSize,\n    /// Numeric transfer accounting cannot be represented on this host.\n    #[error(\"numeric transfer accounting overflow\")]\n    AccountingOverflow,""",
    "accounting error variant",
)
text = replace_once(
    text,
    "    /// Restore requires independent snapshot verification.\n    #[error(\"backup snapshot is not verified: {0}\")]\n    SnapshotUnverified(String),",
    """    /// Restore requires independent snapshot verification.\n    #[error(\"backup snapshot is not verified: {0}\")]\n    SnapshotUnverified(String),\n    /// A local invariant failed despite a preceding successful state transition.\n    #[error(\"internal B01 invariant failed: {0}\")]\n    InternalInvariant(&'static str),""",
    "internal invariant variant",
)

text = sub_once(
    text,
    r"fn sha256_prefix\(path: &Path, len: u64\) -> Result<String, std::io::Error> \{[\s\S]*?\n\}\n\nfn sha256_file\(path: &Path\) -> Result<String, std::io::Error> \{[\s\S]*?\n\}",
    '''fn sha256_prefix(path: &Path, len: u64) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut remaining = len;
    let mut buffer = vec![0_u8; 64 * 1024];
    while remaining > 0 {
        let request = usize::try_from(remaining)
            .unwrap_or(buffer.len())
            .min(buffer.len());
        let read = file.read(&mut buffer[..request])?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "source ended while hashing accepted prefix",
            ));
        }
        hasher.update(&buffer[..read]);
        remaining = remaining.saturating_sub(u64::try_from(read).unwrap_or(u64::MAX));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}''',
    "hash helpers",
)

path.write_text(text, encoding="utf-8")

# Cursor is read-only input; update B01 call sites to borrow it explicitly.
tests_path = Path("crates/ptah-transfer/tests/b01.rs")
tests = tests_path.read_text(encoding="utf-8")
tests = tests.replace("UploadCursor::default(),", "&UploadCursor::default(),")
tests = tests.replace("first.cursor.clone(), 91 * 1024", "&first.cursor, 91 * 1024")
tests = tests.replace("first.cursor, 4, None", "&first.cursor, 4, None")
tests = tests.replace("            UploadCursor {\n", "            &UploadCursor {\n")
tests_path.write_text(tests, encoding="utf-8")

mutation_path = Path("crates/ptah-transfer/tests/b01_source_mutation.rs")
mutation = mutation_path.read_text(encoding="utf-8")
mutation = mutation.replace("UploadCursor::default(), 64 * 1024", "&UploadCursor::default(), 64 * 1024")
mutation_path.write_text(mutation, encoding="utf-8")
