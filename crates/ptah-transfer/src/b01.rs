use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;

/// Transfer priority used by the B01 scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransferPriority {
    /// Background work that may yield to all other classes.
    Low,
    /// Default work.
    Normal,
    /// Operator-selected high-priority work.
    High,
    /// Recovery or otherwise explicitly urgent work.
    Critical,
}

/// Whether a queued transfer depends on an optional remote adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferLane {
    /// Work whose execution can remain local to the current Node.
    Local,
    /// Work that requires a remote Node/provider boundary.
    Remote,
}

/// One deterministic queued transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedTransfer {
    /// Stable caller-owned job identity.
    pub id: String,
    /// Scheduling priority.
    pub priority: TransferPriority,
    /// Local or remote execution lane.
    pub lane: TransferLane,
    sequence: u64,
}

/// Bounded queue policy. Reserved local slots prevent optional remote work from starving local work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueuePolicy {
    /// Maximum jobs selected for one scheduling batch.
    pub max_active: usize,
    /// Slots reserved for local work while local work is pending.
    pub reserved_local_slots: usize,
}

/// Deterministic transfer queue ordered by priority then FIFO sequence.
#[derive(Debug, Default)]
pub struct TransferQueue {
    next_sequence: u64,
    pending: Vec<QueuedTransfer>,
}

impl TransferQueue {
    /// Enqueue one job. Duplicate IDs are rejected so queue identity cannot silently alias.
    pub fn enqueue(
        &mut self,
        id: impl Into<String>,
        priority: TransferPriority,
        lane: TransferLane,
    ) -> Result<(), B01Error> {
        let id = id.into();
        if self.pending.iter().any(|item| item.id == id) {
            return Err(B01Error::DuplicateQueueId(id));
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.pending.push(QueuedTransfer {
            id,
            priority,
            lane,
            sequence,
        });
        Ok(())
    }

    /// Number of pending jobs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether no jobs are pending.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Select one bounded execution batch while preserving local capacity.
    pub fn schedule(&mut self, policy: QueuePolicy) -> Result<Vec<QueuedTransfer>, B01Error> {
        if policy.max_active == 0 || policy.reserved_local_slots > policy.max_active {
            return Err(B01Error::InvalidQueuePolicy);
        }

        let target = policy.max_active.min(self.pending.len());
        let mut selected = Vec::with_capacity(target);
        while selected.len() < target && !self.pending.is_empty() {
            let local_pending = self.pending.iter().any(|item| item.lane == TransferLane::Local);
            let remote_selected = selected
                .iter()
                .filter(|item: &&QueuedTransfer| item.lane == TransferLane::Remote)
                .count();
            let remote_limit = policy.max_active.saturating_sub(policy.reserved_local_slots);
            let require_local = local_pending && remote_selected >= remote_limit;

            let index = self
                .pending
                .iter()
                .enumerate()
                .filter(|(_, item)| !require_local || item.lane == TransferLane::Local)
                .max_by_key(|(_, item)| (item.priority, std::cmp::Reverse(item.sequence)))
                .map(|(index, _)| index)
                .ok_or(B01Error::InvalidQueuePolicy)?;
            selected.push(self.pending.swap_remove(index));
        }
        Ok(selected)
    }
}

/// Resume cursor for a provider upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UploadCursor {
    /// Exact source offset already durably accepted by the provider sink.
    pub accepted_offset: u64,
}

/// Result of one bounded resumable upload pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumableUploadReport {
    /// Offset from which this pass started.
    pub starting_offset: u64,
    /// Offset durably accepted after this pass.
    pub accepted_offset: u64,
    /// Total source size.
    pub source_size: u64,
    /// SHA-256 of the complete source bytes.
    pub source_sha256: String,
    /// Whether the source is completely transferred.
    pub complete: bool,
}

/// Minimal provider contract needed for offset-safe upload resume.
pub trait ResumableUploadSink {
    /// Number of bytes the provider says are durably accepted for this upload identity.
    fn accepted_len(&self) -> Result<u64, String>;
    /// Write exact bytes at the current accepted offset.
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), String>;
    /// Finalize the provider object only after all source bytes are accepted.
    fn finalize(&mut self) -> Result<(), String>;
}

/// Stream a local source into a provider sink, optionally stopping after a byte budget.
///
/// The sink's durable offset must exactly match the caller cursor. A mismatch fails closed rather
/// than overwriting or skipping provider bytes.
pub fn resumable_upload_file(
    source: &Path,
    sink: &mut dyn ResumableUploadSink,
    cursor: UploadCursor,
    chunk_size: usize,
    byte_budget: Option<u64>,
) -> Result<ResumableUploadReport, B01Error> {
    if chunk_size == 0 {
        return Err(B01Error::InvalidChunkSize);
    }
    let source_size = fs::metadata(source)?.len();
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

    let source_sha256 = sha256_file(source)?;
    let starting_offset = cursor.accepted_offset;
    let mut accepted_offset = starting_offset;
    let mut remaining_budget = byte_budget.unwrap_or(u64::MAX);
    let mut file = File::open(source)?;
    file.seek(SeekFrom::Start(starting_offset))?;
    let mut buffer = vec![0_u8; chunk_size];

    while accepted_offset < source_size && remaining_budget > 0 {
        let remaining_source = source_size - accepted_offset;
        let request = usize::try_from(
            remaining_source
                .min(remaining_budget)
                .min(u64::try_from(chunk_size).expect("usize fits u64")),
        )
        .expect("bounded request fits usize");
        let read = file.read(&mut buffer[..request])?;
        if read == 0 {
            return Err(B01Error::UnexpectedSourceEof);
        }
        sink.write_at(accepted_offset, &buffer[..read])
            .map_err(B01Error::Adapter)?;
        let read_u64 = u64::try_from(read).expect("usize fits u64");
        accepted_offset += read_u64;
        remaining_budget = remaining_budget.saturating_sub(read_u64);
    }

    let complete = accepted_offset == source_size;
    if complete {
        sink.finalize().map_err(B01Error::Adapter)?;
    }
    Ok(ResumableUploadReport {
        starting_offset,
        accepted_offset,
        source_size,
        source_sha256,
        complete,
    })
}

/// One exact verified download range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedRange {
    /// Start offset.
    pub start: u64,
    /// Number of verified bytes.
    pub len: u64,
}

/// Durable range cursor for segmented download resume.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DownloadCursor {
    verified: BTreeMap<u64, u64>,
}

impl DownloadCursor {
    /// Mark one exact range as verified.
    pub fn mark_verified(&mut self, range: VerifiedRange) {
        self.verified.insert(range.start, range.len);
    }

    /// Whether an exact range has already been verified.
    #[must_use]
    pub fn contains(&self, range: VerifiedRange) -> bool {
        self.verified.get(&range.start) == Some(&range.len)
    }

    /// Number of verified ranges.
    #[must_use]
    pub fn len(&self) -> usize {
        self.verified.len()
    }

    /// Whether no verified ranges are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.verified.is_empty()
    }
}

/// Source capable of serving exact byte ranges.
pub trait RangeSource {
    /// Stable source identity used only for execution evidence and reporting.
    fn source_id(&self) -> &str;
    /// Return exactly the requested range or an adapter error.
    fn read_range(&mut self, start: u64, len: usize) -> Result<Vec<u8>, String>;
}

/// One retained failed source attempt during segmented download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFailure {
    /// Source identity.
    pub source_id: String,
    /// Segment start offset.
    pub start: u64,
    /// Provider error or invalid-range explanation.
    pub error: String,
}

/// Result of one segmented/multi-source download pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentedDownloadReport {
    /// Updated durable resume cursor.
    pub cursor: DownloadCursor,
    /// Number of ranges reused from a prior pass.
    pub resumed_ranges: usize,
    /// Number of new ranges downloaded in this pass.
    pub downloaded_ranges: usize,
    /// Source IDs that successfully contributed bytes.
    pub successful_sources: Vec<String>,
    /// Failed source attempts retained instead of erased.
    pub failures: Vec<SourceFailure>,
    /// Whether every required segment is verified.
    pub complete: bool,
    /// Whole-file SHA-256 when complete.
    pub destination_sha256: Option<String>,
}

/// Download fixed-size segments from multiple sources with fallback and exact-range resume.
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

    let mut resumed_ranges = 0_usize;
    let mut downloaded_ranges = 0_usize;
    let mut failures = Vec::new();
    let mut successful_sources = Vec::new();
    let mut successful_source_set = HashSet::new();
    let segment_size_u64 = u64::try_from(segment_size).expect("usize fits u64");
    let segment_count = if expected_size == 0 {
        0
    } else {
        expected_size.div_ceil(segment_size_u64)
    };

    for segment_index in 0..segment_count {
        let start = segment_index * segment_size_u64;
        let len_u64 = (expected_size - start).min(segment_size_u64);
        let range = VerifiedRange {
            start,
            len: len_u64,
        };
        if cursor.contains(range) {
            resumed_ranges += 1;
            continue;
        }
        if max_new_segments.is_some_and(|limit| downloaded_ranges >= limit) {
            break;
        }

        let len = usize::try_from(len_u64).expect("segment length fits usize");
        let mut segment_bytes = None;
        let source_count = sources.len();
        let preferred = usize::try_from(segment_index % u64::try_from(source_count).expect("usize fits u64"))
            .expect("modulo result fits usize");
        for attempt in 0..source_count {
            let source_index = (preferred + attempt) % source_count;
            let source = &mut sources[source_index];
            match source.read_range(start, len) {
                Ok(bytes) if bytes.len() == len => {
                    let source_id = source.source_id().to_owned();
                    if successful_source_set.insert(source_id.clone()) {
                        successful_sources.push(source_id);
                    }
                    segment_bytes = Some(bytes);
                    break;
                }
                Ok(bytes) => failures.push(SourceFailure {
                    source_id: source.source_id().to_owned(),
                    start,
                    error: format!("short range: expected {len} bytes, observed {}", bytes.len()),
                }),
                Err(error) => failures.push(SourceFailure {
                    source_id: source.source_id().to_owned(),
                    start,
                    error,
                }),
            }
        }
        let bytes = segment_bytes.ok_or(B01Error::SegmentUnavailable { start, len })?;
        output.seek(SeekFrom::Start(start))?;
        output.write_all(&bytes)?;
        output.flush()?;
        cursor.mark_verified(range);
        downloaded_ranges += 1;
    }

    let complete = usize::try_from(segment_count).is_ok_and(|count| cursor.len() == count);
    let destination_sha256 = if complete {
        let digest = sha256_file(destination)?;
        if let Some(expected) = expected_sha256 {
            if digest != expected {
                return Err(B01Error::DigestMismatch {
                    expected: expected.to_owned(),
                    observed: digest,
                });
            }
        }
        Some(digest)
    } else {
        None
    };

    Ok(SegmentedDownloadReport {
        cursor,
        resumed_ranges,
        downloaded_ranges,
        successful_sources,
        failures,
        complete,
        destination_sha256,
    })
}

/// Export boundary implemented by Node-to-Node, object-store and Drive adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportTargetKind {
    /// Another Ptah Node.
    Node,
    /// Object-store provider.
    ObjectStore,
    /// Drive-style provider.
    Drive,
}

/// Positive adapter receipt. It proves only the adapter's bounded export result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportReceipt {
    /// Adapter target kind.
    pub target: ExportTargetKind,
    /// Provider/object reference returned by the adapter.
    pub destination_ref: String,
    /// Exact exported byte count.
    pub byte_count: u64,
    /// SHA-256 of exported bytes as observed by the caller.
    pub sha256: String,
}

/// Export adapter contract used by B01 orchestration.
pub trait ExportAdapter {
    /// Adapter class.
    fn target_kind(&self) -> ExportTargetKind;
    /// Export exact bytes under the adapter's own authorization boundary.
    fn export(&mut self, bytes: &[u8], sha256: &str) -> Result<ExportReceipt, String>;
}

/// Result of local-first export with one optional remote target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOutcome {
    /// Mandatory local/object-store receipt.
    pub primary: ExportReceipt,
    /// Optional remote receipt when the remote adapter succeeded.
    pub remote: Option<ExportReceipt>,
    /// Optional remote failure retained without rewriting primary success.
    pub remote_failure: Option<String>,
}

/// Execute a mandatory primary export and then an optional remote export.
///
/// Remote failure is observable but cannot roll back or hide the completed primary result.
pub fn export_with_optional_remote(
    bytes: &[u8],
    primary: &mut dyn ExportAdapter,
    remote: Option<&mut dyn ExportAdapter>,
) -> Result<ExportOutcome, B01Error> {
    let digest = sha256_bytes(bytes);
    let primary_receipt = primary.export(bytes, &digest).map_err(B01Error::Adapter)?;
    let (remote_receipt, remote_failure) = if let Some(remote) = remote {
        match remote.export(bytes, &digest) {
            Ok(receipt) => (Some(receipt), None),
            Err(error) => (None, Some(error)),
        }
    } else {
        (None, None)
    };
    Ok(ExportOutcome {
        primary: primary_receipt,
        remote: remote_receipt,
        remote_failure,
    })
}

/// Deduplicated byte admission record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupAdmission {
    /// Canonical content digest used by this local policy index.
    pub sha256: String,
    /// Stable content-addressed key.
    pub object_key: String,
    /// Whether the same digest was already admitted.
    pub deduplicated: bool,
    /// Number of logical references retained by this policy index.
    pub reference_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DedupEntry {
    object_key: String,
    reference_count: u64,
}

/// Small policy index layered on top of A07's canonical content-addressed storage semantics.
#[derive(Debug, Default)]
pub struct DedupIndex {
    entries: HashMap<String, DedupEntry>,
}

impl DedupIndex {
    /// Admit bytes and return a stable content-addressed key.
    pub fn admit(&mut self, bytes: &[u8]) -> DedupAdmission {
        let sha256 = sha256_bytes(bytes);
        let entry = self.entries.entry(sha256.clone()).or_insert_with(|| DedupEntry {
            object_key: format!("sha256/{}/{}", &sha256[..2], sha256),
            reference_count: 0,
        });
        let deduplicated = entry.reference_count > 0;
        entry.reference_count = entry.reference_count.saturating_add(1);
        DedupAdmission {
            sha256,
            object_key: entry.object_key.clone(),
            deduplicated,
            reference_count: entry.reference_count,
        }
    }
}

/// One storage generation considered by retention policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionCandidate {
    /// Stable candidate identity.
    pub id: String,
    /// Monotonic storage generation.
    pub generation: u64,
    /// Whether the candidate has independent verification evidence.
    pub verified: bool,
    /// Explicit caller pin that forbids automatic pruning.
    pub pinned: bool,
}

/// Safe retention policy. Automatic pruning applies only to older verified, unpinned generations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Number of newest verified generations that must be retained.
    pub keep_latest_verified: usize,
}

/// Deterministic retention decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrunePlan {
    /// IDs safe to prune under this policy.
    pub prune: Vec<String>,
    /// IDs retained, including unverified and pinned state.
    pub retain: Vec<String>,
}

/// Build a conservative prune plan that never automatically deletes unverified or pinned state.
#[must_use]
pub fn plan_retention(candidates: &[RetentionCandidate], policy: RetentionPolicy) -> PrunePlan {
    let mut verified_unpinned: Vec<&RetentionCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.verified && !candidate.pinned)
        .collect();
    verified_unpinned.sort_by_key(|candidate| std::cmp::Reverse(candidate.generation));
    let keep_ids: HashSet<&str> = verified_unpinned
        .iter()
        .take(policy.keep_latest_verified)
        .map(|candidate| candidate.id.as_str())
        .collect();

    let mut prune = Vec::new();
    let mut retain = Vec::new();
    for candidate in candidates {
        if candidate.verified && !candidate.pinned && !keep_ids.contains(candidate.id.as_str()) {
            prune.push(candidate.id.clone());
        } else {
            retain.push(candidate.id.clone());
        }
    }
    prune.sort();
    retain.sort();
    PrunePlan { prune, retain }
}

/// Sync state remains distinct from backup state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// Both observed sides match the cursor.
    InSync,
    /// One side advanced and synchronization work is pending.
    Pending,
    /// Both sides advanced independently and require explicit resolution.
    Conflict,
}

/// Durable sync cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCursor {
    /// Last reconciled local revision token.
    pub local_revision: String,
    /// Last reconciled remote revision token.
    pub remote_revision: String,
    /// Monotonic cursor sequence.
    pub sequence: u64,
}

/// Explicit conflict record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncConflict {
    /// Local revision that diverged.
    pub local_revision: String,
    /// Remote revision that diverged.
    pub remote_revision: String,
    /// Cursor sequence at which the conflict was observed.
    pub cursor_sequence: u64,
}

/// Caller-selected resolution. Ptah does not infer a winner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Advance both cursor sides to the local revision.
    KeepLocal,
    /// Advance both cursor sides to the remote revision.
    KeepRemote,
    /// Preserve divergent revisions; caller supplies the resulting local/remote tokens.
    KeepBoth {
        /// Resulting local revision token.
        local_revision: String,
        /// Resulting remote revision token.
        remote_revision: String,
    },
    /// Caller-created merged revision becomes the reconciled revision on both sides.
    Merged(String),
}

/// Retained resolution record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncResolutionRecord {
    /// Conflict that was resolved.
    pub conflict: SyncConflict,
    /// Caller-selected resolution.
    pub resolution: ConflictResolution,
    /// Cursor after applying the explicit resolution.
    pub cursor: SyncCursor,
}

/// One explicit sync relationship.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRelationship {
    /// Stable relationship identity.
    pub id: String,
    /// Reconciliation cursor.
    pub cursor: SyncCursor,
    /// Current state.
    pub state: SyncState,
    /// Current explicit conflict, if any.
    pub conflict: Option<SyncConflict>,
}

impl SyncRelationship {
    /// Construct an initially reconciled relationship.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        local_revision: impl Into<String>,
        remote_revision: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            cursor: SyncCursor {
                local_revision: local_revision.into(),
                remote_revision: remote_revision.into(),
                sequence: 0,
            },
            state: SyncState::InSync,
            conflict: None,
        }
    }

    /// Observe exact current local/remote revision tokens.
    pub fn observe(
        &mut self,
        local_revision: impl Into<String>,
        remote_revision: impl Into<String>,
    ) -> SyncState {
        let local_revision = local_revision.into();
        let remote_revision = remote_revision.into();
        let local_changed = local_revision != self.cursor.local_revision;
        let remote_changed = remote_revision != self.cursor.remote_revision;
        self.state = match (local_changed, remote_changed) {
            (false, false) => SyncState::InSync,
            (true, true) if local_revision != remote_revision => {
                self.conflict = Some(SyncConflict {
                    local_revision,
                    remote_revision,
                    cursor_sequence: self.cursor.sequence,
                });
                SyncState::Conflict
            }
            _ => {
                self.conflict = None;
                SyncState::Pending
            }
        };
        self.state
    }

    /// Resolve only an explicit conflict using a caller-selected policy.
    pub fn resolve(
        &mut self,
        resolution: ConflictResolution,
    ) -> Result<SyncResolutionRecord, B01Error> {
        let conflict = self.conflict.clone().ok_or(B01Error::NoSyncConflict)?;
        let (local_revision, remote_revision) = match &resolution {
            ConflictResolution::KeepLocal => (
                conflict.local_revision.clone(),
                conflict.local_revision.clone(),
            ),
            ConflictResolution::KeepRemote => (
                conflict.remote_revision.clone(),
                conflict.remote_revision.clone(),
            ),
            ConflictResolution::KeepBoth {
                local_revision,
                remote_revision,
            } => (local_revision.clone(), remote_revision.clone()),
            ConflictResolution::Merged(revision) => (revision.clone(), revision.clone()),
        };
        self.cursor = SyncCursor {
            local_revision,
            remote_revision,
            sequence: self.cursor.sequence.saturating_add(1),
        };
        self.state = SyncState::InSync;
        self.conflict = None;
        Ok(SyncResolutionRecord {
            conflict,
            resolution,
            cursor: self.cursor.clone(),
        })
    }
}

/// Immutable file entry inside one B01 backup snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupEntry {
    /// Caller-owned logical path in the backup set.
    pub path: String,
    /// Exact SHA-256 digest.
    pub sha256: String,
    /// Exact retained bytes.
    pub bytes: Vec<u8>,
}

/// B01 backup snapshot. This is byte backup state, not a Workspace checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSnapshot {
    /// Stable snapshot identity.
    pub id: String,
    /// Monotonic creation sequence.
    pub sequence: u64,
    /// Snapshot entries.
    pub entries: Vec<BackupEntry>,
    /// Whether every entry was independently rehashed after snapshot creation.
    pub verified: bool,
}

/// Backup retention policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupPolicy {
    /// Number of newest verified snapshots to keep during pruning.
    pub keep_latest_verified: usize,
}

/// Restore result deliberately excludes Workspace recovery claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredBackup {
    /// Snapshot restored.
    pub snapshot_id: String,
    /// Restored logical files.
    pub files: Vec<(String, Vec<u8>)>,
    /// Always false: restored bytes are not proof of Workspace recovery.
    pub workspace_recovery_claim: bool,
}

/// In-memory backup repository used by the B01 policy/runtime layer.
#[derive(Debug, Default)]
pub struct BackupRepository {
    next_sequence: u64,
    snapshots: Vec<BackupSnapshot>,
}

impl BackupRepository {
    /// Create one immutable byte snapshot. Duplicate logical paths are rejected.
    pub fn create_snapshot(
        &mut self,
        id: impl Into<String>,
        files: Vec<(String, Vec<u8>)>,
    ) -> Result<&BackupSnapshot, B01Error> {
        let id = id.into();
        if self.snapshots.iter().any(|snapshot| snapshot.id == id) {
            return Err(B01Error::DuplicateSnapshotId(id));
        }
        let mut seen = HashSet::new();
        let mut entries = Vec::with_capacity(files.len());
        for (path, bytes) in files {
            if !seen.insert(path.clone()) {
                return Err(B01Error::DuplicateBackupPath(path));
            }
            entries.push(BackupEntry {
                path,
                sha256: sha256_bytes(&bytes),
                bytes,
            });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let snapshot = BackupSnapshot {
            id,
            sequence: self.next_sequence,
            entries,
            verified: false,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.snapshots.push(snapshot);
        Ok(self.snapshots.last().expect("snapshot was just pushed"))
    }

    /// Rehash every retained entry before marking a snapshot verified.
    pub fn verify_snapshot(&mut self, id: &str) -> Result<(), B01Error> {
        let snapshot = self
            .snapshots
            .iter_mut()
            .find(|snapshot| snapshot.id == id)
            .ok_or_else(|| B01Error::SnapshotNotFound(id.to_owned()))?;
        for entry in &snapshot.entries {
            let observed = sha256_bytes(&entry.bytes);
            if observed != entry.sha256 {
                return Err(B01Error::DigestMismatch {
                    expected: entry.sha256.clone(),
                    observed,
                });
            }
        }
        snapshot.verified = true;
        Ok(())
    }

    /// Prune only older verified snapshots; unverified snapshots are retained for diagnosis.
    pub fn prune(&mut self, policy: BackupPolicy) -> Vec<String> {
        let mut verified_sequences: Vec<u64> = self
            .snapshots
            .iter()
            .filter(|snapshot| snapshot.verified)
            .map(|snapshot| snapshot.sequence)
            .collect();
        verified_sequences.sort_by_key(|sequence| std::cmp::Reverse(*sequence));
        let keep: HashSet<u64> = verified_sequences
            .into_iter()
            .take(policy.keep_latest_verified)
            .collect();
        let mut pruned = Vec::new();
        self.snapshots.retain(|snapshot| {
            let remove = snapshot.verified && !keep.contains(&snapshot.sequence);
            if remove {
                pruned.push(snapshot.id.clone());
            }
            !remove
        });
        pruned.sort();
        pruned
    }

    /// Restore exact bytes only from an independently verified snapshot.
    pub fn restore(&self, id: &str) -> Result<RestoredBackup, B01Error> {
        let snapshot = self
            .snapshots
            .iter()
            .find(|snapshot| snapshot.id == id)
            .ok_or_else(|| B01Error::SnapshotNotFound(id.to_owned()))?;
        if !snapshot.verified {
            return Err(B01Error::SnapshotUnverified(id.to_owned()));
        }
        Ok(RestoredBackup {
            snapshot_id: snapshot.id.clone(),
            files: snapshot
                .entries
                .iter()
                .map(|entry| (entry.path.clone(), entry.bytes.clone()))
                .collect(),
            workspace_recovery_claim: false,
        })
    }

    /// Current snapshot identities in creation order.
    #[must_use]
    pub fn snapshot_ids(&self) -> Vec<String> {
        self.snapshots
            .iter()
            .map(|snapshot| snapshot.id.clone())
            .collect()
    }
}

/// B01 transfer/storage expansion failures.
#[derive(Debug, Error)]
pub enum B01Error {
    /// Filesystem I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Adapter/provider failure.
    #[error("adapter failure: {0}")]
    Adapter(String),
    /// Zero-sized transfer chunks are invalid.
    #[error("chunk or segment size must be greater than zero")]
    InvalidChunkSize,
    /// Queue policy cannot be satisfied.
    #[error("invalid queue policy")]
    InvalidQueuePolicy,
    /// Duplicate queue identity.
    #[error("duplicate queue job id: {0}")]
    DuplicateQueueId(String),
    /// Resume cursor is beyond source size.
    #[error("resume offset {offset} exceeds source size {size}")]
    ResumeOffsetOutOfRange { offset: u64, size: u64 },
    /// Provider offset does not match the retained caller cursor.
    #[error("resume sink mismatch: cursor={cursor}, sink={sink}")]
    ResumeSinkMismatch { cursor: u64, sink: u64 },
    /// Source ended before its declared size.
    #[error("source ended before declared size")]
    UnexpectedSourceEof,
    /// No range source was configured.
    #[error("segmented download requires at least one source")]
    NoRangeSource,
    /// Every source failed for one exact range.
    #[error("no source could provide segment at {start} with length {len}")]
    SegmentUnavailable { start: u64, len: usize },
    /// Whole-content digest mismatch.
    #[error("digest mismatch: expected {expected}, observed {observed}")]
    DigestMismatch { expected: String, observed: String },
    /// Conflict resolution was requested when no conflict exists.
    #[error("no explicit sync conflict exists")]
    NoSyncConflict,
    /// Duplicate backup snapshot identity.
    #[error("duplicate backup snapshot id: {0}")]
    DuplicateSnapshotId(String),
    /// Duplicate logical path inside one snapshot.
    #[error("duplicate backup path: {0}")]
    DuplicateBackupPath(String),
    /// Backup snapshot does not exist.
    #[error("backup snapshot not found: {0}")]
    SnapshotNotFound(String),
    /// Restore requires independent snapshot verification.
    #[error("backup snapshot is not verified: {0}")]
    SnapshotUnverified(String),
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Utility path returned by tests/consumers that want a deterministic partial-file sibling.
#[must_use]
pub fn partial_path_for(destination: &Path) -> PathBuf {
    let mut path = destination.as_os_str().to_owned();
    path.push(".partial");
    PathBuf::from(path)
}
