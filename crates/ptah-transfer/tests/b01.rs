//! B01 transfer and storage acceptance regressions.

use ptah_transfer::{
    B01Error, BackupPolicy, BackupRepository, ConflictResolution, DedupIndex, DownloadCursor,
    ExportAdapter, ExportReceipt, ExportTargetKind, QueuePolicy, RangeSource, ResumableUploadSink,
    RetentionCandidate, RetentionPolicy, SyncRelationship, SyncState, TransferLane,
    TransferPriority, TransferQueue, UploadCursor, VerifiedRange, export_with_optional_remote,
    plan_retention, resumable_upload_file, segmented_download,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new() -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("ptah-b01-{}-{sequence}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp root");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Default)]
struct MemoryUploadSink {
    bytes: Vec<u8>,
    finalized: bool,
}

impl ResumableUploadSink for MemoryUploadSink {
    fn accepted_len(&self) -> Result<u64, String> {
        Ok(self.bytes.len() as u64)
    }

    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), String> {
        if offset != self.bytes.len() as u64 {
            return Err(format!(
                "non-contiguous provider write: offset={offset}, accepted={}",
                self.bytes.len()
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), String> {
        self.finalized = true;
        Ok(())
    }
}

struct ByteRangeSource {
    id: String,
    bytes: Vec<u8>,
    fail_starts: Vec<u64>,
    calls: usize,
}

impl ByteRangeSource {
    fn new(id: &str, bytes: &[u8]) -> Self {
        Self {
            id: id.to_owned(),
            bytes: bytes.to_vec(),
            fail_starts: Vec::new(),
            calls: 0,
        }
    }
}

impl RangeSource for ByteRangeSource {
    fn source_id(&self) -> &str {
        &self.id
    }

    fn read_range(&mut self, start: u64, len: usize) -> Result<Vec<u8>, String> {
        self.calls += 1;
        if self.fail_starts.contains(&start) {
            return Err(format!("{} unavailable at {start}", self.id));
        }
        let start = usize::try_from(start).map_err(|_| "range too large".to_owned())?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| "range overflow".to_owned())?;
        self.bytes
            .get(start..end)
            .map(ToOwned::to_owned)
            .ok_or_else(|| "range outside source".to_owned())
    }
}

struct MemoryExport {
    kind: ExportTargetKind,
    destination: String,
    fail: bool,
    bytes: Vec<u8>,
}

impl MemoryExport {
    fn new(kind: ExportTargetKind, destination: &str) -> Self {
        Self {
            kind,
            destination: destination.to_owned(),
            fail: false,
            bytes: Vec::new(),
        }
    }
}

impl ExportAdapter for MemoryExport {
    fn target_kind(&self) -> ExportTargetKind {
        self.kind
    }

    fn export(&mut self, bytes: &[u8], sha256: &str) -> Result<ExportReceipt, String> {
        if self.fail {
            return Err(format!("{:?} adapter unavailable", self.kind));
        }
        self.bytes = bytes.to_vec();
        Ok(ExportReceipt {
            target: self.kind,
            destination_ref: self.destination.clone(),
            byte_count: bytes.len() as u64,
            sha256: sha256.to_owned(),
        })
    }
}

#[test]
fn interrupted_large_upload_resumes_from_exact_provider_offset() {
    let temp = TempRoot::new();
    let source = temp.path().join("large-upload.bin");
    let bytes: Vec<u8> = (0..1_500_000)
        .map(|index| u8::try_from(index % 251).expect("modulo fits u8"))
        .collect();
    fs::write(&source, &bytes).expect("write source");
    let mut sink = MemoryUploadSink::default();

    let first = resumable_upload_file(
        &source,
        &mut sink,
        &UploadCursor::default(),
        64 * 1024,
        Some(430_000),
    )
    .expect("first bounded upload pass");
    assert!(!first.complete);
    assert_eq!(first.accepted_offset, 430_000);
    assert!(!sink.finalized);

    let second = resumable_upload_file(&source, &mut sink, &first.cursor, 91 * 1024, None)
        .expect("resume upload");
    assert!(second.complete);
    assert_eq!(second.starting_offset, 430_000);
    assert_eq!(second.accepted_offset, bytes.len() as u64);
    assert!(sink.finalized);
    assert_eq!(sink.bytes, bytes);
    assert_eq!(second.source_sha256, sha256(&sink.bytes));
}

#[test]
fn upload_resume_rejects_cursor_provider_disagreement() {
    let temp = TempRoot::new();
    let source = temp.path().join("source.bin");
    fs::write(&source, b"0123456789").expect("write source");
    let mut sink = MemoryUploadSink {
        bytes: b"01234".to_vec(),
        finalized: false,
    };
    assert!(matches!(
        resumable_upload_file(
            &source,
            &mut sink,
            &UploadCursor {
                accepted_offset: 4,
                ..UploadCursor::default()
            },
            4,
            None,
        ),
        Err(B01Error::ResumeSinkMismatch { cursor: 4, sink: 5 })
    ));
}

#[test]
fn upload_resume_rejects_changed_source_identity() {
    let temp = TempRoot::new();
    let source = temp.path().join("identity-fenced-upload.bin");
    fs::write(&source, b"abcdefghij").expect("write source");
    let mut sink = MemoryUploadSink::default();
    let first = resumable_upload_file(&source, &mut sink, &UploadCursor::default(), 4, Some(5))
        .expect("first pass");
    fs::write(&source, b"abcdeXXXXX").expect("mutate source");
    assert!(matches!(
        resumable_upload_file(&source, &mut sink, &first.cursor, 4, None),
        Err(B01Error::ResumeSourceIdentityMismatch)
    ));
    assert_eq!(sink.bytes, b"abcde");
    assert!(!sink.finalized);
}

#[test]
fn segmented_multi_source_download_resumes_and_falls_back_without_erasing_failure() {
    let temp = TempRoot::new();
    let destination = temp.path().join("segmented.bin");
    let bytes: Vec<u8> = (0..900_000)
        .map(|index| u8::try_from((index * 7) % 253).expect("modulo fits u8"))
        .collect();
    let expected = sha256(&bytes);
    let segment_size = 128 * 1024;

    let mut first_source = ByteRangeSource::new("primary", &bytes);
    let mut second_source = ByteRangeSource::new("secondary", &bytes);
    first_source.fail_starts.push((2 * segment_size) as u64);

    let mut sources: [&mut dyn RangeSource; 2] = [&mut first_source, &mut second_source];
    let first = segmented_download(
        &mut sources,
        &destination,
        bytes.len() as u64,
        segment_size,
        DownloadCursor::default(),
        Some(3),
        Some(&expected),
    )
    .expect("first download pass");
    assert!(!first.complete);
    assert_eq!(first.downloaded_ranges, 3);
    assert_eq!(first.cursor.len(), 3);
    assert!(!first.failures.is_empty());

    let second = segmented_download(
        &mut sources,
        &destination,
        bytes.len() as u64,
        segment_size,
        first.cursor,
        None,
        Some(&expected),
    )
    .expect("resume download");
    assert!(second.complete);
    assert_eq!(second.resumed_ranges, 3);
    assert_eq!(
        second.destination_sha256.as_deref(),
        Some(expected.as_str())
    );
    assert_eq!(fs::read(destination).expect("read destination"), bytes);
    assert!(!second.successful_sources.is_empty());
}

#[test]
fn verified_download_ranges_are_digest_bound_not_filename_or_progress_claims() {
    let mut cursor = DownloadCursor::default();
    let exact = VerifiedRange {
        start: 0,
        len: 128,
        sha256: "a".repeat(64),
    };
    cursor.mark_verified(exact.clone());
    assert!(cursor.contains(&exact));
    assert!(!cursor.contains(&VerifiedRange {
        start: 0,
        len: 127,
        sha256: exact.sha256.clone(),
    }));
    assert!(!cursor.contains(&VerifiedRange {
        start: 0,
        len: 128,
        sha256: "b".repeat(64),
    }));
}

#[test]
fn segmented_resume_rejects_corrupted_retained_range() {
    let temp = TempRoot::new();
    let destination = temp.path().join("corrupt-resume.bin");
    let bytes: Vec<u8> = (0..400_000)
        .map(|index| u8::try_from(index % 241).expect("modulo fits u8"))
        .collect();
    let expected = sha256(&bytes);
    let mut first_source = ByteRangeSource::new("primary", &bytes);
    let mut second_source = ByteRangeSource::new("secondary", &bytes);
    let mut sources: [&mut dyn RangeSource; 2] = [&mut first_source, &mut second_source];
    let first = segmented_download(
        &mut sources,
        &destination,
        bytes.len() as u64,
        64 * 1024,
        DownloadCursor::default(),
        Some(2),
        Some(&expected),
    )
    .expect("first pass");
    let mut partial = fs::OpenOptions::new()
        .write(true)
        .open(&destination)
        .expect("open retained partial");
    partial.seek(SeekFrom::Start(0)).expect("seek");
    partial.write_all(b"X").expect("corrupt retained range");
    partial.flush().expect("flush corruption");
    assert!(matches!(
        segmented_download(
            &mut sources,
            &destination,
            bytes.len() as u64,
            64 * 1024,
            first.cursor,
            None,
            Some(&expected),
        ),
        Err(B01Error::ResumeRangeDigestMismatch { start: 0, .. })
    ));
}

#[test]
fn segmented_download_preserves_progress_when_all_sources_fail_later_segment() {
    let temp = TempRoot::new();
    let destination = temp.path().join("blocked-segment.bin");
    let bytes = vec![7_u8; 300_000];
    let mut first_source = ByteRangeSource::new("primary", &bytes);
    let mut second_source = ByteRangeSource::new("secondary", &bytes);
    first_source.fail_starts.push((64 * 1024) as u64);
    second_source.fail_starts.push((64 * 1024) as u64);
    let mut sources: [&mut dyn RangeSource; 2] = [&mut first_source, &mut second_source];
    let report = segmented_download(
        &mut sources,
        &destination,
        bytes.len() as u64,
        64 * 1024,
        DownloadCursor::default(),
        None,
        None,
    )
    .expect("partial progress is a retained report");
    assert!(!report.complete);
    assert_eq!(report.downloaded_ranges, 1);
    assert_eq!(report.cursor.len(), 1);
    assert_eq!(report.failures.len(), 2);
    assert_eq!(
        report.blocked_segment.as_ref().map(|value| value.start),
        Some((64 * 1024) as u64)
    );
}

#[test]
fn segmented_download_rejects_cursor_ranges_outside_required_geometry() {
    let temp = TempRoot::new();
    let destination = temp.path().join("stale-cursor.bin");
    let bytes = vec![9_u8; 128 * 1024];
    let mut cursor = DownloadCursor::default();
    cursor.mark_verified(VerifiedRange {
        start: 1,
        len: 64 * 1024,
        sha256: "a".repeat(64),
    });
    let mut source = ByteRangeSource::new("primary", &bytes);
    let mut sources: [&mut dyn RangeSource; 1] = [&mut source];
    assert!(matches!(
        segmented_download(
            &mut sources,
            &destination,
            bytes.len() as u64,
            64 * 1024,
            cursor,
            None,
            None,
        ),
        Err(B01Error::InvalidDownloadCursorRange { start: 1, .. })
    ));
}

#[test]
fn priority_queue_preserves_local_capacity_while_local_work_is_pending() {
    let mut queue = TransferQueue::default();
    queue
        .enqueue(
            "remote-critical",
            TransferPriority::Critical,
            TransferLane::Remote,
        )
        .expect("enqueue");
    queue
        .enqueue("remote-high", TransferPriority::High, TransferLane::Remote)
        .expect("enqueue");
    queue
        .enqueue(
            "local-normal",
            TransferPriority::Normal,
            TransferLane::Local,
        )
        .expect("enqueue");
    queue
        .enqueue("local-low", TransferPriority::Low, TransferLane::Local)
        .expect("enqueue");

    let batch = queue
        .schedule(QueuePolicy {
            max_active: 3,
            reserved_local_slots: 1,
        })
        .expect("schedule");
    assert_eq!(batch.len(), 3);
    assert_eq!(batch[0].id, "remote-critical");
    assert_eq!(batch[1].id, "remote-high");
    assert_eq!(batch[2].id, "local-normal");
}

#[test]
fn optional_drive_failure_does_not_block_primary_object_store_work() {
    let bytes = b"local-first-export";
    let mut object_store = MemoryExport::new(ExportTargetKind::ObjectStore, "object:sha256");
    let mut drive = MemoryExport::new(ExportTargetKind::Drive, "drive:file");
    drive.fail = true;

    let outcome = export_with_optional_remote(bytes, &mut object_store, Some(&mut drive))
        .expect("primary export remains successful");
    assert_eq!(outcome.primary.target, ExportTargetKind::ObjectStore);
    assert_eq!(object_store.bytes, bytes);
    assert!(outcome.remote.is_none());
    assert!(
        outcome
            .remote_failure
            .as_deref()
            .is_some_and(|value| value.contains("Drive"))
    );
}

#[test]
fn node_object_store_and_drive_share_one_bounded_export_contract() {
    let bytes = b"adapter-contract";
    for kind in [
        ExportTargetKind::Node,
        ExportTargetKind::ObjectStore,
        ExportTargetKind::Drive,
    ] {
        let mut adapter = MemoryExport::new(kind, "destination");
        let outcome =
            export_with_optional_remote(bytes, &mut adapter, None).expect("adapter export");
        assert_eq!(outcome.primary.target, kind);
        assert_eq!(outcome.primary.byte_count, bytes.len() as u64);
        assert_eq!(outcome.primary.sha256, sha256(bytes));
    }
}

#[test]
fn content_deduplication_reuses_digest_key_without_collapsing_logical_references() {
    let mut index = DedupIndex::default();
    let first = index.admit(b"same-content");
    let second = index.admit(b"same-content");
    assert!(!first.deduplicated);
    assert!(second.deduplicated);
    assert_eq!(first.sha256, second.sha256);
    assert_eq!(first.object_key, second.object_key);
    assert_eq!(first.reference_count, 1);
    assert_eq!(second.reference_count, 2);
}

#[test]
fn retention_prunes_only_old_verified_unpinned_generations() {
    let candidates = vec![
        RetentionCandidate {
            id: "verified-old".to_owned(),
            generation: 1,
            verified: true,
            pinned: false,
        },
        RetentionCandidate {
            id: "unverified-old".to_owned(),
            generation: 2,
            verified: false,
            pinned: false,
        },
        RetentionCandidate {
            id: "pinned-old".to_owned(),
            generation: 3,
            verified: true,
            pinned: true,
        },
        RetentionCandidate {
            id: "verified-new".to_owned(),
            generation: 4,
            verified: true,
            pinned: false,
        },
    ];
    let plan = plan_retention(
        &candidates,
        RetentionPolicy {
            keep_latest_verified: 1,
        },
    );
    assert_eq!(plan.prune, vec!["verified-old"]);
    assert!(plan.retain.contains(&"unverified-old".to_owned()));
    assert!(plan.retain.contains(&"pinned-old".to_owned()));
    assert!(plan.retain.contains(&"verified-new".to_owned()));
}

#[test]
fn synchronization_conflict_is_explicit_and_ptah_does_not_choose_the_winner() {
    let mut relationship = SyncRelationship::new("sync-1", "local-r1", "remote-r1");
    assert_eq!(
        relationship.observe("local-r2", "remote-r2"),
        SyncState::Conflict
    );
    let conflict = relationship.conflict.clone().expect("explicit conflict");
    assert_eq!(conflict.local_revision, "local-r2");
    assert_eq!(conflict.remote_revision, "remote-r2");

    let resolution = relationship
        .resolve(ConflictResolution::Merged("merged-r3".to_owned()))
        .expect("caller-selected merge");
    assert_eq!(relationship.state, SyncState::InSync);
    assert_eq!(resolution.cursor.local_revision, "merged-r3");
    assert_eq!(resolution.cursor.remote_revision, "merged-r3");
    assert_eq!(resolution.cursor.sequence, 1);
}

#[test]
fn one_sided_sync_change_is_pending_until_explicit_reconciliation() {
    let mut relationship = SyncRelationship::new("sync-2", "l1", "r1");
    assert_eq!(relationship.observe("l2", "r1"), SyncState::Pending);
    assert!(relationship.conflict.is_none());
    assert!(matches!(
        relationship.resolve(ConflictResolution::KeepLocal),
        Err(B01Error::NoSyncConflict)
    ));
    let cursor = relationship
        .reconcile_pending()
        .expect("commit non-conflicting sync result");
    assert_eq!(relationship.state, SyncState::InSync);
    assert_eq!(cursor.local_revision, "l2");
    assert_eq!(cursor.remote_revision, "r1");
    assert_eq!(cursor.sequence, 1);
}

#[test]
fn returning_in_sync_clears_stale_conflict_and_blocks_old_resolution() {
    let mut relationship = SyncRelationship::new("sync-3", "l1", "r1");
    assert_eq!(relationship.observe("l2", "r2"), SyncState::Conflict);
    assert!(relationship.conflict.is_some());
    assert_eq!(relationship.observe("l1", "r1"), SyncState::InSync);
    assert!(relationship.conflict.is_none());
    assert!(matches!(
        relationship.resolve(ConflictResolution::KeepLocal),
        Err(B01Error::NoSyncConflict)
    ));
}

#[test]
fn backup_requires_verification_and_restored_bytes_never_claim_workspace_recovery() {
    let mut backups = BackupRepository::default();
    backups
        .create_snapshot(
            "snapshot-1",
            vec![
                ("objects/a.bin".to_owned(), b"alpha".to_vec()),
                ("objects/b.bin".to_owned(), b"beta".to_vec()),
            ],
        )
        .expect("create snapshot");
    assert!(matches!(
        backups.restore("snapshot-1"),
        Err(B01Error::SnapshotUnverified(_))
    ));
    backups
        .verify_snapshot("snapshot-1")
        .expect("verify snapshot");
    let restored = backups
        .restore("snapshot-1")
        .expect("restore verified bytes");
    assert_eq!(restored.snapshot_id, "snapshot-1");
    assert!(!restored.workspace_recovery_claim);
    assert_eq!(restored.files.len(), 2);
}

#[test]
fn backup_pruning_is_separate_from_sync_and_retains_unverified_snapshots() {
    let mut backups = BackupRepository::default();
    for id in ["snapshot-1", "snapshot-2", "snapshot-3"] {
        backups
            .create_snapshot(id, vec![("payload".to_owned(), id.as_bytes().to_vec())])
            .expect("snapshot");
    }
    backups.verify_snapshot("snapshot-1").expect("verify");
    backups.verify_snapshot("snapshot-2").expect("verify");
    let pruned = backups.prune(BackupPolicy {
        keep_latest_verified: 1,
    });
    assert_eq!(pruned, vec!["snapshot-1"]);
    assert_eq!(
        backups.snapshot_ids(),
        vec!["snapshot-2".to_owned(), "snapshot-3".to_owned()]
    );

    let sync = SyncRelationship::new("unrelated-sync", "l1", "r1");
    assert_eq!(sync.state, SyncState::InSync);
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
