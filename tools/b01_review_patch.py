#!/usr/bin/env python3
from pathlib import Path
import re


def sub1(text: str, pattern: str, replacement: str, label: str, flags: int = 0) -> str:
    result, count = re.subn(pattern, replacement, text, count=1, flags=flags)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return result


source_path = Path("crates/ptah-transfer/src/b01.rs")
source = source_path.read_text(encoding="utf-8")

# Upload resume must bind both provider offset and immutable source bytes.
source = sub1(
    source,
    r"""/// Resume cursor for a provider upload\.\n#\[derive\(Debug, Clone, Copy, PartialEq, Eq, Default\)\]\npub struct UploadCursor \{\n    /// Exact source offset already durably accepted by the provider sink\.\n    pub accepted_offset: u64,\n\}""",
    """/// Resume cursor for a provider upload.\n#[derive(Debug, Clone, PartialEq, Eq, Default)]\npub struct UploadCursor {\n    /// Exact source offset already durably accepted by the provider sink.\n    pub accepted_offset: u64,\n    /// Exact source size bound to this provider upload identity.\n    pub source_size: Option<u64>,\n    /// Whole-source SHA-256 bound to this provider upload identity.\n    pub source_sha256: Option<String>,\n}""",
    "upload cursor",
)
source = sub1(
    source,
    r"""pub struct ResumableUploadReport \{\n    /// Offset from which this pass started\.\n    pub starting_offset: u64,""",
    """pub struct ResumableUploadReport {\n    /// Resume cursor bound to the exact source identity and accepted provider offset.\n    pub cursor: UploadCursor,\n    /// Offset from which this pass started.\n    pub starting_offset: u64,""",
    "upload report cursor",
)
source = sub1(
    source,
    r"""    let source_size = fs::metadata\(source\)\?\.len\(\);\n    if cursor\.accepted_offset > source_size \{""",
    """    let source_size = fs::metadata(source)?.len();\n    let source_sha256 = sha256_file(source)?;\n    if cursor.source_size.is_some_and(|expected| expected != source_size)\n        || cursor\n            .source_sha256\n            .as_deref()\n            .is_some_and(|expected| expected != source_sha256.as_str())\n    {\n        return Err(B01Error::ResumeSourceIdentityMismatch);\n    }\n    if cursor.accepted_offset > source_size {""",
    "upload source identity fence",
)
source = sub1(
    source,
    r"""\n    let source_sha256 = sha256_file\(source\)\?;\n    let starting_offset = cursor\.accepted_offset;\n    let mut accepted_offset = starting_offset;\n    let mut remaining_budget = byte_budget\.unwrap_or\(u64::MAX\);\n    let mut file = File::open\(source\)\?;\n    file\.seek\(SeekFrom::Start\(starting_offset\)\)\?;\n    let mut buffer = vec!\[0_u8; chunk_size\];""",
    """\n    let starting_offset = cursor.accepted_offset;\n    let mut accepted_offset = starting_offset;\n    let mut remaining_budget = byte_budget.unwrap_or(u64::MAX);\n    let mut file = File::open(source)?;\n    let mut sent_prefix_hasher = Sha256::new();\n    let mut prefix_remaining = starting_offset;\n    let mut prefix_buffer = [0_u8; 64 * 1024];\n    while prefix_remaining > 0 {\n        let request = usize::try_from(\n            prefix_remaining.min(u64::try_from(prefix_buffer.len()).expect(\"usize fits u64\")),\n        )\n        .expect(\"prefix request fits usize\");\n        let read = file.read(&mut prefix_buffer[..request])?;\n        if read == 0 {\n            return Err(B01Error::UnexpectedSourceEof);\n        }\n        sent_prefix_hasher.update(&prefix_buffer[..read]);\n        prefix_remaining -= u64::try_from(read).expect(\"usize fits u64\");\n    }\n    file.seek(SeekFrom::Start(starting_offset))?;\n    let mut buffer = vec![0_u8; chunk_size];""",
    "upload stream hasher setup",
)
source = sub1(
    source,
    r"""        sink\.write_at\(accepted_offset, &buffer\[\.\.read\]\)\n            \.map_err\(B01Error::Adapter\)\?;\n        let read_u64 = u64::try_from\(read\)\.expect\(\"usize fits u64\"\);""",
    """        sent_prefix_hasher.update(&buffer[..read]);\n        sink.write_at(accepted_offset, &buffer[..read])\n            .map_err(B01Error::Adapter)?;\n        let read_u64 = u64::try_from(read).expect(\"usize fits u64\");""",
    "upload streamed bytes hash",
)
source = sub1(
    source,
    r"""    let complete = accepted_offset == source_size;\n    if complete \{\n        sink\.finalize\(\)\.map_err\(B01Error::Adapter\)\?;\n    \}\n    Ok\(ResumableUploadReport \{\n        starting_offset,""",
    """    let sent_prefix_sha256 = format!(\"{:x}\", sent_prefix_hasher.finalize());\n    let retained_prefix_sha256 = sha256_prefix(source, accepted_offset)?;\n    if sent_prefix_sha256 != retained_prefix_sha256 {\n        return Err(B01Error::SourceChangedDuringUpload {\n            expected: retained_prefix_sha256,\n            observed: sent_prefix_sha256,\n        });\n    }\n    let post_source_size = fs::metadata(source)?.len();\n    let post_source_sha256 = sha256_file(source)?;\n    if post_source_size != source_size || post_source_sha256 != source_sha256 {\n        return Err(B01Error::ResumeSourceIdentityMismatch);\n    }\n\n    let complete = accepted_offset == source_size;\n    if complete {\n        sink.finalize().map_err(B01Error::Adapter)?;\n    }\n    Ok(ResumableUploadReport {\n        cursor: UploadCursor {\n            accepted_offset,\n            source_size: Some(source_size),\n            source_sha256: Some(source_sha256.clone()),\n        },\n        starting_offset,""",
    "upload final integrity fence",
)

# Download cursor must bind exact retained bytes, survive crashes, and preserve partial failures.
source = sub1(
    source,
    r"""/// One exact verified download range\..*?/// Source capable of serving exact byte ranges\.""",
    """/// One exact verified download range.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct VerifiedRange {\n    /// Start offset.\n    pub start: u64,\n    /// Number of verified bytes.\n    pub len: u64,\n    /// SHA-256 of the exact retained range bytes.\n    pub sha256: String,\n}\n\n/// Durable digest-bound range cursor for segmented download resume.\n#[derive(Debug, Clone, PartialEq, Eq, Default)]\npub struct DownloadCursor {\n    verified: BTreeMap<u64, VerifiedRange>,\n}\n\nimpl DownloadCursor {\n    /// Mark one exact range as verified.\n    pub fn mark_verified(&mut self, range: VerifiedRange) {\n        self.verified.insert(range.start, range);\n    }\n\n    /// Whether the exact range identity, geometry and digest are retained.\n    #[must_use]\n    pub fn contains(&self, range: &VerifiedRange) -> bool {\n        self.verified.get(&range.start) == Some(range)\n    }\n\n    fn get(&self, start: u64, len: u64) -> Option<&VerifiedRange> {\n        self.verified.get(&start).filter(|range| range.len == len)\n    }\n\n    fn validate_for(&self, expected_size: u64, segment_size: u64) -> Result<(), B01Error> {\n        for range in self.verified.values() {\n            let valid_geometry = range.start < expected_size\n                && range.start % segment_size == 0\n                && range.len == (expected_size - range.start).min(segment_size);\n            let valid_digest = range.sha256.len() == 64\n                && range.sha256.chars().all(|value| value.is_ascii_hexdigit());\n            if !valid_geometry || !valid_digest {\n                return Err(B01Error::InvalidDownloadCursorRange {\n                    start: range.start,\n                    len: range.len,\n                });\n            }\n        }\n        if expected_size == 0 && !self.verified.is_empty() {\n            return Err(B01Error::InvalidDownloadCursorRange { start: 0, len: 0 });\n        }\n        Ok(())\n    }\n\n    /// Number of verified ranges.\n    #[must_use]\n    pub fn len(&self) -> usize {\n        self.verified.len()\n    }\n\n    /// Whether no verified ranges are retained.\n    #[must_use]\n    pub fn is_empty(&self) -> bool {\n        self.verified.is_empty()\n    }\n}\n\n/// Source capable of serving exact byte ranges.""",
    "download cursor identity",
    re.S,
)
source = sub1(
    source,
    r"""pub struct SegmentedDownloadReport \{(.*?)    /// Whether every required segment is verified\.\n    pub complete: bool,""",
    r"""pub struct SegmentedDownloadReport {\1    /// Segment that blocked this pass after every source failed, if any.\n    pub blocked_segment: Option<BlockedSegment>,\n    /// Whether every required segment is verified.\n    pub complete: bool,""",
    "download partial report field",
    re.S,
)
source = sub1(
    source,
    r"""/// Result of one segmented/multi-source download pass\.\n#\[derive\(Debug, Clone, PartialEq, Eq\)\]\npub struct SegmentedDownloadReport""",
    """/// Exact segment that could not be obtained from any configured source.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct BlockedSegment {\n    /// Segment start offset.\n    pub start: u64,\n    /// Segment length.\n    pub len: usize,\n}\n\n/// Result of one segmented/multi-source download pass.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct SegmentedDownloadReport""",
    "blocked segment type",
)
source = sub1(
    source,
    r"""    let segment_size_u64 = u64::try_from\(segment_size\)\.expect\(\"usize fits u64\"\);\n    let segment_count = if expected_size == 0 \{""",
    """    let segment_size_u64 = u64::try_from(segment_size).expect(\"usize fits u64\");\n    cursor.validate_for(expected_size, segment_size_u64)?;\n    let segment_count = if expected_size == 0 {""",
    "validate download cursor geometry",
)
source = sub1(
    source,
    r"""        let range = VerifiedRange \{\n            start,\n            len: len_u64,\n        \};\n        if cursor\.contains\(range\) \{\n            resumed_ranges \+= 1;\n            continue;\n        \}""",
    """        if let Some(verified) = cursor.get(start, len_u64) {\n            let len = usize::try_from(len_u64).expect(\"segment length fits usize\");\n            let mut retained = vec![0_u8; len];\n            output.seek(SeekFrom::Start(start))?;\n            output.read_exact(&mut retained)?;\n            let observed = sha256_bytes(&retained);\n            if observed != verified.sha256 {\n                return Err(B01Error::ResumeRangeDigestMismatch {\n                    start,\n                    expected: verified.sha256.clone(),\n                    observed,\n                });\n            }\n            resumed_ranges += 1;\n            continue;\n        }""",
    "download resume digest verification",
)
source = sub1(
    source,
    r"""        let bytes = segment_bytes\.ok_or\(B01Error::SegmentUnavailable \{ start, len \}\)\?;\n        output\.seek\(SeekFrom::Start\(start\)\)\?;""",
    """        let Some(bytes) = segment_bytes else {\n            return Ok(SegmentedDownloadReport {\n                cursor,\n                resumed_ranges,\n                downloaded_ranges,\n                successful_sources,\n                failures,\n                blocked_segment: Some(BlockedSegment { start, len }),\n                complete: false,\n                destination_sha256: None,\n            });\n        };\n        output.seek(SeekFrom::Start(start))?;""",
    "preserve unavailable segment progress",
)
source = sub1(
    source,
    r"""        output\.write_all\(&bytes\)\?;\n        output\.flush\(\)\?;\n        cursor\.mark_verified\(range\);\n        downloaded_ranges \+= 1;""",
    """        output.write_all(&bytes)?;\n        output.flush()?;\n        output.sync_data()?;\n        cursor.mark_verified(VerifiedRange {\n            start,\n            len: len_u64,\n            sha256: sha256_bytes(&bytes),\n        });\n        downloaded_ranges += 1;""",
    "durable range admission",
)
source = sub1(
    source,
    r"""    let complete = usize::try_from\(segment_count\)\.is_ok_and\(\|count\| cursor\.len\(\) == count\);""",
    """    let complete = (0..segment_count).all(|segment_index| {\n        let start = segment_index * segment_size_u64;\n        let len = (expected_size - start).min(segment_size_u64);\n        cursor.get(start, len).is_some()\n    });""",
    "required range completion",
)
source = sub1(
    source,
    r"""        successful_sources,\n        failures,\n        complete,""",
    """        successful_sources,\n        failures,\n        blocked_segment: None,\n        complete,""",
    "normal download report",
)

# Sync needs a real non-conflict reconciliation transition and stale-conflict clearing.
source = sub1(
    source,
    r"""    /// Current explicit conflict, if any\.\n    pub conflict: Option<SyncConflict>,\n\}""",
    """    /// Current explicit conflict, if any.\n    pub conflict: Option<SyncConflict>,\n    pending_observation: Option<SyncCursor>,\n}""",
    "sync pending field",
)
source = sub1(
    source,
    r"""            state: SyncState::InSync,\n            conflict: None,\n        \}""",
    """            state: SyncState::InSync,\n            conflict: None,\n            pending_observation: None,\n        }""",
    "sync pending init",
)
source = sub1(
    source,
    r"""        self\.state = match \(local_changed, remote_changed\) \{\n            \(false, false\) => SyncState::InSync,\n            \(true, true\) if local_revision != remote_revision => \{\n                self\.conflict = Some\(SyncConflict \{\n                    local_revision,\n                    remote_revision,\n                    cursor_sequence: self\.cursor\.sequence,\n                \}\);\n                SyncState::Conflict\n            \}\n            _ => \{\n                self\.conflict = None;\n                SyncState::Pending\n            \}\n        \};""",
    """        self.state = match (local_changed, remote_changed) {\n            (false, false) => {\n                self.conflict = None;\n                self.pending_observation = None;\n                SyncState::InSync\n            }\n            (true, true) if local_revision != remote_revision => {\n                self.pending_observation = None;\n                self.conflict = Some(SyncConflict {\n                    local_revision,\n                    remote_revision,\n                    cursor_sequence: self.cursor.sequence,\n                });\n                SyncState::Conflict\n            }\n            _ => {\n                self.conflict = None;\n                self.pending_observation = Some(SyncCursor {\n                    local_revision,\n                    remote_revision,\n                    sequence: self.cursor.sequence.saturating_add(1),\n                });\n                SyncState::Pending\n            }\n        };""",
    "sync observation transitions",
)
source = sub1(
    source,
    r"""    /// Resolve only an explicit conflict using a caller-selected policy\.\n    pub fn resolve\(""",
    """    /// Commit a previously observed non-conflicting synchronization result.\n    pub fn reconcile_pending(&mut self) -> Result<SyncCursor, B01Error> {\n        if self.state != SyncState::Pending {\n            return Err(B01Error::NoPendingSync);\n        }\n        let cursor = self\n            .pending_observation\n            .take()\n            .ok_or(B01Error::NoPendingSync)?;\n        self.cursor = cursor.clone();\n        self.state = SyncState::InSync;\n        self.conflict = None;\n        Ok(cursor)\n    }\n\n    /// Resolve only an explicit conflict using a caller-selected policy.\n    pub fn resolve(""",
    "sync reconcile method",
)
source = sub1(
    source,
    r"""    \) -> Result<SyncResolutionRecord, B01Error> \{\n        let conflict = self\.conflict\.clone\(\)\.ok_or\(B01Error::NoSyncConflict\)\?;""",
    """    ) -> Result<SyncResolutionRecord, B01Error> {\n        if self.state != SyncState::Conflict {\n            return Err(B01Error::NoSyncConflict);\n        }\n        let conflict = self.conflict.clone().ok_or(B01Error::NoSyncConflict)?;""",
    "resolve requires conflict state",
)
source = sub1(
    source,
    r"""        self\.state = SyncState::InSync;\n        self\.conflict = None;\n        Ok\(SyncResolutionRecord \{""",
    """        self.state = SyncState::InSync;\n        self.conflict = None;\n        self.pending_observation = None;\n        Ok(SyncResolutionRecord {""",
    "clear pending after conflict resolution",
)

# Add exact errors for all new fail-closed boundaries.
source = sub1(
    source,
    r"""    /// Provider offset does not match the retained caller cursor\.\n    #\[error\(\"resume sink mismatch: cursor=\{cursor\}, sink=\{sink\}\"\)\]\n    ResumeSinkMismatch \{ cursor: u64, sink: u64 \},""",
    """    /// Provider offset does not match the retained caller cursor.\n    #[error(\"resume sink mismatch: cursor={cursor}, sink={sink}\")]\n    ResumeSinkMismatch { cursor: u64, sink: u64 },\n    /// Source size or digest changed after the retained upload cursor was created.\n    #[error(\"upload resume source identity changed\")]\n    ResumeSourceIdentityMismatch,\n    /// Bytes read for upload changed relative to the retained source prefix.\n    #[error(\"upload source changed while streaming: expected {expected}, observed {observed}\")]\n    SourceChangedDuringUpload { expected: String, observed: String },\n    /// A retained download range no longer matches its verified digest.\n    #[error(\"download resume range digest mismatch at {start}: expected {expected}, observed {observed}\")]\n    ResumeRangeDigestMismatch {\n        /// Start offset of the stale/corrupt retained range.\n        start: u64,\n        /// Retained verified SHA-256.\n        expected: String,\n        /// Re-read SHA-256.\n        observed: String,\n    },\n    /// A retained cursor range is outside the current expected geometry.\n    #[error(\"invalid retained download cursor range at {start} with length {len}\")]\n    InvalidDownloadCursorRange { start: u64, len: u64 },""",
    "resume errors",
)
source = sub1(
    source,
    r"""    /// Conflict resolution was requested when no conflict exists\.\n    #\[error\(\"no explicit sync conflict exists\"\)\]\n    NoSyncConflict,""",
    """    /// Conflict resolution was requested when no conflict exists.\n    #[error(\"no explicit sync conflict exists\")]\n    NoSyncConflict,\n    /// Non-conflicting reconciliation was requested with no pending observation.\n    #[error(\"no pending synchronization observation exists\")]\n    NoPendingSync,""",
    "sync errors",
)
source = sub1(
    source,
    r"""fn sha256_file\(path: &Path\) -> Result<String, std::io::Error> \{""",
    """fn sha256_prefix(path: &Path, len: u64) -> Result<String, std::io::Error> {\n    let mut file = File::open(path)?;\n    let mut hasher = Sha256::new();\n    let mut remaining = len;\n    let mut buffer = [0_u8; 64 * 1024];\n    while remaining > 0 {\n        let request = usize::try_from(\n            remaining.min(u64::try_from(buffer.len()).expect(\"usize fits u64\")),\n        )\n        .expect(\"prefix request fits usize\");\n        let read = file.read(&mut buffer[..request])?;\n        if read == 0 {\n            return Err(std::io::Error::new(\n                std::io::ErrorKind::UnexpectedEof,\n                \"source ended while hashing accepted prefix\",\n            ));\n        }\n        hasher.update(&buffer[..read]);\n        remaining -= u64::try_from(read).expect(\"usize fits u64\");\n    }\n    Ok(format!(\"{:x}\", hasher.finalize()))\n}\n\nfn sha256_file(path: &Path) -> Result<String, std::io::Error> {""",
    "prefix hash helper",
)
source_path.write_text(source, encoding="utf-8")

# Acceptance regressions.
tests_path = Path("crates/ptah-transfer/tests/b01.rs")
tests = tests_path.read_text(encoding="utf-8")
tests = sub1(
    tests,
    r"""use std::\{\n    fs,\n    path::\{Path, PathBuf\},""",
    """use std::{\n    fs,\n    io::{Seek, SeekFrom, Write},\n    path::{Path, PathBuf},""",
    "test io imports",
)
tests = sub1(
    tests,
    r"""        UploadCursor \{\n            accepted_offset: first\.accepted_offset,\n        \},""",
    """        first.cursor.clone(),""",
    "bound upload resume cursor",
)
tests = sub1(
    tests,
    r"""            UploadCursor \{ accepted_offset: 4 \},""",
    """            UploadCursor {\n                accepted_offset: 4,\n                ..UploadCursor::default()\n            },""",
    "cursor mismatch fixture",
)

# Source identity changes between passes must fail before continuation.
tests = sub1(
    tests,
    r"""#\[test\]\nfn segmented_multi_source_download_resumes_and_falls_back_without_erasing_failure\(\) \{""",
    """#[test]\nfn upload_resume_rejects_changed_source_identity() {\n    let temp = TempRoot::new();\n    let source = temp.path().join(\"identity-fenced-upload.bin\");\n    fs::write(&source, b\"abcdefghij\").expect(\"write source\");\n    let mut sink = MemoryUploadSink::default();\n    let first = resumable_upload_file(\n        &source,\n        &mut sink,\n        UploadCursor::default(),\n        4,\n        Some(5),\n    )\n    .expect(\"first pass\");\n    fs::write(&source, b\"abcdeXXXXX\").expect(\"mutate source\");\n    assert!(matches!(\n        resumable_upload_file(&source, &mut sink, first.cursor, 4, None),\n        Err(B01Error::ResumeSourceIdentityMismatch)\n    ));\n    assert_eq!(sink.bytes, b\"abcde\");\n    assert!(!sink.finalized);\n}\n\n#[test]\nfn segmented_multi_source_download_resumes_and_falls_back_without_erasing_failure() {""",
    "upload identity regression",
)

# Range cursors are digest-bound and stale/corrupt partial files fail closed.
tests = sub1(
    tests,
    r"""#\[test\]\nfn verified_download_ranges_are_exact_not_filename_or_progress_claims\(\) \{.*?\n\}\n\n#\[test\]\nfn priority_queue_preserves_local_capacity_while_local_work_is_pending""",
    """#[test]\nfn verified_download_ranges_are_digest_bound_not_filename_or_progress_claims() {\n    let mut cursor = DownloadCursor::default();\n    let exact = VerifiedRange {\n        start: 0,\n        len: 128,\n        sha256: \"a\".repeat(64),\n    };\n    cursor.mark_verified(exact.clone());\n    assert!(cursor.contains(&exact));\n    assert!(!cursor.contains(&VerifiedRange {\n        start: 0,\n        len: 127,\n        sha256: exact.sha256.clone(),\n    }));\n    assert!(!cursor.contains(&VerifiedRange {\n        start: 0,\n        len: 128,\n        sha256: \"b\".repeat(64),\n    }));\n}\n\n#[test]\nfn segmented_resume_rejects_corrupted_retained_range() {\n    let temp = TempRoot::new();\n    let destination = temp.path().join(\"corrupt-resume.bin\");\n    let bytes: Vec<u8> = (0..400_000)\n        .map(|index| u8::try_from(index % 241).expect(\"modulo fits u8\"))\n        .collect();\n    let expected = sha256(&bytes);\n    let mut first_source = ByteRangeSource::new(\"primary\", &bytes);\n    let mut second_source = ByteRangeSource::new(\"secondary\", &bytes);\n    let mut sources: [&mut dyn RangeSource; 2] = [&mut first_source, &mut second_source];\n    let first = segmented_download(\n        &mut sources,\n        &destination,\n        bytes.len() as u64,\n        64 * 1024,\n        DownloadCursor::default(),\n        Some(2),\n        Some(&expected),\n    )\n    .expect(\"first pass\");\n    let mut partial = fs::OpenOptions::new()\n        .write(true)\n        .open(&destination)\n        .expect(\"open retained partial\");\n    partial.seek(SeekFrom::Start(0)).expect(\"seek\");\n    partial.write_all(b\"X\").expect(\"corrupt retained range\");\n    partial.flush().expect(\"flush corruption\");\n    assert!(matches!(\n        segmented_download(\n            &mut sources,\n            &destination,\n            bytes.len() as u64,\n            64 * 1024,\n            first.cursor,\n            None,\n            Some(&expected),\n        ),\n        Err(B01Error::ResumeRangeDigestMismatch { start: 0, .. })\n    ));\n}\n\n#[test]\nfn segmented_download_preserves_progress_when_all_sources_fail_later_segment() {\n    let temp = TempRoot::new();\n    let destination = temp.path().join(\"blocked-segment.bin\");\n    let bytes = vec![7_u8; 300_000];\n    let mut first_source = ByteRangeSource::new(\"primary\", &bytes);\n    let mut second_source = ByteRangeSource::new(\"secondary\", &bytes);\n    first_source.fail_starts.push((64 * 1024) as u64);\n    second_source.fail_starts.push((64 * 1024) as u64);\n    let mut sources: [&mut dyn RangeSource; 2] = [&mut first_source, &mut second_source];\n    let report = segmented_download(\n        &mut sources,\n        &destination,\n        bytes.len() as u64,\n        64 * 1024,\n        DownloadCursor::default(),\n        None,\n        None,\n    )\n    .expect(\"partial progress is a retained report\");\n    assert!(!report.complete);\n    assert_eq!(report.downloaded_ranges, 1);\n    assert_eq!(report.cursor.len(), 1);\n    assert_eq!(report.failures.len(), 2);\n    assert_eq!(report.blocked_segment.as_ref().map(|value| value.start), Some((64 * 1024) as u64));\n}\n\n#[test]\nfn segmented_download_rejects_cursor_ranges_outside_required_geometry() {\n    let temp = TempRoot::new();\n    let destination = temp.path().join(\"stale-cursor.bin\");\n    let bytes = vec![9_u8; 128 * 1024];\n    let mut cursor = DownloadCursor::default();\n    cursor.mark_verified(VerifiedRange {\n        start: 1,\n        len: 64 * 1024,\n        sha256: \"a\".repeat(64),\n    });\n    let mut source = ByteRangeSource::new(\"primary\", &bytes);\n    let mut sources: [&mut dyn RangeSource; 1] = [&mut source];\n    assert!(matches!(\n        segmented_download(\n            &mut sources,\n            &destination,\n            bytes.len() as u64,\n            64 * 1024,\n            cursor,\n            None,\n            None,\n        ),\n        Err(B01Error::InvalidDownloadCursorRange { start: 1, .. })\n    ));\n}\n\n#[test]\nfn priority_queue_preserves_local_capacity_while_local_work_is_pending""",
    "download integrity regressions",
    re.S,
)

# Pending sync must have a normal reconciliation path; stale conflicts must not survive InSync.
tests = sub1(
    tests,
    r"""#\[test\]\nfn one_sided_sync_change_is_pending_not_conflict_or_automatic_merge\(\) \{.*?\n\}""",
    """#[test]\nfn one_sided_sync_change_is_pending_until_explicit_reconciliation() {\n    let mut relationship = SyncRelationship::new(\"sync-2\", \"l1\", \"r1\");\n    assert_eq!(relationship.observe(\"l2\", \"r1\"), SyncState::Pending);\n    assert!(relationship.conflict.is_none());\n    assert!(matches!(\n        relationship.resolve(ConflictResolution::KeepLocal),\n        Err(B01Error::NoSyncConflict)\n    ));\n    let cursor = relationship\n        .reconcile_pending()\n        .expect(\"commit non-conflicting sync result\");\n    assert_eq!(relationship.state, SyncState::InSync);\n    assert_eq!(cursor.local_revision, \"l2\");\n    assert_eq!(cursor.remote_revision, \"r1\");\n    assert_eq!(cursor.sequence, 1);\n}\n\n#[test]\nfn returning_in_sync_clears_stale_conflict_and_blocks_old_resolution() {\n    let mut relationship = SyncRelationship::new(\"sync-3\", \"l1\", \"r1\");\n    assert_eq!(relationship.observe(\"l2\", \"r2\"), SyncState::Conflict);\n    assert!(relationship.conflict.is_some());\n    assert_eq!(relationship.observe(\"l1\", \"r1\"), SyncState::InSync);\n    assert!(relationship.conflict.is_none());\n    assert!(matches!(\n        relationship.resolve(ConflictResolution::KeepLocal),\n        Err(B01Error::NoSyncConflict)\n    ));\n}""",
    "sync reconciliation regressions",
    re.S,
)

tests_path.write_text(tests, encoding="utf-8")

# Exact-head proof count and documentation move with the reviewed corpus.
workflow_path = Path(".github/workflows/b01-transfer-storage-expansion.yml")
workflow = workflow_path.read_text(encoding="utf-8")
if "13 passed; 0 failed;" not in workflow or "'b01_acceptance_test_count': 13" not in workflow:
    raise SystemExit("B01 workflow count anchors changed unexpectedly")
workflow = workflow.replace("13 passed; 0 failed;", "19 passed; 0 failed;", 1)
workflow = workflow.replace("'b01_acceptance_test_count': 13", "'b01_acceptance_test_count': 19", 1)
workflow_path.write_text(workflow, encoding="utf-8")

doc_path = Path("B01_TRANSFER_STORAGE_EXPANSION.md")
doc = doc_path.read_text(encoding="utf-8")
doc = doc.replace(
    "resumable upload from an exact provider-accepted offset, including fail-closed cursor/provider disagreement;",
    "resumable upload from an exact provider-accepted offset, with source size/digest fencing, streamed-prefix verification and fail-closed cursor/provider disagreement;",
    1,
)
doc = doc.replace(
    "segmented download with exact verified-range cursor, multi-source selection, source fallback and retained source failures;",
    "segmented download with digest-bound verified-range cursor, crash-durable range admission, multi-source fallback and retained source failures;",
    1,
)
doc = doc.replace(
    "8. explicit Sync Relationship, Cursor, Conflict and caller-selected Resolution state;",
    "8. explicit Sync Relationship, Cursor, Conflict, non-conflict reconciliation and caller-selected Resolution state;",
    1,
)
doc_path.write_text(doc, encoding="utf-8")
