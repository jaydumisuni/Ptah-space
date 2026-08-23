#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


source_path = Path("crates/ptah-transfer/src/b01.rs")
source = source_path.read_text(encoding="utf-8")
source = replace_once(
    source,
    "    ResumeOffsetOutOfRange { offset: u64, size: u64 },",
    """    ResumeOffsetOutOfRange {
        /// Retained resume offset.
        offset: u64,
        /// Current source size.
        size: u64,
    },""",
    "ResumeOffsetOutOfRange docs",
)
source = replace_once(
    source,
    "    ResumeSinkMismatch { cursor: u64, sink: u64 },",
    """    ResumeSinkMismatch {
        /// Retained caller cursor offset.
        cursor: u64,
        /// Provider-reported accepted offset.
        sink: u64,
    },""",
    "ResumeSinkMismatch docs",
)
source = replace_once(
    source,
    "    SourceChangedDuringUpload { expected: String, observed: String },",
    """    SourceChangedDuringUpload {
        /// Digest of the retained source prefix after streaming.
        expected: String,
        /// Digest of the exact prefix bytes streamed to the provider.
        observed: String,
    },""",
    "SourceChangedDuringUpload docs",
)
source = replace_once(
    source,
    "    InvalidDownloadCursorRange { start: u64, len: u64 },",
    """    InvalidDownloadCursorRange {
        /// Invalid retained range start offset.
        start: u64,
        /// Invalid retained range length.
        len: u64,
    },""",
    "InvalidDownloadCursorRange docs",
)
source = replace_once(
    source,
    "    SegmentUnavailable { start: u64, len: usize },",
    """    SegmentUnavailable {
        /// Start offset of the unavailable segment.
        start: u64,
        /// Requested unavailable segment length.
        len: usize,
    },""",
    "SegmentUnavailable docs",
)
source = replace_once(
    source,
    "    DigestMismatch { expected: String, observed: String },",
    """    DigestMismatch {
        /// Expected whole-content SHA-256.
        expected: String,
        /// Observed whole-content SHA-256.
        observed: String,
    },""",
    "DigestMismatch docs",
)
source_path.write_text(source, encoding="utf-8")

tests_path = Path("crates/ptah-transfer/tests/b01.rs")
tests = tests_path.read_text(encoding="utf-8")
if not tests.startswith("//! B01 transfer and storage acceptance regressions.\n"):
    tests = "//! B01 transfer and storage acceptance regressions.\n\n" + tests
tests_path.write_text(tests, encoding="utf-8")
