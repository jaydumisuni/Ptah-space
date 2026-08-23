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

source = sub1(
    source,
    r"""/// Resume cursor for a provider upload\.\n#\[derive\(Debug, Clone, Copy, PartialEq, Eq, Default\)\]\npub struct UploadCursor \{\n    /// Exact source offset already durably accepted by the provider sink\.\n    pub accepted_offset: u64,\n\}""",
    """/// Resume cursor for a provider upload.\n#[derive(Debug, Clone, PartialEq, Eq, Default)]\npub struct UploadCursor {\n    /// Exact source offset already durably accepted by the provider sink.\n    pub accepted_offset: u64,\n    /// Source size observed by the first accepted pass.\n    pub source_size: Option<u64>,\n    /// Whole-source SHA-256 observed by the first accepted pass.\n    pub source_sha256: Option<String>,\n}""",
    "upload cursor",
)
source = sub1(
    source,
    r"""pub struct ResumableUploadReport \{\n    /// Offset from which this pass started\..*?\n    pub starting_offset: u64,""",
    """pub struct ResumableUploadReport {\n    /// Resume cursor bound to the exact source identity and accepted provider offset.\n    pub cursor: UploadCursor,\n    /// Offset from which this pass started.\n    pub starting_offset: u64,""",
    "upload report cursor",
    re.S,
)
source = sub1(
    source,
    r"""    let source_size = fs::metadata\(source\)\?\.len\(\);\n    if cursor\.accepted_offset > source_size \{""",
    """    let source_size = fs::metadata(source)?.len();\n    let source_sha256 = sha256_file(source)?;\n    if cursor.source_size.is_some_and(|expected| expected != source_size)\n        || cursor\n            .source_sha256\n            .as_deref()\n            .is_some_and(|expected| expected != source_sha256.as_str())\n    {\n        return Err(B01Error::ResumeSourceIdentityMismatch);\n    }\n    if cursor.accepted_offset > source_size {""",
    "upload source identity fence",
)
source = sub1(
    source,
    r"""\n    let source_sha256 = sha256_file\(source\)\?;\n    let starting_offset = cursor\.accepted_offset;""",
    """\n    let starting_offset = cursor.accepted_offset;""",
    "duplicate source hash",
)
source = sub1(
    source,
    r"""    Ok\(ResumableUploadReport \{\n        starting_offset,""",
    """    Ok(ResumableUploadReport {\n        cursor: UploadCursor {\n            accepted_offset,\n            source_size: Some(source_size),\n            source_sha256: Some(source_sha256.clone()),\n        },\n        starting_offset,""",
    "upload report construction",
)

source = sub1(
    source,
    r"""/// One exact verified download range\..*?/// Source capable of serving exact byte ranges\.""",
    """/// One exact verified download range.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct VerifiedRange {\n    /// Start offset.\n    pub start: u64,\n    /// Number of verified bytes.\n    pub len: u64,\n    /// SHA-256 of the exact retained range bytes.\n    pub sha256: String,\n}\n\n/// Durable digest-bound range cursor for segmented download resume.\n#[derive(Debug, Clone, PartialEq, Eq, Default)]\npub struct DownloadCursor {\n    verified: BTreeMap<u64, VerifiedRange>,\n}\n\nimpl DownloadCursor {\n    /// Mark one exact range as verified.\n    pub fn mark_verified(&mut self, range: VerifiedRange) {\n        self.verified.insert(range.start, range);\n    }\n\n    /// Whether the exact range identity, geometry and digest are retained.\n    #[must_use]\n    pub fn contains(&self, range: &VerifiedRange) -> bool {\n        self.verified.get(&range.start) == Some(range)\n    }\n\n    fn get(&self, start: u64, len: u64) -> Option<&VerifiedRange> {\n        self.verified.get(&start).filter(|range| range.len == len)\n    }\n\n    /// Number of verified ranges.\n    #[must_use]\n    pub fn len(&self) -> usize {\n        self.verified.len()\n    }\n\n    /// Whether no verified ranges are retained.\n    #[must_use]\n    pub fn is_empty(&self) -> bool {\n        self.verified.is_empty()\n    }\n}\n\n/// Source capable of serving exact byte ranges.""",
    "download cursor identity",
    re.S,
)
source = sub1(
    source,
    r"""        let range = VerifiedRange \{\n            start,\n            len: len_u64,\n        \};\n        if cursor\.contains\(range\) \{\n            resumed_ranges \+= 1;\n            continue;\n        \}""",
    """        if let Some(verified) = cursor.get(start, len_u64) {\n            let len = usize::try_from(len_u64).expect(\"segment length fits usize\");\n            let mut retained = vec![0_u8; len];\n            output.seek(SeekFrom::Start(start))?;\n            output.read_exact(&mut retained)?;\n            let observed = sha256_bytes(&retained);\n            if observed != verified.sha256 {\n                return Err(B01Error::ResumeRangeDigestMismatch {\n                    start,\n                    expected: verified.sha256.clone(),\n                    observed,\n                });\n            }\n            resumed_ranges += 1;\n            continue;\n        }""",
    "download resume verification",
)
source = sub1(
    source,
    r"""        output\.write_all\(&bytes\)\?;\n        output\.flush\(\)\?;\n        cursor\.mark_verified\(range\);\n        downloaded_ranges \+= 1;""",
    """        output.write_all(&bytes)?;\n        output.flush()?;\n        cursor.mark_verified(VerifiedRange {\n            start,\n            len: len_u64,\n            sha256: sha256_bytes(&bytes),\n        });\n        downloaded_ranges += 1;""",
    "download range admission",
)
source = sub1(
    source,
    r"""    /// Provider offset does not match the retained caller cursor\.\n    #\[error\(\"resume sink mismatch: cursor=\{cursor\}, sink=\{sink\}\"\)\]\n    ResumeSinkMismatch \{ cursor: u64, sink: u64 \},""",
    """    /// Provider offset does not match the retained caller cursor.\n    #[error(\"resume sink mismatch: cursor={cursor}, sink={sink}\")]\n    ResumeSinkMismatch { cursor: u64, sink: u64 },\n    /// Source size or digest changed after the retained upload cursor was created.\n    #[error(\"upload resume source identity changed\")]\n    ResumeSourceIdentityMismatch,\n    /// A retained download range no longer matches its verified digest.\n    #[error(\"download resume range digest mismatch at {start}: expected {expected}, observed {observed}\")]\n    ResumeRangeDigestMismatch {\n        /// Start offset of the stale/corrupt retained range.\n        start: u64,\n        /// Retained verified SHA-256.\n        expected: String,\n        /// Re-read SHA-256.\n        observed: String,\n    },""",
    "resume errors",
)
source_path.write_text(source, encoding="utf-8")

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
tests = sub1(
    tests,
    r"""#\[test\]\nfn segmented_multi_source_download_resumes_and_falls_back_without_erasing_failure\(\) \{""",
    """#[test]\nfn upload_resume_rejects_changed_source_identity() {\n    let temp = TempRoot::new();\n    let source = temp.path().join(\"identity-fenced-upload.bin\");\n    fs::write(&source, b\"abcdefghij\").expect(\"write source\");\n    let mut sink = MemoryUploadSink::default();\n    let first = resumable_upload_file(\n        &source,\n        &mut sink,\n        UploadCursor::default(),\n        4,\n        Some(5),\n    )\n    .expect(\"first pass\");\n    fs::write(&source, b\"abcdeXXXXX\").expect(\"mutate source\");\n    assert!(matches!(\n        resumable_upload_file(&source, &mut sink, first.cursor, 4, None),\n        Err(B01Error::ResumeSourceIdentityMismatch)\n    ));\n    assert_eq!(sink.bytes, b\"abcde\");\n    assert!(!sink.finalized);\n}\n\n#[test]\nfn segmented_multi_source_download_resumes_and_falls_back_without_erasing_failure() {""",
    "upload identity regression",
)
tests = sub1(
    tests,
    r"""#\[test\]\nfn verified_download_ranges_are_exact_not_filename_or_progress_claims\(\) \{.*?\n\}\n\n#\[test\]\nfn priority_queue_preserves_local_capacity_while_local_work_is_pending""",
    """#[test]\nfn verified_download_ranges_are_digest_bound_not_filename_or_progress_claims() {\n    let mut cursor = DownloadCursor::default();\n    let exact = VerifiedRange {\n        start: 0,\n        len: 128,\n        sha256: \"a\".repeat(64),\n    };\n    cursor.mark_verified(exact.clone());\n    assert!(cursor.contains(&exact));\n    assert!(!cursor.contains(&VerifiedRange {\n        start: 0,\n        len: 127,\n        sha256: exact.sha256.clone(),\n    }));\n    assert!(!cursor.contains(&VerifiedRange {\n        start: 0,\n        len: 128,\n        sha256: \"b\".repeat(64),\n    }));\n}\n\n#[test]\nfn segmented_resume_rejects_corrupted_retained_range() {\n    let temp = TempRoot::new();\n    let destination = temp.path().join(\"corrupt-resume.bin\");\n    let bytes: Vec<u8> = (0..400_000)\n        .map(|index| u8::try_from(index % 241).expect(\"modulo fits u8\"))\n        .collect();\n    let expected = sha256(&bytes);\n    let mut first_source = ByteRangeSource::new(\"primary\", &bytes);\n    let mut second_source = ByteRangeSource::new(\"secondary\", &bytes);\n    let mut sources: [&mut dyn RangeSource; 2] = [&mut first_source, &mut second_source];\n    let first = segmented_download(\n        &mut sources,\n        &destination,\n        bytes.len() as u64,\n        64 * 1024,\n        DownloadCursor::default(),\n        Some(2),\n        Some(&expected),\n    )\n    .expect(\"first pass\");\n    let mut partial = fs::OpenOptions::new()\n        .write(true)\n        .open(&destination)\n        .expect(\"open retained partial\");\n    partial.seek(SeekFrom::Start(0)).expect(\"seek\");\n    partial.write_all(b\"X\").expect(\"corrupt retained range\");\n    partial.flush().expect(\"flush corruption\");\n    assert!(matches!(\n        segmented_download(\n            &mut sources,\n            &destination,\n            bytes.len() as u64,\n            64 * 1024,\n            first.cursor,\n            None,\n            Some(&expected),\n        ),\n        Err(B01Error::ResumeRangeDigestMismatch { start: 0, .. })\n    ));\n}\n\n#[test]\nfn priority_queue_preserves_local_capacity_while_local_work_is_pending""",
    "download digest regressions",
    re.S,
)
tests_path.write_text(tests, encoding="utf-8")

workflow_path = Path(".github/workflows/b01-transfer-storage-expansion.yml")
workflow = workflow_path.read_text(encoding="utf-8")
if "13 passed; 0 failed;" not in workflow or "'b01_acceptance_test_count': 13" not in workflow:
    raise SystemExit("B01 workflow count anchors changed unexpectedly")
workflow = workflow.replace("13 passed; 0 failed;", "15 passed; 0 failed;", 1)
workflow = workflow.replace("'b01_acceptance_test_count': 13", "'b01_acceptance_test_count': 15", 1)
workflow_path.write_text(workflow, encoding="utf-8")

doc_path = Path("B01_TRANSFER_STORAGE_EXPANSION.md")
doc = doc_path.read_text(encoding="utf-8")
doc = doc.replace(
    "resumable upload from an exact provider-accepted offset, including fail-closed cursor/provider disagreement;",
    "resumable upload from an exact provider-accepted offset, with source size/digest fencing and fail-closed cursor/provider disagreement;",
    1,
)
doc = doc.replace(
    "segmented download with exact verified-range cursor, multi-source selection, source fallback and retained source failures;",
    "segmented download with digest-bound verified-range cursor, multi-source selection, source fallback and retained source failures;",
    1,
)
doc_path.write_text(doc, encoding="utf-8")
