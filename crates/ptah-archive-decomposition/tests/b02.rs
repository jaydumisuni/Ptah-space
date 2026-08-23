//! B02 general type detection and progressive decomposition acceptance regressions.

use ptah_archive_decomposition::{
    ArchiveBackend, B02Error, BackendIdentity, DecompositionBudget, DecompositionSpec,
    DetectorOutcome, MemberKind, ParseReport, ParseTerminal, ParsedMember, ProgressiveLevel,
    ProgressiveSpec, TypeAgreement, TypeDetector, TypeSignal, progressive_decompose,
};
use ptah_identifiers::EntityRef;
use ptah_object_store::ProductionEvidence;
use std::cell::Cell;

const ARCHIVE_TYPE: &str = "application/x-ptah-fixture-archive";
const ROOT: &[u8] = b"PTAH-B02-ROOT";
const NESTED: &[u8] = b"PTAH-B02-NESTED";
const DEEP: &[u8] = b"PTAH-B02-DEEP";
const README: &[u8] = b"plain readme";
const LEAF: &[u8] = b"plain leaf";

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid fixture reference")
}

fn production() -> ProductionEvidence {
    ProductionEvidence {
        activity_ref: reference("core.activity"),
        operation_ref: reference("core.operation"),
        attempt_ref: reference("core.attempt"),
        receipt_refs: vec![reference("proof.receipt")],
    }
}

fn spec(level: ProgressiveLevel, max_depth: u32, declared_type: Option<&str>) -> ProgressiveSpec {
    let mut budget = DecompositionBudget::default();
    budget.max_depth = max_depth;
    budget.max_members = 64;
    budget.max_expanded_bytes = 1024 * 1024;
    budget.max_member_bytes = 256 * 1024;
    ProgressiveSpec {
        declared_type: declared_type.map(ToOwned::to_owned),
        requested_level: level,
        archive_media_types: vec![ARCHIVE_TYPE.to_owned()],
        archive_spec: DecompositionSpec {
            workspace_ref: reference("core.workspace"),
            authority_ref: reference("auth.authority"),
            source_revision_ref: reference("object.revision"),
            production: production(),
            budget,
            requested_level: "B02".to_owned(),
        },
    }
}

struct FixtureArchiveBackend {
    calls: Cell<usize>,
}

impl FixtureArchiveBackend {
    fn new() -> Self {
        Self {
            calls: Cell::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl ArchiveBackend for FixtureArchiveBackend {
    fn identity(&self) -> BackendIdentity {
        BackendIdentity {
            provider_ref: reference("runtime.provider"),
            provider_generation: 2,
            implementation: "b02-fixture-archive".to_owned(),
            implementation_version: "1.0.0".to_owned(),
            source_sha256: "a".repeat(64),
            executable_sha256: "b".repeat(64),
        }
    }

    fn parse(
        &self,
        bytes: &[u8],
    ) -> Result<ParseReport, ptah_archive_decomposition::DecompositionError> {
        self.calls.set(self.calls.get() + 1);
        let report = if bytes == ROOT {
            ParseReport {
                format: Some("ptah-fixture".to_owned()),
                members: vec![
                    ParsedMember {
                        path: "nested.arc".to_owned(),
                        kind: MemberKind::Regular,
                        bytes: NESTED.to_vec(),
                    },
                    ParsedMember {
                        path: "readme.txt".to_owned(),
                        kind: MemberKind::Regular,
                        bytes: README.to_vec(),
                    },
                ],
                terminal: ParseTerminal::Complete,
                warnings: Vec::new(),
                limitations: Vec::new(),
            }
        } else if bytes == NESTED {
            ParseReport {
                format: Some("ptah-fixture".to_owned()),
                members: vec![ParsedMember {
                    path: "deep.arc".to_owned(),
                    kind: MemberKind::Regular,
                    bytes: DEEP.to_vec(),
                }],
                terminal: ParseTerminal::Complete,
                warnings: Vec::new(),
                limitations: Vec::new(),
            }
        } else if bytes == DEEP {
            ParseReport {
                format: Some("ptah-fixture".to_owned()),
                members: vec![ParsedMember {
                    path: "leaf.txt".to_owned(),
                    kind: MemberKind::Regular,
                    bytes: LEAF.to_vec(),
                }],
                terminal: ParseTerminal::Complete,
                warnings: Vec::new(),
                limitations: Vec::new(),
            }
        } else {
            ParseReport {
                format: None,
                members: Vec::new(),
                terminal: ParseTerminal::UnsupportedFormat,
                warnings: Vec::new(),
                limitations: vec!["fixture backend does not decompose this child".to_owned()],
            }
        };
        Ok(report)
    }
}

struct MagicDetector {
    id: &'static str,
    calls: Cell<usize>,
}

impl MagicDetector {
    fn new(id: &'static str) -> Self {
        Self {
            id,
            calls: Cell::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl TypeDetector for MagicDetector {
    fn detector_id(&self) -> &str {
        self.id
    }

    fn detect(&self, bytes: &[u8]) -> Result<Option<TypeSignal>, String> {
        self.calls.set(self.calls.get() + 1);
        let media_type = if matches!(bytes, ROOT | NESTED | DEEP) {
            Some(ARCHIVE_TYPE)
        } else if matches!(bytes, README | LEAF) {
            Some("text/plain")
        } else {
            None
        };
        Ok(media_type.map(|media_type| TypeSignal {
            media_type: media_type.to_owned(),
            confidence_milli: 950,
            detail: format!("{} fixture observation", self.id),
        }))
    }
}

struct FixedDetector {
    id: &'static str,
    media_type: &'static str,
    calls: Cell<usize>,
}

impl FixedDetector {
    fn new(id: &'static str, media_type: &'static str) -> Self {
        Self {
            id,
            media_type,
            calls: Cell::new(0),
        }
    }
}

impl TypeDetector for FixedDetector {
    fn detector_id(&self) -> &str {
        self.id
    }

    fn detect(&self, _bytes: &[u8]) -> Result<Option<TypeSignal>, String> {
        self.calls.set(self.calls.get() + 1);
        Ok(Some(TypeSignal {
            media_type: self.media_type.to_owned(),
            confidence_milli: 900,
            detail: "fixed fixture observation".to_owned(),
        }))
    }
}

struct FailingDetector {
    id: &'static str,
}

impl TypeDetector for FailingDetector {
    fn detector_id(&self) -> &str {
        self.id
    }

    fn detect(&self, _bytes: &[u8]) -> Result<Option<TypeSignal>, String> {
        Err("fixture detector unavailable".to_owned())
    }
}

#[test]
fn level_zero_does_not_invoke_detectors_or_archive_backend() {
    let detector = MagicDetector::new("magic-a");
    let backend = FixtureArchiveBackend::new();
    let report = progressive_decompose(
        ROOT,
        &spec(ProgressiveLevel::L0, 2, Some("application/octet-stream")),
        &[&detector],
        Some(&backend),
    )
    .expect("L0 report");

    assert_eq!(report.achieved_level, ProgressiveLevel::L0);
    assert_eq!(detector.calls(), 0);
    assert_eq!(backend.calls(), 0);
    assert!(report.children.is_empty());
    assert!(report.type_assessment.detector_evidence.is_empty());
}

#[test]
fn detector_disagreement_is_preserved_and_blocks_decomposer_selection() {
    let archive = FixedDetector::new("archive-detector", ARCHIVE_TYPE);
    let pdf = FixedDetector::new("pdf-detector", "application/pdf");
    let backend = FixtureArchiveBackend::new();
    let report = progressive_decompose(
        ROOT,
        &spec(ProgressiveLevel::L3, 2, None),
        &[&archive, &pdf],
        Some(&backend),
    )
    .expect("disputed report");

    assert_eq!(
        report.type_assessment.agreement,
        TypeAgreement::Disputed(vec![
            "application/pdf".to_owned(),
            ARCHIVE_TYPE.to_owned()
        ])
    );
    assert_eq!(report.achieved_level, ProgressiveLevel::L1);
    assert_eq!(backend.calls(), 0);
    assert_eq!(report.type_assessment.detector_evidence.len(), 2);
    assert!(
        report
            .unsupported_regions
            .iter()
            .any(|item| item.contains("detector disagreement"))
    );
    assert!(report.searchable_metadata.iter().any(|item| {
        item.key == "disputed_types" && item.value.contains("application/pdf")
    }));
}

#[test]
fn declared_type_mismatch_is_explicit_without_rewriting_observed_type() {
    let first = MagicDetector::new("magic-a");
    let second = MagicDetector::new("magic-b");
    let report = progressive_decompose(
        ROOT,
        &spec(ProgressiveLevel::L1, 2, Some("text/plain")),
        &[&first, &second],
        None,
    )
    .expect("L1 report");

    assert_eq!(
        report.type_assessment.agreement,
        TypeAgreement::Agreed(ARCHIVE_TYPE.to_owned())
    );
    assert_eq!(
        report.type_assessment.declared_matches_agreed_type,
        Some(false)
    );
    assert!(report.searchable_metadata.iter().any(|item| {
        item.key == "declared_matches_agreed_type" && item.value == "false"
    }));
}

#[test]
fn detector_failure_is_retained_without_erasing_independent_positive_evidence() {
    let magic = MagicDetector::new("magic-a");
    let failing = FailingDetector { id: "broken-b" };
    let report = progressive_decompose(
        ROOT,
        &spec(ProgressiveLevel::L1, 2, None),
        &[&magic, &failing],
        None,
    )
    .expect("bounded detector failure");

    assert_eq!(
        report.type_assessment.agreement,
        TypeAgreement::Agreed(ARCHIVE_TYPE.to_owned())
    );
    assert!(matches!(
        report.type_assessment.detector_evidence[1].outcome,
        DetectorOutcome::Failed(_)
    ));
    assert!(report.searchable_metadata.iter().any(|item| {
        item.key == "detector.broken-b.failure"
            && item.value.contains("fixture detector unavailable")
    }));
}

#[test]
fn level_two_produces_root_inventory_without_recursive_children() {
    let first = MagicDetector::new("magic-a");
    let second = MagicDetector::new("magic-b");
    let backend = FixtureArchiveBackend::new();
    let report = progressive_decompose(
        ROOT,
        &spec(ProgressiveLevel::L2, 4, Some(ARCHIVE_TYPE)),
        &[&first, &second],
        Some(&backend),
    )
    .expect("L2 inventory");

    assert_eq!(report.achieved_level, ProgressiveLevel::L2);
    assert_eq!(backend.calls(), 1);
    assert_eq!(report.children.len(), 2);
    assert!(report.children.iter().any(|child| child.child_path == "nested.arc"));
    assert!(report.children.iter().any(|child| child.child_path == "readme.txt"));
    assert!(
        report
            .children
            .iter()
            .all(|child| !child.child_path.contains('/'))
    );
    assert!(report.searchable_metadata.iter().any(|item| {
        item.path.as_deref() == Some("nested.arc")
            && item.key == "agreed_type"
            && item.value == ARCHIVE_TYPE
    }));
}

#[test]
fn level_three_builds_child_graph_and_marks_recursion_boundary_explicitly() {
    let original = ROOT.to_vec();
    let first = MagicDetector::new("magic-a");
    let second = MagicDetector::new("magic-b");
    let backend = FixtureArchiveBackend::new();
    let report = progressive_decompose(
        ROOT,
        &spec(ProgressiveLevel::L3, 1, Some(ARCHIVE_TYPE)),
        &[&first, &second],
        Some(&backend),
    )
    .expect("L3 bounded decomposition");

    assert_eq!(ROOT, original.as_slice());
    assert_eq!(report.achieved_level, ProgressiveLevel::L3);
    let nested = report
        .children
        .iter()
        .find(|child| child.child_path == "nested.arc/deep.arc")
        .expect("nested child retained");
    assert_eq!(nested.parent_path.as_deref(), Some("nested.arc"));
    assert_eq!(nested.depth, 1);
    assert!(
        report
            .unsupported_regions
            .iter()
            .any(|item| item.contains("recursion limit 1 reached")
                && item.contains("nested.arc/deep.arc"))
    );
    assert!(report.searchable_metadata.iter().any(|item| {
        item.path.as_deref() == Some("nested.arc/deep.arc") && item.key == "sha256"
    }));
}

#[test]
fn deeper_level_three_reaches_leaf_when_resource_policy_allows_it() {
    let first = MagicDetector::new("magic-a");
    let second = MagicDetector::new("magic-b");
    let backend = FixtureArchiveBackend::new();
    let report = progressive_decompose(
        ROOT,
        &spec(ProgressiveLevel::L3, 2, None),
        &[&first, &second],
        Some(&backend),
    )
    .expect("deep L3 decomposition");

    assert_eq!(report.achieved_level, ProgressiveLevel::L3);
    assert!(report.children.iter().any(|child| {
        child.child_path == "nested.arc/deep.arc/leaf.txt"
            && child.parent_path.as_deref() == Some("nested.arc/deep.arc")
    }));
    assert!(
        !report
            .unsupported_regions
            .iter()
            .any(|item| item.contains("recursion limit"))
    );
}

#[test]
fn unsupported_agreed_type_remains_explicit_and_does_not_call_archive_backend() {
    let first = FixedDetector::new("plain-a", "text/plain");
    let second = FixedDetector::new("plain-b", "text/plain");
    let backend = FixtureArchiveBackend::new();
    let report = progressive_decompose(
        ROOT,
        &spec(ProgressiveLevel::L3, 2, None),
        &[&first, &second],
        Some(&backend),
    )
    .expect("unsupported type report");

    assert_eq!(report.achieved_level, ProgressiveLevel::L1);
    assert_eq!(backend.calls(), 0);
    assert!(
        report
            .unsupported_regions
            .iter()
            .any(|item| item.contains("no B02 decomposer is registered for agreed type text/plain"))
    );
}

#[test]
fn duplicate_detector_identity_fails_closed_before_any_detection() {
    let first = MagicDetector::new("same");
    let second = MagicDetector::new("same");
    let error = progressive_decompose(
        ROOT,
        &spec(ProgressiveLevel::L1, 2, None),
        &[&first, &second],
        None,
    )
    .expect_err("duplicate detector identity must fail");

    assert!(matches!(error, B02Error::DuplicateDetectorId(ref id) if id == "same"));
    assert_eq!(first.calls(), 0);
    assert_eq!(second.calls(), 0);
}
