use crate::{
    ArchiveBackend, DecompositionError, DecompositionOutcome, DecompositionPlan, DecompositionSpec,
    MemberKind, RecoveredMember, decompose,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use thiserror::Error;

/// Progressive B02 inspection level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProgressiveLevel {
    /// Identity and caller-declared metadata only. No detector is invoked.
    L0,
    /// Aggregate type-detector evidence.
    L1,
    /// Produce a bounded structural inventory when a matching decomposer exists.
    L2,
    /// Perform bounded recursive decomposition and child discovery.
    L3,
}

impl ProgressiveLevel {
    /// Stable level token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::L0 => "L0",
            Self::L1 => "L1",
            Self::L2 => "L2",
            Self::L3 => "L3",
        }
    }
}

/// One positive mechanical type signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeSignal {
    /// Detector-observed type token, normally a media type.
    pub media_type: String,
    /// Detector confidence from 0 through 1000, where 1000 is maximum confidence.
    pub confidence_milli: u16,
    /// Bounded detector detail retained as evidence, not semantic authority.
    pub detail: String,
}

/// Mechanical detector outcome retained without collapsing disagreement or failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectorOutcome {
    /// Detector emitted a positive type observation.
    Observed(TypeSignal),
    /// Detector examined the bytes but did not identify a type.
    NoMatch,
    /// Detector failed or emitted invalid evidence.
    Failed(String),
}

/// One detector evidence record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorEvidence {
    /// Stable detector identity supplied by the detector implementation.
    pub detector_id: String,
    /// Exact bounded mechanical outcome.
    pub outcome: DetectorOutcome,
}

/// Replaceable B02 type detector. Detectors provide evidence only; they do not authorize work.
pub trait TypeDetector {
    /// Stable detector identity used to keep independent evidence distinguishable.
    fn detector_id(&self) -> &str;

    /// Inspect immutable bytes and return a bounded mechanical observation.
    ///
    /// # Errors
    /// Returns an implementation-defined failure when the detector cannot produce a bounded
    /// observation. B02 retains that failure as evidence instead of erasing other detectors.
    fn detect(&self, bytes: &[u8]) -> Result<Option<TypeSignal>, String>;
}

/// Aggregate type result. A disputed set is never silently collapsed to one winner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeAgreement {
    /// No detector emitted a valid positive type signal.
    Unknown,
    /// All positive signals agree on one normalized type token.
    Agreed(String),
    /// Positive signals disagree. All distinct normalized types are retained in sorted order.
    Disputed(Vec<String>),
}

/// Root or child type assessment with all detector evidence retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeAssessment {
    /// Caller-declared type when one was supplied.
    pub declared_type: Option<String>,
    /// Independent detector evidence in invocation order.
    pub detector_evidence: Vec<DetectorEvidence>,
    /// Agreement state derived only from valid positive detector signals.
    pub agreement: TypeAgreement,
    /// Comparison with the agreed observed type. `None` means no truthful comparison is possible.
    pub declared_matches_agreed_type: Option<bool>,
}

impl TypeAssessment {
    /// Return the agreed observed type only when positive detector evidence is non-conflicting.
    #[must_use]
    pub fn agreed_type(&self) -> Option<&str> {
        match &self.agreement {
            TypeAgreement::Agreed(value) => Some(value.as_str()),
            TypeAgreement::Unknown | TypeAgreement::Disputed(_) => None,
        }
    }
}

/// Caller request for generic progressive decomposition.
#[derive(Debug, Clone)]
pub struct ProgressiveSpec {
    /// Optional caller-declared type. It is compared with detector evidence, never trusted blindly.
    pub declared_type: Option<String>,
    /// Maximum progressive level requested by the caller.
    pub requested_level: ProgressiveLevel,
    /// Types that may be handed to the existing A12 archive decomposer.
    pub archive_media_types: Vec<String>,
    /// Existing A12 authority, source identity and resource policy.
    pub archive_spec: DecompositionSpec,
}

/// Generic child relationship projected from the A12 inventory without replacing A07 identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildRelationship {
    /// Parent logical path when this is a nested child.
    pub parent_path: Option<String>,
    /// Child logical path relative to the original source.
    pub child_path: String,
    /// A12 member kind.
    pub kind: MemberKind,
    /// Immediate containing archive depth.
    pub depth: u32,
    /// Exact retained byte size when byte-backed.
    pub byte_size: u64,
    /// Exact child digest when byte-backed.
    pub sha256: Option<String>,
    /// Child type assessment when bytes were available for mechanical detection.
    pub type_assessment: Option<TypeAssessment>,
}

/// Searchable metadata item derived from evidence already present in the B02 report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchMetadata {
    /// Logical child path, or `None` for source-level metadata.
    pub path: Option<String>,
    /// Stable metadata key.
    pub key: String,
    /// Exact searchable value.
    pub value: String,
    /// Evidence source that produced this metadata projection.
    pub source: String,
}

/// Truthful B02 result. Unsupported and uncertain regions remain explicit.
#[derive(Debug, Clone)]
pub struct ProgressiveReport {
    /// SHA-256 of the immutable original source bytes.
    pub source_sha256: String,
    /// Caller-requested maximum level.
    pub requested_level: ProgressiveLevel,
    /// Highest level actually achieved without inventing unsupported semantics.
    pub achieved_level: ProgressiveLevel,
    /// Source-level type assessment.
    pub type_assessment: TypeAssessment,
    /// Generic child relationship graph projected from A12 inventory evidence.
    pub children: Vec<ChildRelationship>,
    /// Searchable evidence-derived metadata.
    pub searchable_metadata: Vec<SearchMetadata>,
    /// Regions or progressions B02 could not truthfully decompose.
    pub unsupported_regions: Vec<String>,
    /// Bounded warnings inherited from mechanical facilities.
    pub warnings: Vec<String>,
    /// Bounded limitations inherited from mechanical facilities and B02 progression policy.
    pub limitations: Vec<String>,
    /// Underlying A12 outcome when archive decomposition was attempted.
    pub archive_outcome: Option<DecompositionOutcome>,
}

/// B02 configuration or decomposition failures.
#[derive(Debug, Error)]
pub enum B02Error {
    /// Two configured detectors use the same stable identity.
    #[error("duplicate detector identity: {0}")]
    DuplicateDetectorId(String),
    /// Detector identity is empty after normalization.
    #[error("detector identity must not be empty")]
    EmptyDetectorId,
    /// Configured archive type token is empty after normalization.
    #[error("archive media type must not be empty")]
    EmptyArchiveMediaType,
    /// Existing A12 decomposition could not produce a truthful bounded plan.
    #[error(transparent)]
    Archive(#[from] DecompositionError),
}

/// Perform generic progressive type detection/decomposition over immutable source bytes.
///
/// B02 never chooses between conflicting detector types. Archive decomposition is selected only
/// when positive detector evidence agrees on a configured archive type. Unsupported progression
/// remains explicit in the returned report instead of becoming a false success.
///
/// # Errors
/// Returns [`B02Error`] for ambiguous detector configuration, invalid archive type configuration,
/// or an A12 backend/planning failure that prevents a bounded archive plan.
pub fn progressive_decompose(
    source_bytes: &[u8],
    spec: &ProgressiveSpec,
    detectors: &[&dyn TypeDetector],
    archive_backend: Option<&dyn ArchiveBackend>,
) -> Result<ProgressiveReport, B02Error> {
    validate_detector_ids(detectors)?;
    let archive_types = normalize_archive_types(&spec.archive_media_types)?;
    let source_sha256 = sha256_bytes(source_bytes);
    let declared_type = spec.declared_type.as_deref().map(normalize_type);

    if spec.requested_level == ProgressiveLevel::L0 {
        let type_assessment = TypeAssessment {
            declared_type: declared_type.clone(),
            detector_evidence: Vec::new(),
            agreement: TypeAgreement::Unknown,
            declared_matches_agreed_type: None,
        };
        return Ok(ProgressiveReport {
            source_sha256,
            requested_level: spec.requested_level,
            achieved_level: ProgressiveLevel::L0,
            searchable_metadata: root_metadata(&type_assessment),
            type_assessment,
            children: Vec::new(),
            unsupported_regions: Vec::new(),
            warnings: Vec::new(),
            limitations: Vec::new(),
            archive_outcome: None,
        });
    }

    let type_assessment = assess_type(source_bytes, declared_type, detectors);
    let mut report = ProgressiveReport {
        source_sha256,
        requested_level: spec.requested_level,
        achieved_level: ProgressiveLevel::L1,
        searchable_metadata: root_metadata(&type_assessment),
        type_assessment,
        children: Vec::new(),
        unsupported_regions: Vec::new(),
        warnings: Vec::new(),
        limitations: Vec::new(),
        archive_outcome: None,
    };
    if spec.requested_level == ProgressiveLevel::L1 {
        return Ok(report);
    }

    let Some(agreed_type) = report.type_assessment.agreed_type().map(ToOwned::to_owned) else {
        match &report.type_assessment.agreement {
            TypeAgreement::Unknown => report
                .unsupported_regions
                .push("no detector established an agreed source type".to_owned()),
            TypeAgreement::Disputed(types) => report.unsupported_regions.push(format!(
                "detector disagreement prevents decomposer selection: {}",
                types.join(", ")
            )),
            TypeAgreement::Agreed(_) => unreachable!("agreed type was already extracted"),
        }
        return Ok(report);
    };
    if !archive_types.contains(agreed_type.as_str()) {
        report.unsupported_regions.push(format!(
            "no B02 decomposer is registered for agreed type {agreed_type}"
        ));
        return Ok(report);
    }
    let Some(backend) = archive_backend else {
        report.unsupported_regions.push(format!(
            "archive decomposer unavailable for agreed type {agreed_type}"
        ));
        return Ok(report);
    };

    let mut archive_spec = spec.archive_spec.clone();
    if spec.requested_level == ProgressiveLevel::L2 {
        "L2_inventoried".clone_into(&mut archive_spec.requested_level);
        archive_spec.budget.max_depth = 0;
    } else {
        "L3_decomposed".clone_into(&mut archive_spec.requested_level);
    }
    let plan = decompose(source_bytes, &archive_spec, backend)?;
    apply_archive_plan(
        &mut report,
        &plan,
        detectors,
        &archive_types,
        spec.requested_level,
    );
    debug_assert_eq!(report.source_sha256, sha256_bytes(source_bytes));
    Ok(report)
}

fn validate_detector_ids(detectors: &[&dyn TypeDetector]) -> Result<(), B02Error> {
    let mut seen = HashSet::new();
    for detector in detectors {
        let id = detector.detector_id().trim();
        if id.is_empty() {
            return Err(B02Error::EmptyDetectorId);
        }
        if !seen.insert(id.to_owned()) {
            return Err(B02Error::DuplicateDetectorId(id.to_owned()));
        }
    }
    Ok(())
}

fn normalize_archive_types(values: &[String]) -> Result<HashSet<String>, B02Error> {
    let mut result = HashSet::new();
    for value in values {
        let normalized = normalize_type(value);
        if normalized.is_empty() {
            return Err(B02Error::EmptyArchiveMediaType);
        }
        result.insert(normalized);
    }
    Ok(result)
}

fn assess_type(
    bytes: &[u8],
    declared_type: Option<String>,
    detectors: &[&dyn TypeDetector],
) -> TypeAssessment {
    let mut evidence = Vec::with_capacity(detectors.len());
    let mut observed = BTreeSet::new();
    for detector in detectors {
        let detector_id = detector.detector_id().trim().to_owned();
        let outcome = match detector.detect(bytes) {
            Ok(Some(mut signal)) => {
                signal.media_type = normalize_type(&signal.media_type);
                if signal.media_type.is_empty() {
                    DetectorOutcome::Failed("detector emitted an empty type token".to_owned())
                } else if signal.confidence_milli > 1000 {
                    DetectorOutcome::Failed(format!(
                        "detector confidence {} exceeds 1000",
                        signal.confidence_milli
                    ))
                } else {
                    observed.insert(signal.media_type.clone());
                    DetectorOutcome::Observed(signal)
                }
            }
            Ok(None) => DetectorOutcome::NoMatch,
            Err(error) => DetectorOutcome::Failed(error),
        };
        evidence.push(DetectorEvidence {
            detector_id,
            outcome,
        });
    }
    let agreement = match observed.len() {
        0 => TypeAgreement::Unknown,
        1 => TypeAgreement::Agreed(observed.into_iter().next().unwrap_or_default()),
        _ => TypeAgreement::Disputed(observed.into_iter().collect()),
    };
    let declared_matches_agreed_type = match (&declared_type, &agreement) {
        (Some(declared), TypeAgreement::Agreed(observed)) => Some(declared == observed),
        _ => None,
    };
    TypeAssessment {
        declared_type,
        detector_evidence: evidence,
        agreement,
        declared_matches_agreed_type,
    }
}

fn apply_archive_plan(
    report: &mut ProgressiveReport,
    plan: &DecompositionPlan,
    detectors: &[&dyn TypeDetector],
    archive_types: &HashSet<String>,
    requested_level: ProgressiveLevel,
) {
    report.archive_outcome = Some(plan.outcome);
    report.warnings.extend(plan.warnings.iter().cloned());
    report.limitations.extend(plan.limitations.iter().cloned());
    report
        .unsupported_regions
        .extend(plan.unknown_gaps.iter().cloned());

    let recovered: HashMap<usize, &RecoveredMember> = plan
        .recovered_members
        .iter()
        .map(|member| (member.inventory_index, member))
        .collect();
    for (index, entry) in plan.inventory.iter().enumerate() {
        let parent_path = logical_parent(&entry.logical_path);
        let type_assessment = recovered
            .get(&index)
            .map(|member| assess_type(&member.bytes, None, detectors));
        let child = ChildRelationship {
            parent_path,
            child_path: entry.logical_path.clone(),
            kind: entry.kind,
            depth: entry.depth,
            byte_size: entry.byte_size,
            sha256: entry.member_sha256.clone(),
            type_assessment,
        };
        append_child_metadata(&mut report.searchable_metadata, &child);
        report.children.push(child);
    }

    if requested_level == ProgressiveLevel::L3 {
        mark_recursion_boundaries(report, plan, archive_types);
    }
    report.achieved_level = if plan.inventory.is_empty() {
        ProgressiveLevel::L1
    } else if requested_level == ProgressiveLevel::L2 || plan.recovered_members.is_empty() {
        ProgressiveLevel::L2
    } else {
        ProgressiveLevel::L3
    };
    dedup_strings(&mut report.unsupported_regions);
    dedup_strings(&mut report.warnings);
    dedup_strings(&mut report.limitations);
}

fn mark_recursion_boundaries(
    report: &mut ProgressiveReport,
    plan: &DecompositionPlan,
    archive_types: &HashSet<String>,
) {
    for child in &report.children {
        if child.depth < plan.budget_request.max_depth {
            continue;
        }
        let Some(assessment) = &child.type_assessment else {
            continue;
        };
        let Some(media_type) = assessment.agreed_type() else {
            continue;
        };
        if archive_types.contains(media_type) {
            let reason = format!(
                "recursion limit {} reached at decomposable child {}",
                plan.budget_request.max_depth, child.child_path
            );
            report.unsupported_regions.push(reason.clone());
            report.limitations.push(reason);
        }
    }
}

fn root_metadata(assessment: &TypeAssessment) -> Vec<SearchMetadata> {
    let mut metadata = Vec::new();
    if let Some(declared) = &assessment.declared_type {
        metadata.push(SearchMetadata {
            path: None,
            key: "declared_type".to_owned(),
            value: declared.clone(),
            source: "caller".to_owned(),
        });
    }
    match &assessment.agreement {
        TypeAgreement::Unknown => metadata.push(SearchMetadata {
            path: None,
            key: "observed_type_state".to_owned(),
            value: "unknown".to_owned(),
            source: "detector_aggregate".to_owned(),
        }),
        TypeAgreement::Agreed(value) => metadata.push(SearchMetadata {
            path: None,
            key: "agreed_type".to_owned(),
            value: value.clone(),
            source: "detector_aggregate".to_owned(),
        }),
        TypeAgreement::Disputed(values) => metadata.push(SearchMetadata {
            path: None,
            key: "disputed_types".to_owned(),
            value: values.join(","),
            source: "detector_aggregate".to_owned(),
        }),
    }
    if let Some(matches) = assessment.declared_matches_agreed_type {
        metadata.push(SearchMetadata {
            path: None,
            key: "declared_matches_agreed_type".to_owned(),
            value: matches.to_string(),
            source: "type_comparison".to_owned(),
        });
    }
    for evidence in &assessment.detector_evidence {
        match &evidence.outcome {
            DetectorOutcome::Observed(signal) => {
                metadata.push(SearchMetadata {
                    path: None,
                    key: format!("detector.{}.type", evidence.detector_id),
                    value: signal.media_type.clone(),
                    source: evidence.detector_id.clone(),
                });
                metadata.push(SearchMetadata {
                    path: None,
                    key: format!("detector.{}.confidence_milli", evidence.detector_id),
                    value: signal.confidence_milli.to_string(),
                    source: evidence.detector_id.clone(),
                });
            }
            DetectorOutcome::NoMatch => metadata.push(SearchMetadata {
                path: None,
                key: format!("detector.{}.state", evidence.detector_id),
                value: "no_match".to_owned(),
                source: evidence.detector_id.clone(),
            }),
            DetectorOutcome::Failed(error) => metadata.push(SearchMetadata {
                path: None,
                key: format!("detector.{}.failure", evidence.detector_id),
                value: error.clone(),
                source: evidence.detector_id.clone(),
            }),
        }
    }
    metadata
}

fn append_child_metadata(metadata: &mut Vec<SearchMetadata>, child: &ChildRelationship) {
    let path = Some(child.child_path.clone());
    metadata.push(SearchMetadata {
        path: path.clone(),
        key: "member_kind".to_owned(),
        value: child.kind.as_str().to_owned(),
        source: "a12_inventory".to_owned(),
    });
    metadata.push(SearchMetadata {
        path: path.clone(),
        key: "byte_size".to_owned(),
        value: child.byte_size.to_string(),
        source: "a12_inventory".to_owned(),
    });
    metadata.push(SearchMetadata {
        path: path.clone(),
        key: "depth".to_owned(),
        value: child.depth.to_string(),
        source: "a12_inventory".to_owned(),
    });
    if let Some(digest) = &child.sha256 {
        metadata.push(SearchMetadata {
            path: path.clone(),
            key: "sha256".to_owned(),
            value: digest.clone(),
            source: "a12_inventory".to_owned(),
        });
    }
    if let Some(assessment) = &child.type_assessment {
        match &assessment.agreement {
            TypeAgreement::Agreed(value) => metadata.push(SearchMetadata {
                path,
                key: "agreed_type".to_owned(),
                value: value.clone(),
                source: "detector_aggregate".to_owned(),
            }),
            TypeAgreement::Disputed(values) => metadata.push(SearchMetadata {
                path,
                key: "disputed_types".to_owned(),
                value: values.join(","),
                source: "detector_aggregate".to_owned(),
            }),
            TypeAgreement::Unknown => {}
        }
    }
}

fn logical_parent(path: &str) -> Option<String> {
    path.rsplit_once('/').map(|(parent, _)| parent.to_owned())
}

fn normalize_type(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn dedup_strings(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
