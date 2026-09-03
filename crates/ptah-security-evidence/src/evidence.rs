use ptah_identifiers::EntityRef;

use crate::{CoverageProjection, D07Error};

/// Explicit relationship between one immutable Observation and a Finding interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationRelation {
    /// Observation supports the interpretation.
    Supports,
    /// Observation contradicts the interpretation.
    Contradicts,
    /// Observation may duplicate another source observation.
    PossibleDuplicate,
    /// Same location but a different rule or interpretation.
    SameLocationDifferentRule,
    /// Same package but a different advisory.
    SamePackageDifferentAdvisory,
    /// Static/source and runtime evidence may be related.
    SourceAndRuntimeRelated,
    /// Observations cannot be compared mechanically.
    NotComparable,
    /// A newer Observation supersedes an older Observation without deleting it.
    SupersedesObservation,
}

/// One exact Observation relation retained without requiring `EntityRef: Ord`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationCorrelation {
    /// Exact immutable Observation reference.
    pub observation_ref: EntityRef,
    /// Caller/reviewer-authored relation.
    pub relation: CorrelationRelation,
}

/// Provider-neutral projection of one immutable security Observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationProjection {
    /// Canonical `security.observation` reference.
    pub observation_ref: EntityRef,
    /// Exact subjects observed.
    pub subject_refs: Vec<EntityRef>,
    /// Exact evidence retained for the Observation.
    pub evidence_refs: Vec<EntityRef>,
    /// Scanner/provider-local aliases retained only as evidence.
    pub scanner_aliases: Vec<String>,
    /// Bounded observed facts.
    pub observed_facts: Vec<String>,
}

impl ObservationProjection {
    /// Observation identity never doubles as Finding identity.
    #[must_use]
    pub const fn finding_identity(&self) -> Option<&EntityRef> {
        None
    }
}

/// Reviewed Finding candidate that retains all source Observations and relations.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingDraft {
    /// Exact Finding subjects.
    pub subject_refs: Vec<EntityRef>,
    /// Immutable source Observations.
    pub observation_refs: Vec<EntityRef>,
    /// Explicit correlation relations; contradictory relations remain retained.
    pub correlations: Vec<ObservationCorrelation>,
    /// Severity dimension, separate from confidence/acceptance.
    pub severity: String,
    /// Mechanical confidence in the interpretation.
    pub confidence: f64,
    /// Exploitability dimension, separate from severity.
    pub exploitability: String,
}

impl FindingDraft {
    /// Validate that a candidate has explicit bounded review before canonical confirmation.
    ///
    /// # Errors
    /// Returns [`D07Error`] for absent review, malformed confidence, or incomplete correlation evidence.
    pub fn validate_confirmation(&self, review_ref: Option<&EntityRef>) -> Result<(), D07Error> {
        let Some(review_ref) = review_ref else {
            return Err(D07Error::ReviewRequired);
        };
        if review_ref.entity_kind.as_str() != "security.review_decision" {
            return Err(D07Error::ReviewRequired);
        }
        if self.subject_refs.is_empty()
            || self.observation_refs.is_empty()
            || self.severity.trim().is_empty()
            || self.exploitability.trim().is_empty()
            || !self.confidence.is_finite()
            || !(0.0..=1.0).contains(&self.confidence)
        {
            return Err(D07Error::InvalidFindingDraft);
        }
        if self.observation_refs.iter().any(|observation| {
            !self
                .correlations
                .iter()
                .any(|binding| binding.observation_ref == *observation)
        }) {
            return Err(D07Error::InvalidFindingDraft);
        }
        Ok(())
    }

    /// Return every correlated Observation reference without deleting contradictions.
    #[must_use]
    pub fn correlated_observation_refs(&self) -> Vec<EntityRef> {
        self.correlations
            .iter()
            .map(|binding| binding.observation_ref.clone())
            .collect()
    }
}

/// Bounded Claim projection; Claim remains separate from its Evidence Bundles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimProjection {
    /// Exact bounded claim sentence.
    pub statement: String,
    /// Explicit claimant identity.
    pub claimant_ref: EntityRef,
    /// Authority scopes under which the claimant may state the Claim.
    pub authority_scope: Vec<String>,
    /// Exact subjects to which the Claim applies.
    pub subject_refs: Vec<EntityRef>,
    /// Exact Evidence Bundles supporting or qualifying the Claim.
    pub evidence_bundle_refs: Vec<EntityRef>,
}

impl ClaimProjection {
    /// Construct a bounded Claim only with explicit claimant, authority scope, subjects and evidence.
    ///
    /// # Errors
    /// Returns [`D07Error::InvalidClaim`] when any required boundary is absent.
    pub fn new(
        statement: String,
        claimant_ref: Option<EntityRef>,
        authority_scope: Vec<String>,
        subject_refs: Vec<EntityRef>,
        evidence_bundle_refs: Vec<EntityRef>,
    ) -> Result<Self, D07Error> {
        let claimant_ref = claimant_ref.ok_or(D07Error::InvalidClaim)?;
        if statement.trim().is_empty()
            || authority_scope.is_empty()
            || authority_scope.iter().any(|scope| scope.trim().is_empty())
            || subject_refs.is_empty()
            || evidence_bundle_refs.is_empty()
        {
            return Err(D07Error::InvalidClaim);
        }
        Ok(Self {
            statement,
            claimant_ref,
            authority_scope,
            subject_refs,
            evidence_bundle_refs,
        })
    }
}

/// Exact content/collector/A04 binding for one Evidence Item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceItemBinding {
    /// Exact Content/Object/Artifact reference.
    pub content_ref: EntityRef,
    /// Canonical lowercase SHA-256 of retained evidence bytes.
    pub sha256: String,
    /// Exact collector identity.
    pub collector_ref: EntityRef,
    /// Exact A04 Activity that collected the evidence.
    pub activity_ref: EntityRef,
    /// Exact A04 Attempt that collected the evidence.
    pub attempt_ref: EntityRef,
}

impl EvidenceItemBinding {
    /// Construct one exact Evidence Item binding.
    ///
    /// # Errors
    /// Returns [`D07Error::InvalidEvidenceBinding`] for mutable/invalid content or A04 bindings.
    pub fn new(
        content_ref: EntityRef,
        sha256: String,
        collector_ref: EntityRef,
        activity_ref: EntityRef,
        attempt_ref: EntityRef,
    ) -> Result<Self, D07Error> {
        let content_kind = content_ref.entity_kind.as_str();
        if !matches!(
            content_kind,
            "core.content" | "core.object_revision" | "core.artifact"
        ) || activity_ref.entity_kind.as_str() != "core.activity"
            || attempt_ref.entity_kind.as_str() != "core.attempt"
            || crate::assessment::require_sha256(&sha256).is_err()
        {
            return Err(D07Error::InvalidEvidenceBinding);
        }
        Ok(Self {
            content_ref,
            sha256,
            collector_ref,
            activity_ref,
            attempt_ref,
        })
    }
}

/// Evidence Bundle coverage classification from the frozen WP12 vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceCoverage {
    /// Complete only for the exact bounded Claim scope.
    CompleteForClaimScope,
    /// Explicit partial coverage.
    Partial,
    /// Coverage is unknown.
    Unknown,
}

/// Mechanical Evidence Bundle projection used to block coverage overclaiming.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceBundleProjection {
    /// Exact Evidence Item references retained by the bundle.
    pub evidence_item_refs: Vec<EntityRef>,
    /// Bundle coverage claim.
    pub coverage: EvidenceCoverage,
    /// Explicit limitations.
    pub limitations: Vec<String>,
}

impl EvidenceBundleProjection {
    /// Check a bundle coverage claim against the actual assessment coverage projection.
    ///
    /// # Errors
    /// Returns [`D07Error`] when evidence is absent or complete coverage is overclaimed.
    pub fn validate_against(&self, coverage: &CoverageProjection) -> Result<(), D07Error> {
        if self.evidence_item_refs.is_empty() {
            return Err(D07Error::InvalidEvidenceBinding);
        }
        if self.coverage == EvidenceCoverage::CompleteForClaimScope {
            coverage.validate()?;
            if !coverage.complete {
                return Err(D07Error::EvidenceCoverageOverclaim);
            }
        }
        Ok(())
    }
}
