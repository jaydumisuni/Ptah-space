use ptah_activity_runtime::AttemptContext;
use ptah_identifiers::EntityRef;

use crate::D07Error;

/// Explicit request boundary for one fresh validation run.
#[derive(Debug, Clone)]
pub struct ValidationRequest {
    /// Findings under validation.
    pub finding_refs: Vec<EntityRef>,
    /// Claims under validation.
    pub claim_refs: Vec<EntityRef>,
    /// Exact environment evidence required for reproducible interpretation.
    pub environment_refs: Vec<EntityRef>,
    /// Prior Attempts that must never be reused.
    pub prior_attempt_refs: Vec<EntityRef>,
    /// Exact physical A04 context for the new run.
    pub attempt_context: AttemptContext,
}

impl ValidationRequest {
    /// Validate fresh Attempt identity and exact environment evidence.
    ///
    /// # Errors
    /// Returns [`D07Error`] when environment evidence is absent or an Attempt is reused.
    pub fn validate_attempt(&self, attempt_ref: &EntityRef) -> Result<(), D07Error> {
        if self.environment_refs.is_empty() {
            return Err(D07Error::MissingEnvironmentEvidence);
        }
        if attempt_ref.entity_kind.as_str() != "core.attempt"
            || self.prior_attempt_refs.contains(attempt_ref)
        {
            return Err(D07Error::FreshAttemptRequired);
        }
        if self.finding_refs.is_empty() && self.claim_refs.is_empty() {
            return Err(D07Error::InvalidReviewDecision);
        }
        Ok(())
    }
}

/// Explicit bounded reviewer outcome; it is never inferred from Evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewOutcome {
    /// Reviewer accepts the bounded Claim/Finding.
    Accepted,
    /// Reviewer accepts only with retained limitations.
    AcceptedWithLimitations,
    /// Reviewer rejects the bounded Claim/Finding.
    Rejected,
    /// Evidence is insufficient for a determination.
    Inconclusive,
    /// Review remains explicitly disputed.
    Disputed,
}

/// Derived review decision projection containing references only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewDecisionProjection {
    /// Exact Finding references reviewed.
    pub finding_refs: Vec<EntityRef>,
    /// Exact Claim references reviewed.
    pub claim_refs: Vec<EntityRef>,
    /// Exact Validation Run references considered.
    pub validation_run_refs: Vec<EntityRef>,
    /// Explicit reviewer identity.
    pub reviewer_ref: EntityRef,
    /// Bounded review authority scopes.
    pub authority_scope: Vec<String>,
    /// Explicit review outcome.
    pub outcome: ReviewOutcome,
    /// Retained reasons for the decision.
    pub reasons: Vec<String>,
}

impl ReviewDecisionProjection {
    /// Validate the bounded review projection without mutating any source records.
    ///
    /// # Errors
    /// Returns [`D07Error::InvalidReviewDecision`] when required review evidence is absent.
    pub fn validate(&self) -> Result<(), D07Error> {
        if self.finding_refs.is_empty()
            || self.validation_run_refs.is_empty()
            || self.authority_scope.is_empty()
            || self.reasons.is_empty()
            || self
                .authority_scope
                .iter()
                .any(|scope| scope.trim().is_empty())
            || self.reasons.iter().any(|reason| reason.trim().is_empty())
        {
            return Err(D07Error::InvalidReviewDecision);
        }
        Ok(())
    }
}

/// Accepted Risk projection that never mutates the Finding it references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRiskProjection {
    /// Exact Findings covered by the risk acceptance.
    pub finding_refs: Vec<EntityRef>,
    /// Explicit authority accepting the bounded risk.
    pub authority_ref: EntityRef,
    /// Exact expiry timestamp after which review is required again.
    pub expires_at: String,
}

impl AcceptedRiskProjection {
    /// Determine whether the accepted risk remains active at `now`.
    ///
    /// # Errors
    /// Returns [`D07Error::InvalidTimestamp`] for malformed UTC timestamps.
    pub fn is_active_at(&self, now: &str) -> Result<bool, D07Error> {
        if self.finding_refs.is_empty()
            || !crate::assessment::valid_utc(now)
            || !crate::assessment::valid_utc(&self.expires_at)
        {
            return Err(D07Error::InvalidTimestamp);
        }
        Ok(now < self.expires_at.as_str())
    }
}

/// Dispute projection retaining all submitted Claims and Evidence Bundles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputeProjection {
    /// Findings under dispute.
    pub finding_refs: Vec<EntityRef>,
    /// All competing Claim references submitted to the dispute.
    pub claim_refs: Vec<EntityRef>,
    /// All submitted Evidence Bundle references.
    pub evidence_bundle_refs: Vec<EntityRef>,
}

impl DisputeProjection {
    /// Validate that a dispute contains all three bounded reference families.
    ///
    /// # Errors
    /// Returns [`D07Error::InvalidDispute`] when a position/evidence family is absent.
    pub fn validate(&self) -> Result<(), D07Error> {
        if self.finding_refs.is_empty()
            || self.claim_refs.len() < 2
            || self.evidence_bundle_refs.len() < 2
        {
            return Err(D07Error::InvalidDispute);
        }
        Ok(())
    }
}
