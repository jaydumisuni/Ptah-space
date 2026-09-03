use ptah_activity_runtime::AttemptContext;
use ptah_identifiers::EntityRef;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::D07Error;

/// Frozen caller-authored reproduction protocol projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReproductionProtocolProjection {
    /// Stable caller protocol key; content digest remains the exact version identity.
    pub protocol_key: String,
    /// Exact Claim dimensions the protocol attempts to reproduce.
    pub claim_scope: Vec<String>,
    /// Exact immutable protocol inputs.
    pub required_inputs: Vec<EntityRef>,
    /// Exact environment requirements.
    pub environment_requirements: Vec<String>,
    /// Explicit independence requirements.
    pub independence_requirements: Vec<String>,
    /// Bounded success criteria.
    pub success_criteria: Vec<String>,
    /// Bounded failure criteria.
    pub failure_criteria: Vec<String>,
}

impl ReproductionProtocolProjection {
    /// Compute a deterministic digest over all protocol boundaries.
    ///
    /// # Errors
    /// Returns [`D07Error::Serialization`] if serialization fails.
    pub fn digest(&self) -> Result<String, D07Error> {
        if self.protocol_key.trim().is_empty()
            || self.claim_scope.is_empty()
            || self.required_inputs.is_empty()
            || self.environment_requirements.is_empty()
            || self.independence_requirements.is_empty()
            || self.success_criteria.is_empty()
            || self.failure_criteria.is_empty()
        {
            return Err(D07Error::InvalidReproductionProtocol);
        }
        let bytes =
            serde_json::to_vec(self).map_err(|error| D07Error::Serialization(error.to_string()))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

/// Reproduction Request is intent only and deliberately exposes no A04 identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReproductionRequestProjection {
    /// Claims requested for reproduction.
    pub claim_refs: Vec<EntityRef>,
    /// Findings requested for reproduction.
    pub finding_refs: Vec<EntityRef>,
    /// Exact frozen Reproduction Protocol.
    pub protocol_ref: EntityRef,
    /// Requested environment constraints.
    pub requested_environment_constraints: Vec<String>,
    /// Required independence constraints.
    pub independence_requirements: Vec<String>,
    /// Caller requesting reproduction.
    pub requested_by_ref: EntityRef,
    /// Exact request time.
    pub requested_at: String,
}

impl ReproductionRequestProjection {
    /// Validate request-only boundaries.
    ///
    /// # Errors
    /// Returns [`D07Error::InvalidReproductionRequest`] when request inputs are incomplete.
    pub fn validate(&self) -> Result<(), D07Error> {
        if (self.claim_refs.is_empty() && self.finding_refs.is_empty())
            || self.protocol_ref.entity_kind.as_str() != "security.reproduction_protocol"
            || self.requested_environment_constraints.is_empty()
            || self.independence_requirements.is_empty()
            || !crate::assessment::valid_utc(&self.requested_at)
        {
            return Err(D07Error::InvalidReproductionRequest);
        }
        Ok(())
    }

    /// A request never creates execution by itself.
    #[must_use]
    pub const fn is_execution(&self) -> bool {
        false
    }

    /// A request contains no Activity identity.
    #[must_use]
    pub const fn activity_ref(&self) -> Option<&EntityRef> {
        None
    }
}

/// Mechanical independence evidence for one reproduction run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReproductionIndependence {
    /// Run did not reuse the original mutable/cache state.
    pub fresh_cache: bool,
    /// Environment was frozen/immutable for the run.
    pub immutable_environment: bool,
    /// Run authority is demonstrably distinct where independence requires it.
    pub distinct_authority: bool,
    /// Exact evidence supporting independence assertions.
    pub evidence_refs: Vec<EntityRef>,
}

impl ReproductionIndependence {
    /// Validate that independence is evidenced rather than asserted by name.
    ///
    /// # Errors
    /// Returns [`D07Error::IndependenceNotProven`] for reused/mutable/shared conditions.
    pub fn validate(&self) -> Result<(), D07Error> {
        if !self.fresh_cache
            || !self.immutable_environment
            || !self.distinct_authority
            || self.evidence_refs.is_empty()
        {
            return Err(D07Error::IndependenceNotProven);
        }
        Ok(())
    }
}

/// Exact reproduction execution request; execution remains A04-owned.
#[derive(Debug, Clone)]
pub struct ReproductionRunRequest {
    /// Exact canonical Reproduction Request.
    pub request_ref: EntityRef,
    /// Exact frozen Reproduction Protocol.
    pub protocol_ref: EntityRef,
    /// Exact environment evidence references.
    pub environment_refs: Vec<EntityRef>,
    /// Exact independence evidence references.
    pub independence_evidence_refs: Vec<EntityRef>,
    /// Prior A04 Attempts that cannot be reused.
    pub prior_attempt_refs: Vec<EntityRef>,
    /// Caller-owned A04 Activity Request.
    pub activity_request_ref: EntityRef,
    /// Workspace identity retained by A04.
    pub workspace_ref: EntityRef,
    /// Caller identity retained by A04.
    pub caller_ref: EntityRef,
    /// Explicit execution authority.
    pub authority_ref: EntityRef,
    /// Explicit intent identity.
    pub intent_ref: EntityRef,
    /// Exact A04 physical execution context.
    pub attempt_context: AttemptContext,
    /// Mechanical independence projection.
    pub independence: ReproductionIndependence,
}

impl ReproductionRunRequest {
    /// Validate a fresh Attempt and exact environment/independence boundaries.
    ///
    /// # Errors
    /// Returns [`D07Error`] for reused Attempt identity or unproven independence.
    pub fn validate_attempt(&self, attempt_ref: &EntityRef) -> Result<(), D07Error> {
        if self.request_ref.entity_kind.as_str() != "security.reproduction_request"
            || self.protocol_ref.entity_kind.as_str() != "security.reproduction_protocol"
            || self.environment_refs.is_empty()
            || self.independence_evidence_refs.is_empty()
            || self.activity_request_ref.entity_kind.as_str() != "core.activity_request"
        {
            return Err(D07Error::InvalidReproductionRequest);
        }
        self.independence.validate()?;
        if attempt_ref.entity_kind.as_str() != "core.attempt"
            || self.prior_attempt_refs.contains(attempt_ref)
        {
            return Err(D07Error::FreshAttemptRequired);
        }
        Ok(())
    }
}

/// Frozen reproduction run outcome vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReproductionOutcome {
    /// Claim was reproduced under the exact protocol.
    Reproduced,
    /// Claim was not reproduced under the exact protocol.
    NotReproduced,
    /// Only part of the Claim scope reproduced.
    PartiallyReproduced,
    /// Reproduction work failed mechanically.
    Failed,
    /// Evidence was insufficient for a determination.
    Inconclusive,
}

/// Separate comparison decision over the immutable Reproduction Run history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReproductionComparisonDecision {
    /// Reproduction supports the original Claim.
    SupportsClaim,
    /// Reproduction supports only part of the original Claim.
    PartiallySupports,
    /// Reproduction contradicts the original Claim.
    ContradictsClaim,
    /// Comparison evidence is inconclusive.
    Inconclusive,
}

/// Comparison projection that retains all negative/partial/failed/inconclusive outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReproductionComparisonProjection {
    /// Exact original Claims being compared.
    pub original_claim_refs: Vec<EntityRef>,
    /// Exact Reproduction Run.
    pub reproduction_run_ref: EntityRef,
    /// Immutable retained run outcomes/history.
    pub outcome_history: Vec<ReproductionOutcome>,
    /// Separate comparison decision.
    pub decision: ReproductionComparisonDecision,
}

impl ReproductionComparisonProjection {
    /// Validate retained comparison boundaries without rewriting original Claims or outcomes.
    ///
    /// # Errors
    /// Returns [`D07Error::InvalidReproductionComparison`] when history is incomplete.
    pub fn validate(&self) -> Result<(), D07Error> {
        if self.original_claim_refs.is_empty()
            || self.reproduction_run_ref.entity_kind.as_str() != "security.reproduction_run"
            || self.outcome_history.is_empty()
        {
            return Err(D07Error::InvalidReproductionComparison);
        }
        Ok(())
    }
}
