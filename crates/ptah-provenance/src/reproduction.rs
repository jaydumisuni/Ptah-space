use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};

use crate::{D06Error, ExactSubject, VerificationDecision};

/// Frozen WP07 independence requirement vocabulary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependenceRequirement {
    /// Execute on a different Node.
    DifferentNode,
    /// Execute through a different Provider Instance.
    DifferentProviderInstance,
    /// Use a different Provider implementation.
    DifferentProviderImplementation,
    /// Use a different backend implementation.
    DifferentBackend,
    /// Use a different operator/principal.
    DifferentOperator,
    /// Disable build/output cache reuse.
    CacheDisabled,
    /// Resolve source again rather than reusing prior materialization.
    FreshSourceResolution,
    /// Registered requirement outside the frozen native vocabulary.
    OtherRegistered,
}

/// Frozen WP07 reproduction cache policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CachePolicy {
    /// Cache use is disabled.
    Disabled,
    /// Only independently verified source cache may be used.
    OnlyVerifiedSourceCache,
    /// Reuse of the same backend cache is forbidden.
    SameBackendForbidden,
    /// Cache use must be declared and compared.
    DeclaredAndCompared,
    /// Registered cache policy outside the frozen native vocabulary.
    OtherRegistered,
}

/// Mechanical execution classification considered for reproduction admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReproductionExecutionKind {
    /// New build execution producing a distinct Build Run.
    FreshBuild,
    /// Existing cached output reused without a new independent build.
    CacheHit,
    /// Existing output merely re-verified.
    Reverification,
}

/// Versioned reproduction request projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproductionRequestProjection {
    /// Canonical Reproduction Request identity.
    pub request_ref: EntityRef,
    /// Exact original Build Run.
    pub original_build_run_ref: EntityRef,
    /// Exact Recipe Revision.
    pub recipe_revision_ref: EntityRef,
    /// Exact comparison protocol revision.
    pub comparison_protocol_ref: EntityRef,
    /// Caller-authored independence requirements.
    pub independence_requirements: Vec<IndependenceRequirement>,
    /// Reproduction cache policy.
    pub cache_policy: CachePolicy,
}

/// Replaceable backend/tool evidence associated with one reproduction run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendEvidence {
    /// Exact Provider Revision used by the run.
    pub provider_revision_ref: EntityRef,
    /// Exact Provider Instance generation/fence.
    pub provider_generation: u64,
    /// Exact tool Object/Package Revision evidence.
    pub tool_revision_ref: EntityRef,
}

/// Admitted independent reproduction run projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproductionRunProjection {
    /// Canonical Reproduction Run identity.
    pub run_ref: EntityRef,
    /// Reproduction Request identity.
    pub request_ref: EntityRef,
    /// Original Build Run retained unchanged.
    pub original_build_run_ref: EntityRef,
    /// Distinct reproduction Build Run.
    pub reproduction_build_run_ref: EntityRef,
    /// Exact Recipe Revision.
    pub recipe_revision_ref: EntityRef,
    /// Exact comparison protocol.
    pub comparison_protocol_ref: EntityRef,
    /// Evidence satisfying the declared independence requirements.
    pub independence_evidence_refs: Vec<EntityRef>,
    /// Mechanical execution classification.
    pub execution_kind: ReproductionExecutionKind,
    /// Mechanical outcome retained even when negative/inconclusive.
    pub decision: VerificationDecision,
    /// Replaceable provider/tool evidence.
    pub backend: BackendEvidence,
}

impl ReproductionRunProjection {
    /// Admit one independent reproduction run.
    ///
    /// # Errors
    /// Returns [`D06Error::InvalidReproduction`] unless the reproduction uses a distinct fresh Build Run,
    /// has declared independence requirements, and retains explicit independence evidence.
    pub fn new(
        request: &ReproductionRequestProjection,
        reproduction_build_run_ref: EntityRef,
        independence_evidence_refs: Vec<EntityRef>,
        execution_kind: ReproductionExecutionKind,
        decision: VerificationDecision,
        backend: BackendEvidence,
    ) -> Result<Self, D06Error> {
        if request.original_build_run_ref == reproduction_build_run_ref
            || request.independence_requirements.is_empty()
            || independence_evidence_refs.is_empty()
            || execution_kind != ReproductionExecutionKind::FreshBuild
            || request.original_build_run_ref.entity_kind.as_str() != "build.run"
            || reproduction_build_run_ref.entity_kind.as_str() != "build.run"
        {
            return Err(D06Error::InvalidReproduction);
        }
        Ok(Self {
            run_ref: EntityRef::new("proof.reproduction_run")
                .map_err(|_| D06Error::InvalidReproduction)?,
            request_ref: request.request_ref.clone(),
            original_build_run_ref: request.original_build_run_ref.clone(),
            reproduction_build_run_ref,
            recipe_revision_ref: request.recipe_revision_ref.clone(),
            comparison_protocol_ref: request.comparison_protocol_ref.clone(),
            independence_evidence_refs,
            execution_kind,
            decision,
            backend,
        })
    }

    /// Replace only provider/tool evidence while preserving all Ptah proof/build identities.
    #[must_use]
    pub fn with_replacement_backend(&self, backend: BackendEvidence) -> Self {
        let mut replaced = self.clone();
        replaced.backend = backend;
        replaced
    }
}

/// Frozen WP07 reproduction comparison class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonClass {
    /// Outputs are byte-identical.
    ByteIdentical,
    /// Outputs are functionally equivalent within the declared protocol.
    FunctionallyEquivalentWithinProtocol,
    /// Outputs differ but only within an explicitly accepted variance.
    DifferentButAcceptedVariance,
    /// Outputs are not equivalent.
    NotEquivalent,
    /// Comparison evidence is inconclusive.
    Inconclusive,
    /// Comparison could not be completed.
    Blocked,
}

/// Independent comparison evidence between original and reproduced subjects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproductionComparisonProjection {
    /// Canonical Comparison identity.
    pub comparison_ref: EntityRef,
    /// Original exact subject.
    pub original_subject: ExactSubject,
    /// Reproduced exact subject.
    pub reproduced_subject: ExactSubject,
    /// Comparison class.
    pub comparison_class: ComparisonClass,
    /// Supporting comparison evidence.
    pub evidence_refs: Vec<EntityRef>,
}

impl ReproductionComparisonProjection {
    /// Whether this comparison establishes exact byte identity rather than functional equivalence.
    #[must_use]
    pub const fn is_byte_identical(&self) -> bool {
        matches!(self.comparison_class, ComparisonClass::ByteIdentical)
    }
}
