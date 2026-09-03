use ptah_activity_runtime::AttemptContext;
use ptah_identifiers::EntityRef;

use crate::D07Error;

/// Exact patch binding. A path is an alias and never patch identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchBinding {
    /// Proposal that led to this patch; Proposal remains a distinct identity.
    pub proposal_ref: EntityRef,
    /// Exact A07 Object/Revision containing patch bytes.
    pub patch_object_ref: EntityRef,
    /// Exact immutable base revisions against which the patch was produced.
    pub base_revision_refs: Vec<EntityRef>,
    /// Exact generator/provider revision.
    pub generator_ref: EntityRef,
    /// Canonical digest of patch evidence bytes.
    pub sha256: String,
    /// Optional path alias; never canonical identity.
    pub path_alias: Option<String>,
}

impl PatchBinding {
    /// Construct an exact Patch binding without converting a Proposal or path into identity.
    ///
    /// # Errors
    /// Returns [`D07Error::InvalidPatchBinding`] when object/base/digest boundaries are absent.
    pub fn new(
        proposal_ref: EntityRef,
        patch_object_ref: EntityRef,
        base_revision_refs: Vec<EntityRef>,
        generator_ref: EntityRef,
        sha256: String,
        path_alias: Option<String>,
    ) -> Result<Self, D07Error> {
        if proposal_ref.entity_kind.as_str() != "security.remediation_proposal"
            || !matches!(
                patch_object_ref.entity_kind.as_str(),
                "core.object_revision" | "core.artifact"
            )
            || base_revision_refs.is_empty()
            || base_revision_refs
                .iter()
                .any(|reference| reference.entity_kind.as_str() != "core.object_revision")
            || crate::assessment::require_sha256(&sha256).is_err()
        {
            return Err(D07Error::InvalidPatchBinding);
        }
        Ok(Self {
            proposal_ref,
            patch_object_ref,
            base_revision_refs,
            generator_ref,
            sha256,
            path_alias,
        })
    }

    /// Return the exact A07 object identity; path aliases are deliberately excluded.
    #[must_use]
    pub const fn patch_identity(&self) -> &EntityRef {
        &self.patch_object_ref
    }
}

/// Caller-authorized request to execute an already-created Patch.
#[derive(Debug, Clone)]
pub struct RemediationExecutionRequest {
    /// Exact Proposal identity.
    pub proposal_ref: EntityRef,
    /// Exact Patch identity.
    pub patch_ref: EntityRef,
    /// Exact target revisions.
    pub target_refs: Vec<EntityRef>,
    /// Exact verified backup references.
    pub backup_refs: Vec<EntityRef>,
    /// Caller-owned A04 Activity Request identity.
    pub activity_request_ref: EntityRef,
    /// Explicit authority for the remediation execution.
    pub authority_ref: EntityRef,
    /// Exact physical A04 Attempt context.
    pub attempt_context: AttemptContext,
}

impl RemediationExecutionRequest {
    /// Validate execution bindings without claiming execution success.
    ///
    /// # Errors
    /// Returns [`D07Error::InvalidRemediationRequest`] for missing exact references.
    pub fn validate(&self) -> Result<(), D07Error> {
        if self.proposal_ref.entity_kind.as_str() != "security.remediation_proposal"
            || self.patch_ref.entity_kind.as_str() != "security.patch"
            || self.target_refs.is_empty()
            || self.backup_refs.is_empty()
            || self.activity_request_ref.entity_kind.as_str() != "core.activity_request"
        {
            return Err(D07Error::InvalidRemediationRequest);
        }
        Ok(())
    }
}

/// Provider acknowledgement of patch application; it is not verification evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationAcknowledgement {
    remediation_run_ref: EntityRef,
    outcome: &'static str,
}

impl RemediationAcknowledgement {
    /// Retain an application acknowledgement at the frozen `applied_unverified` boundary.
    #[must_use]
    pub const fn applied_unverified(remediation_run_ref: EntityRef) -> Self {
        Self {
            remediation_run_ref,
            outcome: "applied_unverified",
        }
    }

    /// Mechanical acknowledgement outcome.
    #[must_use]
    pub const fn outcome(&self) -> &'static str {
        self.outcome
    }

    /// Application acknowledgement can never satisfy independent post-fix verification.
    #[must_use]
    pub const fn satisfies_post_fix_verification(&self) -> bool {
        false
    }

    /// Exact Remediation Run referenced by the acknowledgement.
    #[must_use]
    pub const fn remediation_run_ref(&self) -> &EntityRef {
        &self.remediation_run_ref
    }
}

/// Frozen post-fix review decision vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostFixDecision {
    /// Independent verification proves the finding fixed within the bounded scope.
    FixedVerified,
    /// Mitigation is present but explicit limitations remain.
    MitigatedWithLimitations,
    /// Verification shows the issue is not fixed.
    NotFixed,
    /// A previously closed issue has regressed.
    Regressed,
    /// Verification evidence remains inconclusive.
    Inconclusive,
}

/// Exact independent Post-Fix Verification request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostFixVerificationRequest {
    /// Remediation Run being verified.
    pub remediation_run_ref: EntityRef,
    /// Exact Finding references under verification.
    pub finding_refs: Vec<EntityRef>,
    /// Exact fixed target revisions.
    pub target_refs: Vec<EntityRef>,
    /// Exact environment evidence.
    pub environment_refs: Vec<EntityRef>,
    /// Prior A04 Attempts that cannot be reused.
    pub prior_attempt_refs: Vec<EntityRef>,
    /// Explicit verification decision.
    pub decision: PostFixDecision,
    /// Evidence Bundles supporting the decision.
    pub evidence_bundle_refs: Vec<EntityRef>,
}

impl PostFixVerificationRequest {
    /// Validate a fresh A04 Attempt and exact target/environment/evidence boundaries.
    ///
    /// # Errors
    /// Returns [`D07Error`] when verification lacks exact evidence or reuses an Attempt.
    pub fn validate_attempt(&self, attempt_ref: &EntityRef) -> Result<(), D07Error> {
        if self.remediation_run_ref.entity_kind.as_str() != "security.remediation_run"
            || self.finding_refs.is_empty()
            || self.target_refs.is_empty()
            || self.environment_refs.is_empty()
            || self.evidence_bundle_refs.is_empty()
        {
            return Err(D07Error::InvalidPostFixVerification);
        }
        if attempt_ref.entity_kind.as_str() != "core.attempt"
            || self.prior_attempt_refs.contains(attempt_ref)
        {
            return Err(D07Error::FreshAttemptRequired);
        }
        Ok(())
    }

    /// Return immutable decision history with a new verification appended, never rewritten.
    #[must_use]
    pub fn history_after(&self, prior: Option<PostFixDecision>) -> Vec<PostFixDecision> {
        let mut history = Vec::with_capacity(2);
        if let Some(prior) = prior {
            history.push(prior);
        }
        history.push(self.decision);
        history
    }
}
