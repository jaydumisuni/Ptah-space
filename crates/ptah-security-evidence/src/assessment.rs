use std::collections::{BTreeMap, BTreeSet};

use ptah_activity_runtime::{
    ActivityRuntime, ActivitySpec, AttemptContext, IdempotencyClass, OperationSpec, RetryClass,
    SideEffectClass,
};
use ptah_identifiers::{EntityId, EntityRef};
use ptah_workspace::WorkspaceStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::D07Error;

/// Caller-selected security test class. D07 never chooses one itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityTestClass {
    /// Source/static inspection.
    SourceStatic,
    /// Artifact/package inventory.
    ArtifactInventory,
    /// Vulnerability/advisory matching.
    VulnerabilityMatch,
    /// Configuration/policy observation.
    ConfigurationPolicy,
    /// Secret-detection observation.
    SecretDetection,
    /// Licence observation.
    LicenceObservation,
    /// Passive dynamic observation.
    PassiveDynamic,
    /// Active dynamic assessment.
    ActiveDynamic,
    /// Fuzz assessment.
    Fuzz,
    /// Explicit exploit-validation assessment.
    ExploitValidation,
    /// Explicit offensive agentic assessment.
    OffensiveAgentic,
    /// Supply-chain graph analysis.
    SupplyChainGraphAnalysis,
    /// Reproduction/replay assessment.
    ReproductionOrReplay,
}

impl SecurityTestClass {
    fn scope(self) -> &'static str {
        match self {
            Self::SourceStatic => "security.assess.source_static",
            Self::ArtifactInventory => "security.assess.artifact_inventory",
            Self::VulnerabilityMatch => "security.assess.vulnerability_match",
            Self::ConfigurationPolicy => "security.assess.configuration_policy",
            Self::SecretDetection => "security.assess.secret_detection",
            Self::LicenceObservation => "security.assess.licence_observation",
            Self::PassiveDynamic => "security.assess.passive_dynamic",
            Self::ActiveDynamic => "security.assess.active_dynamic",
            Self::Fuzz => "security.assess.fuzz",
            Self::ExploitValidation => "security.assess.exploit_validation",
            Self::OffensiveAgentic => "security.assess.offensive_agentic",
            Self::SupplyChainGraphAnalysis => "security.assess.supply_chain_graph",
            Self::ReproductionOrReplay => "security.assess.reproduction",
        }
    }

    fn side_effect(self) -> SideEffectClass {
        match self {
            Self::SourceStatic
            | Self::ArtifactInventory
            | Self::VulnerabilityMatch
            | Self::ConfigurationPolicy
            | Self::SecretDetection
            | Self::LicenceObservation
            | Self::PassiveDynamic
            | Self::SupplyChainGraphAnalysis => SideEffectClass::ObservationOnly,
            Self::ActiveDynamic | Self::Fuzz | Self::ReproductionOrReplay => {
                SideEffectClass::Reversible
            }
            Self::ExploitValidation | Self::OffensiveAgentic => {
                SideEffectClass::NonIdempotentMutation
            }
        }
    }
}

/// Exact assessment target revision and digest. `locator` is an alias only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentTarget {
    /// Exact immutable target revision.
    pub target_ref: EntityRef,
    /// Canonical lowercase SHA-256 digest.
    pub sha256: String,
    /// Optional path/URL/location alias; never identity.
    pub locator: Option<String>,
}

impl AssessmentTarget {
    /// Build one exact target.
    ///
    /// # Errors
    /// Returns [`D07Error::InvalidDigest`] for a non-canonical SHA-256 digest.
    pub fn new(
        target_ref: EntityRef,
        sha256: String,
        locator: Option<String>,
    ) -> Result<Self, D07Error> {
        require_sha256(&sha256)?;
        Ok(Self {
            target_ref,
            sha256,
            locator,
        })
    }
}

/// Exact scanner/tool/rules/database/model revision inputs selected by the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerRevision {
    /// Exact provider revision.
    pub provider_revision_ref: EntityRef,
    /// Optional exact Package/Plugin revision supplying the scanner.
    pub package_or_plugin_revision_ref: Option<EntityRef>,
    /// Exact ruleset revision when applicable.
    pub ruleset_ref: Option<EntityRef>,
    /// Exact advisory database revision when applicable.
    pub advisory_database_ref: Option<EntityRef>,
    /// Exact policy revision when applicable.
    pub policy_ref: Option<EntityRef>,
    /// Exact model revision when applicable.
    pub model_ref: Option<EntityRef>,
    /// Canonical digest of scanner configuration.
    pub configuration_digest: String,
}

/// Explicit bounded assessment authorization. It never expands itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentAuthorization {
    /// Workspace identity retained for audit/projection.
    pub workspace_ref: EntityRef,
    /// Exact caller/actor identity.
    pub actor_ref: EntityRef,
    /// Exact current A06 Secure Grant.
    pub grant_ref: EntityRef,
    /// Caller-selected policy authorities.
    pub policy_refs: Vec<EntityRef>,
    /// Exact authorized target revisions.
    pub target_refs: Vec<EntityRef>,
    /// Explicit test classes permitted by the caller.
    pub allowed_test_classes: BTreeSet<SecurityTestClass>,
    /// Explicitly forbidden action keys.
    pub forbidden_action_keys: BTreeSet<String>,
    /// Projection validity start.
    pub valid_from: String,
    /// Projection expiry.
    pub expires_at: String,
    /// Privacy policies governing evidence.
    pub privacy_policy_refs: Vec<EntityRef>,
    /// Whether the selected assessment requires an emergency-stop capability.
    pub emergency_stop_required: bool,
    /// Whether cleanup readback is required after side effects.
    pub cleanup_readback_required: bool,
}

impl AssessmentAuthorization {
    /// Deterministic digest over the caller-authored authorization projection.
    ///
    /// # Errors
    /// Returns [`D07Error::Serialization`] if canonical serialization fails.
    pub fn digest(&self) -> Result<String, D07Error> {
        digest_json(self)
    }

    /// Validate exact target/test-class/clock/A06 Grant authority.
    ///
    /// # Errors
    /// Returns a fail-closed [`D07Error`] before any A04 work is created.
    pub fn authorize_at(
        &self,
        workspace: &WorkspaceStore,
        target: &AssessmentTarget,
        class: SecurityTestClass,
        now: &str,
    ) -> Result<(), D07Error> {
        if !valid_utc(now) || !valid_utc(&self.valid_from) || !valid_utc(&self.expires_at) {
            return Err(D07Error::InvalidTimestamp);
        }
        if now < self.valid_from.as_str() {
            return Err(D07Error::AuthorizationNotYetValid);
        }
        if now >= self.expires_at.as_str() {
            return Err(D07Error::AuthorizationExpired);
        }
        if !self.target_refs.contains(&target.target_ref) {
            return Err(D07Error::TargetOutOfScope);
        }
        if !self.allowed_test_classes.contains(&class) {
            return Err(D07Error::TestClassOutOfScope);
        }
        workspace
            .authorize_grant(
                &self.actor_ref,
                &target.target_ref,
                class.scope(),
                &self.grant_ref,
            )
            .map_err(|error| D07Error::A06(error.to_string()))
    }
}

/// Immutable assessment execution plan projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentPlan {
    /// Digest of the exact Authorization used to build this Plan.
    pub authorization_digest: String,
    /// Exact admitted targets.
    pub targets: Vec<AssessmentTarget>,
    /// Exact scanner/tool revision inputs.
    pub scanner_revision: ScannerRevision,
    /// Exact D04 Recipe Revision selected by caller.
    pub recipe_revision_ref: EntityRef,
    /// Exact D04 Compiled Plan selected by caller.
    pub compiled_plan_ref: EntityRef,
    /// Exact operation descriptor revision digests.
    pub operation_descriptor_digests: Vec<String>,
    /// Expected coverage scope.
    pub expected_scope: BTreeSet<String>,
    /// Caller-authored stop conditions.
    pub stop_conditions: Vec<String>,
    /// Output/evidence policies.
    pub output_policy_refs: Vec<EntityRef>,
}

impl AssessmentPlan {
    /// Validate mechanical plan bindings against one exact authorization.
    ///
    /// # Errors
    /// Returns [`D07Error`] for drift, empty scope or malformed digests.
    pub fn validate(&self, authorization: &AssessmentAuthorization) -> Result<(), D07Error> {
        if self.authorization_digest != authorization.digest()?
            || self.targets.is_empty()
            || self.expected_scope.is_empty()
        {
            return Err(D07Error::PlanBindingMismatch);
        }
        for target in &self.targets {
            require_sha256(&target.sha256)?;
            if !authorization.target_refs.contains(&target.target_ref) {
                return Err(D07Error::TargetOutOfScope);
            }
        }
        require_sha256(&self.scanner_revision.configuration_digest)?;
        if self.operation_descriptor_digests.is_empty() {
            return Err(D07Error::PlanBindingMismatch);
        }
        for digest in &self.operation_descriptor_digests {
            require_sha256(digest)?;
        }
        Ok(())
    }

    /// Deterministic identity digest for the full assessment plan projection.
    ///
    /// # Errors
    /// Returns [`D07Error`] when serialization fails.
    pub fn digest(&self) -> Result<String, D07Error> {
        digest_json(self)
    }
}

/// Exact expected/resolved/scanned coverage projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageProjection {
    /// Caller-declared expected scope.
    pub expected_scope: BTreeSet<String>,
    /// Scope successfully resolved to exact targets.
    pub resolved_scope: BTreeSet<String>,
    /// Scope actually assessed.
    pub scanned_scope: BTreeSet<String>,
    /// Explicit skipped scope.
    pub skipped_scope: BTreeSet<String>,
    /// Explicit unsupported scope.
    pub unsupported_scope: BTreeSet<String>,
    /// Scope that produced an error and the retained error code.
    pub error_scope: BTreeMap<String, String>,
    /// Limitations retained for caller/reviewer use.
    pub limitations: Vec<String>,
    /// Whether this projection claims complete coverage.
    pub complete: bool,
}

impl CoverageProjection {
    /// Validate that completeness is never overclaimed.
    ///
    /// # Errors
    /// Returns [`D07Error::CoverageOverclaim`] when any expected scope is missing or qualified.
    pub fn validate(&self) -> Result<(), D07Error> {
        if self.complete {
            let all_scanned = self.expected_scope.is_subset(&self.scanned_scope);
            let no_gaps = self.skipped_scope.is_empty()
                && self.unsupported_scope.is_empty()
                && self.error_scope.is_empty();
            if !all_scanned || !no_gaps {
                return Err(D07Error::CoverageOverclaim);
            }
        }
        Ok(())
    }
}

/// Raw scanner/report aliases retained as evidence, never identity or authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawReportAlias {
    /// Raw path/URL-like locator.
    pub path: String,
    /// Backend/provider-local run identifier.
    pub backend_run_id: String,
}

impl RawReportAlias {
    /// Raw scanner aliases can never grant Ptah identity.
    #[must_use]
    pub const fn grants_identity(&self) -> bool {
        false
    }

    /// Raw scanner aliases can never grant Ptah authority.
    #[must_use]
    pub const fn grants_authority(&self) -> bool {
        false
    }
}

/// Fresh A04 identities allocated only after D07 preflight succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessmentRunMapping {
    /// Fresh A04 Activity.
    pub activity_id: EntityId,
    /// Fresh A04 Operation.
    pub operation_id: EntityId,
    /// Fresh A04 Attempt.
    pub attempt_id: EntityId,
}

/// Borrowed admission inputs collected before D07 mutates A04.
pub struct AssessmentAdmissionRequest<'a> {
    /// Exact authorization projection.
    pub authorization: &'a AssessmentAuthorization,
    /// Exact assessment plan.
    pub plan: &'a AssessmentPlan,
    /// Exact selected target.
    pub target: &'a AssessmentTarget,
    /// Exact caller-selected test class.
    pub class: SecurityTestClass,
    /// Explicit admission timestamp.
    pub now: &'a str,
    /// Exact physical A04 Attempt context.
    pub attempt_context: AttemptContext,
}

/// Thin D07 admission facade borrowing A06 and A04 authorities.
pub struct AssessmentAdmission;

impl AssessmentAdmission {
    /// Validate the entire D07 assessment envelope before creating A04 work.
    ///
    /// # Errors
    /// Returns [`D07Error`] and creates no A04 Activity for any preflight failure.
    pub fn admit(
        runtime: &ActivityRuntime,
        workspace: &WorkspaceStore,
        request: AssessmentAdmissionRequest<'_>,
    ) -> Result<AssessmentRunMapping, D07Error> {
        let authorization = request.authorization;
        let plan = request.plan;
        let target = request.target;
        let class = request.class;
        authorization.authorize_at(workspace, target, class, request.now)?;
        plan.validate(authorization)?;
        if !plan.targets.contains(target) {
            return Err(D07Error::PlanBindingMismatch);
        }
        let activity_id = runtime
            .create_activity(ActivitySpec {
                request_ref: EntityRef::new("security.assessment_request").map_err(id_error)?,
                workspace_ref: authorization.workspace_ref.clone(),
                caller_ref: authorization.actor_ref.clone(),
                authority_ref: authorization.grant_ref.clone(),
                activity_kind: "security.assessment".to_owned(),
                intent_ref: plan.compiled_plan_ref.clone(),
                priority: 0,
                max_attempts: 1,
            })
            .map_err(a04_error)?;
        if runtime.admit_next().map_err(a04_error)? != Some(activity_id) {
            return Err(D07Error::A04(
                "new assessment Activity was not admitted".to_owned(),
            ));
        }
        let operation_id = runtime
            .create_operation(
                activity_id,
                OperationSpec {
                    operation_kind: "security.assess".to_owned(),
                    logical_target_refs: vec![target.target_ref.clone()],
                    command_or_action_ref: plan.compiled_plan_ref.clone(),
                    side_effect_class: class.side_effect(),
                    retry_class: RetryClass::NonRetryable,
                    idempotency_class: IdempotencyClass::OperationIdentity,
                    idempotency_key: None,
                    required_authority_refs: vec![authorization.grant_ref.clone()],
                    precondition_refs: authorization.policy_refs.clone(),
                    desired_proof_refs: plan.output_policy_refs.clone(),
                    compensating_operation_ref: None,
                },
            )
            .map_err(a04_error)?;
        runtime
            .make_operation_ready(operation_id)
            .map_err(a04_error)?;
        let attempt_id = runtime
            .create_attempt(operation_id, request.attempt_context)
            .map_err(a04_error)?;
        Ok(AssessmentRunMapping {
            activity_id,
            operation_id,
            attempt_id,
        })
    }
}

pub(crate) fn require_sha256(value: &str) -> Result<(), D07Error> {
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(D07Error::InvalidDigest)
    }
}

fn valid_utc(value: &str) -> bool {
    value.len() == 20 && value.ends_with('Z') && value.as_bytes().get(10) == Some(&b'T')
}

fn digest_json(value: &impl Serialize) -> Result<String, D07Error> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| D07Error::Serialization(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn a04_error(error: impl std::fmt::Display) -> D07Error {
    D07Error::A04(error.to_string())
}

fn id_error(error: impl std::fmt::Display) -> D07Error {
    D07Error::Identifier(error.to_string())
}
