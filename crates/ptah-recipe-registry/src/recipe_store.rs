use crate::D04Error;
use ptah_identifiers::{EntityId, EntityRef, RecordRevision};
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const V010: &str = "0.1.0";
const RECIPE_SCHEMA: &str = "urn:ptah:schema:build:build-recipe:0.1.0";
const REVISION_SCHEMA: &str = "urn:ptah:schema:build:build-recipe-revision:0.1.1";
const PROPOSAL_SCHEMA: &str = "urn:ptah:schema:build:build-recipe-proposal:0.1.0";
const ACCEPTANCE_SCHEMA: &str = "urn:ptah:schema:build:build-recipe-acceptance:0.1.0";
const PLAN_SCHEMA: &str = "urn:ptah:schema:build:compiled-plan:0.1.0";
const ACCEPTANCE_INDEX_KEY: &str = "ptah.d04.acceptance_refs";
const RECIPE_TYPES: &[&str] = &[
    "source_build",
    "container_image_build",
    "test",
    "package_or_installer",
    "document_or_media_render",
    "application_bundle",
    "firmware_transform_or_rebuild",
    "native_platform_build",
    "composed_release",
    "other_registered",
];
const MATERIAL_CLASSES: &[&str] = &[
    "deterministic_bound",
    "mutable_but_snapshotted",
    "volatile_declared",
    "external_service_observed",
    "unresolved_or_unknown",
    "secret_reference",
];
const PROOF_DOMAINS: &[&str] = &[
    "build_execution",
    "output_integrity",
    "export_availability",
    "sbom_inventory",
    "attestation_creation",
    "attestation_policy_verification",
    "signature_verification",
    "functional_test",
    "independent_review",
    "independent_reproduction",
    "release_acceptance",
];

/// Stable logical Recipe metadata supplied by the caller.
#[derive(Debug, Clone)]
pub struct RecipeInput {
    /// Stable namespaced Recipe key.
    pub recipe_key: String,
    /// Human-readable name.
    pub name: String,
    /// Human-readable summary.
    pub summary: String,
    /// Exact authority retained by A03.
    pub authority_ref: EntityRef,
    /// Exact creation timestamp.
    pub created_at: String,
}

/// Frozen WP07 material binding input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterialBindingInput {
    /// Stable binding key.
    pub binding_key: String,
    /// Frozen WP07 material class.
    pub material_class: String,
    /// Exact material subject.
    pub subject_ref: EntityRef,
    /// Exact resolution timestamp.
    pub resolved_at: String,
    /// Supporting evidence.
    pub evidence_refs: Vec<EntityRef>,
}

/// Frozen WP07 proof requirement input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequirementInput {
    /// Frozen proof domain.
    pub proof_domain: String,
    /// Whether proof is required.
    pub required: bool,
    /// Exact Protocol/Policy refs.
    pub protocol_or_policy_refs: Vec<EntityRef>,
}

/// Immutable Recipe step input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeStepInput {
    /// Stable step key.
    pub step_key: String,
    /// Human-readable name.
    pub name: String,
    /// Namespaced step type.
    pub step_type: String,
    /// Dependency step keys.
    pub dependency_step_keys: Vec<String>,
    /// Material binding keys.
    pub input_binding_keys: Vec<String>,
    /// Exact output declarations.
    pub output_declaration_refs: Vec<EntityRef>,
    /// Exact Facility requirements.
    pub facility_requirement_refs: Vec<EntityRef>,
    /// Exact opaque credential requirements.
    pub credential_requirement_refs: Vec<EntityRef>,
    /// Exact service requirements.
    pub service_requirement_refs: Vec<EntityRef>,
    /// Frozen network requirement.
    pub network_requirement: Option<String>,
    /// Frozen cache policy.
    pub cache_policy: Option<String>,
    /// Frozen WP07 side-effect class.
    pub side_effect_class: Option<String>,
    /// Explicit limitations.
    pub limitations: Vec<String>,
}

/// Immutable Recipe Revision payload.
#[derive(Debug, Clone)]
pub struct RecipeRevisionInput {
    /// Strictly monotonic Recipe Revision number.
    pub recipe_revision_number: u64,
    /// Frozen WP07 Recipe type.
    pub recipe_type: String,
    /// Exact content Object Revision.
    pub content_ref: EntityRef,
    /// Exact content digests.
    pub content_digest_refs: Vec<EntityRef>,
    /// Exact Workspace Revision.
    pub workspace_revision_ref: EntityRef,
    /// Exact source Object Revisions.
    pub source_object_revision_refs: Vec<EntityRef>,
    /// Material bindings.
    pub material_bindings: Vec<MaterialBindingInput>,
    /// Ordered immutable steps.
    pub steps: Vec<RecipeStepInput>,
    /// Exact Facility requirements.
    pub facility_requirement_refs: Vec<EntityRef>,
    /// Exact Capability requirements.
    pub capability_requirement_refs: Vec<EntityRef>,
    /// Exact opaque credential requirements.
    pub credential_requirement_refs: Vec<EntityRef>,
    /// Exact service requirements.
    pub service_requirement_refs: Vec<EntityRef>,
    /// Exact output declarations.
    pub output_declaration_refs: Vec<EntityRef>,
    /// Proof requirements.
    pub proof_requirements: Vec<ProofRequirementInput>,
    /// Caller Policy refs.
    pub caller_policy_refs: Vec<EntityRef>,
    /// Exact creator.
    pub created_by_ref: EntityRef,
    /// Exact creation timestamp.
    pub created_at: String,
    /// Explicit limitations.
    pub limitations: Vec<String>,
}

/// Proposal for one exact Recipe Revision.
#[derive(Debug, Clone)]
pub struct RecipeProposalInput {
    /// Exact proposed Recipe Revision.
    pub proposed_recipe_revision_ref: EntityRef,
    /// Frozen proposal source.
    pub proposal_source: String,
    /// Exact proposer.
    pub proposer_ref: EntityRef,
    /// Source evidence.
    pub source_evidence_refs: Vec<EntityRef>,
    /// Bounded zero-to-one confidence.
    pub confidence: f64,
    /// Explicit assumptions.
    pub assumptions: Vec<String>,
    /// Explicit unsupported/unknown scope.
    pub unsupported_or_unknown: Vec<String>,
    /// Exact proposal timestamp.
    pub proposed_at: String,
    /// Explicit limitations.
    pub limitations: Vec<String>,
}

/// Frozen WP07 Acceptance decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceDecision {
    /// Accepted.
    Accepted,
    /// Accepted with retained conditions.
    AcceptedWithConditions,
    /// Rejected.
    Rejected,
    /// Requires a new revision.
    NeedsRevision,
    /// Explicitly expired.
    Expired,
}

impl AcceptanceDecision {
    fn permits_execution(self) -> bool {
        matches!(self, Self::Accepted | Self::AcceptedWithConditions)
    }
    fn text(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::AcceptedWithConditions => "accepted_with_conditions",
            Self::Rejected => "rejected",
            Self::NeedsRevision => "needs_revision",
            Self::Expired => "expired",
        }
    }
}

/// Separate authorized Acceptance over a Proposal/Revision pair.
#[derive(Debug, Clone)]
pub struct RecipeAcceptanceInput {
    /// Exact Recipe Revision.
    pub recipe_revision_ref: EntityRef,
    /// Exact Proposal.
    pub proposal_ref: EntityRef,
    /// Frozen decision.
    pub decision: AcceptanceDecision,
    /// Exact decision maker.
    pub decided_by_ref: EntityRef,
    /// Exact governing Policies.
    pub policy_refs: Vec<EntityRef>,
    /// Exact condition refs.
    pub condition_refs: Vec<EntityRef>,
    /// Supporting evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Optional validity end.
    pub valid_until: Option<String>,
    /// Exact decision timestamp.
    pub decided_at: String,
    /// Optional reason.
    pub reason: Option<String>,
    /// Explicit limitations.
    pub limitations: Vec<String>,
}

/// Recipe-step mapping in one backend-specific Compiled Plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStepMappingInput {
    /// Exact Recipe step key.
    pub recipe_step_key: String,
    /// Backend aliases only.
    pub backend_step_alias_refs: Vec<EntityRef>,
    /// Namespaced operation templates.
    pub operation_templates: Vec<String>,
}

/// One Compiled Plan requirement result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanRequirementResultInput {
    /// Stable requirement key.
    pub requirement_key: String,
    /// Frozen WP07 result.
    pub result: String,
    /// Supporting evidence.
    pub evidence_refs: Vec<EntityRef>,
}

/// Canonical Compiled Plan input.
#[derive(Debug, Clone)]
pub struct CompiledPlanRecordInput {
    /// Exact Recipe Revision.
    pub recipe_revision_ref: EntityRef,
    /// Exact Acceptance.
    pub acceptance_ref: EntityRef,
    /// Exact backend Facility Revision.
    pub backend_facility_revision_ref: EntityRef,
    /// Exact backend Provider Revision.
    pub backend_provider_revision_ref: EntityRef,
    /// Exact compiler/adapter Revision.
    pub compiler_or_adapter_revision_ref: EntityRef,
    /// Exact A07 plan Object Revision.
    pub plan_object_ref: EntityRef,
    /// Exact plan digests.
    pub plan_content_digest_refs: Vec<EntityRef>,
    /// Step mappings.
    pub step_mappings: Vec<PlanStepMappingInput>,
    /// Requirement results.
    pub requirement_results: Vec<PlanRequirementResultInput>,
    /// Exact creation timestamp.
    pub created_at: String,
    /// Explicit limitations.
    pub limitations: Vec<String>,
}

/// Result of creating one stable Recipe plus first immutable Revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedRecipe {
    /// Stable logical Recipe.
    pub recipe_ref: EntityRef,
    /// Exact immutable Revision.
    pub revision_ref: EntityRef,
}

/// Minimal logical Recipe projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeRecordView {
    /// Stable logical Recipe.
    pub recipe_ref: EntityRef,
    /// Exact current immutable Revision.
    pub current_revision_ref: EntityRef,
    /// Ordered retained Revisions.
    pub revision_refs: Vec<EntityRef>,
}

/// Exact accepted Revision plus its separate Acceptance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRevision {
    /// Exact Recipe Revision.
    pub recipe_revision_ref: EntityRef,
    /// Exact Acceptance.
    pub acceptance_ref: EntityRef,
}

/// A03-backed canonical WP07 Recipe persistence facade.
pub struct RecipeStore {
    ledger: Ledger,
}

impl RecipeStore {
    /// Open or create the canonical A03 ledger.
    ///
    /// # Errors
    /// Returns an error when A03 cannot open or migrate the ledger.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, D04Error> {
        Ok(Self {
            ledger: Ledger::open(path).map_err(ledger_error)?,
        })
    }

    /// Atomically create one stable Recipe and its first immutable Revision.
    ///
    /// # Errors
    /// Returns an error for invalid input or A03 persistence failure.
    pub fn create_recipe_with_revision(
        &mut self,
        recipe: &RecipeInput,
        revision: &RecipeRevisionInput,
    ) -> Result<CreatedRecipe, D04Error> {
        if revision.recipe_revision_number != 1 {
            return Err(D04Error::RecipeRevisionConflict {
                expected: 1,
                actual: revision.recipe_revision_number,
            });
        }
        validate_recipe_key(&recipe.recipe_key)?;
        validate_revision(revision)?;
        let recipe_ref = EntityRef::new("build.recipe").map_err(identifier_error)?;
        let revision_ref = exact_ref("build.recipe_revision", 1)?;
        let revision_record = make_revision_record(
            &recipe_ref,
            &revision_ref,
            None,
            &recipe.authority_ref,
            revision,
        )?;
        let recipe_record = canonical(json!({
            "envelope": envelope(&recipe_ref, RECIPE_SCHEMA, V010, 1, &recipe.authority_ref),
            "lifecycle": lifecycle("build.recipe.lifecycle", "active", 1, &recipe.created_at),
            "recipe_key": recipe.recipe_key,
            "name": recipe.name,
            "summary": recipe.summary,
            "current_revision_ref": revision_ref,
            "revision_refs": [revision_ref],
            "limitations": [],
            "extensions": {},
        }))?;
        let write = self.ledger.begin_write().map_err(ledger_error)?;
        write.insert(&revision_record).map_err(ledger_error)?;
        write.insert(&recipe_record).map_err(ledger_error)?;
        write.commit().map_err(ledger_error)?;
        Ok(CreatedRecipe {
            recipe_ref,
            revision_ref,
        })
    }

    /// Add one immutable Revision and advance the stable Recipe projection.
    ///
    /// # Errors
    /// Returns an error for missing Recipe, non-monotonic numbering, invalid
    /// Revision shape, or A03 failure.
    pub fn add_revision(
        &mut self,
        recipe_ref: &EntityRef,
        revision: &RecipeRevisionInput,
    ) -> Result<EntityRef, D04Error> {
        validate_revision(revision)?;
        let current = self
            .ledger
            .latest_record(recipe_ref.entity_id)
            .map_err(ledger_error)?
            .ok_or_else(|| D04Error::RecipeNotFound {
                recipe_id: recipe_ref.entity_id.to_string(),
            })?;
        require_kind(&current, "build.recipe")?;
        let current_revision_ref = entity_ref_field(current.document(), "current_revision_ref")?;
        let current_revision = self.require_revision(&current_revision_ref)?;
        let current_number = u64_field(current_revision.document(), "recipe_revision_number")?;
        let expected = current_number
            .checked_add(1)
            .ok_or_else(|| invalid_recipe("recipe revision overflow"))?;
        if revision.recipe_revision_number != expected {
            return Err(D04Error::RecipeRevisionConflict {
                expected,
                actual: revision.recipe_revision_number,
            });
        }
        let new_revision_ref = exact_ref("build.recipe_revision", 1)?;
        let revision_record = make_revision_record(
            recipe_ref,
            &new_revision_ref,
            Some(current_revision_ref),
            current.authority_ref(),
            revision,
        )?;
        let mut updated = current.document().clone();
        let next_record_revision = current
            .record_revision()
            .value()
            .checked_add(1)
            .ok_or_else(|| invalid_recipe("record revision overflow"))?;
        set_envelope_revision(&mut updated, next_record_revision)?;
        set_field(
            &mut updated,
            "current_revision_ref",
            json!(new_revision_ref),
        )?;
        let mut refs = entity_ref_array(&updated, "revision_refs")?;
        refs.push(new_revision_ref.clone());
        set_field(&mut updated, "revision_refs", json!(refs))?;
        let updated_record = canonical(updated)?;
        let write = self.ledger.begin_write().map_err(ledger_error)?;
        write.insert(&revision_record).map_err(ledger_error)?;
        write.insert(&updated_record).map_err(ledger_error)?;
        write.commit().map_err(ledger_error)?;
        Ok(new_revision_ref)
    }

    /// Read the latest stable Recipe projection.
    ///
    /// # Errors
    /// Returns an error for malformed retained state or A03 failure.
    pub fn recipe(&self, recipe_id: EntityId) -> Result<Option<RecipeRecordView>, D04Error> {
        let Some(record) = self.ledger.latest_record(recipe_id).map_err(ledger_error)? else {
            return Ok(None);
        };
        require_kind(&record, "build.recipe")?;
        Ok(Some(RecipeRecordView {
            recipe_ref: EntityRef::from_id(record.entity_id(), "build.recipe")
                .map_err(identifier_error)?,
            current_revision_ref: entity_ref_field(record.document(), "current_revision_ref")?,
            revision_refs: entity_ref_array(record.document(), "revision_refs")?,
        }))
    }

    /// Persist one separate Proposal for an exact Recipe Revision.
    ///
    /// # Errors
    /// Returns an error for invalid proposal input/binding or A03 failure.
    pub fn propose(&mut self, proposal: &RecipeProposalInput) -> Result<EntityRef, D04Error> {
        if !proposal.confidence.is_finite() || !(0.0..=1.0).contains(&proposal.confidence) {
            return Err(invalid_recipe("proposal confidence"));
        }
        self.require_revision(&proposal.proposed_recipe_revision_ref)?;
        let proposal_ref = exact_ref("build.recipe_proposal", 1)?;
        let record = canonical(json!({
            "envelope": envelope(&proposal_ref, PROPOSAL_SCHEMA, V010, 1, &proposal.proposer_ref),
            "proposed_recipe_revision_ref": proposal.proposed_recipe_revision_ref,
            "proposal_source": proposal.proposal_source,
            "proposer_ref": proposal.proposer_ref,
            "source_evidence_refs": proposal.source_evidence_refs,
            "confidence": proposal.confidence,
            "assumptions": proposal.assumptions,
            "unsupported_or_unknown": proposal.unsupported_or_unknown,
            "proposed_at": proposal.proposed_at,
            "limitations": proposal.limitations,
            "extensions": {},
        }))?;
        self.insert_one(&record)?;
        Ok(proposal_ref)
    }

    /// Persist one separate Acceptance and index its reference on the Recipe.
    ///
    /// # Errors
    /// Returns an error if Proposal/Revision identity disagrees or A03 fails.
    pub fn accept(&mut self, acceptance: &RecipeAcceptanceInput) -> Result<EntityRef, D04Error> {
        let revision = self.require_revision(&acceptance.recipe_revision_ref)?;
        let proposal = self
            .ledger
            .latest_record(acceptance.proposal_ref.entity_id)
            .map_err(ledger_error)?
            .ok_or(D04Error::AcceptanceBindingMismatch)?;
        require_kind(&proposal, "build.recipe_proposal")?;
        if entity_ref_field(proposal.document(), "proposed_recipe_revision_ref")?
            != acceptance.recipe_revision_ref
        {
            return Err(D04Error::AcceptanceBindingMismatch);
        }
        let recipe_ref = entity_ref_field(revision.document(), "recipe_ref")?;
        let recipe = self
            .ledger
            .latest_record(recipe_ref.entity_id)
            .map_err(ledger_error)?
            .ok_or_else(|| D04Error::RecipeNotFound {
                recipe_id: recipe_ref.entity_id.to_string(),
            })?;
        require_kind(&recipe, "build.recipe")?;
        let acceptance_ref = exact_ref("build.recipe_acceptance", 1)?;
        let mut document = json!({
            "envelope": envelope(&acceptance_ref, ACCEPTANCE_SCHEMA, V010, 1, &acceptance.decided_by_ref),
            "recipe_revision_ref": acceptance.recipe_revision_ref,
            "proposal_ref": acceptance.proposal_ref,
            "decision": acceptance.decision,
            "decided_by_ref": acceptance.decided_by_ref,
            "policy_refs": acceptance.policy_refs,
            "condition_refs": acceptance.condition_refs,
            "evidence_refs": acceptance.evidence_refs,
            "valid_until": acceptance.valid_until,
            "decided_at": acceptance.decided_at,
            "reason": acceptance.reason,
            "limitations": acceptance.limitations,
            "extensions": {},
        });
        strip_null_fields(&mut document);
        let acceptance_record = canonical(document)?;
        let mut updated = recipe.document().clone();
        let mut refs = acceptance_refs(&updated)?;
        refs.push(acceptance_ref.clone());
        set_acceptance_refs(&mut updated, &refs)?;
        set_envelope_revision(&mut updated, recipe.record_revision().value() + 1)?;
        let updated_recipe = canonical(updated)?;
        let write = self.ledger.begin_write().map_err(ledger_error)?;
        write.insert(&acceptance_record).map_err(ledger_error)?;
        write.insert(&updated_recipe).map_err(ledger_error)?;
        write.commit().map_err(ledger_error)?;
        Ok(acceptance_ref)
    }

    /// Resolve the latest separate Acceptance for an exact Recipe Revision.
    ///
    /// # Errors
    /// Returns an error when Acceptance is absent, blocks execution, expired,
    /// malformed, or inaccessible through A03.
    pub fn accepted_revision_at(
        &self,
        recipe_revision_ref: &EntityRef,
        observed_at: &str,
    ) -> Result<AcceptedRevision, D04Error> {
        let revision = self.require_revision(recipe_revision_ref)?;
        let recipe_ref = entity_ref_field(revision.document(), "recipe_ref")?;
        let recipe = self
            .ledger
            .latest_record(recipe_ref.entity_id)
            .map_err(ledger_error)?
            .ok_or_else(|| D04Error::RecipeNotFound {
                recipe_id: recipe_ref.entity_id.to_string(),
            })?;
        require_kind(&recipe, "build.recipe")?;
        for acceptance_ref in acceptance_refs(recipe.document())?.iter().rev() {
            let Some(record) = self
                .ledger
                .latest_record(acceptance_ref.entity_id)
                .map_err(ledger_error)?
            else {
                continue;
            };
            require_kind(&record, "build.recipe_acceptance")?;
            if entity_ref_field(record.document(), "recipe_revision_ref")? != *recipe_revision_ref {
                continue;
            }
            let decision = acceptance_decision(record.document())?;
            if !decision.permits_execution() {
                return Err(D04Error::AcceptanceRejected {
                    decision: decision.text().to_owned(),
                });
            }
            if let Some(valid_until) = string_option(record.document(), "valid_until")?
                && observed_at > valid_until.as_str()
            {
                return Err(D04Error::AcceptanceExpired { valid_until });
            }
            return Ok(AcceptedRevision {
                recipe_revision_ref: recipe_revision_ref.clone(),
                acceptance_ref: acceptance_ref.clone(),
            });
        }
        Err(D04Error::AcceptanceMissing {
            recipe_revision_id: recipe_revision_ref.entity_id.to_string(),
        })
    }

    /// Persist one backend-specific Compiled Plan after exact binding checks.
    ///
    /// # Errors
    /// Returns an error if Revision/Acceptance binding is invalid or A03 fails.
    pub fn record_compiled_plan(
        &mut self,
        plan: &CompiledPlanRecordInput,
    ) -> Result<EntityRef, D04Error> {
        self.require_revision(&plan.recipe_revision_ref)?;
        let acceptance = self
            .ledger
            .latest_record(plan.acceptance_ref.entity_id)
            .map_err(ledger_error)?
            .ok_or(D04Error::PlanBindingMismatch)?;
        require_kind(&acceptance, "build.recipe_acceptance")?;
        if entity_ref_field(acceptance.document(), "recipe_revision_ref")?
            != plan.recipe_revision_ref
            || !acceptance_decision(acceptance.document())?.permits_execution()
        {
            return Err(D04Error::PlanBindingMismatch);
        }
        let plan_ref = exact_ref("build.compiled_plan", 1)?;
        let record = canonical(json!({
            "envelope": envelope(&plan_ref, PLAN_SCHEMA, V010, 1, acceptance.authority_ref()),
            "recipe_revision_ref": plan.recipe_revision_ref,
            "acceptance_ref": plan.acceptance_ref,
            "backend_facility_revision_ref": plan.backend_facility_revision_ref,
            "backend_provider_revision_ref": plan.backend_provider_revision_ref,
            "compiler_or_adapter_revision_ref": plan.compiler_or_adapter_revision_ref,
            "plan_object_ref": plan.plan_object_ref,
            "plan_content_digest_refs": plan.plan_content_digest_refs,
            "step_mappings": plan.step_mappings,
            "requirement_results": plan.requirement_results,
            "created_at": plan.created_at,
            "limitations": plan.limitations,
            "extensions": {},
        }))?;
        self.insert_one(&record)?;
        Ok(plan_ref)
    }

    fn require_revision(&self, revision_ref: &EntityRef) -> Result<CanonicalRecord, D04Error> {
        let record = self
            .ledger
            .latest_record(revision_ref.entity_id)
            .map_err(ledger_error)?
            .ok_or_else(|| invalid_stored("recipe_revision_ref"))?;
        require_kind(&record, "build.recipe_revision")?;
        Ok(record)
    }

    fn insert_one(&mut self, record: &CanonicalRecord) -> Result<(), D04Error> {
        let write = self.ledger.begin_write().map_err(ledger_error)?;
        write.insert(record).map_err(ledger_error)?;
        write.commit().map_err(ledger_error)
    }
}

fn make_revision_record(
    recipe_ref: &EntityRef,
    revision_ref: &EntityRef,
    parent_ref: Option<EntityRef>,
    authority_ref: &EntityRef,
    revision: &RecipeRevisionInput,
) -> Result<CanonicalRecord, D04Error> {
    canonical(json!({
        "envelope": envelope(revision_ref, REVISION_SCHEMA, "0.1.1", 1, authority_ref),
        "recipe_ref": recipe_ref,
        "recipe_revision_id": revision_ref.entity_id,
        "recipe_revision_number": revision.recipe_revision_number,
        "parent_revision_refs": parent_ref.into_iter().collect::<Vec<_>>(),
        "recipe_type": revision.recipe_type,
        "content_ref": revision.content_ref,
        "content_digest_refs": revision.content_digest_refs,
        "workspace_revision_ref": revision.workspace_revision_ref,
        "source_object_revision_refs": revision.source_object_revision_refs,
        "material_bindings": revision.material_bindings,
        "steps": revision.steps,
        "facility_requirement_refs": revision.facility_requirement_refs,
        "capability_requirement_refs": revision.capability_requirement_refs,
        "credential_requirement_refs": revision.credential_requirement_refs,
        "service_requirement_refs": revision.service_requirement_refs,
        "output_declaration_refs": revision.output_declaration_refs,
        "proof_requirements": revision.proof_requirements,
        "caller_policy_refs": revision.caller_policy_refs,
        "created_by_ref": revision.created_by_ref,
        "created_at": revision.created_at,
        "limitations": revision.limitations,
        "extensions": {},
    }))
}

fn validate_revision(revision: &RecipeRevisionInput) -> Result<(), D04Error> {
    if revision.recipe_revision_number == 0 || revision.steps.is_empty() {
        return Err(invalid_recipe("recipe revision number/steps"));
    }
    if !RECIPE_TYPES.contains(&revision.recipe_type.as_str()) {
        return Err(invalid_recipe("recipe_type"));
    }
    if revision
        .material_bindings
        .iter()
        .any(|v| !MATERIAL_CLASSES.contains(&v.material_class.as_str()))
    {
        return Err(invalid_recipe("material_class"));
    }
    if revision
        .proof_requirements
        .iter()
        .any(|v| !PROOF_DOMAINS.contains(&v.proof_domain.as_str()))
    {
        return Err(invalid_recipe("proof_domain"));
    }
    let bindings: BTreeSet<_> = revision
        .material_bindings
        .iter()
        .map(|v| v.binding_key.as_str())
        .collect();
    if bindings.len() != revision.material_bindings.len() {
        return Err(invalid_recipe("duplicate material binding"));
    }
    let step_keys: BTreeSet<_> = revision.steps.iter().map(|v| v.step_key.as_str()).collect();
    if step_keys.len() != revision.steps.len() {
        return Err(invalid_recipe("duplicate step key"));
    }
    for step in &revision.steps {
        if step
            .input_binding_keys
            .iter()
            .any(|v| !bindings.contains(v.as_str()))
            || step
                .dependency_step_keys
                .iter()
                .any(|v| !step_keys.contains(v.as_str()) || v == &step.step_key)
        {
            return Err(invalid_recipe("step dependency or material binding"));
        }
    }
    validate_acyclic(&revision.steps)
}

fn validate_acyclic(steps: &[RecipeStepInput]) -> Result<(), D04Error> {
    let graph: BTreeMap<_, _> = steps
        .iter()
        .map(|v| (v.step_key.as_str(), v.dependency_step_keys.as_slice()))
        .collect();
    let mut active = BTreeSet::new();
    let mut done = BTreeSet::new();
    for key in graph.keys() {
        if !visit_step(key, &graph, &mut active, &mut done) {
            return Err(invalid_recipe("cyclic step graph"));
        }
    }
    Ok(())
}

fn validate_recipe_key(value: &str) -> Result<(), D04Error> {
    let valid = value.contains('.')
        && value.chars().next().is_some_and(|v| v.is_ascii_lowercase())
        && value
            .chars()
            .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || matches!(v, '.' | '_' | '-'));
    if valid {
        Ok(())
    } else {
        Err(invalid_recipe("recipe_key"))
    }
}

fn exact_ref(kind: &str, revision: u64) -> Result<EntityRef, D04Error> {
    let mut value = EntityRef::new(kind).map_err(identifier_error)?;
    value.record_revision = Some(RecordRevision::new(revision).map_err(identifier_error)?);
    Ok(value)
}

fn envelope(
    entity_ref: &EntityRef,
    schema_id: &str,
    schema_version: &str,
    revision: u64,
    authority_ref: &EntityRef,
) -> Value {
    json!({
        "entity_id": entity_ref.entity_id,
        "entity_kind": entity_ref.entity_kind,
        "schema_id": schema_id,
        "schema_version": schema_version,
        "record_revision": revision,
        "authority_ref": authority_ref,
    })
}

fn lifecycle(machine: &str, state: &str, sequence: u64, entered_at: &str) -> Value {
    json!({
        "state_machine_name": machine,
        "state_machine_version": V010,
        "current_state": state,
        "state_sequence": sequence,
        "entered_at": entered_at,
        "transition_receipt_refs": [],
    })
}

fn canonical(document: Value) -> Result<CanonicalRecord, D04Error> {
    CanonicalRecord::from_document(document).map_err(ledger_error)
}

fn require_kind(record: &CanonicalRecord, expected: &str) -> Result<(), D04Error> {
    let actual = record.entity_kind().as_str();
    if actual == expected {
        Ok(())
    } else {
        Err(D04Error::RecordKindMismatch {
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        })
    }
}

fn entity_ref_field(document: &Value, field: &str) -> Result<EntityRef, D04Error> {
    serde_json::from_value(
        document
            .get(field)
            .cloned()
            .ok_or_else(|| invalid_stored(field))?,
    )
    .map_err(|_| invalid_stored(field))
}

fn entity_ref_array(document: &Value, field: &str) -> Result<Vec<EntityRef>, D04Error> {
    serde_json::from_value(
        document
            .get(field)
            .cloned()
            .ok_or_else(|| invalid_stored(field))?,
    )
    .map_err(|_| invalid_stored(field))
}

fn u64_field(document: &Value, field: &str) -> Result<u64, D04Error> {
    document
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_stored(field))
}

fn string_option(document: &Value, field: &str) -> Result<Option<String>, D04Error> {
    match document.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(v)) => Ok(Some(v.clone())),
        Some(_) => Err(invalid_stored(field)),
    }
}

fn acceptance_decision(document: &Value) -> Result<AcceptanceDecision, D04Error> {
    serde_json::from_value(
        document
            .get("decision")
            .cloned()
            .ok_or_else(|| invalid_stored("decision"))?,
    )
    .map_err(|_| invalid_stored("decision"))
}

fn acceptance_refs(document: &Value) -> Result<Vec<EntityRef>, D04Error> {
    let Some(entry) = document
        .get("extensions")
        .and_then(|v| v.get(ACCEPTANCE_INDEX_KEY))
    else {
        return Ok(Vec::new());
    };
    serde_json::from_value(
        entry
            .get("value")
            .cloned()
            .ok_or_else(|| invalid_stored("acceptance index"))?,
    )
    .map_err(|_| invalid_stored("acceptance index"))
}

fn set_acceptance_refs(document: &mut Value, refs: &[EntityRef]) -> Result<(), D04Error> {
    let extensions = document
        .get_mut("extensions")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid_stored("extensions"))?;
    extensions.insert(
        ACCEPTANCE_INDEX_KEY.to_owned(),
        json!({
            "schema_id": "urn:ptah:extension:d04:acceptance-refs:0.1.0",
            "schema_version": V010,
            "value": refs,
        }),
    );
    Ok(())
}

fn set_envelope_revision(document: &mut Value, revision: u64) -> Result<(), D04Error> {
    document
        .get_mut("envelope")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid_stored("envelope"))?
        .insert("record_revision".to_owned(), json!(revision));
    Ok(())
}

fn set_field(document: &mut Value, field: &str, value: Value) -> Result<(), D04Error> {
    document
        .as_object_mut()
        .ok_or_else(|| invalid_stored("document"))?
        .insert(field.to_owned(), value);
    Ok(())
}

fn strip_null_fields(document: &mut Value) {
    if let Some(object) = document.as_object_mut() {
        object.retain(|_, value| !value.is_null());
    }
}

fn invalid_recipe(value: &str) -> D04Error {
    D04Error::InvalidRecipe(value.to_owned())
}
fn invalid_stored(value: &str) -> D04Error {
    D04Error::InvalidStoredRecord(value.to_owned())
}
fn ledger_error(error: impl std::fmt::Display) -> D04Error {
    D04Error::Ledger(error.to_string())
}
fn identifier_error(error: impl std::fmt::Display) -> D04Error {
    invalid_recipe(&error.to_string())
}

fn visit_step<'a>(
    node: &'a str,
    graph: &BTreeMap<&'a str, &'a [String]>,
    active: &mut BTreeSet<&'a str>,
    done: &mut BTreeSet<&'a str>,
) -> bool {
    if done.contains(node) {
        return true;
    }
    if !active.insert(node) {
        return false;
    }
    if let Some(deps) = graph.get(node) {
        for dep in *deps {
            if !visit_step(dep.as_str(), graph, active, done) {
                return false;
            }
        }
    }
    active.remove(node);
    done.insert(node);
    true
}
