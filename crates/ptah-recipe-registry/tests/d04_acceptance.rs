#![allow(missing_docs)]
use ptah_activity_runtime::{IdempotencyClass, RetryClass, SideEffectClass};
use ptah_identifiers::EntityRef;
use ptah_recipe_registry::{
    AcceptanceDecision, CompiledPlanRecordInput, D04Error, MaterialBindingInput, OperationCatalog,
    OperationDescriptorRevision, OperationEffectClass, PlanRequirementResultInput,
    PlanStepMappingInput, ProofRequirementInput, RecipeAcceptanceInput, RecipeInput,
    RecipeProposalInput, RecipeRevisionInput, RecipeStepInput, RecipeStore,
};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid reference")
}

fn descriptor(key: &str, provider_generation: u64) -> OperationDescriptorRevision {
    OperationDescriptorRevision {
        operation_key: key.to_owned(),
        descriptor_version: "1.0.0".to_owned(),
        facility_revision_ref: reference("runtime.facility_revision"),
        provider_revision_ref: reference("runtime.provider_revision"),
        provider_instance_ref: Some(reference("runtime.provider_instance")),
        provider_generation: Some(provider_generation),
        freshness_token: Some(format!("generation-{provider_generation}")),
        capability_refs: vec![reference("core.capability")],
        input_schema_refs: Vec::new(),
        output_schema_refs: Vec::new(),
        effect: OperationEffectClass::Observe,
        a04_side_effect: SideEffectClass::ObservationOnly,
        retry_class: RetryClass::RetrySafe,
        idempotency_class: IdempotencyClass::NoneRequired,
        required_grant_refs: Vec::new(),
        caller_approval_required: false,
        materialization_required: false,
        supported_preconditions: Vec::new(),
        expected_receipt_states: vec!["operation_completed".to_owned()],
        limits: Vec::new(),
    }
}

#[test]
fn exposes_exact_adr0037_effect_vocabulary() {
    assert_eq!(OperationEffectClass::ALL.len(), 7);
    assert_eq!(
        serde_json::to_value(OperationEffectClass::ALL).expect("serialize"),
        serde_json::json!([
            "observe",
            "draft",
            "simulate",
            "mutate",
            "publish",
            "destructive",
            "external_side_effect"
        ])
    );
}

#[test]
fn incompatible_effect_and_a04_side_effect_fails_closed() {
    let mut value = descriptor("workspace.delete", 4);
    value.effect = OperationEffectClass::Destructive;
    value.a04_side_effect = SideEffectClass::ObservationOnly;
    assert!(matches!(
        value.validate(),
        Err(D04Error::EffectCompatibility { .. })
    ));
}

#[test]
fn descriptor_digest_is_deterministic_and_revision_bound() {
    let first = descriptor("source.search", 2);
    let same = first.clone();
    let mut changed_generation = first.clone();
    changed_generation.provider_generation = Some(3);
    changed_generation.freshness_token = Some("generation-3".to_owned());
    assert_eq!(
        first.digest().expect("digest"),
        same.digest().expect("digest")
    );
    assert_ne!(
        first.digest().expect("digest"),
        changed_generation.digest().expect("digest")
    );
}

#[test]
fn catalog_retains_ambiguity_instead_of_selecting_provider() {
    let mut catalog = OperationCatalog::default();
    catalog
        .register(descriptor("source.search", 2))
        .expect("first");
    catalog
        .register(descriptor("source.search", 3))
        .expect("second");
    let result = catalog
        .resolve("source.search", None, None)
        .expect("lookup");
    assert!(result.is_ambiguous());
    assert_eq!(result.candidates().len(), 2);
}

fn ledger_path(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "ptah-d04-{label}-{}-{}.sqlite",
        std::process::id(),
        ptah_identifiers::EntityId::new_v7()
    ))
}

fn revision_input(number: u64) -> RecipeRevisionInput {
    RecipeRevisionInput {
        recipe_revision_number: number,
        recipe_type: "test".to_owned(),
        content_ref: reference("core.object_revision"),
        content_digest_refs: vec![reference("core.content")],
        workspace_revision_ref: reference("workspace.revision"),
        source_object_revision_refs: vec![reference("core.object_revision")],
        material_bindings: vec![MaterialBindingInput {
            binding_key: "source".to_owned(),
            material_class: "deterministic_bound".to_owned(),
            subject_ref: reference("core.object_revision"),
            resolved_at: "2026-09-02T12:00:00Z".to_owned(),
            evidence_refs: vec![reference("security.evidence_item")],
        }],
        steps: vec![RecipeStepInput {
            step_key: "inspect".to_owned(),
            name: "Inspect source".to_owned(),
            step_type: "test.inspect".to_owned(),
            dependency_step_keys: Vec::new(),
            input_binding_keys: vec!["source".to_owned()],
            output_declaration_refs: vec![reference("build.output_declaration")],
            facility_requirement_refs: vec![reference("runtime.facility_revision")],
            credential_requirement_refs: Vec::new(),
            service_requirement_refs: Vec::new(),
            network_requirement: Some("none".to_owned()),
            cache_policy: Some("disabled".to_owned()),
            side_effect_class: Some("read_only".to_owned()),
            limitations: Vec::new(),
        }],
        facility_requirement_refs: vec![reference("runtime.facility_revision")],
        capability_requirement_refs: vec![reference("core.capability")],
        credential_requirement_refs: Vec::new(),
        service_requirement_refs: Vec::new(),
        output_declaration_refs: vec![reference("build.output_declaration")],
        proof_requirements: vec![ProofRequirementInput {
            proof_domain: "functional_test".to_owned(),
            required: true,
            protocol_or_policy_refs: vec![reference("core.policy")],
        }],
        caller_policy_refs: vec![reference("core.policy")],
        created_by_ref: reference("core.actor"),
        created_at: "2026-09-02T12:00:00Z".to_owned(),
        limitations: Vec::new(),
    }
}

fn create_recipe_revision_and_proposal(
    store: &mut RecipeStore,
    key: &str,
) -> (EntityRef, EntityRef, EntityRef) {
    let created = store
        .create_recipe_with_revision(
            &RecipeInput {
                recipe_key: key.to_owned(),
                name: format!("Recipe {key}"),
                summary: "D04 acceptance recipe".to_owned(),
                authority_ref: reference("core.actor"),
                created_at: "2026-09-02T12:00:00Z".to_owned(),
            },
            &revision_input(1),
        )
        .expect("create recipe");
    let proposal = store
        .propose(&RecipeProposalInput {
            proposed_recipe_revision_ref: created.revision_ref.clone(),
            proposal_source: "human".to_owned(),
            proposer_ref: reference("core.actor"),
            source_evidence_refs: vec![reference("security.evidence_item")],
            confidence: 1.0,
            assumptions: Vec::new(),
            unsupported_or_unknown: Vec::new(),
            proposed_at: "2026-09-02T12:01:00Z".to_owned(),
            limitations: Vec::new(),
        })
        .expect("proposal");
    (created.recipe_ref, created.revision_ref, proposal)
}

#[test]
fn recipe_identity_and_revision_survive_ledger_reopen() {
    let path = ledger_path("restart");
    let (recipe_ref, revision_ref) = {
        let mut store = RecipeStore::open(&path).expect("open");
        let (recipe, revision, _) = create_recipe_revision_and_proposal(&mut store, "d04.restart");
        (recipe, revision)
    };
    let store = RecipeStore::open(&path).expect("reopen");
    let recovered = store
        .recipe(recipe_ref.entity_id)
        .expect("read")
        .expect("recipe");
    assert_eq!(recovered.recipe_ref, recipe_ref);
    assert_eq!(recovered.current_revision_ref, revision_ref);
    let _ = std::fs::remove_file(path);
}

#[test]
fn recipe_revision_is_immutable_and_monotonic() {
    let path = ledger_path("revision");
    let mut store = RecipeStore::open(&path).expect("open");
    let (recipe_ref, first, _) = create_recipe_revision_and_proposal(&mut store, "d04.revision");
    let second = store
        .add_revision(&recipe_ref, &revision_input(2))
        .expect("second revision");
    assert_ne!(first.entity_id, second.entity_id);
    assert!(matches!(
        store.add_revision(&recipe_ref, &revision_input(2)),
        Err(D04Error::RecipeRevisionConflict { .. })
    ));
    let _ = std::fs::remove_file(path);
}

#[test]
fn proposal_does_not_imply_acceptance() {
    let path = ledger_path("proposal");
    let mut store = RecipeStore::open(&path).expect("open");
    let (_, revision_ref, _) = create_recipe_revision_and_proposal(&mut store, "d04.proposal");
    assert!(matches!(
        store.accepted_revision_at(&revision_ref, "2026-09-02T12:02:00Z"),
        Err(D04Error::AcceptanceMissing { .. })
    ));
    let _ = std::fs::remove_file(path);
}

#[test]
fn acceptance_must_bind_exact_proposal_and_recipe_revision() {
    let path = ledger_path("accept-binding");
    let mut store = RecipeStore::open(&path).expect("open");
    let (_, left_revision, _) = create_recipe_revision_and_proposal(&mut store, "d04.left");
    let (_, _, right_proposal) = create_recipe_revision_and_proposal(&mut store, "d04.right");
    let result = store.accept(&RecipeAcceptanceInput {
        recipe_revision_ref: left_revision,
        proposal_ref: right_proposal,
        decision: AcceptanceDecision::Accepted,
        decided_by_ref: reference("core.actor"),
        policy_refs: vec![reference("core.policy")],
        condition_refs: Vec::new(),
        evidence_refs: vec![reference("security.evidence_item")],
        valid_until: None,
        decided_at: "2026-09-02T12:03:00Z".to_owned(),
        reason: Some("caller decision".to_owned()),
        limitations: Vec::new(),
    });
    assert!(matches!(result, Err(D04Error::AcceptanceBindingMismatch)));
    let _ = std::fs::remove_file(path);
}

fn accept_revision(
    store: &mut RecipeStore,
    revision_ref: EntityRef,
    proposal_ref: EntityRef,
    decision: AcceptanceDecision,
    valid_until: Option<&str>,
) -> EntityRef {
    store
        .accept(&RecipeAcceptanceInput {
            recipe_revision_ref: revision_ref,
            proposal_ref,
            decision,
            decided_by_ref: reference("core.actor"),
            policy_refs: vec![reference("core.policy")],
            condition_refs: Vec::new(),
            evidence_refs: vec![reference("security.evidence_item")],
            valid_until: valid_until.map(str::to_owned),
            decided_at: "2026-09-02T12:03:00Z".to_owned(),
            reason: Some("caller decision".to_owned()),
            limitations: Vec::new(),
        })
        .expect("acceptance record")
}

#[test]
fn rejected_and_expired_acceptance_block_planning() {
    let path = ledger_path("accept-state");
    let mut store = RecipeStore::open(&path).expect("open");
    let (_, rejected_revision, rejected_proposal) =
        create_recipe_revision_and_proposal(&mut store, "d04.rejected");
    accept_revision(
        &mut store,
        rejected_revision.clone(),
        rejected_proposal,
        AcceptanceDecision::Rejected,
        None,
    );
    assert!(matches!(
        store.accepted_revision_at(&rejected_revision, "2026-09-02T12:04:00Z"),
        Err(D04Error::AcceptanceRejected { .. })
    ));

    let (_, expired_revision, expired_proposal) =
        create_recipe_revision_and_proposal(&mut store, "d04.expired");
    accept_revision(
        &mut store,
        expired_revision.clone(),
        expired_proposal,
        AcceptanceDecision::Accepted,
        Some("2026-09-02T12:03:30Z"),
    );
    assert!(matches!(
        store.accepted_revision_at(&expired_revision, "2026-09-02T12:04:00Z"),
        Err(D04Error::AcceptanceExpired { .. })
    ));
    let _ = std::fs::remove_file(path);
}

#[test]
fn backend_replacement_creates_distinct_plan_without_changing_recipe_identity() {
    let path = ledger_path("plans");
    let mut store = RecipeStore::open(&path).expect("open");
    let (recipe_ref, revision_ref, proposal_ref) =
        create_recipe_revision_and_proposal(&mut store, "d04.plans");
    let acceptance_ref = accept_revision(
        &mut store,
        revision_ref.clone(),
        proposal_ref,
        AcceptanceDecision::Accepted,
        None,
    );
    let plan_input = |provider: EntityRef| CompiledPlanRecordInput {
        recipe_revision_ref: revision_ref.clone(),
        acceptance_ref: acceptance_ref.clone(),
        backend_facility_revision_ref: reference("runtime.facility_revision"),
        backend_provider_revision_ref: provider,
        compiler_or_adapter_revision_ref: reference("runtime.provider_revision"),
        plan_object_ref: reference("core.object_revision"),
        plan_content_digest_refs: vec![reference("core.content")],
        step_mappings: vec![PlanStepMappingInput {
            recipe_step_key: "inspect".to_owned(),
            backend_step_alias_refs: Vec::new(),
            operation_templates: vec!["test.inspect".to_owned()],
        }],
        requirement_results: vec![PlanRequirementResultInput {
            requirement_key: "provider.compatibility".to_owned(),
            result: "satisfied".to_owned(),
            evidence_refs: vec![reference("security.evidence_item")],
        }],
        created_at: "2026-09-02T12:04:00Z".to_owned(),
        limitations: Vec::new(),
    };
    let first = store
        .record_compiled_plan(&plan_input(reference("runtime.provider_revision")))
        .expect("first plan");
    let second = store
        .record_compiled_plan(&plan_input(reference("runtime.provider_revision")))
        .expect("replacement plan");
    assert_ne!(first.entity_id, second.entity_id);
    let recipe = store.recipe(recipe_ref.entity_id).unwrap().unwrap();
    assert_eq!(recipe.recipe_ref, recipe_ref);
    assert_eq!(recipe.current_revision_ref, revision_ref);
    let _ = std::fs::remove_file(path);
}
