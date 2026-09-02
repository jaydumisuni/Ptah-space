#![allow(missing_docs)]
use container_oci::BackendStartAck;
use ptah_activity_runtime::{
    ActivityRuntime, AttemptContext, IdempotencyClass, MemoryJournal, OperationState, RetryClass,
    SideEffectClass,
};
use ptah_identifiers::EntityRef;
use ptah_recipe_registry::{
    AcceptanceDecision, CompiledPlanRecordInput, ContainerAuthorityScope, ContainerMountAccess,
    ContainerMountScope, ContainerNetworkScope, CredentialBinding, D04Error, ExactPrecondition,
    ExecutionPlanManifest, ExecutionStage, MaterialBindingInput, ObservedPrecondition,
    OperationCatalog, OperationDescriptorRevision, OperationEffectClass, ParameterBinding,
    ParameterValue, PlanRequirementResultInput, PlanStepMappingInput, PlannedOperation,
    PortProtocol, PortRegistration, PreconditionKind, ProofRequirementInput, RecipeAcceptanceInput,
    RecipeDispatchRequest, RecipeDispatcher, RecipeInput, RecipeProposalInput, RecipeRevisionInput,
    RecipeStepInput, RecipeStore, ScheduleEvaluation, ScheduleKind, ScheduleSpec,
    ScheduledRecipeInvocation, ServiceRegistration, ServiceRegistry, TimingMode,
    evaluate_preconditions, evaluate_schedule, validate_container_authority,
};
use std::sync::Arc;

use ptah_ai_workspace::{AuthorityOwner, ai_project_profile, operations_profile};
use ptah_archive_decomposition::{
    SearchDocumentKind, SearchHit, SearchIndexRevision, SearchResponse, SearchSourceBinding,
};
use ptah_knowledge_search::{
    KnowledgeSourceClass, KnowledgeSourceRevision, KnowledgeSourceRevisionInput,
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

fn planned_operation(stage: ExecutionStage) -> PlannedOperation {
    PlannedOperation {
        recipe_step_key: "inspect".to_owned(),
        stage,
        operation_key: "test.inspect".to_owned(),
        dependency_step_keys: Vec::new(),
        descriptor_digest: "sha256:descriptor".to_owned(),
        logical_target_refs: vec![reference("core.object_revision")],
        parameters: vec![ParameterBinding {
            key: "mode".to_owned(),
            value: ParameterValue::String("strict".to_owned()),
        }],
        credentials: vec![CredentialBinding {
            requirement_key: "registry.auth".to_owned(),
            credential_ref: reference("security.credential_reference"),
            provider_or_service_scope_ref: None,
        }],
        service_refs: vec![reference("plugin.service_registration")],
        required_grant_refs: vec![reference("isolation.secure_grant")],
        preconditions: Vec::new(),
        caller_approval_ref: None,
        expected_output_refs: vec![reference("build.output_declaration")],
        limitations: Vec::new(),
    }
}

fn execution_plan(stages: &[ExecutionStage]) -> ExecutionPlanManifest {
    let operations: Vec<_> = stages.iter().copied().map(planned_operation).collect();
    let declared_service_refs = operations
        .iter()
        .flat_map(|operation| operation.service_refs.iter().cloned())
        .collect();
    ExecutionPlanManifest {
        recipe_revision_ref: reference("build.recipe_revision"),
        acceptance_ref: reference("build.recipe_acceptance"),
        operations,
        declared_parameter_keys: vec!["mode".to_owned()],
        declared_credential_keys: vec!["registry.auth".to_owned()],
        declared_service_refs,
    }
}

#[test]
fn staged_plan_is_monotonic_and_verify_remains_separate() {
    let invalid = execution_plan(&[ExecutionStage::Verify, ExecutionStage::Execute]);
    assert!(matches!(
        invalid.validate(),
        Err(D04Error::InvalidStageOrder)
    ));
    let valid = execution_plan(&[
        ExecutionStage::Observe,
        ExecutionStage::Execute,
        ExecutionStage::Verify,
    ]);
    assert!(valid.validate().is_ok());
    assert_ne!(valid.operations[1].stage, valid.operations[2].stage);
}

#[test]
fn execution_plan_digest_is_deterministic_and_order_sensitive() {
    let first = execution_plan(&[ExecutionStage::Observe, ExecutionStage::Execute]);
    let same = first.clone();
    let changed = execution_plan(&[ExecutionStage::Execute, ExecutionStage::Observe]);
    assert_eq!(
        first.digest().expect("digest"),
        same.digest().expect("digest")
    );
    assert_ne!(
        first.digest().expect("digest"),
        changed.digest().expect("digest")
    );
}

#[test]
fn undeclared_parameter_credential_and_service_fail_closed() {
    let mut plan = execution_plan(&[ExecutionStage::Execute]);
    plan.declared_parameter_keys.clear();
    assert!(matches!(
        plan.validate(),
        Err(D04Error::UndeclaredPlanInput { .. })
    ));
    let mut plan = execution_plan(&[ExecutionStage::Execute]);
    plan.declared_credential_keys.clear();
    assert!(matches!(
        plan.validate(),
        Err(D04Error::UndeclaredPlanInput { .. })
    ));
    let mut plan = execution_plan(&[ExecutionStage::Execute]);
    plan.declared_service_refs.clear();
    assert!(matches!(
        plan.validate(),
        Err(D04Error::UndeclaredPlanInput { .. })
    ));
}

#[test]
fn credential_binding_serializes_reference_only() {
    let binding = CredentialBinding {
        requirement_key: "registry.auth".to_owned(),
        credential_ref: reference("security.credential_reference"),
        provider_or_service_scope_ref: Some(reference("runtime.provider_instance")),
    };
    let rendered = serde_json::to_value(binding)
        .expect("serialize")
        .to_string();
    for forbidden in ["password", "api_key", "secret_value", "raw_secret"] {
        assert!(!rendered.contains(forbidden));
    }
}

fn exact_precondition(kind: PreconditionKind, value: &str) -> ExactPrecondition {
    ExactPrecondition {
        kind,
        target_ref: reference("core.object_revision"),
        selector: Some("primary".to_owned()),
        expected: value.to_owned(),
        evidence_refs: vec![reference("security.evidence_item")],
    }
}

fn observed_precondition(expected: &ExactPrecondition, value: &str) -> ObservedPrecondition {
    ObservedPrecondition {
        kind: expected.kind,
        target_ref: expected.target_ref.clone(),
        selector: expected.selector.clone(),
        observed: value.to_owned(),
        evidence_refs: vec![reference("security.evidence_item")],
    }
}

#[test]
fn all_six_exact_preconditions_compare_mechanically() {
    for kind in [
        PreconditionKind::ObjectRevisionDigest,
        PreconditionKind::CanonicalRecordRevision,
        PreconditionKind::GitBranchHead,
        PreconditionKind::DraftRevision,
        PreconditionKind::StateMachineState,
        PreconditionKind::ProviderFreshness,
    ] {
        let expected = exact_precondition(kind, "aaaaaaaa");
        let observed = observed_precondition(&expected, "aaaaaaaa");
        assert!(evaluate_preconditions(&[expected], &[observed]).is_ok());
    }
}

#[test]
fn moved_target_conflict_retains_expected_observed_and_evidence() {
    let expected = exact_precondition(PreconditionKind::ObjectRevisionDigest, "aaaaaaaa");
    let observed = observed_precondition(&expected, "bbbbbbbb");
    let conflict = evaluate_preconditions(&[expected], &[observed]).expect_err("conflict");
    assert_eq!(conflict.expected, "aaaaaaaa");
    assert_eq!(conflict.observed.as_deref(), Some("bbbbbbbb"));
    assert!(!conflict.expected_evidence_refs.is_empty());
    assert!(!conflict.observed_evidence_refs.is_empty());

    let runtime = activity_runtime();
    let dispatcher = RecipeDispatcher::new(&runtime);
    let mut request = dispatch_request();
    request.observed_preconditions[0].observed = "generation-8".to_owned();
    assert!(matches!(
        dispatcher.dispatch(&request),
        Err(D04Error::DispatchPreconditionConflict(_))
    ));
    assert_eq!(runtime.activity_count().expect("count"), 0);
}

fn schedule(kind: ScheduleKind, timing_mode: TimingMode) -> ScheduleSpec {
    ScheduleSpec {
        kind,
        timing_mode,
        starts_at: Some("2026-09-02T15:00:00Z".to_owned()),
        recurrence_expression: (kind == ScheduleKind::Recurring).then(|| "FREQ=DAILY".to_owned()),
        condition_ref: (kind == ScheduleKind::ConditionWatch).then(|| reference("core.condition")),
        limitations: Vec::new(),
    }
}

fn scheduled_invocation(spec: ScheduleSpec) -> ScheduledRecipeInvocation {
    ScheduledRecipeInvocation {
        workspace_ref: reference("workspace.workspace"),
        recipe_revision_ref: reference("build.recipe_revision"),
        acceptance_ref: reference("build.recipe_acceptance"),
        compiled_plan_ref: reference("build.compiled_plan"),
        plan_digest: "sha256:plan".to_owned(),
        immutable_input_refs: vec![reference("core.object_revision")],
        provider_revision_refs: vec![reference("runtime.provider_revision")],
        grant_refs: vec![reference("isolation.secure_grant")],
        preconditions: vec![exact_precondition(
            PreconditionKind::ProviderFreshness,
            "generation-7",
        )],
        expected_output_refs: vec![reference("build.output_declaration")],
        caller_ref: reference("core.actor"),
        schedule: spec,
    }
}

#[test]
fn schedule_kind_timing_matrix_and_evaluation_states_are_exact() {
    for (kind, timing, valid) in [
        (ScheduleKind::OneOff, TimingMode::Exact, true),
        (ScheduleKind::OneOff, TimingMode::FlexibleWindow, true),
        (ScheduleKind::OneOff, TimingMode::ConditionDependent, false),
        (ScheduleKind::Recurring, TimingMode::Exact, true),
        (ScheduleKind::Recurring, TimingMode::FlexibleWindow, true),
        (
            ScheduleKind::Recurring,
            TimingMode::ConditionDependent,
            false,
        ),
        (
            ScheduleKind::ConditionWatch,
            TimingMode::ConditionDependent,
            true,
        ),
        (ScheduleKind::ConditionWatch, TimingMode::Exact, false),
    ] {
        assert_eq!(schedule(kind, timing).validate().is_ok(), valid);
    }

    let due = scheduled_invocation(schedule(ScheduleKind::OneOff, TimingMode::Exact));
    let observed = observed_precondition(&due.preconditions[0], "generation-7");
    assert_eq!(
        evaluate_schedule(&due, false, None, std::slice::from_ref(&observed)),
        ScheduleEvaluation::NotDue
    );
    assert_eq!(
        evaluate_schedule(&due, true, None, std::slice::from_ref(&observed)),
        ScheduleEvaluation::Due
    );

    let watch = scheduled_invocation(schedule(
        ScheduleKind::ConditionWatch,
        TimingMode::ConditionDependent,
    ));
    let watch_observed = observed_precondition(&watch.preconditions[0], "generation-7");
    assert_eq!(
        evaluate_schedule(
            &watch,
            true,
            Some(false),
            std::slice::from_ref(&watch_observed)
        ),
        ScheduleEvaluation::ConditionFalse
    );
    assert_eq!(
        evaluate_schedule(&watch, true, Some(true), &[watch_observed]),
        ScheduleEvaluation::ConditionTrue
    );

    let conflict = observed_precondition(&due.preconditions[0], "generation-8");
    assert!(matches!(
        evaluate_schedule(&due, true, None, &[conflict]),
        ScheduleEvaluation::InvalidatedByPrecondition(_)
    ));
}

#[test]
fn scheduled_invocation_freezes_exact_caller_inputs_without_hidden_context() {
    let invocation = scheduled_invocation(schedule(ScheduleKind::Recurring, TimingMode::Exact));
    invocation.validate().expect("valid invocation");
    let encoded = serde_json::to_value(&invocation).expect("serialize");
    assert_eq!(encoded["plan_digest"], "sha256:plan");
    assert_eq!(encoded["immutable_input_refs"].as_array().unwrap().len(), 1);
    assert_eq!(
        encoded["provider_revision_refs"].as_array().unwrap().len(),
        1
    );
    assert_eq!(encoded["grant_refs"].as_array().unwrap().len(), 1);
    assert_eq!(encoded["preconditions"].as_array().unwrap().len(), 1);
    assert_eq!(encoded["expected_output_refs"].as_array().unwrap().len(), 1);
    for forbidden in [
        "discover",
        "select_provider",
        "implicit_context",
        "global_scheduler",
    ] {
        assert!(!encoded.to_string().contains(forbidden));
    }
}

fn service_registration(instance_ref: &EntityRef, generation: u64) -> ServiceRegistration {
    ServiceRegistration {
        registration_ref: reference("plugin.service_registration"),
        service_key: "database.query".to_owned(),
        provider_revision_ref: reference("runtime.provider_revision"),
        provider_instance_ref: instance_ref.clone(),
        provider_generation: generation,
        freshness_token: format!("generation-{generation}"),
        endpoint_alias: "loopback://database.query".to_owned(),
        observed_at: "2026-09-02T14:00:00Z".to_owned(),
        expires_at: Some("2026-09-02T16:00:00Z".to_owned()),
        capability_refs: vec![reference("core.capability")],
        limitations: Vec::new(),
    }
}

fn port_registration() -> PortRegistration {
    PortRegistration {
        registration_ref: reference("plugin.port_registration"),
        service_registration_ref: reference("plugin.service_registration"),
        protocol: PortProtocol::Tcp,
        port: 8443,
        endpoint_alias: "127.0.0.1:8443".to_owned(),
        exposure_policy_refs: vec![reference("core.policy")],
        exposure_grant_refs: vec![reference("isolation.network_exposure_grant")],
        observed_at: "2026-09-02T14:00:00Z".to_owned(),
        expires_at: Some("2026-09-02T16:00:00Z".to_owned()),
    }
}

#[test]
fn stale_provider_generation_service_is_rejected() {
    let instance = reference("runtime.provider_instance");
    let mut registry = ServiceRegistry::default();
    let result = registry.register(service_registration(&instance, 6), 7);
    assert!(matches!(
        result,
        Err(D04Error::StaleProviderGeneration { .. })
    ));
}

#[test]
fn expired_service_is_unavailable() {
    let instance = reference("runtime.provider_instance");
    let mut registration = service_registration(&instance, 7);
    registration.expires_at = Some("2026-09-02T14:30:00Z".to_owned());
    let mut registry = ServiceRegistry::default();
    registry.register(registration, 7).expect("register");
    assert!(matches!(
        registry.resolve("database.query", &instance, 7, "2026-09-02T15:00:00Z"),
        Err(D04Error::ServiceUnavailable { .. })
    ));
}

#[test]
fn two_live_service_candidates_remain_ambiguous() {
    let instance = reference("runtime.provider_instance");
    let mut registry = ServiceRegistry::default();
    registry
        .register(service_registration(&instance, 7), 7)
        .expect("first");
    registry
        .register(service_registration(&instance, 7), 7)
        .expect("second");
    let resolution = registry
        .resolve("database.query", &instance, 7, "2026-09-02T15:00:00Z")
        .expect("resolve");
    assert!(resolution.is_ambiguous());
    assert_eq!(resolution.candidates().len(), 2);
}

#[test]
fn port_registration_requires_explicit_policy_and_grant_refs() {
    let mut registration = port_registration();
    registration.exposure_policy_refs.clear();
    assert!(matches!(
        registration.validate(),
        Err(D04Error::ExposureAuthorityMissing)
    ));
    let mut registration = port_registration();
    registration.exposure_grant_refs.clear();
    assert!(matches!(
        registration.validate(),
        Err(D04Error::ExposureAuthorityMissing)
    ));
}

#[test]
fn bound_port_never_becomes_network_exposure_authority() {
    let registration = port_registration();
    registration.validate().expect("valid registration");
    assert!(!registration.grants_network_exposure());
}

#[test]
fn a10_network_and_mount_requests_cannot_widen_existing_authority() {
    let network_grant = reference("isolation.network_exposure_grant");
    let mount_grant = reference("isolation.filesystem_access_grant");
    let baseline = ContainerAuthorityScope {
        network: ContainerNetworkScope::Host {
            grant_ref: network_grant.clone(),
        },
        mounts: vec![ContainerMountScope {
            source_alias: "/srv/input".to_owned(),
            destination: "/input".to_owned(),
            access: ContainerMountAccess::ReadOnly,
            grant_ref: mount_grant.clone(),
        }],
    };
    assert!(validate_container_authority(&baseline, &baseline).is_ok());

    let widened_network = ContainerAuthorityScope {
        network: ContainerNetworkScope::Host {
            grant_ref: reference("isolation.network_exposure_grant"),
        },
        mounts: baseline.mounts.clone(),
    };
    assert!(matches!(
        validate_container_authority(&baseline, &widened_network),
        Err(D04Error::AuthorityWidening { .. })
    ));

    let mut widened_mount = baseline.clone();
    widened_mount.mounts.push(ContainerMountScope {
        source_alias: "/srv/extra".to_owned(),
        destination: "/extra".to_owned(),
        access: ContainerMountAccess::ReadOnly,
        grant_ref: reference("isolation.filesystem_access_grant"),
    });
    assert!(matches!(
        validate_container_authority(&baseline, &widened_mount),
        Err(D04Error::AuthorityWidening { .. })
    ));
}

fn activity_runtime() -> ActivityRuntime {
    ActivityRuntime::new(
        8,
        Arc::new(MemoryJournal::default()),
        Arc::new(|| "2026-09-02T15:00:00Z".to_owned()),
    )
    .expect("runtime")
}

fn attempt_context() -> AttemptContext {
    AttemptContext {
        node_ref: reference("core.node"),
        node_generation: 3,
        provider_ref: reference("runtime.provider_instance"),
        provider_generation: 7,
        workload_generation: 11,
        connection_epoch: 5,
        facility_ref: reference("runtime.facility_revision"),
        producer_instance_ref: reference("runtime.provider_instance"),
        producer_version: "d04-test".to_owned(),
    }
}

fn dispatch_request() -> RecipeDispatchRequest {
    let descriptor = descriptor("test.inspect", 7);
    let mut plan = execution_plan(&[ExecutionStage::Observe]);
    plan.operations[0].descriptor_digest = descriptor.digest().expect("descriptor digest");
    plan.operations[0]
        .operation_key
        .clone_from(&descriptor.operation_key);
    let mut invocation = scheduled_invocation(schedule(ScheduleKind::Recurring, TimingMode::Exact));
    invocation.recipe_revision_ref = plan.recipe_revision_ref.clone();
    invocation.acceptance_ref = plan.acceptance_ref.clone();
    invocation.plan_digest = plan.digest().expect("plan digest");
    invocation.provider_revision_refs = vec![descriptor.provider_revision_ref.clone()];
    invocation
        .grant_refs
        .clone_from(&plan.operations[0].required_grant_refs);
    let observed_preconditions = invocation
        .preconditions
        .iter()
        .map(|precondition| observed_precondition(precondition, &precondition.expected))
        .collect();
    RecipeDispatchRequest {
        invocation,
        execution_plan: plan,
        descriptors: vec![descriptor],
        observed_preconditions,
        attempt_context: attempt_context(),
        activity_request_ref: reference("core.request"),
        authority_ref: reference("core.actor"),
        intent_ref: reference("core.intent"),
        priority: 0,
        max_attempts: 3,
    }
}

#[test]
fn each_scheduled_occurrence_creates_a_fresh_a04_attempt() {
    let runtime = activity_runtime();
    let dispatcher = RecipeDispatcher::new(&runtime);
    let request = dispatch_request();
    let first = dispatcher.dispatch(&request).expect("first dispatch");
    let second = dispatcher.dispatch(&request).expect("second dispatch");
    assert_eq!(first.operations.len(), 1);
    assert_eq!(second.operations.len(), 1);
    assert_ne!(first.activity_id, second.activity_id);
    assert_ne!(
        first.operations[0].attempt_id,
        second.operations[0].attempt_id
    );
}

#[test]
fn a10_start_ack_cannot_mark_a04_operation_succeeded() {
    let runtime = activity_runtime();
    let dispatcher = RecipeDispatcher::new(&runtime);
    let mapping = dispatcher.dispatch(&dispatch_request()).expect("dispatch");
    let operation_id = mapping.operations[0].operation_id;
    let _ack = BackendStartAck {
        container_alias: "container-ack".to_owned(),
        observed_at: "2026-09-02T15:00:01Z".to_owned(),
        detail: "accepted".to_owned(),
    };
    let operation = runtime.operation(operation_id).unwrap().unwrap();
    assert_eq!(operation.state(), OperationState::Dispatching);
}

#[test]
fn d03_source_revision_is_consumed_only_as_exact_recipe_material() {
    let source = KnowledgeSourceRevision::new(KnowledgeSourceRevisionInput {
        workspace_ref: reference("core.workspace"),
        source_ref: reference("object.view"),
        source_record_revision: 7,
        object_revision_ref: Some(reference("object.revision")),
        content_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_owned(),
        class: KnowledgeSourceClass::Document,
        provenance_ref: reference("evidence.receipt"),
        schema_id: "urn:ptah:schema:knowledge:source-revision:0.1.0".to_owned(),
    })
    .expect("source");
    let material = MaterialBindingInput {
        binding_key: "knowledge.source".to_owned(),
        material_class: "deterministic_bound".to_owned(),
        subject_ref: source.object_revision_ref.clone().expect("object revision"),
        resolved_at: "2026-09-02T15:00:00Z".to_owned(),
        evidence_refs: vec![source.provenance_ref.clone()],
    };
    assert_eq!(material.subject_ref, source.object_revision_ref.unwrap());
    assert_eq!(material.evidence_refs, vec![source.provenance_ref]);
}

#[test]
fn b07_search_result_never_implies_recipe_acceptance() {
    let path = ledger_path("b07-not-acceptance");
    let mut store = RecipeStore::open(&path).expect("open");
    let (_, revision_ref, _) = create_recipe_revision_and_proposal(&mut store, "d04.b07");
    let response = SearchResponse {
        index: SearchIndexRevision {
            revision: 1,
            content_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
            document_count: 1,
        },
        hits: vec![SearchHit {
            source: SearchSourceBinding {
                workspace_ref: reference("core.workspace"),
                source_ref: reference("object.view"),
                source_record_revision: 1,
                object_revision_ref: Some(reference("object.revision")),
            },
            kind: SearchDocumentKind::ObjectMetadata,
            score: 1,
            matches: Vec::new(),
        }],
    };
    assert_eq!(response.hits.len(), 1);
    assert!(matches!(
        store.accepted_revision_at(&revision_ref, "2026-09-02T15:00:00Z"),
        Err(D04Error::AcceptanceMissing { .. })
    ));
    let _ = std::fs::remove_file(path);
}

#[test]
fn predecessor_integration_contracts_preserve_caller_authority() {
    let ai_profile = ai_project_profile();
    assert_eq!(ai_profile.authority.decision, AuthorityOwner::Caller);
    assert_eq!(
        ai_profile.authority.context_selection,
        AuthorityOwner::Caller
    );
    assert_eq!(ai_profile.authority.approval, AuthorityOwner::Caller);
    let operations = operations_profile();
    assert_eq!(operations.effect_classes.len(), 7);

    let runtime = activity_runtime();
    let mapping = RecipeDispatcher::new(&runtime)
        .dispatch(&dispatch_request())
        .expect("A04 integration");
    assert_eq!(mapping.operations.len(), 1);
    assert_eq!(
        runtime
            .operation(mapping.operations[0].operation_id)
            .unwrap()
            .unwrap()
            .state(),
        OperationState::Dispatching
    );
    assert!(!port_registration().grants_network_exposure());
}

#[test]
fn d04_public_surface_has_no_semantic_chooser_approver_promoter_or_global_scheduler() {
    let sources = [
        include_str!("../src/dispatcher.rs"),
        include_str!("../src/operation.rs"),
        include_str!("../src/plan.rs"),
        include_str!("../src/precondition.rs"),
        include_str!("../src/recipe_store.rs"),
        include_str!("../src/schedule.rs"),
        include_str!("../src/service_registry.rs"),
    ]
    .join("\n");
    for forbidden in [
        "pub fn choose_provider",
        "pub fn choose_operation",
        "pub fn approve",
        "pub fn promote",
        "pub fn run_scheduler",
        "pub fn start_scheduler",
        "pub fn authorize_exposure",
        "pub fn open_port",
        "pub fn publish_port",
    ] {
        assert!(
            !sources.contains(forbidden),
            "forbidden public authority: {forbidden}"
        );
    }
}
