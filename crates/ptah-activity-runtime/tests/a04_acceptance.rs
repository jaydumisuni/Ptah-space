use ptah_activity_runtime::{
    ActivityRuntime, ActivitySpec, ActivityState, AttemptContext, AttemptState, IdempotencyClass,
    MemoryJournal, OperationSpec, OperationState, RetryClass, RuntimeError, SideEffectClass,
    WorkerFormationSpec, WorkerRole,
};
use ptah_identifiers::{EntityId, EntityRef};
use ptah_receipts::{
    AuthorityClass, ProofLevel, ReceiptContext, ReceiptKind, ReceiptOutcome, ReceiptSpec,
};
use std::{collections::HashSet, sync::Arc};

const ACTIVITY_KIND: &str = "core.activity";
const OPERATION_KIND: &str = "core.operation";
const ATTEMPT_KIND: &str = "core.attempt";

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid reference")
}

fn runtime(limit: usize) -> ActivityRuntime {
    ActivityRuntime::new(
        limit,
        Arc::new(MemoryJournal::default()),
        Arc::new(|| "2026-08-16T16:50:00Z".to_owned()),
    )
    .expect("runtime")
}

fn activity_spec() -> ActivitySpec {
    ActivitySpec {
        request_ref: reference("core.activity_request"),
        workspace_ref: reference("workspace.workspace"),
        caller_ref: reference("identity.principal"),
        authority_ref: reference("identity.principal"),
        activity_kind: "test.concurrent_work".to_owned(),
        intent_ref: reference("knowledge.intent"),
        priority: 0,
        max_attempts: 3,
    }
}

fn operation_spec() -> OperationSpec {
    OperationSpec {
        operation_kind: "test.observe".to_owned(),
        logical_target_refs: vec![reference("object.object")],
        command_or_action_ref: reference("runtime.action"),
        side_effect_class: SideEffectClass::ObservationOnly,
        retry_class: RetryClass::RetrySafe,
        idempotency_class: IdempotencyClass::ExplicitKey,
        idempotency_key: Some("test-operation-key".to_owned()),
        required_authority_refs: vec![reference("isolation.policy")],
        precondition_refs: Vec::new(),
        desired_proof_refs: vec![reference("proof.claim")],
        compensating_operation_ref: None,
    }
}

fn attempt_context() -> AttemptContext {
    AttemptContext {
        node_ref: reference("core.node"),
        node_generation: 4,
        provider_ref: reference("runtime.provider"),
        provider_generation: 2,
        workload_generation: 8,
        connection_epoch: 5,
        facility_ref: reference("runtime.facility"),
        producer_instance_ref: reference("runtime.provider_instance"),
        producer_version: "1.0.0".to_owned(),
    }
}

fn setup_attempt(runtime: &ActivityRuntime) -> (EntityId, EntityId, EntityId) {
    let activity = runtime.create_activity(activity_spec()).expect("Activity");
    assert_eq!(runtime.admit_next().expect("admit"), Some(activity));
    let operation = runtime
        .create_operation(activity, operation_spec())
        .expect("Operation");
    runtime.make_operation_ready(operation).expect("ready");
    let attempt = runtime
        .create_attempt(operation, attempt_context())
        .expect("Attempt");
    runtime.dispatch_attempt(attempt).expect("dispatch");
    runtime.accept_attempt(attempt).expect("accept");
    runtime.begin_attempt_execution(attempt).expect("execution");
    (activity, operation, attempt)
}

fn completion_receipt(
    runtime: &ActivityRuntime,
    activity: EntityId,
    operation: EntityId,
    attempt: EntityId,
    levels: Vec<ProofLevel>,
) -> ReceiptSpec {
    let attempt_record = runtime.attempt(attempt).expect("query").expect("Attempt");
    let context = attempt_record.context().clone();
    ReceiptSpec {
        kind: ReceiptKind::OperationObservation,
        outcome: ReceiptOutcome::Positive,
        authority_class: AuthorityClass::PtahNode,
        context: ReceiptContext {
            activity_ref: EntityRef::from_id(activity, ACTIVITY_KIND).expect("Activity ref"),
            operation_ref: EntityRef::from_id(operation, OPERATION_KIND).expect("Operation ref"),
            attempt_ref: EntityRef::from_id(attempt, ATTEMPT_KIND).expect("Attempt ref"),
            idempotency_key: Some("test-operation-key".to_owned()),
            correlation_nonce: attempt_record.correlation_nonce().to_owned(),
            node_ref: context.node_ref,
            node_generation: context.node_generation,
            provider_ref: context.provider_ref,
            provider_generation: context.provider_generation,
            workload_generation: context.workload_generation,
            connection_epoch: context.connection_epoch,
            facility_ref: context.facility_ref,
            producer_instance_ref: context.producer_instance_ref,
            producer_version: context.producer_version,
        },
        producer_identity_evidence_refs: vec![reference("proof.evidence")],
        proof_claim_refs: vec![reference("proof.claim")],
        proof_levels: levels,
        previous_or_superseded_receipt_refs: Vec::new(),
        summary: "exact bounded execution proof".to_owned(),
        limitations: Vec::new(),
        occurred_at: "2026-08-16T16:50:00Z".to_owned(),
    }
}

#[test]
fn ten_independent_activities_are_admitted_without_cross_collapse() {
    let runtime = runtime(10);
    let ids: Vec<_> = (0..10)
        .map(|_| runtime.create_activity(activity_spec()).expect("Activity"))
        .collect();

    for id in &ids {
        assert_eq!(runtime.admit_next().expect("admit"), Some(*id));
    }

    assert_eq!(runtime.running_count().expect("running"), 10);
    for id in ids {
        assert_eq!(
            runtime
                .activity(id)
                .expect("query")
                .expect("Activity")
                .state(),
            ActivityState::Running
        );
    }
}

#[test]
fn retry_requires_policy_and_fresh_attempt_identity_and_nonce() {
    let runtime = runtime(1);
    let (_, operation, first) = setup_attempt(&runtime);
    runtime.fail_attempt(first, "PTAH_RETRYABLE").expect("fail");

    assert!(matches!(
        runtime.retry_operation(operation, None, attempt_context()),
        Err(RuntimeError::RetryPolicyRequired)
    ));

    let second = runtime
        .retry_operation(
            operation,
            Some(reference("isolation.policy")),
            attempt_context(),
        )
        .expect("retry");
    assert_ne!(first, second);
    assert_ne!(
        runtime
            .attempt(first)
            .expect("query")
            .expect("first")
            .correlation_nonce(),
        runtime
            .attempt(second)
            .expect("query")
            .expect("second")
            .correlation_nonce()
    );
}

#[test]
fn acknowledgement_and_attempt_completion_do_not_skip_operation_acceptance() {
    let runtime = runtime(1);
    let (activity, operation, attempt) = setup_attempt(&runtime);
    let acknowledgement = runtime
        .append_receipt(completion_receipt(
            &runtime,
            activity,
            operation,
            attempt,
            vec![ProofLevel::Accepted],
        ))
        .expect("acknowledgement");
    assert!(matches!(
        runtime.complete_attempt(attempt, acknowledgement),
        Err(RuntimeError::InsufficientCompletionProof)
    ));

    let proof = runtime
        .append_receipt(completion_receipt(
            &runtime,
            activity,
            operation,
            attempt,
            vec![ProofLevel::OperationCompleted],
        ))
        .expect("proof");
    runtime
        .complete_attempt(attempt, proof)
        .expect("Attempt complete");
    assert_eq!(
        runtime
            .attempt(attempt)
            .expect("query")
            .expect("Attempt")
            .state(),
        AttemptState::Completed
    );
    assert_eq!(
        runtime
            .operation(operation)
            .expect("query")
            .expect("Operation")
            .state(),
        OperationState::Executing
    );
    assert_eq!(
        runtime
            .activity(activity)
            .expect("query")
            .expect("Activity")
            .state(),
        ActivityState::Running
    );

    let result = reference("object.result");
    runtime
        .prove_operation_succeeded(operation, proof, vec![result.clone()])
        .expect("Operation proof");
    runtime
        .complete_activity(activity, vec![result])
        .expect("Activity completion");
    assert_eq!(
        runtime
            .activity(activity)
            .expect("query")
            .expect("Activity")
            .state(),
        ActivityState::Completed
    );
}

#[test]
fn cancellation_is_scoped_and_cancelled_work_remains_queryable() {
    let runtime = runtime(2);
    let first = runtime.create_activity(activity_spec()).expect("first");
    let second = runtime.create_activity(activity_spec()).expect("second");
    runtime.admit_next().expect("admit first");
    runtime.admit_next().expect("admit second");

    runtime
        .cancel_activity(first, reference("core.cancellation_request"))
        .expect("cancel first");

    assert_eq!(
        runtime
            .activity(first)
            .expect("query")
            .expect("first")
            .state(),
        ActivityState::Cancelled
    );
    assert_eq!(
        runtime
            .activity(second)
            .expect("query")
            .expect("second")
            .state(),
        ActivityState::Running
    );
}

#[test]
fn ten_for_two_formation_keeps_primary_and_verifier_lanes_independent() {
    let runtime = runtime(1);
    let activity = runtime.create_activity(activity_spec()).expect("Activity");
    let formation_id = runtime
        .create_worker_formation(
            activity,
            WorkerFormationSpec {
                recipe_or_plan_ref: reference("build.recipe"),
                roles: vec![WorkerRole::Primary, WorkerRole::Verifier],
                workers_per_role: 10,
                max_slots: 20,
                require_independent_verifier: true,
            },
        )
        .expect("formation");
    let formation = runtime
        .worker_formation(formation_id)
        .expect("query")
        .expect("formation");

    assert_eq!(formation.slots.len(), 20);
    let groups: HashSet<_> = formation
        .slots
        .iter()
        .map(|slot| slot.independence_group.as_str())
        .collect();
    assert_eq!(groups, HashSet::from(["primary", "verifier"]));
    assert!(formation.accepted_result_ref.is_none());
}

#[test]
fn conflicting_worker_outputs_remain_visible_until_explicit_acceptance() {
    let runtime = runtime(1);
    let activity = runtime.create_activity(activity_spec()).expect("Activity");
    let formation_id = runtime
        .create_worker_formation(
            activity,
            WorkerFormationSpec {
                recipe_or_plan_ref: reference("build.recipe"),
                roles: vec![WorkerRole::Primary, WorkerRole::Verifier],
                workers_per_role: 1,
                max_slots: 2,
                require_independent_verifier: true,
            },
        )
        .expect("formation");
    let slots = runtime
        .worker_formation(formation_id)
        .expect("query")
        .expect("formation")
        .slots;

    let left = reference("object.result");
    let right = reference("object.result");
    runtime
        .complete_worker(formation_id, slots[0].id, left.clone())
        .expect("left");
    runtime
        .complete_worker(formation_id, slots[1].id, right)
        .expect("right");

    assert_eq!(
        runtime
            .worker_conflicts(formation_id)
            .expect("conflicts")
            .len(),
        1
    );
    assert!(
        runtime
            .worker_formation(formation_id)
            .expect("query")
            .expect("formation")
            .accepted_result_ref
            .is_none()
    );
    runtime
        .accept_worker_result(formation_id, left)
        .expect("explicit acceptance");
    assert!(
        runtime
            .worker_formation(formation_id)
            .expect("query")
            .expect("formation")
            .accepted_result_ref
            .is_some()
    );
}

#[test]
fn repeated_failures_emit_advisory_without_self_starting_new_activity() {
    let runtime = runtime(3);
    let mut last_activity = None;
    for _ in 0..3 {
        let (activity, _, attempt) = setup_attempt(&runtime);
        last_activity = Some(activity);
        runtime
            .fail_attempt(attempt, "PTAH_REPEATED")
            .expect("fail");
    }

    assert_eq!(runtime.activity_count().expect("count"), 3);
    let activity = last_activity.expect("last Activity");
    let replay = runtime.events().replay(activity, 0).expect("replay");
    assert!(
        replay
            .iter()
            .any(|event| event.event_type() == "diagnostic.repeated_failure")
    );
    assert_eq!(runtime.activity_count().expect("count"), 3);
}
