fn create_attempt_fixture(
    runtime: &ActivityRuntime,
    workspace_ref: &EntityRef,
    authority_ref: &EntityRef,
) -> (EntityId, EntityId, EntityId, AttemptContext, String) {
    let activity_id = runtime
        .create_activity(ActivitySpec {
            request_ref: reference("core.request"),
            workspace_ref: workspace_ref.clone(),
            caller_ref: authority_ref.clone(),
            authority_ref: authority_ref.clone(),
            activity_kind: "object.a07_proof".to_owned(),
            intent_ref: reference("core.intent"),
            priority: 0,
            max_attempts: 2,
        })
        .expect("create Activity");
    assert_eq!(
        runtime.admit_next().expect("admit Activity"),
        Some(activity_id)
    );
    let operation_id = runtime
        .create_operation(
            activity_id,
            OperationSpec {
                operation_kind: "object.a07_operation".to_owned(),
                logical_target_refs: vec![reference("object.object")],
                command_or_action_ref: reference("core.command"),
                side_effect_class: SideEffectClass::IdempotentMutation,
                retry_class: RetryClass::RetrySafe,
                idempotency_class: IdempotencyClass::NoneRequired,
                idempotency_key: None,
                required_authority_refs: vec![authority_ref.clone()],
                precondition_refs: Vec::new(),
                desired_proof_refs: vec![reference("proof.claim")],
                compensating_operation_ref: None,
            },
        )
        .expect("create Operation");
    runtime
        .make_operation_ready(operation_id)
        .expect("make ready");
    let context = AttemptContext {
        node_ref: reference("core.node"),
        node_generation: 7,
        provider_ref: reference("runtime.provider"),
        provider_generation: 3,
        workload_generation: 11,
        connection_epoch: 5,
        facility_ref: reference("runtime.facility"),
        producer_instance_ref: reference("runtime.provider_instance"),
        producer_version: "a07-proof-producer-1.0.0".to_owned(),
    };
    let attempt_id = runtime
        .create_attempt(operation_id, context.clone())
        .expect("create Attempt");
    runtime
        .dispatch_attempt(attempt_id)
        .expect("dispatch Attempt");
    runtime.accept_attempt(attempt_id).expect("accept Attempt");
    runtime
        .begin_attempt_execution(attempt_id)
        .expect("begin Attempt");
    let nonce = runtime
        .attempt(attempt_id)
        .expect("read Attempt")
        .expect("Attempt retained")
        .correlation_nonce()
        .to_owned();
    (activity_id, operation_id, attempt_id, context, nonce)
}
