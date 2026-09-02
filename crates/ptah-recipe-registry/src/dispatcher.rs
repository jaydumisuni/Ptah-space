use crate::{
    D04Error, ExecutionPlanManifest, ExecutionStage, ObservedPrecondition,
    OperationDescriptorRevision, PlannedOperation, ScheduledRecipeInvocation,
    evaluate_preconditions,
};
use ptah_activity_runtime::{
    ActivityRuntime, ActivitySpec, AttemptContext, IdempotencyClass, OperationSpec, RetryClass,
};
use ptah_identifiers::{EntityId, EntityRef};
use std::collections::BTreeSet;

/// Fully explicit mechanical request for one already-selected Recipe invocation.
#[derive(Debug, Clone)]
pub struct RecipeDispatchRequest {
    /// Exact scheduled invocation with caller-owned identity/input boundaries.
    pub invocation: ScheduledRecipeInvocation,
    /// Exact immutable staged execution Plan.
    pub execution_plan: ExecutionPlanManifest,
    /// Exact descriptor revisions required by the Plan; D04 never selects alternatives.
    pub descriptors: Vec<OperationDescriptorRevision>,
    /// Explicit current observations used to re-check frozen preconditions.
    pub observed_preconditions: Vec<ObservedPrecondition>,
    /// Exact physical A04 Attempt context supplied by the caller/provider layer.
    pub attempt_context: AttemptContext,
    /// Exact caller request identity retained by A04.
    pub activity_request_ref: EntityRef,
    /// Exact authority retained by A04.
    pub authority_ref: EntityRef,
    /// Exact intent identity retained by A04.
    pub intent_ref: EntityRef,
    /// Explicit A04 priority.
    pub priority: i64,
    /// Explicit per-Activity A04 Attempt budget.
    pub max_attempts: u64,
}

/// Mapping of one ready Recipe step/stage to its fresh A04 runtime identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeOperationMapping {
    /// Immutable Recipe step key.
    pub recipe_step_key: String,
    /// D04 stage associated with this Operation.
    pub stage: ExecutionStage,
    /// Fresh logical A04 Operation identity.
    pub operation_id: EntityId,
    /// Fresh physical A04 Attempt identity.
    pub attempt_id: EntityId,
}

/// Mechanical D04-to-A04 mapping evidence for one dispatch occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeDispatchMapping {
    /// Fresh A04 Activity identity for this occurrence.
    pub activity_id: EntityId,
    /// Root-ready Operation/Attempt mappings created by this occurrence.
    pub operations: Vec<RecipeOperationMapping>,
    /// Recipe step keys withheld because dependencies remain unresolved.
    pub deferred_step_keys: Vec<String>,
}

/// Thin D04 dispatcher borrowing the existing A04 runtime authority.
pub struct RecipeDispatcher<'runtime> {
    runtime: &'runtime ActivityRuntime,
}

impl<'runtime> RecipeDispatcher<'runtime> {
    /// Borrow one existing A04 runtime without taking completion/proof authority.
    #[must_use]
    pub const fn new(runtime: &'runtime ActivityRuntime) -> Self {
        Self { runtime }
    }

    /// Create fresh A04 Activity/Operation/Attempt identities after all D04 preflight gates pass.
    ///
    /// # Errors
    /// Returns [`D04Error`] for binding/precondition failures or A04 mechanical rejection.
    /// All D04 validation is completed before `create_activity`; a D04 validation error
    /// therefore creates no A04 Activity or Attempt.
    pub fn dispatch(
        &self,
        request: &RecipeDispatchRequest,
    ) -> Result<RecipeDispatchMapping, D04Error> {
        let prepared = preflight(request)?;
        let activity_id = self
            .runtime
            .create_activity(ActivitySpec {
                request_ref: request.activity_request_ref.clone(),
                workspace_ref: request.invocation.workspace_ref.clone(),
                caller_ref: request.invocation.caller_ref.clone(),
                authority_ref: request.authority_ref.clone(),
                activity_kind: "recipe.execute".to_owned(),
                intent_ref: request.intent_ref.clone(),
                priority: request.priority,
                max_attempts: request.max_attempts,
            })
            .map_err(a04_error)?;
        let admitted = self.runtime.admit_next().map_err(a04_error)?;
        if admitted != Some(activity_id) {
            return Err(D04Error::A04Adapter(
                "new Activity was not admitted".to_owned(),
            ));
        }

        let mut operations = Vec::new();
        for ready in prepared.ready {
            let idempotency_key =
                idempotency_key(ready.descriptor.idempotency_class, request, ready.index);
            let operation_id = self
                .runtime
                .create_operation(
                    activity_id,
                    OperationSpec {
                        operation_kind: ready.operation.operation_key.clone(),
                        logical_target_refs: ready.operation.logical_target_refs.clone(),
                        command_or_action_ref: request.invocation.compiled_plan_ref.clone(),
                        side_effect_class: ready.descriptor.a04_side_effect,
                        retry_class: ready.descriptor.retry_class,
                        idempotency_class: ready.descriptor.idempotency_class,
                        idempotency_key,
                        required_authority_refs: authority_refs(ready.operation, ready.descriptor),
                        precondition_refs: precondition_evidence_refs(request, ready.operation),
                        desired_proof_refs: Vec::new(),
                        compensating_operation_ref: None,
                    },
                )
                .map_err(a04_error)?;
            self.runtime
                .make_operation_ready(operation_id)
                .map_err(a04_error)?;
            let attempt_id = self
                .runtime
                .create_attempt(operation_id, request.attempt_context.clone())
                .map_err(a04_error)?;
            operations.push(RecipeOperationMapping {
                recipe_step_key: ready.operation.recipe_step_key.clone(),
                stage: ready.operation.stage,
                operation_id,
                attempt_id,
            });
        }

        Ok(RecipeDispatchMapping {
            activity_id,
            operations,
            deferred_step_keys: prepared.deferred,
        })
    }
}

struct ReadyOperation<'request> {
    index: usize,
    operation: &'request PlannedOperation,
    descriptor: &'request OperationDescriptorRevision,
}

struct PreparedDispatch<'request> {
    ready: Vec<ReadyOperation<'request>>,
    deferred: Vec<String>,
}

fn preflight(request: &RecipeDispatchRequest) -> Result<PreparedDispatch<'_>, D04Error> {
    request.invocation.validate()?;
    request.execution_plan.validate()?;
    if request.execution_plan.recipe_revision_ref != request.invocation.recipe_revision_ref
        || request.execution_plan.acceptance_ref != request.invocation.acceptance_ref
        || request.execution_plan.digest()? != request.invocation.plan_digest
    {
        return Err(D04Error::DispatchBindingMismatch(
            "Recipe Revision/Acceptance/Plan digest".to_owned(),
        ));
    }
    if request.max_attempts == 0 {
        return Err(D04Error::DispatchBindingMismatch("max_attempts".to_owned()));
    }

    let all_step_keys = request
        .execution_plan
        .operations
        .iter()
        .map(|operation| operation.recipe_step_key.as_str())
        .collect::<BTreeSet<_>>();
    let mut all_preconditions = request.invocation.preconditions.clone();
    let mut ready = Vec::new();
    let mut deferred = Vec::new();

    for (index, operation) in request.execution_plan.operations.iter().enumerate() {
        if operation
            .dependency_step_keys
            .iter()
            .any(|dependency| !all_step_keys.contains(dependency.as_str()))
        {
            return Err(D04Error::DispatchBindingMismatch(
                "unknown Recipe step dependency".to_owned(),
            ));
        }
        all_preconditions.extend(operation.preconditions.iter().cloned());
        let descriptor = descriptor_for(request, operation)?;
        validate_descriptor_authority(request, operation, descriptor)?;
        if descriptor.retry_class == RetryClass::CompensatingActionRequired {
            return Err(D04Error::DispatchBindingMismatch(
                "compensating operation ref is not represented by this Plan".to_owned(),
            ));
        }
        if operation.dependency_step_keys.is_empty() {
            ready.push(ReadyOperation {
                index,
                operation,
                descriptor,
            });
        } else {
            deferred.push(operation.recipe_step_key.clone());
        }
    }

    evaluate_preconditions(&all_preconditions, &request.observed_preconditions)
        .map_err(D04Error::DispatchPreconditionConflict)?;
    Ok(PreparedDispatch { ready, deferred })
}

fn descriptor_for<'request>(
    request: &'request RecipeDispatchRequest,
    operation: &PlannedOperation,
) -> Result<&'request OperationDescriptorRevision, D04Error> {
    request
        .descriptors
        .iter()
        .find(|descriptor| {
            descriptor.operation_key == operation.operation_key
                && descriptor
                    .digest()
                    .is_ok_and(|digest| digest == operation.descriptor_digest)
        })
        .ok_or_else(|| D04Error::DispatchBindingMismatch("exact operation descriptor".to_owned()))
}

fn validate_descriptor_authority(
    request: &RecipeDispatchRequest,
    operation: &PlannedOperation,
    descriptor: &OperationDescriptorRevision,
) -> Result<(), D04Error> {
    if !request
        .invocation
        .provider_revision_refs
        .contains(&descriptor.provider_revision_ref)
    {
        return Err(D04Error::DispatchBindingMismatch(
            "Provider Revision".to_owned(),
        ));
    }
    if operation
        .required_grant_refs
        .iter()
        .chain(descriptor.required_grant_refs.iter())
        .any(|grant| !request.invocation.grant_refs.contains(grant))
    {
        return Err(D04Error::DispatchBindingMismatch("Grant ref".to_owned()));
    }
    Ok(())
}

fn authority_refs(
    operation: &PlannedOperation,
    descriptor: &OperationDescriptorRevision,
) -> Vec<EntityRef> {
    let mut refs = descriptor.required_grant_refs.clone();
    for grant in &operation.required_grant_refs {
        if !refs.contains(grant) {
            refs.push(grant.clone());
        }
    }
    refs
}

fn precondition_evidence_refs(
    request: &RecipeDispatchRequest,
    operation: &PlannedOperation,
) -> Vec<EntityRef> {
    let mut refs = Vec::new();
    for precondition in request
        .invocation
        .preconditions
        .iter()
        .chain(operation.preconditions.iter())
    {
        for evidence in &precondition.evidence_refs {
            if !refs.contains(evidence) {
                refs.push(evidence.clone());
            }
        }
    }
    refs
}

fn idempotency_key(
    class: IdempotencyClass,
    request: &RecipeDispatchRequest,
    index: usize,
) -> Option<String> {
    if matches!(
        class,
        IdempotencyClass::ExplicitKey
            | IdempotencyClass::ProviderKey
            | IdempotencyClass::ReceiptGuarded
    ) {
        Some(format!("d04-{}-{index}", request.invocation.plan_digest))
    } else {
        None
    }
}

fn a04_error(error: impl std::fmt::Display) -> D04Error {
    D04Error::A04Adapter(error.to_string())
}
