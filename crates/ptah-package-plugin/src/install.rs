use ptah_activity_runtime::{
    ActivityRuntime, ActivitySpec, AttemptContext, IdempotencyClass, OperationSpec, RetryClass,
    SideEffectClass,
};
use ptah_identifiers::{EntityId, EntityRef};
use serde::{Deserialize, Serialize};

use crate::D05Error;

/// Exact package installation request; caller selects every identity and authority reference.
#[derive(Clone, Debug)]
pub struct InstallRequest {
    /// Stable logical Package.
    pub package_ref: EntityRef,
    /// Exact immutable Package Revision.
    pub package_revision_ref: EntityRef,
    /// Exact resolved dependency graph.
    pub resolved_graph_ref: EntityRef,
    /// Exact immutable package lock.
    pub lock_record_ref: EntityRef,
    /// Target Workspace.
    pub workspace_ref: EntityRef,
    /// Exact Provider instance.
    pub provider_instance_ref: EntityRef,
    /// Exact Provider generation.
    pub provider_generation: u64,
    /// Exact installed Object Revision refs.
    pub installed_object_refs: Vec<EntityRef>,
    /// Caller request retained by A04.
    pub activity_request_ref: EntityRef,
    /// Exact caller identity.
    pub caller_ref: EntityRef,
    /// Exact authority reference.
    pub authority_ref: EntityRef,
    /// Exact intent reference.
    pub intent_ref: EntityRef,
}

/// Provider/package-manager acknowledgement retained only as evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInstallAck {
    /// Backend/package-manager alias only.
    pub backend_alias: String,
    /// Acknowledgement timestamp.
    pub accepted_at: String,
    /// Evidence supporting the acknowledgement.
    pub evidence_refs: Vec<EntityRef>,
}

/// A04-bound package installation handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageInstallHandle {
    /// Stable logical Package.
    pub package_ref: EntityRef,
    /// Exact immutable Package Revision.
    pub package_revision_ref: EntityRef,
    /// Canonical Package Installation identity.
    pub installation_ref: EntityRef,
    /// Fresh A04 Activity identity.
    pub activity_id: EntityId,
    /// Fresh A04 Operation identity.
    pub operation_id: EntityId,
    /// Fresh A04 Attempt identity.
    pub attempt_id: EntityId,
    /// Exact Provider instance.
    pub provider_instance_ref: EntityRef,
    /// Exact Provider generation.
    pub provider_generation: u64,
    /// Mechanical D05 verification projection.
    pub verification_state: String,
    /// Backend acknowledgement retained as evidence only.
    pub ack: PackageInstallAck,
}

/// Thin D05 package installer over the existing A04 runtime.
pub struct PackageInstaller;

impl PackageInstaller {
    /// Create fresh A04 Activity/Operation/Attempt evidence for one exact package install.
    ///
    /// # Errors
    /// Returns [`D05Error`] if identity/generation validation or A04 orchestration fails.
    pub fn begin_install(
        runtime: &ActivityRuntime,
        request: &InstallRequest,
        context: AttemptContext,
        ack: &PackageInstallAck,
    ) -> Result<PackageInstallHandle, D05Error> {
        if request.package_ref.entity_kind != "package.package"
            || request.package_revision_ref.entity_kind != "package.revision"
            || request.provider_generation == 0
            || request.provider_generation != context.provider_generation
            || request.installed_object_refs.is_empty()
            || ack.backend_alias.trim().is_empty()
            || ack.evidence_refs.is_empty()
        {
            return Err(D05Error::InvalidLifecycleRecord);
        }
        let activity_id = runtime
            .create_activity(ActivitySpec {
                request_ref: request.activity_request_ref.clone(),
                workspace_ref: request.workspace_ref.clone(),
                caller_ref: request.caller_ref.clone(),
                authority_ref: request.authority_ref.clone(),
                activity_kind: "package.install".to_owned(),
                intent_ref: request.intent_ref.clone(),
                priority: 0,
                max_attempts: 3,
            })
            .map_err(a04_error)?;
        if runtime.admit_next().map_err(a04_error)? != Some(activity_id) {
            return Err(D05Error::ActivityRuntime(
                "installation activity not admitted".into(),
            ));
        }
        let operation_id = runtime
            .create_operation(
                activity_id,
                OperationSpec {
                    operation_kind: "package.install".to_owned(),
                    logical_target_refs: vec![request.package_revision_ref.clone()],
                    command_or_action_ref: request.lock_record_ref.clone(),
                    side_effect_class: SideEffectClass::Reversible,
                    retry_class: RetryClass::RetrySafe,
                    idempotency_class: IdempotencyClass::OperationIdentity,
                    idempotency_key: Some(format!("package-install-{activity_id}")),
                    required_authority_refs: vec![request.authority_ref.clone()],
                    precondition_refs: vec![
                        request.resolved_graph_ref.clone(),
                        request.lock_record_ref.clone(),
                    ],
                    desired_proof_refs: Vec::new(),
                    compensating_operation_ref: None,
                },
            )
            .map_err(a04_error)?;
        runtime
            .make_operation_ready(operation_id)
            .map_err(a04_error)?;
        let attempt_id = runtime
            .create_attempt(operation_id, context)
            .map_err(a04_error)?;
        let installation_ref = EntityRef::new("package.installation")
            .map_err(|e| D05Error::ActivityRuntime(e.to_string()))?;
        Ok(PackageInstallHandle {
            package_ref: request.package_ref.clone(),
            package_revision_ref: request.package_revision_ref.clone(),
            installation_ref,
            activity_id,
            operation_id,
            attempt_id,
            provider_instance_ref: request.provider_instance_ref.clone(),
            provider_generation: request.provider_generation,
            verification_state: "unverified".to_owned(),
            ack: ack.clone(),
        })
    }

    /// Explicitly retry one failed installation through A04, producing a fresh Attempt.
    ///
    /// # Errors
    /// Returns [`D05Error`] when A04 does not permit or cannot create the retry.
    pub fn retry_install(
        runtime: &ActivityRuntime,
        handle: &PackageInstallHandle,
        policy_ref: EntityRef,
        context: AttemptContext,
    ) -> Result<EntityId, D05Error> {
        runtime
            .retry_operation(handle.operation_id, Some(policy_ref), context)
            .map_err(a04_error)
    }
}

fn a04_error(error: impl std::fmt::Display) -> D05Error {
    D05Error::ActivityRuntime(error.to_string())
}
