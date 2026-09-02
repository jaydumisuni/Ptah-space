use ptah_activity_runtime::{
    ActivityRuntime, ActivitySpec, AttemptContext, IdempotencyClass, OperationSpec, RetryClass,
    SideEffectClass,
};
use ptah_identifiers::{EntityId, EntityRef};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{D05Error, PluginInstanceRecord};

/// Mechanical update decision; decision is not execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateDecision {
    /// Candidate revision is approved for a separately-authorized execution.
    Approved,
    /// Candidate revision is rejected.
    Rejected,
    /// Candidate revision still requires governed review.
    ReviewRequired,
}

/// Versioned Plugin update decision evidence with no execution identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginUpdateDecision {
    /// Stable logical Plugin.
    pub plugin_ref: EntityRef,
    /// Exact currently selected Plugin Revision.
    pub current_revision_ref: EntityRef,
    /// Exact candidate Plugin Revision.
    pub candidate_revision_ref: EntityRef,
    /// Exact compatibility observation.
    pub compatibility_ref: EntityRef,
    /// Exact verification refs considered by the decision.
    pub verification_refs: Vec<EntityRef>,
    /// Mechanical caller-supplied decision.
    pub decision: UpdateDecision,
    /// Decision timestamp.
    pub decided_at: String,
    /// Exact decision maker.
    pub decided_by_ref: EntityRef,
}

/// Exact caller-authored Plugin change request.
#[derive(Clone, Debug)]
pub struct PluginChangeRequest {
    /// Stable logical Plugin identity.
    pub plugin_ref: EntityRef,
    /// Exact source/current Plugin Revision.
    pub from_revision_ref: EntityRef,
    /// Exact target Plugin Revision.
    pub to_revision_ref: EntityRef,
    /// Target Workspace.
    pub workspace_ref: EntityRef,
    /// Caller request retained by A04.
    pub activity_request_ref: EntityRef,
    /// Exact caller.
    pub caller_ref: EntityRef,
    /// Exact authority.
    pub authority_ref: EntityRef,
    /// Exact intent.
    pub intent_ref: EntityRef,
    /// Pre-existing verification refs used as preconditions, not completion proof.
    pub verification_refs: Vec<EntityRef>,
}

/// Kind of Plugin mutation represented by one A04-backed handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginChangeKind {
    /// Update to a candidate Revision.
    Update,
    /// Roll back to a prior Revision.
    Rollback,
    /// Remove Plugin materialization/runtime state.
    Removal,
}

/// Fresh A04 identities for one Plugin change attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginChangeHandle {
    /// Change kind.
    pub kind: PluginChangeKind,
    /// Stable Plugin.
    pub plugin_ref: EntityRef,
    /// Source Revision.
    pub from_revision_ref: EntityRef,
    /// Target Revision.
    pub to_revision_ref: EntityRef,
    /// Fresh A04 Activity.
    pub activity_id: EntityId,
    /// Fresh A04 Operation.
    pub operation_id: EntityId,
    /// Fresh A04 Attempt.
    pub attempt_id: EntityId,
    /// Whether independent post-verification has been attached to this projection.
    pub verified: bool,
}

/// Independently verified post-change evidence projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginChangeEvidence {
    /// Stable Plugin identity.
    pub plugin_ref: EntityRef,
    /// Exact Revision observed after the change.
    pub revision_ref: EntityRef,
    /// Exact Plugin Instance generation observed after the change.
    pub instance_generation: u64,
    /// Independent verification outcome.
    pub verified: bool,
    /// Supporting evidence refs.
    pub evidence_refs: Vec<EntityRef>,
}

/// Provider uninstall acknowledgement only; not verified removal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginUninstallAck {
    /// Plugin-host/package-manager alias only.
    pub backend_alias: String,
    /// Supporting acknowledgement evidence.
    pub evidence_refs: Vec<EntityRef>,
}

/// One required staged Plugin-removal post-condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RemovalStage {
    /// Activation is disabled.
    ActivationDisabled,
    /// Capability Grants are revoked.
    GrantsRevoked,
    /// Plugin Instances are stopped.
    InstancesStopped,
    /// Service/port/dependency registrations are removed.
    RegistrationsRemoved,
    /// Package materialization is uninstalled.
    PackageUninstalled,
    /// Cleanup/readback is independently verified.
    CleanupVerified,
}

/// Required staged proof for a complete Plugin removal claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovalProof {
    /// Completed removal stages.
    pub completed_stages: BTreeSet<RemovalStage>,
    /// Exact proof evidence refs.
    pub evidence_refs: Vec<EntityRef>,
}

/// Thin Plugin mutation facade over A04.
pub struct PluginChangeExecutor;

impl PluginChangeExecutor {
    /// Start one separately-authorized Plugin update.
    ///
    /// # Errors
    /// Returns [`D05Error`] when identity validation or A04 orchestration fails.
    pub fn begin_update(
        runtime: &ActivityRuntime,
        request: &PluginChangeRequest,
        context: AttemptContext,
    ) -> Result<PluginChangeHandle, D05Error> {
        begin_change(runtime, request, context, PluginChangeKind::Update)
    }

    /// Start one separately-authorized Plugin rollback with fresh A04 identities.
    ///
    /// # Errors
    /// Returns [`D05Error`] when identity validation or A04 orchestration fails.
    pub fn begin_rollback(
        runtime: &ActivityRuntime,
        request: &PluginChangeRequest,
        context: AttemptContext,
    ) -> Result<PluginChangeHandle, D05Error> {
        begin_change(runtime, request, context, PluginChangeKind::Rollback)
    }

    /// Start one separately-authorized Plugin removal with fresh A04 identities.
    ///
    /// # Errors
    /// Returns [`D05Error`] when identity validation or A04 orchestration fails.
    pub fn begin_removal(
        runtime: &ActivityRuntime,
        request: &PluginChangeRequest,
        context: AttemptContext,
    ) -> Result<PluginChangeHandle, D05Error> {
        begin_change(runtime, request, context, PluginChangeKind::Removal)
    }

    /// Attach independent post-update evidence without changing A04 success state.
    ///
    /// # Errors
    /// Returns [`D05Error`] if evidence or generation is invalid or handle kind is wrong.
    pub fn verify_update(
        handle: &PluginChangeHandle,
        instance_generation: u64,
        evidence_refs: Vec<EntityRef>,
    ) -> Result<PluginChangeEvidence, D05Error> {
        if handle.kind != PluginChangeKind::Update
            || instance_generation == 0
            || evidence_refs.is_empty()
        {
            return Err(D05Error::VerificationIncomplete);
        }
        Ok(PluginChangeEvidence {
            plugin_ref: handle.plugin_ref.clone(),
            revision_ref: handle.to_revision_ref.clone(),
            instance_generation,
            verified: true,
            evidence_refs,
        })
    }

    /// Attach independent post-rollback evidence.
    ///
    /// # Errors
    /// Returns [`D05Error`] if evidence is absent or the handle is not a rollback.
    pub fn verify_rollback(
        handle: &PluginChangeHandle,
        evidence_refs: &[EntityRef],
    ) -> Result<PluginChangeHandle, D05Error> {
        if handle.kind != PluginChangeKind::Rollback || evidence_refs.is_empty() {
            return Err(D05Error::VerificationIncomplete);
        }
        let mut verified = handle.clone();
        verified.verified = true;
        Ok(verified)
    }

    /// Validate every required staged removal post-condition.
    ///
    /// # Errors
    /// Returns [`D05Error::RemovalVerificationIncomplete`] unless every stage and evidence are present.
    pub fn verify_removal(
        handle: &PluginChangeHandle,
        proof: &RemovalProof,
    ) -> Result<PluginChangeHandle, D05Error> {
        let required = BTreeSet::from([
            RemovalStage::ActivationDisabled,
            RemovalStage::GrantsRevoked,
            RemovalStage::InstancesStopped,
            RemovalStage::RegistrationsRemoved,
            RemovalStage::PackageUninstalled,
            RemovalStage::CleanupVerified,
        ]);
        if handle.kind != PluginChangeKind::Removal
            || proof.completed_stages != required
            || proof.evidence_refs.is_empty()
        {
            return Err(D05Error::RemovalVerificationIncomplete);
        }
        let mut verified = handle.clone();
        verified.verified = true;
        Ok(verified)
    }

    /// Rebind one stable Plugin Instance to a replacement host generation without rekeying Ptah identity.
    ///
    /// # Errors
    /// Returns [`D05Error::StalePluginRuntime`] for non-monotonic generations or invalid Provider identity.
    pub fn replace_host(
        instance: &PluginInstanceRecord,
        provider_instance_ref: EntityRef,
        provider_generation: u64,
        instance_generation: u64,
    ) -> Result<PluginInstanceRecord, D05Error> {
        if provider_instance_ref.entity_kind != "runtime.provider_instance"
            || provider_generation <= instance.provider_generation
            || instance_generation <= instance.generation
        {
            return Err(D05Error::StalePluginRuntime);
        }
        let mut replacement = instance.clone();
        replacement.provider_instance_ref = provider_instance_ref;
        replacement.provider_generation = provider_generation;
        replacement.generation = instance_generation;
        replacement.runtime_aliases.clear();
        Ok(replacement)
    }
}

fn begin_change(
    runtime: &ActivityRuntime,
    request: &PluginChangeRequest,
    context: AttemptContext,
    kind: PluginChangeKind,
) -> Result<PluginChangeHandle, D05Error> {
    validate_request(request)?;
    let operation_kind = match kind {
        PluginChangeKind::Update => "plugin.update",
        PluginChangeKind::Rollback => "plugin.rollback",
        PluginChangeKind::Removal => "plugin.remove",
    };
    let activity_id = runtime
        .create_activity(ActivitySpec {
            request_ref: request.activity_request_ref.clone(),
            workspace_ref: request.workspace_ref.clone(),
            caller_ref: request.caller_ref.clone(),
            authority_ref: request.authority_ref.clone(),
            activity_kind: operation_kind.to_owned(),
            intent_ref: request.intent_ref.clone(),
            priority: 0,
            max_attempts: 2,
        })
        .map_err(a04_error)?;
    if runtime.admit_next().map_err(a04_error)? != Some(activity_id) {
        return Err(D05Error::ActivityRuntime(
            "plugin change activity not admitted".into(),
        ));
    }
    let side_effect_class = if kind == PluginChangeKind::Removal {
        SideEffectClass::Destructive
    } else {
        SideEffectClass::Reversible
    };
    let operation_id = runtime
        .create_operation(
            activity_id,
            OperationSpec {
                operation_kind: operation_kind.to_owned(),
                logical_target_refs: vec![
                    request.plugin_ref.clone(),
                    request.to_revision_ref.clone(),
                ],
                command_or_action_ref: request.to_revision_ref.clone(),
                side_effect_class,
                retry_class: RetryClass::ManualResumeOnly,
                idempotency_class: IdempotencyClass::OperationIdentity,
                idempotency_key: Some(format!("{operation_kind}-{activity_id}")),
                required_authority_refs: vec![request.authority_ref.clone()],
                precondition_refs: request.verification_refs.clone(),
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
    Ok(PluginChangeHandle {
        kind,
        plugin_ref: request.plugin_ref.clone(),
        from_revision_ref: request.from_revision_ref.clone(),
        to_revision_ref: request.to_revision_ref.clone(),
        activity_id,
        operation_id,
        attempt_id,
        verified: false,
    })
}

fn validate_request(request: &PluginChangeRequest) -> Result<(), D05Error> {
    if request.plugin_ref.entity_kind != "plugin.plugin"
        || request.from_revision_ref.entity_kind != "plugin.revision"
        || request.to_revision_ref.entity_kind != "plugin.revision"
        || request.workspace_ref.entity_kind != "core.workspace"
        || request.verification_refs.is_empty()
    {
        return Err(D05Error::InvalidLifecycleRecord);
    }
    Ok(())
}

fn a04_error(error: impl std::fmt::Display) -> D05Error {
    D05Error::ActivityRuntime(error.to_string())
}
