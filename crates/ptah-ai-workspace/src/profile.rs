//! Provider-independent D02 runtime profile descriptors.

/// Accepted neutral AI Project Workspace profile identity.
pub const AI_PROJECT_PROFILE_ID: &str = "ptah.workspace.ai_project.v1";
/// Accepted compatible deep Workspace operations profile identity.
pub const OPERATIONS_PROFILE_ID: &str = "ptah.workspace.operations.v2";

/// Mechanical operation effect vocabulary accepted by ADR-0037.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationEffectClass {
    /// Observe without mutation.
    Observe,
    /// Produce a draft without publishing.
    Draft,
    /// Simulate a possible effect.
    Simulate,
    /// Mutate bounded state.
    Mutate,
    /// Publish externally visible state.
    Publish,
    /// Destructive operation.
    Destructive,
    /// Operation with an externally authoritative side effect.
    ExternalSideEffect,
}

/// Mechanical Object availability vocabulary accepted by ADR-0037.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvailabilityState {
    /// External reference only; bytes are not locally materialized.
    ExternalReference,
    /// Derived searchable/indexed reference.
    IndexedReference,
    /// Explicit read-only mount.
    MountedReadOnly,
    /// Explicitly materialized local copy.
    MaterializedCopy,
    /// Generated Artifact.
    GeneratedArtifact,
}

/// Mechanical Activity/result vocabulary accepted by ADR-0037.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityResultState {
    /// Mechanically succeeded.
    Succeeded,
    /// Mechanically failed.
    Failed,
    /// Caller/provider declined execution.
    Declined,
    /// Cancelled.
    Cancelled,
    /// Not run.
    NotRun,
    /// Some retained work completed but the whole result did not.
    PartiallyCompleted,
}

/// Mechanical schedule timing vocabulary accepted by ADR-0037.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingMode {
    /// Exact caller-specified time.
    Exact,
    /// Caller-specified flexible time window.
    FlexibleWindow,
    /// Condition-dependent execution.
    ConditionDependent,
}

/// Neutral D02 composition descriptor. This is code metadata, not canonical Ptah state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProfileDescriptor {
    /// Exact profile identity.
    pub profile_id: &'static str,
    /// Ptah has no semantic decision authority in this profile.
    pub decision_authority: bool,
    /// Ptah has no context-selection authority.
    pub context_selection_authority: bool,
    /// Ptah has no review-verdict authority.
    pub review_authority: bool,
    /// Ptah has no approval authority.
    pub approval_authority: bool,
    /// The profile introduces no new Core entity.
    pub new_core_entity_required: bool,
}

/// D02-relevant `operations.v2` compatibility metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationsCompatibilityDescriptor {
    /// Exact profile identity.
    pub profile_id: &'static str,
    /// Accepted mechanical effect classes.
    pub effect_classes: Vec<OperationEffectClass>,
    /// Accepted availability states.
    pub availability_states: Vec<AvailabilityState>,
    /// Accepted result states.
    pub result_states: Vec<ActivityResultState>,
    /// Accepted timing modes.
    pub timing_modes: Vec<TimingMode>,
    /// External Provider permission is not a Ptah Grant.
    pub provider_permission_separate_from_grant: bool,
    /// Ptah Grant is not caller/human approval.
    pub grant_separate_from_caller_approval: bool,
}

/// Return the immutable neutral AI Project Workspace runtime descriptor.
#[must_use]
pub fn ai_project_profile() -> RuntimeProfileDescriptor {
    RuntimeProfileDescriptor {
        profile_id: AI_PROJECT_PROFILE_ID,
        decision_authority: false,
        context_selection_authority: false,
        review_authority: false,
        approval_authority: false,
        new_core_entity_required: false,
    }
}

/// Return the immutable D02-relevant deep Workspace operations compatibility descriptor.
#[must_use]
pub fn operations_profile() -> OperationsCompatibilityDescriptor {
    use ActivityResultState::{Cancelled, Declined, Failed, NotRun, PartiallyCompleted, Succeeded};
    use AvailabilityState::{
        ExternalReference, GeneratedArtifact, IndexedReference, MaterializedCopy, MountedReadOnly,
    };
    use OperationEffectClass::{
        Destructive, Draft, ExternalSideEffect, Mutate, Observe, Publish, Simulate,
    };
    use TimingMode::{ConditionDependent, Exact, FlexibleWindow};

    OperationsCompatibilityDescriptor {
        profile_id: OPERATIONS_PROFILE_ID,
        effect_classes: vec![
            Observe,
            Draft,
            Simulate,
            Mutate,
            Publish,
            Destructive,
            ExternalSideEffect,
        ],
        availability_states: vec![
            ExternalReference,
            IndexedReference,
            MountedReadOnly,
            MaterializedCopy,
            GeneratedArtifact,
        ],
        result_states: vec![
            Succeeded,
            Failed,
            Declined,
            Cancelled,
            NotRun,
            PartiallyCompleted,
        ],
        timing_modes: vec![Exact, FlexibleWindow, ConditionDependent],
        provider_permission_separate_from_grant: true,
        grant_separate_from_caller_approval: true,
    }
}
