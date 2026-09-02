//! D02 AI Project Workspace runtime acceptance corpus.

use ptah_ai_workspace::{
    ActivityResultState, AvailabilityState, OperationEffectClass, TimingMode, ai_project_profile,
    operations_profile,
};

#[test]
fn d02_exposes_both_neutral_profile_ids_without_ptah_decision_authority() {
    let ai = ai_project_profile();
    let ops = operations_profile();

    assert_eq!(ai.profile_id, "ptah.workspace.ai_project.v1");
    assert_eq!(ops.profile_id, "ptah.workspace.operations.v2");
    assert!(!ai.decision_authority);
    assert!(!ai.context_selection_authority);
    assert!(!ai.review_authority);
    assert!(!ai.approval_authority);
    assert!(!ai.new_core_entity_required);
}

#[test]
fn operations_v2_vocabularies_match_adr0037() {
    use ActivityResultState::{Cancelled, Declined, Failed, NotRun, PartiallyCompleted, Succeeded};
    use AvailabilityState::{
        ExternalReference, GeneratedArtifact, IndexedReference, MaterializedCopy, MountedReadOnly,
    };
    use OperationEffectClass::{
        Destructive, Draft, ExternalSideEffect, Mutate, Observe, Publish, Simulate,
    };
    use TimingMode::{ConditionDependent, Exact, FlexibleWindow};

    let ops = operations_profile();
    assert_eq!(
        ops.effect_classes,
        vec![
            Observe,
            Draft,
            Simulate,
            Mutate,
            Publish,
            Destructive,
            ExternalSideEffect,
        ]
    );
    assert_eq!(
        ops.availability_states,
        vec![
            ExternalReference,
            IndexedReference,
            MountedReadOnly,
            MaterializedCopy,
            GeneratedArtifact,
        ]
    );
    assert_eq!(
        ops.result_states,
        vec![
            Succeeded,
            Failed,
            Declined,
            Cancelled,
            NotRun,
            PartiallyCompleted
        ]
    );
    assert_eq!(
        ops.timing_modes,
        vec![Exact, FlexibleWindow, ConditionDependent]
    );
    assert!(ops.provider_permission_separate_from_grant);
    assert!(ops.grant_separate_from_caller_approval);
}
