#![forbid(unsafe_code)]
//! D04 Recipes and service registry composition.
//!
//! This crate composes frozen Ptah Recipe, execution, Provider and authority
//! primitives. It does not create a scheduler, semantic chooser, approval
//! authority, Plugin lifecycle, or network-exposure authority.

mod error;
mod operation;
mod plan;
mod precondition;
mod recipe_store;
mod schedule;

pub use error::D04Error;
pub use operation::{
    OperationCatalog, OperationDescriptorRevision, OperationEffectClass, OperationResolution,
};
pub use plan::{
    CredentialBinding, ExecutionPlanManifest, ExecutionStage, ParameterBinding, ParameterValue,
    PlannedOperation,
};
pub use precondition::{
    ExactPrecondition, ObservedPrecondition, PreconditionConflict, PreconditionKind,
    evaluate_preconditions,
};
pub use recipe_store::{
    AcceptanceDecision, AcceptedRevision, CompiledPlanRecordInput, CreatedRecipe,
    MaterialBindingInput, PlanRequirementResultInput, PlanStepMappingInput, ProofRequirementInput,
    RecipeAcceptanceInput, RecipeInput, RecipeProposalInput, RecipeRecordView, RecipeRevisionInput,
    RecipeStepInput, RecipeStore,
};
pub use schedule::{
    ScheduleEvaluation, ScheduleKind, ScheduleSpec, ScheduledRecipeInvocation, TimingMode,
    evaluate_schedule,
};
