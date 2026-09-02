#![forbid(unsafe_code)]
//! D04 Recipes and service registry composition.
//!
//! This crate composes frozen Ptah Recipe, execution, Provider and authority
//! primitives. It does not create a scheduler, semantic chooser, approval
//! authority, Plugin lifecycle, or network-exposure authority.

mod adapters;
mod dispatcher;
mod error;
mod operation;
mod plan;
mod precondition;
mod recipe_store;
mod schedule;
mod service_registry;

pub use dispatcher::{
    RecipeDispatchMapping, RecipeDispatchRequest, RecipeDispatcher, RecipeOperationMapping,
};
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
pub use service_registry::{
    ContainerAuthorityScope, ContainerMountAccess, ContainerMountScope, ContainerNetworkScope,
    PortProtocol, PortRegistration, ServiceRegistration, ServiceRegistry, ServiceResolution,
    validate_container_authority,
};
