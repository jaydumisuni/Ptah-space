//! D08 Application-platform validation failures.

use thiserror::Error;

/// Failures produced by the D08 application-platform composition boundary.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum D08Error {
    /// Compatibility evidence required by the frozen contract is absent.
    #[error("D08 compatibility evidence is missing")]
    MissingCompatibilityEvidence,
    /// Compatibility is expired, stale, or was not current at the requested observation time.
    #[error("D08 compatibility is stale or expired")]
    StaleCompatibility,
    /// Conditional compatibility omitted the conditions that bound the compatible scope.
    #[error("D08 compatibility conditions are missing")]
    MissingCompatibilityConditions,
    /// A mandatory requirement contradicts a compatible top-level decision.
    #[error("D08 mandatory compatibility requirement is unsatisfied")]
    MandatoryRequirementUnsatisfied,
    /// The requested platform requires Programme E remote-Node authority.
    #[error("D08 platform requires Programme E remote Node authority")]
    RemoteNodeRequired,
    /// No current node-local compatibility record can authorize the requested local operation.
    #[error("D08 node-local compatibility is missing")]
    MissingNodeLocalCompatibility,
    /// The supplied compatibility record covers a different operation.
    #[error("D08 compatibility operation mismatch")]
    CompatibilityOperationMismatch,
    /// Compatibility exists but its top-level decision cannot admit execution.
    #[error("D08 compatibility decision does not admit execution")]
    CompatibilityNotAdmitted,
    /// Exact Application Revision differs from compatibility authority.
    #[error("D08 application revision mismatch")]
    ApplicationRevisionMismatch,
    /// Materialization generation must be positive.
    #[error("D08 materialization generation must be positive")]
    InvalidMaterializationGeneration,
    /// Required privacy policy evidence is absent.
    #[error("D08 privacy policy is missing")]
    MissingPrivacyPolicy,
    /// Launch/request/readiness evidence is absent.
    #[error("D08 launch evidence is missing")]
    MissingLaunchEvidence,
    /// A04 Attempt context differs from the compatibility execution context.
    #[error("D08 attempt context mismatch")]
    AttemptContextMismatch,
    /// A05 process read-back differs from the prepared Application Session context.
    #[error("D08 process context mismatch")]
    ProcessContextMismatch,
    /// Graphical readiness lacks current Window and Display proof.
    #[error("D08 graphical readiness evidence is missing")]
    GraphicalReadinessMissing,
    /// Headless verification received graphical Window/Display evidence that was not admitted.
    #[error("D08 headless readiness includes unexpected graphical evidence")]
    HeadlessReadinessMismatch,
    /// Application/Window/Display Session identity binding differs.
    #[error("D08 session binding mismatch")]
    SessionBindingMismatch,
    /// Provider instance/generation/locality binding differs.
    #[error("D08 provider context mismatch")]
    ProviderContextMismatch,
    /// Current Application Session lifecycle cannot perform the requested transition.
    #[error("D08 application session state does not permit this operation")]
    InvalidSessionState,
    /// Window creation/observation evidence is absent.
    #[error("D08 window evidence is missing")]
    MissingWindowEvidence,
    /// Display Session has no stable declared surface.
    #[error("D08 display surface is missing")]
    MissingDisplaySurface,
    /// Display Session preparation/frame evidence is absent.
    #[error("D08 display evidence is missing")]
    MissingDisplayEvidence,
    /// Display Observation names a surface outside the prepared Display Session.
    #[error("D08 display surface mismatch")]
    DisplaySurfaceMismatch,
    /// Window/Display observation is expired, future-dated, or otherwise stale.
    #[error("D08 observation is stale")]
    StaleObservation,
    /// C10 Device Session does not own the supplied Android Application Session.
    #[error("D08 Android Device/Application Session binding mismatch")]
    AndroidSessionMismatch,
    /// C10 Provider instance/generation/connection epoch is not current across the Android pair.
    #[error("D08 Android Provider context mismatch")]
    AndroidProviderContextMismatch,
    /// C10 Android Application Session is not verified visible/current enough for full availability.
    #[error("D08 Android Application Session is unavailable")]
    AndroidApplicationUnavailable,
    /// Canonical identity could not be constructed for a D08 projection.
    #[error("D08 canonical identity construction failed")]
    IdentityConstructionFailed,
    /// A timestamp is not a strict UTC `Z` timestamp understood by this frozen boundary.
    #[error("D08 timestamp is not canonical UTC-Z")]
    InvalidTimestamp,
}
