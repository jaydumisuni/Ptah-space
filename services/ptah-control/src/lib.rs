#![forbid(unsafe_code)]
//! Human-facing Ptah projection and protected-control fencing for A14 and D01.
//!
//! This crate is deliberately a projection boundary. Canonical runtime truth remains in the
//! owning Ptah runtimes; client layout, cached state and diagnostic advice never become authority.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Exact authority facts carried by a human-visible projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityStamp {
    /// Stable Workspace identity.
    pub workspace_id: String,
    /// Canonical Workspace revision observed by the projection.
    pub workspace_revision: u64,
    /// Stable Session identity.
    pub session_id: String,
    /// Session revision observed by the projection.
    pub session_revision: u64,
    /// Stable Node identity.
    pub node_id: String,
    /// Current Node Generation.
    pub node_generation: u64,
    /// Exact Provider Generations keyed by stable Provider identity.
    pub provider_generations: BTreeMap<String, u64>,
    /// Current control fence. A stale client must not manufacture a fresh fence.
    pub fence: String,
}

/// Human acceptance is intentionally independent from worker/runtime completion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceState {
    /// No caller/reviewer decision has been recorded.
    Pending,
    /// Caller/reviewer explicitly accepted the result.
    Accepted,
    /// Caller/reviewer explicitly rejected the result.
    Rejected,
}

/// One durable Activity row for the Activity Centre.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityView {
    pub id: String,
    pub title: String,
    pub runtime_state: String,
    pub worker_completion: bool,
    pub acceptance: AcceptanceState,
    pub evidence: Vec<String>,
    pub limitation: Option<String>,
}

/// One logical Object/Artifact projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectView {
    pub id: String,
    pub revision: String,
    pub label: String,
    pub artifact: bool,
    pub materialization_state: String,
    pub evidence: Vec<String>,
}

/// One terminal attachment projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalView {
    pub id: String,
    pub activity_id: String,
    pub attached: bool,
    pub provider_id: String,
    pub provider_generation: u64,
    pub limitation: Option<String>,
}

/// One transfer projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferView {
    pub id: String,
    pub state: String,
    pub progress_percent: u8,
    pub partial_retained: bool,
    pub evidence: Vec<String>,
}

/// One browser projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserView {
    pub page_id: String,
    pub profile_id: String,
    pub url: String,
    pub provider_id: String,
    pub provider_generation: u64,
    pub attached: bool,
    pub limitation: Option<String>,
}

/// Node health is an observed fact, not a recommendation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeHealthView {
    pub node_id: String,
    pub generation: u64,
    pub health: String,
    pub ready: bool,
    pub reachable: bool,
    pub pressure: String,
    pub evidence: Vec<String>,
}

/// Provider health is an observed fact, not a recommendation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderHealthView {
    pub provider_id: String,
    pub generation: u64,
    pub health: String,
    pub limitations: Vec<String>,
    pub evidence: Vec<String>,
}

/// Evidence-backed platform advisory. Observations and suggestions are structurally separate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticAdvisory {
    pub id: String,
    pub observed_facts: Vec<String>,
    pub evidence: Vec<String>,
    pub suggestions: Vec<String>,
    pub uncertainty: Option<String>,
    pub state: AdvisoryState,
}

/// Caller-controlled advisory state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryState {
    Open,
    Dismissed,
    Deferred,
    AlternativeChosen,
    UpgradeSubmitted,
}

/// Worker formation projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerView {
    pub formation_id: String,
    pub worker_id: String,
    pub role: String,
    pub checkpoint: Option<String>,
    pub partial_result: Option<String>,
    pub conflict: Option<String>,
    pub completed: bool,
    pub acceptance: AcceptanceState,
}

/// Checkpoint/recovery status exposed to a human.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryView {
    pub checkpoint_id: Option<String>,
    pub checkpoint_integrity: String,
    pub restore_compatibility: String,
    pub recovery_verification: String,
    pub limitations: Vec<String>,
}

/// A limitation/evidence link shown without claiming more than the backing evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLink {
    pub label: String,
    pub reference: String,
}

/// The complete human-visible state envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanSnapshot {
    pub authority: AuthorityStamp,
    pub workspaces: Vec<String>,
    pub activities: Vec<ActivityView>,
    pub objects: Vec<ObjectView>,
    pub terminals: Vec<TerminalView>,
    pub transfers: Vec<TransferView>,
    pub browsers: Vec<BrowserView>,
    pub nodes: Vec<NodeHealthView>,
    pub providers: Vec<ProviderHealthView>,
    pub advisories: Vec<DiagnosticAdvisory>,
    pub workers: Vec<WorkerView>,
    pub recovery: RecoveryView,
    pub evidence_links: Vec<EvidenceLink>,
}

/// Human control actions exposed by the Alpha surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    TerminalInput,
    TerminalReconnect,
    TransferPause,
    TransferResume,
    BrowserNavigate,
    CheckpointRequest,
    WorkspaceReconnect,
    AdvisoryDismiss,
    AdvisoryDefer,
    AdvisoryChooseAlternative,
    SubmitUpgradeActivity,
    AcceptWorkerResult,
}

impl ControlKind {
    /// Controls that can change runtime or caller-owned acceptance state.
    #[must_use]
    pub const fn is_protected(&self) -> bool {
        true
    }

    /// Advisory actions never authorize themselves. Upgrade submission additionally needs approval.
    #[must_use]
    pub const fn requires_explicit_approval(&self) -> bool {
        matches!(self, Self::SubmitUpgradeActivity | Self::AcceptWorkerResult)
    }
}

/// A human request tied to the exact projection from which it was issued.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HumanControlRequest {
    pub request_id: String,
    pub kind: ControlKind,
    pub target_id: String,
    pub expected: AuthorityStamp,
    pub provider_id: Option<String>,
    pub expected_provider_generation: Option<u64>,
    pub approval_id: Option<String>,
    #[serde(default)]
    pub payload: Value,
}

/// A fenced submission. This records permission to dispatch; it is not a success Receipt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedSubmission {
    pub request_id: String,
    pub kind: ControlKind,
    pub target_id: String,
    pub authority: AuthorityStamp,
    pub approval_id: Option<String>,
    pub payload: Value,
    pub state: SubmissionState,
}

/// Submission state is deliberately not operation completion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionState {
    AuthorizedForDispatch,
}

/// Failure to prove current control authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlError {
    WorkspaceMismatch,
    StaleWorkspaceRevision,
    SessionMismatch,
    StaleSessionRevision,
    NodeMismatch,
    StaleNodeGeneration,
    StaleFence,
    ProviderGenerationIncomplete,
    StaleProviderGeneration,
    ApprovalRequired,
    UnknownTarget,
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::WorkspaceMismatch => "workspace identity mismatch",
                Self::StaleWorkspaceRevision => "stale workspace revision",
                Self::SessionMismatch => "session identity mismatch",
                Self::StaleSessionRevision => "stale session revision",
                Self::NodeMismatch => "node identity mismatch",
                Self::StaleNodeGeneration => "stale node generation",
                Self::StaleFence => "stale control fence",
                Self::ProviderGenerationIncomplete => "provider generation evidence incomplete",
                Self::StaleProviderGeneration => "stale provider generation",
                Self::ApprovalRequired => "explicit caller approval required",
                Self::UnknownTarget => "target is absent from the current projection",
            }
        )
    }
}

impl std::error::Error for ControlError {}

/// Validate a protected human request against canonical current projection facts.
///
/// Success means only that dispatch is authorized at this boundary. It does not claim that the
/// requested operation ran or succeeded.
///
/// # Errors
///
/// Returns [`ControlError`] when the supplied authority projection is stale or mismatched, when a
/// Provider generation is incomplete or stale, when the target is absent, or when explicit caller
/// approval required by the requested control is absent or blank.
pub fn authorize_control(
    current: &HumanSnapshot,
    request: HumanControlRequest,
) -> Result<AuthorizedSubmission, ControlError> {
    validate_authority(&current.authority, &request.expected)?;
    validate_provider(current, &request)?;
    validate_target(current, &request)?;
    if request.kind.requires_explicit_approval()
        && request
            .approval_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err(ControlError::ApprovalRequired);
    }

    Ok(AuthorizedSubmission {
        request_id: request.request_id,
        kind: request.kind,
        target_id: request.target_id,
        authority: current.authority.clone(),
        approval_id: request.approval_id,
        payload: request.payload,
        state: SubmissionState::AuthorizedForDispatch,
    })
}

fn validate_authority(
    current: &AuthorityStamp,
    expected: &AuthorityStamp,
) -> Result<(), ControlError> {
    if current.workspace_id != expected.workspace_id {
        return Err(ControlError::WorkspaceMismatch);
    }
    if current.workspace_revision != expected.workspace_revision {
        return Err(ControlError::StaleWorkspaceRevision);
    }
    if current.session_id != expected.session_id {
        return Err(ControlError::SessionMismatch);
    }
    if current.session_revision != expected.session_revision {
        return Err(ControlError::StaleSessionRevision);
    }
    if current.node_id != expected.node_id {
        return Err(ControlError::NodeMismatch);
    }
    if current.node_generation != expected.node_generation {
        return Err(ControlError::StaleNodeGeneration);
    }
    if current.fence != expected.fence {
        return Err(ControlError::StaleFence);
    }
    Ok(())
}

fn validate_provider(
    current: &HumanSnapshot,
    request: &HumanControlRequest,
) -> Result<(), ControlError> {
    match (&request.provider_id, request.expected_provider_generation) {
        (None, None) => Ok(()),
        (Some(provider_id), Some(expected_generation)) => {
            let Some(current_generation) = current.authority.provider_generations.get(provider_id)
            else {
                return Err(ControlError::ProviderGenerationIncomplete);
            };
            if *current_generation != expected_generation {
                return Err(ControlError::StaleProviderGeneration);
            }
            if request.expected.provider_generations.get(provider_id) != Some(&expected_generation)
            {
                return Err(ControlError::StaleProviderGeneration);
            }
            Ok(())
        }
        _ => Err(ControlError::ProviderGenerationIncomplete),
    }
}

fn validate_target(
    current: &HumanSnapshot,
    request: &HumanControlRequest,
) -> Result<(), ControlError> {
    let exists = match request.kind {
        ControlKind::TerminalInput | ControlKind::TerminalReconnect => current
            .terminals
            .iter()
            .any(|item| item.id == request.target_id),
        ControlKind::TransferPause | ControlKind::TransferResume => current
            .transfers
            .iter()
            .any(|item| item.id == request.target_id),
        ControlKind::BrowserNavigate => current
            .browsers
            .iter()
            .any(|item| item.page_id == request.target_id),
        ControlKind::CheckpointRequest | ControlKind::WorkspaceReconnect => {
            current.authority.workspace_id == request.target_id
        }
        ControlKind::AdvisoryDismiss
        | ControlKind::AdvisoryDefer
        | ControlKind::AdvisoryChooseAlternative
        | ControlKind::SubmitUpgradeActivity => current
            .advisories
            .iter()
            .any(|item| item.id == request.target_id),
        ControlKind::AcceptWorkerResult => current
            .workers
            .iter()
            .any(|item| item.worker_id == request.target_id),
    };
    exists.then_some(()).ok_or(ControlError::UnknownTarget)
}

/// Responsive shell classes. Critical controls are invariant across supported projections.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Viewport {
    Desktop,
    Tablet,
    Mobile,
}

/// Which panels and controls a client should render at a given viewport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponsiveProjection {
    pub viewport: Viewport,
    pub panels: Vec<String>,
    pub critical_controls: Vec<ControlKind>,
}

/// Build layout metadata without hiding approval or recovery controls on narrow clients.
#[must_use]
pub fn responsive_projection(viewport: Viewport) -> ResponsiveProjection {
    let panels = vec![
        "home",
        "workspaces",
        "activities",
        "objects",
        "terminals",
        "transfers",
        "browser",
        "health",
        "diagnostics",
        "workers",
        "recovery",
        "operations",
        "availability",
        "results",
        "editor",
        "applications_devices",
        "media_documents",
        "schedules",
        "conflicts",
        "control_transfer",
        "views_limits",
        "evidence",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let critical_controls = vec![
        ControlKind::CheckpointRequest,
        ControlKind::WorkspaceReconnect,
        ControlKind::SubmitUpgradeActivity,
        ControlKind::AcceptWorkerResult,
    ];
    ResponsiveProjection {
        viewport,
        panels,
        critical_controls,
    }
}

/// Client-owned reopen state. It contains presentation choices only, never a Grant or Fence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientReopenState {
    pub selected_workspace_id: String,
    pub selected_session_id: String,
    pub selected_panel: String,
    pub expanded_panels: BTreeSet<String>,
}

/// Reconcile presentation state against a fresh canonical snapshot after reopening a client.
#[must_use]
pub fn reconcile_reopen_state(
    cached: &ClientReopenState,
    fresh: &HumanSnapshot,
) -> ClientReopenState {
    let workspace_matches = cached.selected_workspace_id == fresh.authority.workspace_id;
    let session_matches = cached.selected_session_id == fresh.authority.session_id;
    ClientReopenState {
        selected_workspace_id: fresh.authority.workspace_id.clone(),
        selected_session_id: fresh.authority.session_id.clone(),
        selected_panel: if workspace_matches && session_matches {
            cached.selected_panel.clone()
        } else {
            String::from("home")
        },
        expanded_panels: cached.expanded_panels.clone(),
    }
}

/// Validate structural rules that prevent advisory/runtime truth collapse in a snapshot.
///
/// # Errors
///
/// Returns [`SnapshotError`] when an advisory lacks observed facts, evidence or a separate
/// suggestion, or when an accepted completed result lacks retained evidence.
pub fn validate_snapshot(snapshot: &HumanSnapshot) -> Result<(), SnapshotError> {
    for advisory in &snapshot.advisories {
        if advisory.observed_facts.is_empty() || advisory.evidence.is_empty() {
            return Err(SnapshotError::AdvisoryMissingEvidence(advisory.id.clone()));
        }
        if advisory.suggestions.is_empty() {
            return Err(SnapshotError::AdvisoryMissingSuggestion(
                advisory.id.clone(),
            ));
        }
    }
    for activity in &snapshot.activities {
        if activity.worker_completion
            && activity.acceptance == AcceptanceState::Accepted
            && activity.evidence.is_empty()
        {
            return Err(SnapshotError::AcceptedResultMissingEvidence(
                activity.id.clone(),
            ));
        }
    }
    Ok(())
}

/// Snapshot structural error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    AdvisoryMissingEvidence(String),
    AdvisoryMissingSuggestion(String),
    AcceptedResultMissingEvidence(String),
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AdvisoryMissingEvidence(id) => write!(f, "advisory {id} lacks observed evidence"),
            Self::AdvisoryMissingSuggestion(id) => write!(f, "advisory {id} lacks a suggestion"),
            Self::AcceptedResultMissingEvidence(id) => {
                write!(f, "accepted activity {id} lacks evidence")
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

/// Mechanical effect class exposed by the D01 operation catalog.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationEffectClass {
    /// Observation only; no requested mutation.
    Observe,
    /// Creates a caller-reviewable draft without publishing it.
    Draft,
    /// Computes a hypothetical result without requesting the external effect.
    Simulate,
    /// Changes Ptah or caller-owned state when separately authorized.
    Mutate,
    /// Publishes a caller-owned result to an external boundary.
    Publish,
    /// Destructive mutation requiring an independently reviewed adapter family.
    Destructive,
    /// Requests an effect through an external Provider.
    ExternalSideEffect,
}

/// Truth state for an Object or Artifact reference in the D01 shell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityState {
    /// Only an external reference is held.
    ExternalReference,
    /// The external reference has been indexed without local bytes.
    IndexedReference,
    /// The source is mounted read-only.
    MountedReadOnly,
    /// A distinct local copy has been materialized.
    MaterializedCopy,
    /// Ptah retains a generated Artifact.
    GeneratedArtifact,
}

/// Final result vocabulary surfaced by D01 without collapsing caller acceptance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityResultState {
    /// The owning runtime reports successful completion.
    Succeeded,
    /// The owning runtime reports failure.
    Failed,
    /// The caller declined the requested work.
    Declined,
    /// The Activity was cancelled.
    Cancelled,
    /// The Activity was intentionally not run.
    NotRun,
    /// Some output was retained but the Activity did not fully complete.
    PartiallyCompleted,
}

/// Timing modes understood by the D01 shell. They do not create schedules by themselves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimingMode {
    /// Run at the exact caller-specified time.
    Exact,
    /// Run within the caller-specified flexible window.
    Flexible,
    /// Evaluate a caller-specified condition on its configured cadence.
    Condition,
}

/// Requirement visibility/state for a D01 operation boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementState {
    /// The operation contract requires this boundary.
    Required,
    /// This shell boundary does not require this boundary.
    NotRequired,
    /// The canonical source does not expose whether this boundary is required.
    NotExposed,
}

/// Relationship between external Provider permission and Ptah confirmation policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderPermissionRelation {
    /// Provider permission and Ptah confirmation are independently evaluated facts.
    Separate,
}

/// One mechanically discoverable operation presented by the D01 shell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationDescriptorView {
    /// Stable operation identifier used by the human client.
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Mechanical effect classification.
    pub effect: OperationEffectClass,
    /// Ptah Grant requirement when the canonical source exposes it.
    pub grant_requirement: RequirementState,
    /// Current Grant visibility/status at this projection boundary.
    pub grant_state: String,
    /// Caller confirmation requirement at this shell boundary.
    pub confirmation_requirement: RequirementState,
    /// Current caller-confirmation policy/status.
    pub confirmation_state: String,
    /// Relationship between Provider permission and Ptah confirmation policy.
    pub provider_permission_relation: ProviderPermissionRelation,
    /// Current Provider access visibility/status at this projection boundary.
    pub provider_access_state: String,
    /// Local byte materialization requirement when the canonical source exposes it.
    pub materialization_requirement: RequirementState,
    /// Explicit limitations retained with the descriptor.
    pub limits: Vec<String>,
}

/// D01 availability projection for one current Object or Artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityTruthView {
    /// Stable Object or Artifact identity.
    pub object_id: String,
    /// Exact current Revision reference.
    pub revision: String,
    /// Current availability/materialization truth.
    pub state: AvailabilityState,
    /// Local path only when canonical state actually supplies one; A14 does not.
    pub local_path: Option<String>,
    /// Retained evidence supporting the state.
    pub evidence: Vec<String>,
}

/// Stable result handle projected from one Activity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StableResultView {
    /// Stable handle usable by clients without treating a rendered card as authority.
    pub handle: String,
    /// Stable Activity identity.
    pub activity_id: String,
    /// Mechanical final-state classification, if the runtime state is final.
    pub final_state: Option<ActivityResultState>,
    /// Caller/reviewer acceptance remains independent from runtime completion.
    pub acceptance: String,
    /// Whether a partial Artifact is explicitly retained, when current canonical state says so.
    pub partial_retained: Option<bool>,
    /// Whether this projection currently exposes bounded paging for the result.
    pub pageable: bool,
    /// Whether this projection currently exposes searchable result access.
    pub searchable: bool,
    /// Explicit limitations retained with the result handle.
    pub limitations: Vec<String>,
}

/// Caller-defined schedule projection. D01 does not manufacture instances when none exist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleTruthView {
    /// Stable schedule identity.
    pub schedule_id: String,
    /// Caller-selected timing mode.
    pub timing_mode: TimingMode,
    /// Exact caller-owned input Revision supplied to the scheduled Activity.
    pub input_revision: String,
    /// Provider identity, when the caller selected one.
    pub provider_id: Option<String>,
    /// Grant identity, when required by the owning runtime.
    pub grant_id: Option<String>,
    /// Current mechanical schedule state.
    pub state: String,
}

/// Unresolved conflict or moved-target/precondition state shown to the caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictTruthView {
    /// Stable projection identity for the conflict.
    pub conflict_id: String,
    /// Stable target whose evidence conflicts.
    pub target_id: String,
    /// Exact conflict detail from canonical evidence.
    pub detail: String,
    /// Mechanical conflict state.
    pub state: String,
    /// Ptah leaves semantic reconciliation to the caller/reviewer.
    pub caller_resolution_required: bool,
}

/// A replaceable typed View over canonical Ptah state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedViewDescriptor {
    /// Stable View identity.
    pub view_id: String,
    /// Kind of backing canonical record.
    pub backing_kind: String,
    /// Stable backing record identity.
    pub backing_id: String,
    /// Whether clients may replace the rendering without changing backing truth.
    pub replaceable: bool,
    /// Views are never authority in D01.
    pub authoritative: bool,
}

/// Read-only D01 Human Workspace shell v2 projection built from a validated A14 snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceShellV2Projection {
    /// Exact profile identity accepted by the D01 roadmap amendment.
    pub profile_id: String,
    /// Exact canonical authority stamp inherited from A14.
    pub authority: AuthorityStamp,
    /// Typed operation catalog for controls already owned by A14.
    pub operations: Vec<OperationDescriptorView>,
    /// Reference/materialization truth.
    pub availability: Vec<AvailabilityTruthView>,
    /// Stable result handles and final-state projections.
    pub results: Vec<StableResultView>,
    /// Caller-defined schedules only; empty means none are canonically present.
    pub schedules: Vec<ScheduleTruthView>,
    /// Timing modes the shell can present when a caller supplies a schedule.
    pub supported_timing_modes: Vec<TimingMode>,
    /// Unresolved worker/precondition conflicts.
    pub conflicts: Vec<ConflictTruthView>,
    /// Replaceable renderings of canonical records.
    pub views: Vec<TypedViewDescriptor>,
    /// Visible product and evidence limitations.
    pub limits: Vec<String>,
    /// Ptah does not select semantic context.
    pub context_selection_authority: bool,
    /// Ptah does not approve caller work.
    pub approval_authority: bool,
    /// Ptah does not choose the caller's next action.
    pub next_action_authority: bool,
}

/// Failure to project D01 truth without inventing semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShellV2Error {
    /// A canonical materialization state is outside the accepted D01 vocabulary.
    UnknownAvailabilityState(String),
}

impl fmt::Display for ShellV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownAvailabilityState(value) => {
                write!(f, "unknown availability/materialization state: {value}")
            }
        }
    }
}

impl std::error::Error for ShellV2Error {}

fn availability_state(value: &str) -> Result<AvailabilityState, ShellV2Error> {
    match value {
        "external_reference" => Ok(AvailabilityState::ExternalReference),
        "indexed_reference" => Ok(AvailabilityState::IndexedReference),
        "mounted_read_only" => Ok(AvailabilityState::MountedReadOnly),
        "materialized_copy" => Ok(AvailabilityState::MaterializedCopy),
        "generated_artifact" => Ok(AvailabilityState::GeneratedArtifact),
        other => Err(ShellV2Error::UnknownAvailabilityState(String::from(other))),
    }
}

fn activity_result_state(value: &str) -> Option<ActivityResultState> {
    match value {
        "completed" | "succeeded" => Some(ActivityResultState::Succeeded),
        "failed" => Some(ActivityResultState::Failed),
        "declined" => Some(ActivityResultState::Declined),
        "cancelled" => Some(ActivityResultState::Cancelled),
        "not_run" => Some(ActivityResultState::NotRun),
        "partially_completed" => Some(ActivityResultState::PartiallyCompleted),
        _ => None,
    }
}

fn acceptance_label(value: &AcceptanceState) -> String {
    String::from(match value {
        AcceptanceState::Pending => "pending",
        AcceptanceState::Accepted => "accepted",
        AcceptanceState::Rejected => "rejected",
    })
}

fn operation_descriptor(
    id: &str,
    label: &str,
    effect: OperationEffectClass,
    confirmation_requirement: RequirementState,
) -> OperationDescriptorView {
    OperationDescriptorView {
        id: String::from(id),
        label: String::from(label),
        effect,
        grant_requirement: RequirementState::NotExposed,
        grant_state: String::from("not_exposed_by_a14_projection"),
        confirmation_state: String::from(match confirmation_requirement {
            RequirementState::Required => "explicit_reference_required",
            RequirementState::NotRequired => "not_required_by_this_shell_boundary",
            RequirementState::NotExposed => "not_exposed_by_a14_projection",
        }),
        confirmation_requirement,
        provider_permission_relation: ProviderPermissionRelation::Separate,
        provider_access_state: String::from("provider_specific_not_exposed_by_a14_projection"),
        materialization_requirement: RequirementState::NotExposed,
        limits: vec![
            String::from(
                "authorization records permission to dispatch; it is not completion proof",
            ),
            String::from(
                "Grant and external Provider access status are not present in the A14 snapshot and are therefore not inferred",
            ),
        ],
    }
}

fn build_availability_views(
    snapshot: &HumanSnapshot,
) -> Result<Vec<AvailabilityTruthView>, ShellV2Error> {
    snapshot
        .objects
        .iter()
        .map(|item| {
            Ok(AvailabilityTruthView {
                object_id: item.id.clone(),
                revision: item.revision.clone(),
                state: availability_state(&item.materialization_state)?,
                local_path: None,
                evidence: item.evidence.clone(),
            })
        })
        .collect()
}

fn build_result_views(snapshot: &HumanSnapshot) -> Vec<StableResultView> {
    snapshot
        .activities
        .iter()
        .map(|item| {
            let mut limitations = item.limitation.iter().cloned().collect::<Vec<_>>();
            limitations.push(String::from(
                "incremental page/search access is not exposed by the current A14 snapshot boundary",
            ));
            StableResultView {
                handle: format!("activity:{}", item.id),
                activity_id: item.id.clone(),
                final_state: activity_result_state(&item.runtime_state),
                acceptance: acceptance_label(&item.acceptance),
                partial_retained: None,
                pageable: false,
                searchable: false,
                limitations,
            }
        })
        .collect()
}

fn build_conflict_views(snapshot: &HumanSnapshot) -> Vec<ConflictTruthView> {
    snapshot
        .workers
        .iter()
        .filter_map(|worker| {
            worker.conflict.as_ref().map(|detail| ConflictTruthView {
                conflict_id: format!("worker-conflict:{}", worker.worker_id),
                target_id: worker.worker_id.clone(),
                detail: detail.clone(),
                state: String::from("unresolved"),
                caller_resolution_required: true,
            })
        })
        .collect()
}

fn build_typed_views(snapshot: &HumanSnapshot) -> Vec<TypedViewDescriptor> {
    let activity_views = snapshot
        .activities
        .iter()
        .map(|activity| TypedViewDescriptor {
            view_id: format!("activity-view:{}", activity.id),
            backing_kind: String::from("activity"),
            backing_id: activity.id.clone(),
            replaceable: true,
            authoritative: false,
        });
    let object_views = snapshot.objects.iter().map(|object| TypedViewDescriptor {
        view_id: format!("object-view:{}", object.id),
        backing_kind: String::from(if object.artifact {
            "artifact"
        } else {
            "object"
        }),
        backing_id: object.id.clone(),
        replaceable: true,
        authoritative: false,
    });
    activity_views.chain(object_views).collect()
}

fn operation_catalog() -> Vec<OperationDescriptorView> {
    use OperationEffectClass::{ExternalSideEffect, Mutate};
    use RequirementState::{NotRequired, Required};
    vec![
        operation_descriptor(
            "terminal_input",
            "Send terminal input",
            ExternalSideEffect,
            NotRequired,
        ),
        operation_descriptor(
            "terminal_reconnect",
            "Reconnect terminal",
            Mutate,
            NotRequired,
        ),
        operation_descriptor("transfer_pause", "Pause transfer", Mutate, NotRequired),
        operation_descriptor("transfer_resume", "Resume transfer", Mutate, NotRequired),
        operation_descriptor(
            "browser_navigate",
            "Navigate browser",
            ExternalSideEffect,
            NotRequired,
        ),
        operation_descriptor(
            "checkpoint_request",
            "Create checkpoint",
            Mutate,
            NotRequired,
        ),
        operation_descriptor(
            "workspace_reconnect",
            "Reconnect workspace",
            Mutate,
            NotRequired,
        ),
        operation_descriptor("advisory_dismiss", "Dismiss advisory", Mutate, NotRequired),
        operation_descriptor("advisory_defer", "Defer advisory", Mutate, NotRequired),
        operation_descriptor(
            "advisory_choose_alternative",
            "Choose advisory alternative",
            Mutate,
            NotRequired,
        ),
        operation_descriptor(
            "submit_upgrade_activity",
            "Submit approved upgrade Activity",
            Mutate,
            Required,
        ),
        operation_descriptor(
            "accept_worker_result",
            "Accept worker result",
            Mutate,
            Required,
        ),
    ]
}

fn workspace_shell_limits() -> Vec<String> {
    vec![
        String::from("operation authorization is not completion proof"),
        String::from("typed Views are replaceable projections and never runtime authority"),
        String::from(
            "Ptah does not select context, approve results, or choose the caller's next action",
        ),
        String::from(
            "external Provider permission and Ptah confirmation policy remain separate facts",
        ),
    ]
}

/// Build the D01 Human Workspace shell v2 projection from current canonical A14 truth.
///
/// This function is intentionally read-only. It does not create Grants, approvals, schedules,
/// materialized paths, semantic reconciliations, or operation success claims.
///
/// # Errors
///
/// Returns [`ShellV2Error`] when a canonical availability/materialization state cannot be mapped
/// exactly to the accepted D01 vocabulary.
pub fn build_workspace_shell_v2_projection(
    snapshot: &HumanSnapshot,
) -> Result<WorkspaceShellV2Projection, ShellV2Error> {
    Ok(WorkspaceShellV2Projection {
        profile_id: String::from("ptah.workspace.operations.v2"),
        authority: snapshot.authority.clone(),
        operations: operation_catalog(),
        availability: build_availability_views(snapshot)?,
        results: build_result_views(snapshot),
        schedules: Vec::new(),
        supported_timing_modes: vec![
            TimingMode::Exact,
            TimingMode::Flexible,
            TimingMode::Condition,
        ],
        conflicts: build_conflict_views(snapshot),
        views: build_typed_views(snapshot),
        limits: workspace_shell_limits(),
        context_selection_authority: false,
        approval_authority: false,
        next_action_authority: false,
    })
}
