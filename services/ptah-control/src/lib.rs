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
    /// Human-visible id carried by this projection.
    pub id: String,
    /// Human-visible title carried by this projection.
    pub title: String,
    /// Human-visible runtime state carried by this projection.
    pub runtime_state: String,
    /// Human-visible worker completion carried by this projection.
    pub worker_completion: bool,
    /// Human-visible acceptance carried by this projection.
    pub acceptance: AcceptanceState,
    /// Human-visible evidence carried by this projection.
    pub evidence: Vec<String>,
    /// Human-visible limitation carried by this projection.
    pub limitation: Option<String>,
}

/// One logical Object/Artifact projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectView {
    /// Human-visible id carried by this projection.
    pub id: String,
    /// Human-visible revision carried by this projection.
    pub revision: String,
    /// Human-visible label carried by this projection.
    pub label: String,
    /// Human-visible artifact carried by this projection.
    pub artifact: bool,
    /// Human-visible materialization state carried by this projection.
    pub materialization_state: String,
    /// Human-visible evidence carried by this projection.
    pub evidence: Vec<String>,
}

/// One terminal attachment projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalView {
    /// Human-visible id carried by this projection.
    pub id: String,
    /// Human-visible activity id carried by this projection.
    pub activity_id: String,
    /// Human-visible attached carried by this projection.
    pub attached: bool,
    /// Human-visible provider id carried by this projection.
    pub provider_id: String,
    /// Human-visible provider generation carried by this projection.
    pub provider_generation: u64,
    /// Human-visible limitation carried by this projection.
    pub limitation: Option<String>,
}

/// One transfer projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferView {
    /// Human-visible id carried by this projection.
    pub id: String,
    /// Human-visible state carried by this projection.
    pub state: String,
    /// Human-visible progress percent carried by this projection.
    pub progress_percent: u8,
    /// Human-visible partial retained carried by this projection.
    pub partial_retained: bool,
    /// Human-visible evidence carried by this projection.
    pub evidence: Vec<String>,
}

/// One browser projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserView {
    /// Human-visible page id carried by this projection.
    pub page_id: String,
    /// Human-visible profile id carried by this projection.
    pub profile_id: String,
    /// Human-visible url carried by this projection.
    pub url: String,
    /// Human-visible provider id carried by this projection.
    pub provider_id: String,
    /// Human-visible provider generation carried by this projection.
    pub provider_generation: u64,
    /// Human-visible attached carried by this projection.
    pub attached: bool,
    /// Human-visible limitation carried by this projection.
    pub limitation: Option<String>,
}

/// Node health is an observed fact, not a recommendation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeHealthView {
    /// Human-visible node id carried by this projection.
    pub node_id: String,
    /// Human-visible generation carried by this projection.
    pub generation: u64,
    /// Human-visible health carried by this projection.
    pub health: String,
    /// Human-visible ready carried by this projection.
    pub ready: bool,
    /// Human-visible reachable carried by this projection.
    pub reachable: bool,
    /// Human-visible pressure carried by this projection.
    pub pressure: String,
    /// Human-visible evidence carried by this projection.
    pub evidence: Vec<String>,
}

/// Provider health is an observed fact, not a recommendation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderHealthView {
    /// Human-visible provider id carried by this projection.
    pub provider_id: String,
    /// Human-visible generation carried by this projection.
    pub generation: u64,
    /// Human-visible health carried by this projection.
    pub health: String,
    /// Human-visible limitations carried by this projection.
    pub limitations: Vec<String>,
    /// Human-visible evidence carried by this projection.
    pub evidence: Vec<String>,
}

/// Evidence-backed platform advisory. Observations and suggestions are structurally separate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticAdvisory {
    /// Human-visible id carried by this projection.
    pub id: String,
    /// Human-visible observed facts carried by this projection.
    pub observed_facts: Vec<String>,
    /// Human-visible evidence carried by this projection.
    pub evidence: Vec<String>,
    /// Human-visible suggestions carried by this projection.
    pub suggestions: Vec<String>,
    /// Human-visible uncertainty carried by this projection.
    pub uncertainty: Option<String>,
    /// Human-visible state carried by this projection.
    pub state: AdvisoryState,
}

/// Caller-controlled advisory state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryState {
    /// Represents open.
    Open,
    /// Represents dismissed.
    Dismissed,
    /// Represents deferred.
    Deferred,
    /// Represents alternative chosen.
    AlternativeChosen,
    /// Represents upgrade submitted.
    UpgradeSubmitted,
}

/// Worker formation projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerView {
    /// Human-visible formation id carried by this projection.
    pub formation_id: String,
    /// Human-visible worker id carried by this projection.
    pub worker_id: String,
    /// Human-visible role carried by this projection.
    pub role: String,
    /// Human-visible checkpoint carried by this projection.
    pub checkpoint: Option<String>,
    /// Human-visible partial result carried by this projection.
    pub partial_result: Option<String>,
    /// Human-visible conflict carried by this projection.
    pub conflict: Option<String>,
    /// Human-visible completed carried by this projection.
    pub completed: bool,
    /// Human-visible acceptance carried by this projection.
    pub acceptance: AcceptanceState,
}

/// Checkpoint/recovery status exposed to a human.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryView {
    /// Human-visible checkpoint id carried by this projection.
    pub checkpoint_id: Option<String>,
    /// Human-visible checkpoint integrity carried by this projection.
    pub checkpoint_integrity: String,
    /// Human-visible restore compatibility carried by this projection.
    pub restore_compatibility: String,
    /// Human-visible recovery verification carried by this projection.
    pub recovery_verification: String,
    /// Human-visible limitations carried by this projection.
    pub limitations: Vec<String>,
}

/// A limitation/evidence link shown without claiming more than the backing evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLink {
    /// Human-visible label carried by this projection.
    pub label: String,
    /// Human-visible reference carried by this projection.
    pub reference: String,
}

/// The complete human-visible state envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanSnapshot {
    /// Human-visible authority carried by this projection.
    pub authority: AuthorityStamp,
    /// Human-visible workspaces carried by this projection.
    pub workspaces: Vec<String>,
    /// Human-visible activities carried by this projection.
    pub activities: Vec<ActivityView>,
    /// Human-visible objects carried by this projection.
    pub objects: Vec<ObjectView>,
    /// Human-visible terminals carried by this projection.
    pub terminals: Vec<TerminalView>,
    /// Human-visible transfers carried by this projection.
    pub transfers: Vec<TransferView>,
    /// Human-visible browsers carried by this projection.
    pub browsers: Vec<BrowserView>,
    /// Human-visible nodes carried by this projection.
    pub nodes: Vec<NodeHealthView>,
    /// Human-visible providers carried by this projection.
    pub providers: Vec<ProviderHealthView>,
    /// Human-visible advisories carried by this projection.
    pub advisories: Vec<DiagnosticAdvisory>,
    /// Human-visible workers carried by this projection.
    pub workers: Vec<WorkerView>,
    /// Human-visible recovery carried by this projection.
    pub recovery: RecoveryView,
    /// Human-visible evidence links carried by this projection.
    pub evidence_links: Vec<EvidenceLink>,
}

/// Human control actions exposed by the Alpha surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    /// Represents terminal input.
    TerminalInput,
    /// Represents terminal reconnect.
    TerminalReconnect,
    /// Represents transfer pause.
    TransferPause,
    /// Represents transfer resume.
    TransferResume,
    /// Represents browser navigate.
    BrowserNavigate,
    /// Represents checkpoint request.
    CheckpointRequest,
    /// Represents workspace reconnect.
    WorkspaceReconnect,
    /// Represents advisory dismiss.
    AdvisoryDismiss,
    /// Represents advisory defer.
    AdvisoryDefer,
    /// Represents advisory choose alternative.
    AdvisoryChooseAlternative,
    /// Represents submit upgrade activity.
    SubmitUpgradeActivity,
    /// Represents accept worker result.
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
    /// Human-visible request id carried by this projection.
    pub request_id: String,
    /// Human-visible kind carried by this projection.
    pub kind: ControlKind,
    /// Human-visible target id carried by this projection.
    pub target_id: String,
    /// Human-visible expected carried by this projection.
    pub expected: AuthorityStamp,
    /// Human-visible provider id carried by this projection.
    pub provider_id: Option<String>,
    /// Human-visible expected provider generation carried by this projection.
    pub expected_provider_generation: Option<u64>,
    /// Human-visible approval id carried by this projection.
    pub approval_id: Option<String>,
    #[serde(default)]
    /// Human-visible payload carried by this projection.
    pub payload: Value,
}

/// A fenced submission. This records permission to dispatch; it is not a success Receipt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedSubmission {
    /// Human-visible request id carried by this projection.
    pub request_id: String,
    /// Human-visible kind carried by this projection.
    pub kind: ControlKind,
    /// Human-visible target id carried by this projection.
    pub target_id: String,
    /// Human-visible authority carried by this projection.
    pub authority: AuthorityStamp,
    /// Human-visible approval id carried by this projection.
    pub approval_id: Option<String>,
    /// Human-visible payload carried by this projection.
    pub payload: Value,
    /// Human-visible state carried by this projection.
    pub state: SubmissionState,
}

/// Submission state is deliberately not operation completion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionState {
    /// Represents authorized for dispatch.
    AuthorizedForDispatch,
}

/// Failure to prove current control authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlError {
    /// Represents workspace mismatch.
    WorkspaceMismatch,
    /// Represents stale workspace revision.
    StaleWorkspaceRevision,
    /// Represents session mismatch.
    SessionMismatch,
    /// Represents stale session revision.
    StaleSessionRevision,
    /// Represents node mismatch.
    NodeMismatch,
    /// Represents stale node generation.
    StaleNodeGeneration,
    /// Represents stale fence.
    StaleFence,
    /// Represents provider generation incomplete.
    ProviderGenerationIncomplete,
    /// Represents stale provider generation.
    StaleProviderGeneration,
    /// Represents approval required.
    ApprovalRequired,
    /// Represents unknown target.
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
    /// Represents desktop.
    Desktop,
    /// Represents tablet.
    Tablet,
    /// Represents mobile.
    Mobile,
}

/// Which panels and controls a client should render at a given viewport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponsiveProjection {
    /// Human-visible viewport carried by this projection.
    pub viewport: Viewport,
    /// Human-visible panels carried by this projection.
    pub panels: Vec<String>,
    /// Human-visible critical controls carried by this projection.
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
    /// Human-visible selected workspace id carried by this projection.
    pub selected_workspace_id: String,
    /// Human-visible selected session id carried by this projection.
    pub selected_session_id: String,
    /// Human-visible selected panel carried by this projection.
    pub selected_panel: String,
    /// Human-visible expanded panels carried by this projection.
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
    /// Represents advisory missing evidence.
    AdvisoryMissingEvidence(String),
    /// Represents advisory missing suggestion.
    AdvisoryMissingSuggestion(String),
    /// Represents accepted result missing evidence.
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

/// One read-only D08 Application platform row attached to the D01 shell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationPlatformView {
    /// Stable Application identity.
    pub application_id: String,
    /// Exact Application Revision identity.
    pub application_revision: String,
    /// D08 roadmap platform class.
    pub platform: String,
    /// Mechanical D08 source/disposition.
    pub disposition: String,
    /// Stable Application Session identity when one exists.
    pub session_id: Option<String>,
    /// Application Session lifecycle when one exists.
    pub lifecycle: Option<String>,
    /// Application execution locality when one exists.
    pub locality: Option<String>,
    /// Current bounded Application availability.
    pub availability: String,
    /// Stable Display Session identity when one exists.
    pub display_session_id: Option<String>,
    /// Display Session lifecycle when one exists.
    pub display_lifecycle: Option<String>,
    /// Retained evidence references rendered as canonical IDs.
    pub evidence: Vec<String>,
    /// Explicit limitations retained from the owning D08 runtime.
    pub limitations: Vec<String>,
}

/// Read-only D01 Human Workspace shell v2 projection built from a validated A14 snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceShellV2Projection {
    /// Exact profile identity accepted by the D01 roadmap amendment.
    pub profile_id: String,
    /// Exact canonical authority stamp inherited from A14.
    pub authority: AuthorityStamp,
    /// Supplemental validated D08 Application platform projections.
    pub applications: Vec<ApplicationPlatformView>,
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
        applications: Vec::new(),
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

fn d08_platform_label(platform: ptah_application_runtime::PlatformClass) -> &'static str {
    use ptah_application_runtime::PlatformClass;
    match platform {
        PlatformClass::LinuxNative => "linux_native",
        PlatformClass::LinuxPackaged => "linux_packaged",
        PlatformClass::Android => "android",
        PlatformClass::WindowsNode => "windows_node",
        PlatformClass::WindowsVm => "windows_vm",
        PlatformClass::MacOsNode => "mac_os_node",
        PlatformClass::IosSimulator => "ios_simulator",
    }
}

fn d08_session_lifecycle_label(
    lifecycle: ptah_application_runtime::ApplicationSessionLifecycle,
) -> &'static str {
    use ptah_application_runtime::ApplicationSessionLifecycle;
    match lifecycle {
        ApplicationSessionLifecycle::Preparing => "preparing",
        ApplicationSessionLifecycle::Running => "running",
        ApplicationSessionLifecycle::Degraded => "degraded",
        ApplicationSessionLifecycle::Detached => "detached",
        ApplicationSessionLifecycle::Checkpointing => "checkpointing",
        ApplicationSessionLifecycle::Recovering => "recovering",
        ApplicationSessionLifecycle::Stopped => "stopped",
        ApplicationSessionLifecycle::Failed => "failed",
        ApplicationSessionLifecycle::Uncertain => "uncertain",
    }
}

fn d08_locality_label(locality: ptah_application_runtime::SessionLocality) -> &'static str {
    use ptah_application_runtime::SessionLocality;
    match locality {
        SessionLocality::NodeLocal => "node_local",
        SessionLocality::DeviceLocal => "device_local",
        SessionLocality::RemoteService => "remote_service",
    }
}

fn d08_availability_label(
    availability: ptah_application_runtime::ApplicationAvailability,
) -> &'static str {
    use ptah_application_runtime::ApplicationAvailability;
    match availability {
        ApplicationAvailability::Full => "full",
        ApplicationAvailability::HeadlessOnly => "headless_only",
        ApplicationAvailability::DisplayOnly => "display_only",
        ApplicationAvailability::SemanticOnly => "semantic_only",
        ApplicationAvailability::Partial => "partial",
        ApplicationAvailability::Recovering => "recovering",
        ApplicationAvailability::Unavailable => "unavailable",
        ApplicationAvailability::Unknown => "unknown",
    }
}

fn d08_display_lifecycle_label(
    lifecycle: ptah_application_runtime::DisplayLifecycle,
) -> &'static str {
    use ptah_application_runtime::DisplayLifecycle;
    match lifecycle {
        DisplayLifecycle::Preparing => "preparing",
        DisplayLifecycle::Streaming => "streaming",
        DisplayLifecycle::Degraded => "degraded",
        DisplayLifecycle::Detached => "detached",
        DisplayLifecycle::Recovering => "recovering",
        DisplayLifecycle::Closed => "closed",
        DisplayLifecycle::Failed => "failed",
    }
}

/// Attach validated D08 Application platform snapshots to an existing read-only D01 shell projection.
///
/// This changes presentation data only. It does not mutate D08 runtime state, create controls,
/// change the D01 authority stamp, or infer backing sessions that were not supplied.
pub fn project_application_platform_views(
    shell: &mut WorkspaceShellV2Projection,
    snapshots: &[ptah_application_runtime::ApplicationPlatformSnapshot],
) {
    shell.applications = snapshots
        .iter()
        .map(|snapshot| match snapshot {
            ptah_application_runtime::ApplicationPlatformSnapshot::Session {
                platform,
                session,
                display,
            } => {
                let mut evidence = session
                    .evidence_refs
                    .iter()
                    .map(|reference| reference.entity_id.to_string())
                    .collect::<Vec<_>>();
                let mut limitations = session.limitations.clone();
                if let Some(display) = display {
                    evidence.extend(
                        display
                            .evidence_refs
                            .iter()
                            .map(|reference| reference.entity_id.to_string()),
                    );
                    limitations.extend(display.limitations.iter().cloned());
                }
                ApplicationPlatformView {
                    application_id: session.application_ref.entity_id.to_string(),
                    application_revision: session.application_revision_ref.entity_id.to_string(),
                    platform: String::from(d08_platform_label(*platform)),
                    disposition: String::from("session"),
                    session_id: Some(session.session_ref.entity_id.to_string()),
                    lifecycle: Some(String::from(d08_session_lifecycle_label(session.lifecycle))),
                    locality: Some(String::from(d08_locality_label(session.locality))),
                    availability: String::from(d08_availability_label(session.availability)),
                    display_session_id: display
                        .as_ref()
                        .map(|item| item.display_session_ref.entity_id.to_string()),
                    display_lifecycle: display
                        .as_ref()
                        .map(|item| String::from(d08_display_lifecycle_label(item.lifecycle))),
                    evidence,
                    limitations,
                }
            }
            ptah_application_runtime::ApplicationPlatformSnapshot::RemoteRequirement {
                application_ref,
                application_revision_ref,
                requirement,
            } => ApplicationPlatformView {
                application_id: application_ref.entity_id.to_string(),
                application_revision: application_revision_ref.entity_id.to_string(),
                platform: String::from(d08_platform_label(requirement.platform)),
                disposition: String::from("requires_remote_node"),
                session_id: None,
                lifecycle: None,
                locality: None,
                availability: String::from("unavailable"),
                display_session_id: None,
                display_lifecycle: None,
                evidence: requirement
                    .evidence_refs
                    .iter()
                    .map(|reference| reference.entity_id.to_string())
                    .collect(),
                limitations: requirement.limitations.clone(),
            },
        })
        .collect();
}
