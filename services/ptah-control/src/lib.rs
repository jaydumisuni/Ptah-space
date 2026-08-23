#![forbid(unsafe_code)]
//! Human-facing Ptah projection and protected-control fencing for A14.
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
