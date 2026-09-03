//! D08 local Application Session preparation and read-back verification.

use crate::{
    ApplicationOperation, CompatibilityDecision, D08Error, DisplayLifecycle,
    DisplaySessionProjection, NodeLocalCompatibility, WindowLifecycle, ApplicationWindowProjection,
};
use native_process::{ProcessRecord, ProcessState};
use ptah_activity_runtime::AttemptContext;
use ptah_identifiers::EntityRef;
use ptah_provider_api::ProviderGeneration;
use serde::{Deserialize, Serialize};

/// Frozen execution locality used by D08 Application and Display Session projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLocality {
    /// Application executes on the current Node.
    NodeLocal,
    /// Application executes through an owning Device runtime.
    DeviceLocal,
    /// Future remote-service locality backed by real Programme E authority.
    RemoteService,
}

/// Frozen Application Session lifecycle projection used by D08.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationSessionLifecycle {
    /// Exact compatibility and Attempt exist; runtime readiness is not yet proven.
    Preparing,
    /// Current process and application readiness are proven.
    Running,
    /// Only explicitly bounded application scope is available.
    Degraded,
    /// Runtime remains active without a Shell client attachment.
    Detached,
    /// Checkpoint components are being captured.
    Checkpointing,
    /// A new runtime generation is undergoing verification.
    Recovering,
    /// Runtime stopped and cleanup is verified.
    Stopped,
    /// Session terminated with retained failure evidence.
    Failed,
    /// Runtime or external effects require reconciliation.
    Uncertain,
}

/// Current bounded Application availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationAvailability {
    /// Graphical/runtime scope is fully proven for the admitted operation.
    Full,
    /// Only headless scope is proven.
    HeadlessOnly,
    /// Only display scope is proven.
    DisplayOnly,
    /// Only semantic scope is proven.
    SemanticOnly,
    /// Explicitly bounded partial scope is available.
    Partial,
    /// Availability is undergoing recovery verification.
    Recovering,
    /// No usable application scope is currently proven.
    Unavailable,
    /// Available scope cannot currently be established.
    Unknown,
}

/// Local launch mode admitted by compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchMode {
    /// No graphical Window/Display readiness is requested.
    Headless,
    /// Visible Window and streaming Display readiness are required.
    Graphical,
}

/// Exact input for creating one stable local Application Session in `preparing`.
#[derive(Debug, Clone)]
pub struct LocalLaunchRequest<'a> {
    /// Owning Workspace.
    pub workspace_ref: EntityRef,
    /// Exact Workspace Revision.
    pub workspace_revision_ref: EntityRef,
    /// Exact materialization backing the launch.
    pub materialization_ref: EntityRef,
    /// Positive materialization generation.
    pub materialization_generation: u64,
    /// Stable Application identity.
    pub application_ref: EntityRef,
    /// Exact Application Revision.
    pub application_revision_ref: EntityRef,
    /// Exact installation evidence.
    pub installation_ref: EntityRef,
    /// Owning A04 Activity.
    pub activity_ref: EntityRef,
    /// Owning A04 Operation.
    pub operation_ref: EntityRef,
    /// Exact A04 Attempt.
    pub attempt_ref: EntityRef,
    /// Fixed physical A04 Attempt context.
    pub attempt_context: &'a AttemptContext,
    /// Privacy policies governing application/display evidence.
    pub privacy_policy_refs: Vec<EntityRef>,
    /// Evidence for the admitted launch request.
    pub command_evidence_refs: Vec<EntityRef>,
    /// Request timestamp.
    pub requested_at: String,
    /// Requested local launch mode.
    pub mode: LaunchMode,
}

/// Provider-neutral D08 Application Session projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationSessionProjection {
    /// Stable Application Session identity.
    pub session_ref: EntityRef,
    /// Owning Workspace.
    pub workspace_ref: EntityRef,
    /// Exact Workspace Revision.
    pub workspace_revision_ref: EntityRef,
    /// Exact materialization.
    pub materialization_ref: EntityRef,
    /// Materialization generation.
    pub materialization_generation: u64,
    /// Stable Application identity.
    pub application_ref: EntityRef,
    /// Exact Application Revision.
    pub application_revision_ref: EntityRef,
    /// Installation evidence.
    pub installation_ref: EntityRef,
    /// Compatibility record that admitted the local session.
    pub compatibility_ref: Option<EntityRef>,
    /// Exact Provider Instance.
    pub provider_instance_ref: EntityRef,
    /// Provider generation fence.
    pub provider_generation: ProviderGeneration,
    /// Execution locality.
    pub locality: SessionLocality,
    /// Local Node when locality is Node-local.
    pub node_ref: Option<EntityRef>,
    /// Local Node generation when locality is Node-local.
    pub node_generation: Option<u64>,
    /// Provider connection epoch where applicable.
    pub connection_epoch: Option<u64>,
    /// Owning Device Session for Device-local composition.
    pub device_session_ref: Option<EntityRef>,
    /// A04 Activity.
    pub activity_ref: EntityRef,
    /// A04 Operation.
    pub operation_ref: EntityRef,
    /// A04 Attempt.
    pub attempt_ref: EntityRef,
    /// Canonical process references proven for this session.
    pub process_refs: Vec<EntityRef>,
    /// Canonical Window references proven for this session.
    pub window_refs: Vec<EntityRef>,
    /// Canonical Display Session references proven for this session.
    pub display_session_refs: Vec<EntityRef>,
    /// Canonical semantic-context references proven for this session.
    pub semantic_context_refs: Vec<EntityRef>,
    /// Current bounded availability.
    pub availability: ApplicationAvailability,
    /// Privacy policies governing retained evidence.
    pub privacy_policy_refs: Vec<EntityRef>,
    /// Current Application Session lifecycle.
    pub lifecycle: ApplicationSessionLifecycle,
    /// Launch mode retained so later verification never infers graphical/headless intent.
    pub launch_mode: LaunchMode,
    /// Supporting evidence retained by D08.
    pub evidence_refs: Vec<EntityRef>,
    /// Explicit bounded limitations.
    pub limitations: Vec<String>,
    /// Session creation/start timestamp.
    pub started_at: String,
}

/// Fresh A05/Window/Display read-back presented for local verification.
pub struct LocalReadBack<'a> {
    /// Current A05 process record.
    pub process: &'a ProcessRecord,
    /// Current same-session Window for graphical launch.
    pub window: Option<&'a ApplicationWindowProjection>,
    /// Current same-session Display Session for graphical launch.
    pub display: Option<&'a DisplaySessionProjection>,
    /// Independent application-readiness evidence.
    pub readiness_evidence_refs: Vec<EntityRef>,
    /// Verification observation time.
    pub observed_at: String,
}

/// Prepare one stable Node-local Application Session without claiming runtime readiness.
///
/// # Errors
/// Returns [`D08Error`] when exact compatibility, Attempt context, materialization, privacy, or
/// request evidence is absent, stale, contradictory, or bound to another execution context.
pub fn prepare_local_application_session(
    request: LocalLaunchRequest<'_>,
    compatibility: &NodeLocalCompatibility,
    now: &str,
) -> Result<ApplicationSessionProjection, D08Error> {
    if request.materialization_generation == 0 {
        return Err(D08Error::InvalidMaterializationGeneration);
    }
    if request.privacy_policy_refs.is_empty() {
        return Err(D08Error::MissingPrivacyPolicy);
    }
    if request.command_evidence_refs.is_empty() {
        return Err(D08Error::MissingLaunchEvidence);
    }
    if request.application_revision_ref != compatibility.application_revision_ref {
        return Err(D08Error::ApplicationRevisionMismatch);
    }

    let expected_operation = match request.mode {
        LaunchMode::Headless => ApplicationOperation::LaunchHeadless,
        LaunchMode::Graphical => ApplicationOperation::LaunchGraphical,
    };
    if compatibility.operation != expected_operation {
        return Err(D08Error::CompatibilityOperationMismatch);
    }
    compatibility.validate_at(now)?;
    if !matches!(
        compatibility.decision,
        CompatibilityDecision::Compatible
            | CompatibilityDecision::CompatibleWithConditions
            | CompatibilityDecision::CompatibleForPartialScope
    ) {
        return Err(D08Error::CompatibilityNotAdmitted);
    }

    let context = request.attempt_context;
    if context.node_ref != compatibility.node_ref
        || context.node_generation != compatibility.node_generation
        || context.producer_instance_ref != compatibility.provider_instance_ref
        || context.provider_generation != compatibility.provider_generation.value()
        || context.connection_epoch == 0
    {
        return Err(D08Error::AttemptContextMismatch);
    }

    let mut evidence_refs = compatibility.evidence_refs.clone();
    evidence_refs.extend(request.command_evidence_refs.iter().cloned());

    Ok(ApplicationSessionProjection {
        session_ref: new_ref("application.session")?,
        workspace_ref: request.workspace_ref,
        workspace_revision_ref: request.workspace_revision_ref,
        materialization_ref: request.materialization_ref,
        materialization_generation: request.materialization_generation,
        application_ref: request.application_ref,
        application_revision_ref: request.application_revision_ref,
        installation_ref: request.installation_ref,
        compatibility_ref: Some(compatibility.compatibility_ref.clone()),
        provider_instance_ref: compatibility.provider_instance_ref.clone(),
        provider_generation: compatibility.provider_generation,
        locality: SessionLocality::NodeLocal,
        node_ref: Some(compatibility.node_ref.clone()),
        node_generation: Some(compatibility.node_generation),
        connection_epoch: Some(context.connection_epoch),
        device_session_ref: None,
        activity_ref: request.activity_ref,
        operation_ref: request.operation_ref,
        attempt_ref: request.attempt_ref,
        process_refs: Vec::new(),
        window_refs: Vec::new(),
        display_session_refs: Vec::new(),
        semantic_context_refs: Vec::new(),
        availability: ApplicationAvailability::Unavailable,
        privacy_policy_refs: request.privacy_policy_refs,
        lifecycle: ApplicationSessionLifecycle::Preparing,
        launch_mode: request.mode,
        evidence_refs,
        limitations: compatibility.limitations.clone(),
        started_at: request.requested_at,
    })
}

/// Promote a prepared local session only from exact current A05 and independent readiness proof.
///
/// # Errors
/// Returns [`D08Error`] for stale/foreign process, Window, Display, or readiness evidence.
pub fn verify_local_application_session(
    mut preparing: ApplicationSessionProjection,
    read_back: LocalReadBack<'_>,
) -> Result<ApplicationSessionProjection, D08Error> {
    if preparing.lifecycle != ApplicationSessionLifecycle::Preparing
        || preparing.locality != SessionLocality::NodeLocal
    {
        return Err(D08Error::InvalidSessionState);
    }
    validate_process_context(&preparing, read_back.process)?;
    if read_back.readiness_evidence_refs.is_empty() {
        return Err(D08Error::MissingLaunchEvidence);
    }
    parse_utc_datetime(&read_back.observed_at).ok_or(D08Error::InvalidTimestamp)?;

    match preparing.launch_mode {
        LaunchMode::Graphical => {
            let window = read_back.window.ok_or(D08Error::GraphicalReadinessMissing)?;
            let display = read_back.display.ok_or(D08Error::GraphicalReadinessMissing)?;
            validate_graphical_window(&preparing, window, &read_back.observed_at)?;
            validate_graphical_display(&preparing, display, &read_back.observed_at)?;
            preparing.lifecycle = ApplicationSessionLifecycle::Running;
            preparing.availability = ApplicationAvailability::Full;
            preparing.process_refs = vec![read_back.process.process_ref.clone()];
            preparing.window_refs = vec![window.window_ref.clone()];
            preparing.display_session_refs = vec![display.display_session_ref.clone()];
        }
        LaunchMode::Headless => {
            if read_back.window.is_some() || read_back.display.is_some() {
                return Err(D08Error::HeadlessReadinessMismatch);
            }
            preparing.lifecycle = ApplicationSessionLifecycle::Degraded;
            preparing.availability = ApplicationAvailability::HeadlessOnly;
            preparing.process_refs = vec![read_back.process.process_ref.clone()];
        }
    }
    preparing
        .evidence_refs
        .extend(read_back.readiness_evidence_refs);
    Ok(preparing)
}

fn validate_process_context(
    session: &ApplicationSessionProjection,
    process: &ProcessRecord,
) -> Result<(), D08Error> {
    if process.state != ProcessState::Running
        || process.provider_instance_ref != session.provider_instance_ref
        || process.provider_generation != session.provider_generation
        || Some(&process.node_ref) != session.node_ref.as_ref()
        || Some(process.node_generation) != session.node_generation
    {
        return Err(D08Error::ProcessContextMismatch);
    }
    Ok(())
}

fn validate_graphical_window(
    session: &ApplicationSessionProjection,
    window: &ApplicationWindowProjection,
    now: &str,
) -> Result<(), D08Error> {
    if window.application_session_ref != session.session_ref {
        return Err(D08Error::SessionBindingMismatch);
    }
    if window.provider_generation != session.provider_generation {
        return Err(D08Error::ProviderContextMismatch);
    }
    if window.lifecycle != WindowLifecycle::Visible {
        return Err(D08Error::GraphicalReadinessMissing);
    }
    ensure_projection_current(window.observation_valid_until.as_deref(), now)
}

fn validate_graphical_display(
    session: &ApplicationSessionProjection,
    display: &DisplaySessionProjection,
    now: &str,
) -> Result<(), D08Error> {
    if display.application_session_ref != session.session_ref {
        return Err(D08Error::SessionBindingMismatch);
    }
    if display.provider_instance_ref != session.provider_instance_ref
        || display.provider_generation != session.provider_generation
        || display.locality != session.locality
        || display.node_ref != session.node_ref
        || display.node_generation != session.node_generation
        || display.connection_epoch != session.connection_epoch
    {
        return Err(D08Error::ProviderContextMismatch);
    }
    if display.lifecycle != DisplayLifecycle::Streaming {
        return Err(D08Error::GraphicalReadinessMissing);
    }
    ensure_projection_current(display.observation_valid_until.as_deref(), now)
}

pub(crate) fn ensure_fresh_interval(
    observed_at: &str,
    valid_until: &str,
    now: &str,
) -> Result<(), D08Error> {
    let observed_at = parse_utc_datetime(observed_at).ok_or(D08Error::InvalidTimestamp)?;
    let valid_until = parse_utc_datetime(valid_until).ok_or(D08Error::InvalidTimestamp)?;
    let now = parse_utc_datetime(now).ok_or(D08Error::InvalidTimestamp)?;
    if observed_at > now || valid_until <= now || valid_until <= observed_at {
        return Err(D08Error::StaleObservation);
    }
    Ok(())
}

fn ensure_projection_current(valid_until: Option<&str>, now: &str) -> Result<(), D08Error> {
    let valid_until = valid_until.ok_or(D08Error::GraphicalReadinessMissing)?;
    let valid_until = parse_utc_datetime(valid_until).ok_or(D08Error::InvalidTimestamp)?;
    let now = parse_utc_datetime(now).ok_or(D08Error::InvalidTimestamp)?;
    if valid_until <= now {
        return Err(D08Error::StaleObservation);
    }
    Ok(())
}

fn new_ref(kind: &str) -> Result<EntityRef, D08Error> {
    EntityRef::new(kind).map_err(|_| D08Error::IdentityConstructionFailed)
}

fn parse_utc_datetime(value: &str) -> Option<(u16, u8, u8, u8, u8, u8, u32)> {
    let body = value.strip_suffix('Z')?;
    let (whole, nanos) = match body.split_once('.') {
        Some((whole, fraction)) => {
            if fraction.is_empty()
                || fraction.len() > 9
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            let mut padded = String::from(fraction);
            padded.extend(std::iter::repeat_n('0', 9 - fraction.len()));
            (whole, padded.parse().ok()?)
        }
        None => (body, 0),
    };
    if whole.len() != 19
        || whole.as_bytes().get(4) != Some(&b'-')
        || whole.as_bytes().get(7) != Some(&b'-')
        || whole.as_bytes().get(10) != Some(&b'T')
        || whole.as_bytes().get(13) != Some(&b':')
        || whole.as_bytes().get(16) != Some(&b':')
    {
        return None;
    }
    let year = whole.get(0..4)?.parse().ok()?;
    let month = whole.get(5..7)?.parse().ok()?;
    let day = whole.get(8..10)?.parse().ok()?;
    let hour = whole.get(11..13)?.parse().ok()?;
    let minute = whole.get(14..16)?.parse().ok()?;
    let second = whole.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    Some((year, month, day, hour, minute, second, nanos))
}
