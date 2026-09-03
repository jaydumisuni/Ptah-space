//! D08 canonical Application Window identity and observation validation.

use crate::{
    ApplicationSessionLifecycle, ApplicationSessionProjection, D08Error, ensure_fresh_interval,
};
use ptah_identifiers::EntityRef;
use ptah_provider_api::{EndpointAlias, ProviderGeneration};
use serde::{Deserialize, Serialize};

/// Frozen Application Window lifecycle projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowLifecycle {
    /// Stable Window incarnation exists without visibility proof.
    Created,
    /// Fresh observation proves the Window visible.
    Visible,
    /// Fresh observation proves the Window hidden.
    Hidden,
    /// Window exists with bounded degraded geometry/display/input state.
    Degraded,
    /// A newer Window generation superseded this incarnation.
    Replaced,
    /// Window destruction was observed.
    Closed,
    /// Provider cannot currently prove Window state.
    Unknown,
}

/// Frozen Application Window state-claim vocabulary used by D08 observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStateClaim {
    /// Window is visible.
    Visible,
    /// Window is hidden.
    Hidden,
    /// Window is minimized.
    Minimized,
    /// Window is maximized.
    Maximized,
    /// Window is fullscreen.
    Fullscreen,
    /// Window has focus.
    Focused,
    /// Window is active.
    Active,
    /// Window is occluded.
    Occluded,
    /// Window is outside the active visible region.
    Offscreen,
    /// Window was destroyed.
    Destroyed,
    /// State cannot be established.
    Unknown,
}

/// Stable canonical Application Window projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationWindowProjection {
    /// Stable canonical Window identity, independent of backend handles.
    pub window_ref: EntityRef,
    /// Owning Application Session.
    pub application_session_ref: EntityRef,
    /// Provider generation that owns this Window incarnation.
    pub provider_generation: ProviderGeneration,
    /// Monotonic Window incarnation generation.
    pub generation: u64,
    /// Current Window lifecycle.
    pub lifecycle: WindowLifecycle,
    /// Backend handles retained only as scoped aliases/evidence.
    pub aliases: Vec<EndpointAlias>,
    /// Supporting evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Expiry of the current state observation, when one exists.
    pub observation_valid_until: Option<String>,
}

/// Fresh Provider observation applied to a stable Application Window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowObservation {
    /// Provider generation that produced the observation.
    pub provider_generation: ProviderGeneration,
    /// Window state claims observed together.
    pub state_claims: Vec<WindowStateClaim>,
    /// Supporting evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Observation timestamp.
    pub observed_at: String,
    /// Expiry timestamp for this observation.
    pub valid_until: String,
}

/// Create a stable Window incarnation bound to an exact Application Session.
///
/// # Errors
/// Returns [`D08Error`] when the Application Session cannot own a Window or creation evidence is
/// absent. Backend aliases never participate in canonical identity construction.
pub fn create_application_window(
    session: &ApplicationSessionProjection,
    aliases: Vec<EndpointAlias>,
    evidence_refs: Vec<EntityRef>,
) -> Result<ApplicationWindowProjection, D08Error> {
    if !matches!(
        session.lifecycle,
        ApplicationSessionLifecycle::Preparing
            | ApplicationSessionLifecycle::Running
            | ApplicationSessionLifecycle::Degraded
    ) {
        return Err(D08Error::InvalidSessionState);
    }
    if evidence_refs.is_empty() {
        return Err(D08Error::MissingWindowEvidence);
    }
    Ok(ApplicationWindowProjection {
        window_ref: EntityRef::new("application.window")
            .map_err(|_| D08Error::IdentityConstructionFailed)?,
        application_session_ref: session.session_ref.clone(),
        provider_generation: session.provider_generation,
        generation: 1,
        lifecycle: WindowLifecycle::Created,
        aliases,
        evidence_refs,
        observation_valid_until: None,
    })
}

/// Apply one fresh same-generation Window observation.
///
/// # Errors
/// Returns [`D08Error`] when generation/evidence/freshness is invalid or stale.
pub fn apply_window_observation(
    mut window: ApplicationWindowProjection,
    observation: WindowObservation,
    now: &str,
) -> Result<ApplicationWindowProjection, D08Error> {
    if observation.provider_generation != window.provider_generation {
        return Err(D08Error::ProviderContextMismatch);
    }
    if observation.evidence_refs.is_empty() || observation.state_claims.is_empty() {
        return Err(D08Error::MissingWindowEvidence);
    }
    ensure_fresh_interval(&observation.observed_at, &observation.valid_until, now)?;

    window.lifecycle = if observation
        .state_claims
        .contains(&WindowStateClaim::Destroyed)
    {
        WindowLifecycle::Closed
    } else if observation
        .state_claims
        .contains(&WindowStateClaim::Visible)
    {
        WindowLifecycle::Visible
    } else if observation.state_claims.contains(&WindowStateClaim::Hidden)
        || observation
            .state_claims
            .contains(&WindowStateClaim::Minimized)
    {
        WindowLifecycle::Hidden
    } else if observation
        .state_claims
        .contains(&WindowStateClaim::Unknown)
    {
        WindowLifecycle::Unknown
    } else {
        WindowLifecycle::Degraded
    };
    window.evidence_refs.extend(observation.evidence_refs);
    window.observation_valid_until = Some(observation.valid_until);
    Ok(window)
}
