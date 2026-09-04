//! D08 provider-neutral Display Session preparation and frame observation validation.

use crate::session::ensure_fresh_interval;
use crate::{ApplicationSessionLifecycle, ApplicationSessionProjection, D08Error, SessionLocality};
use ptah_identifiers::EntityRef;
use ptah_provider_api::ProviderGeneration;
use serde::{Deserialize, Serialize};

/// Frozen Display Session lifecycle projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayLifecycle {
    /// Display backend and stable surfaces exist without pixel proof.
    Preparing,
    /// Fresh frame/surface evidence proves pixels are available.
    Streaming,
    /// Quality, geometry, input, or recording scope is partially available.
    Degraded,
    /// Client is detached while display backend may remain active.
    Detached,
    /// A new display generation is undergoing verification.
    Recovering,
    /// Display resources and streams are cleaned up.
    Closed,
    /// Display ended with retained failure evidence.
    Failed,
}

/// Input capability exposed by one Display Session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputCapability {
    /// No input is exposed.
    None,
    /// Display can only be observed.
    ObserveOnly,
    /// Keyboard input is available.
    Keyboard,
    /// Pointer input is available.
    Pointer,
    /// Touch input is available.
    Touch,
    /// Clipboard integration is available.
    Clipboard,
    /// Semantic application control is available.
    Semantic,
    /// Registered input capability outside the core vocabulary.
    OtherRegistered,
}

/// Exact preparation request for one Display Session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplaySessionRequest {
    /// Exact owning Application Session.
    pub application_session_ref: EntityRef,
    /// Exact Provider Instance.
    pub provider_instance_ref: EntityRef,
    /// Provider generation fence.
    pub provider_generation: ProviderGeneration,
    /// Display execution locality.
    pub locality: SessionLocality,
    /// Local Node when Node-local.
    pub node_ref: Option<EntityRef>,
    /// Local Node generation when Node-local.
    pub node_generation: Option<u64>,
    /// Provider connection epoch where applicable.
    pub connection_epoch: Option<u64>,
    /// Owning Device Session when Device-local.
    pub device_session_ref: Option<EntityRef>,
    /// Stable display surface identities declared before streaming.
    pub surface_refs: Vec<EntityRef>,
    /// Input capabilities exposed by the backend.
    pub input_capabilities: Vec<InputCapability>,
    /// Privacy policies governing display evidence.
    pub privacy_policy_refs: Vec<EntityRef>,
    /// Evidence proving display preparation/binding.
    pub evidence_refs: Vec<EntityRef>,
    /// Display preparation timestamp.
    pub started_at: String,
}

/// Provider-neutral Display Session projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplaySessionProjection {
    /// Stable Display Session identity.
    pub display_session_ref: EntityRef,
    /// Exact owning Application Session.
    pub application_session_ref: EntityRef,
    /// Exact Provider Instance.
    pub provider_instance_ref: EntityRef,
    /// Provider generation fence.
    pub provider_generation: ProviderGeneration,
    /// Display locality.
    pub locality: SessionLocality,
    /// Local Node when Node-local.
    pub node_ref: Option<EntityRef>,
    /// Local Node generation when Node-local.
    pub node_generation: Option<u64>,
    /// Provider connection epoch where applicable.
    pub connection_epoch: Option<u64>,
    /// Owning Device Session when Device-local.
    pub device_session_ref: Option<EntityRef>,
    /// Stable declared surface identities.
    pub surface_refs: Vec<EntityRef>,
    /// Exposed input capabilities.
    pub input_capabilities: Vec<InputCapability>,
    /// Privacy policies governing display evidence.
    pub privacy_policy_refs: Vec<EntityRef>,
    /// Current Display Session lifecycle.
    pub lifecycle: DisplayLifecycle,
    /// Applied Display Observation identities.
    pub observation_refs: Vec<EntityRef>,
    /// Supporting evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Explicit bounded limitations.
    pub limitations: Vec<String>,
    /// Session start timestamp.
    pub started_at: String,
    /// Expiry of the current frame/surface observation, when one exists.
    pub observation_valid_until: Option<String>,
}

/// Fresh frame/surface observation for a Display Session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplayObservation {
    /// Stable Display Observation identity.
    pub observation_ref: EntityRef,
    /// Provider generation that produced this observation.
    pub provider_generation: ProviderGeneration,
    /// One stable surface declared by the Display Session.
    pub surface_ref: EntityRef,
    /// Independent frame evidence.
    pub frame_evidence_ref: EntityRef,
    /// Supporting evidence.
    pub evidence_refs: Vec<EntityRef>,
    /// Observation timestamp.
    pub observed_at: String,
    /// Expiry timestamp.
    pub valid_until: String,
}

/// Prepare one Display Session without claiming pixels are available.
///
/// # Errors
/// Returns [`D08Error`] when the Application Session, Provider/locality binding, surfaces, privacy,
/// or preparation evidence are absent or inconsistent.
pub fn prepare_display_session(
    session: &ApplicationSessionProjection,
    request: DisplaySessionRequest,
) -> Result<DisplaySessionProjection, D08Error> {
    if !matches!(
        session.lifecycle,
        ApplicationSessionLifecycle::Preparing
            | ApplicationSessionLifecycle::Running
            | ApplicationSessionLifecycle::Degraded
    ) {
        return Err(D08Error::InvalidSessionState);
    }
    if request.application_session_ref != session.session_ref {
        return Err(D08Error::SessionBindingMismatch);
    }
    if request.provider_instance_ref != session.provider_instance_ref
        || request.provider_generation != session.provider_generation
        || request.locality != session.locality
        || request.node_ref != session.node_ref
        || request.node_generation != session.node_generation
        || request.connection_epoch != session.connection_epoch
        || request.device_session_ref != session.device_session_ref
    {
        return Err(D08Error::ProviderContextMismatch);
    }
    if request.surface_refs.is_empty() {
        return Err(D08Error::MissingDisplaySurface);
    }
    if request.privacy_policy_refs.is_empty() {
        return Err(D08Error::MissingPrivacyPolicy);
    }
    if request.evidence_refs.is_empty() {
        return Err(D08Error::MissingDisplayEvidence);
    }

    Ok(DisplaySessionProjection {
        display_session_ref: EntityRef::new("application.display_session")
            .map_err(|_| D08Error::IdentityConstructionFailed)?,
        application_session_ref: request.application_session_ref,
        provider_instance_ref: request.provider_instance_ref,
        provider_generation: request.provider_generation,
        locality: request.locality,
        node_ref: request.node_ref,
        node_generation: request.node_generation,
        connection_epoch: request.connection_epoch,
        device_session_ref: request.device_session_ref,
        surface_refs: request.surface_refs,
        input_capabilities: request.input_capabilities,
        privacy_policy_refs: request.privacy_policy_refs,
        lifecycle: DisplayLifecycle::Preparing,
        observation_refs: Vec::new(),
        evidence_refs: request.evidence_refs,
        limitations: Vec::new(),
        started_at: request.started_at,
        observation_valid_until: None,
    })
}

/// Apply one current frame/surface observation and promote the Display Session to `streaming`.
///
/// # Errors
/// Returns [`D08Error`] when Provider generation, surface identity, evidence, or observation
/// freshness is invalid.
pub fn apply_display_observation(
    mut display: DisplaySessionProjection,
    observation: DisplayObservation,
    now: &str,
) -> Result<DisplaySessionProjection, D08Error> {
    if observation.provider_generation != display.provider_generation {
        return Err(D08Error::ProviderContextMismatch);
    }
    if !display.surface_refs.contains(&observation.surface_ref) {
        return Err(D08Error::DisplaySurfaceMismatch);
    }
    if observation.evidence_refs.is_empty() {
        return Err(D08Error::MissingDisplayEvidence);
    }
    ensure_fresh_interval(&observation.observed_at, &observation.valid_until, now)?;

    display.lifecycle = DisplayLifecycle::Streaming;
    display.observation_refs.push(observation.observation_ref);
    display.evidence_refs.push(observation.frame_evidence_ref);
    display.evidence_refs.extend(observation.evidence_refs);
    display.observation_valid_until = Some(observation.valid_until);
    Ok(display)
}
