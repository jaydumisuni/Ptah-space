//! D08 read-only composition over verified C10 Android application sessions.

use crate::{
    ApplicationAvailability, ApplicationSessionLifecycle, ApplicationSessionProjection, D08Error,
    LaunchMode, SessionLocality,
};
use ptah_android_runtime::{
    ApplicationSession as AndroidApplicationSession,
    ApplicationSessionState as AndroidApplicationSessionState, DeviceSession as AndroidDeviceSession,
    DeviceSessionState as AndroidDeviceSessionState,
};
use ptah_identifiers::EntityRef;

/// Exact inputs required to project an already-verified C10 Android Application Session into D08.
#[derive(Debug, Clone)]
pub struct AndroidProjectionRequest<'a> {
    /// Current C10 Device Session that owns the application runtime.
    pub device_session: &'a AndroidDeviceSession,
    /// Current verified C10 Application Session.
    pub application_session: &'a AndroidApplicationSession,
    /// Workspace expected to own the projection.
    pub workspace_ref: EntityRef,
    /// Exact Workspace Revision used by the surrounding D08 view.
    pub workspace_revision_ref: EntityRef,
    /// Materialization associated with the application view.
    pub materialization_ref: EntityRef,
    /// Positive materialization generation.
    pub materialization_generation: u64,
    /// Owning A04 Activity reference retained by D08.
    pub activity_ref: EntityRef,
    /// Owning A04 Operation reference retained by D08.
    pub operation_ref: EntityRef,
    /// Exact A04 Attempt reference retained by D08.
    pub attempt_ref: EntityRef,
}

/// Project a verified C10 Android Application Session without duplicating C10 runtime authority.
///
/// The returned D08 session reuses C10's exact `application.session` identity. Android process IDs,
/// activities, visible frames, and Device runtime state remain C10 evidence; this function creates no
/// alternate process, Window, Display Session, lease, fence, input, launch, or stop authority.
///
/// # Errors
/// Returns [`D08Error`] when the Device/Application Session pair is mismatched, stale, unavailable,
/// missing required evidence/privacy authority, or bound to an invalid materialization generation.
pub fn project_android_application_session(
    request: AndroidProjectionRequest<'_>,
) -> Result<ApplicationSessionProjection, D08Error> {
    if request.materialization_generation == 0 {
        return Err(D08Error::InvalidMaterializationGeneration);
    }
    if request.workspace_ref != request.device_session.workspace_ref
        || request.application_session.device_session_ref != request.device_session.session_ref
    {
        return Err(D08Error::AndroidSessionMismatch);
    }
    if request.device_session.state != AndroidDeviceSessionState::Connected {
        return Err(D08Error::AndroidSessionMismatch);
    }
    if request.application_session.provider_instance_ref != request.device_session.provider_instance_ref
        || request.application_session.provider_generation != request.device_session.provider_generation
        || request.application_session.connection_epoch != request.device_session.connection_epoch
    {
        return Err(D08Error::AndroidProviderContextMismatch);
    }
    if request.application_session.state != AndroidApplicationSessionState::Visible
        || request.application_session.evidence_refs.is_empty()
    {
        return Err(D08Error::AndroidApplicationUnavailable);
    }
    if request.device_session.privacy_policy_refs.is_empty() {
        return Err(D08Error::MissingPrivacyPolicy);
    }

    let mut evidence_refs = request.device_session.evidence_refs.clone();
    evidence_refs.extend(request.application_session.evidence_refs.iter().cloned());
    evidence_refs.push(request.application_session.visible_frame_ref.clone());
    evidence_refs.push(request.application_session.semantic_context_ref.clone());

    Ok(ApplicationSessionProjection {
        session_ref: request.application_session.session_ref.clone(),
        workspace_ref: request.workspace_ref,
        workspace_revision_ref: request.workspace_revision_ref,
        materialization_ref: request.materialization_ref,
        materialization_generation: request.materialization_generation,
        application_ref: request.application_session.application_ref.clone(),
        application_revision_ref: request.application_session.application_revision_ref.clone(),
        installation_ref: request.application_session.installation_ref.clone(),
        compatibility_ref: None,
        provider_instance_ref: request.application_session.provider_instance_ref.clone(),
        provider_generation: request.application_session.provider_generation,
        locality: SessionLocality::DeviceLocal,
        node_ref: None,
        node_generation: None,
        connection_epoch: Some(request.application_session.connection_epoch),
        device_session_ref: Some(request.device_session.session_ref.clone()),
        activity_ref: request.activity_ref,
        operation_ref: request.operation_ref,
        attempt_ref: request.attempt_ref,
        process_refs: Vec::new(),
        window_refs: Vec::new(),
        display_session_refs: Vec::new(),
        semantic_context_refs: vec![request.application_session.semantic_context_ref.clone()],
        availability: ApplicationAvailability::Full,
        privacy_policy_refs: request.device_session.privacy_policy_refs.clone(),
        lifecycle: ApplicationSessionLifecycle::Running,
        launch_mode: LaunchMode::Graphical,
        evidence_refs,
        limitations: Vec::new(),
        started_at: request.application_session.started_at.clone(),
    })
}
