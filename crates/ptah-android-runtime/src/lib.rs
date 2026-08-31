#![forbid(unsafe_code)]
//! C10 Android Application and Device Session v1.

use ptah_archive_decomposition::{SignatureObservation, SignatureStatus};
use ptah_device_runtime::{
    DeviceError, DeviceInterfaceRecord, DeviceKind, DeviceLease, DeviceRecord,
};
use ptah_identifiers::{EntityRef, IdentifierError};
use ptah_provider_api::ProviderGeneration;
use thiserror::Error;

/// Schema identifier for the C10 Device Session projection.
pub const DEVICE_SESSION_SCHEMA_ID: &str = "urn:ptah:schema:domain:device-session:0.1.1";
/// Schema identifier for the C10 Application Session projection.
pub const APPLICATION_SESSION_SCHEMA_ID: &str =
    "urn:ptah:schema:application:application-session:0.1.0";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
/// Failures produced by the C10 Android runtime boundary.
pub enum AndroidRuntimeError {
    #[error(transparent)]
    /// Underlying C08 Device authority failure.
    Device(#[from] DeviceError),
    #[error(transparent)]
    /// Identifier construction failure.
    Identifier(#[from] IdentifierError),
    #[error("C10 requires an Android physical device or emulator")]
    /// Requested Device is not an Android physical device or emulator.
    UnsupportedDeviceKind,
    #[error("Android Session context does not match current Device/interface")]
    /// Device/interface/session identities do not agree.
    SessionContextMismatch,
    #[error("Android Session requires supporting evidence")]
    /// Required supporting evidence is absent.
    MissingEvidence,
    #[error("Android Session requires a privacy policy")]
    /// Required privacy policy is absent.
    MissingPrivacyPolicy,
    #[error("Android Session timestamp is empty")]
    /// Required timestamp is empty.
    EmptyTimestamp,
    #[error("Android Session recovery generation overflow")]
    /// Recovery generation cannot advance without overflow.
    RecoveryGenerationOverflow,
    #[error("Android package install context does not match the current Device Session")]
    /// Package operation is not bound to the current Device Session.
    PackageSessionMismatch,
    #[error("Android package install/read-back evidence is incomplete or mismatched")]
    /// Package read-back is incomplete or does not match the admitted install.
    PackageReadBackMismatch,
    #[error("Android package signature was not independently verified for the expected signer")]
    /// Expected package signer was not independently verified.
    PackageSignatureUnverified,
    #[error("Android application launch/read-back evidence is incomplete or mismatched")]
    /// Application launch read-back is incomplete or mismatched.
    ApplicationReadBackMismatch,
    #[error("Android Screen Context is not bound to the current Device/Application Session")]
    /// Screen Context is not bound to the current Device/Application Session.
    ScreenContextMismatch,
    #[error("semantic selector did not match a current target")]
    /// No current semantic target matched the selector.
    SemanticTargetNotFound,
    #[error("semantic selector matched more than one current target")]
    /// More than one current semantic target matched the selector.
    SemanticTargetAmbiguous,
    #[error("semantic target can only be reacquired from a newer compatible Screen Context")]
    /// Target reacquisition did not use a newer compatible Screen Context.
    StaleSemanticContext,
    #[error("Android input action is not bound to the current Screen Context/Session")]
    /// Input action is not bound to the current context or authority.
    InputContextMismatch,
    #[error("Android input acknowledgement did not prove the intended post-condition")]
    /// Input acknowledgement lacks a verified newer post-condition.
    InputPostConditionUnverified,
    #[error("Android application stop was not independently verified")]
    /// Application stop lacks current independent process/activity absence proof.
    ApplicationStopUnverified,
    #[error("Android evidence capture/read-back was incomplete or mismatched")]
    /// Evidence artifact read-back is incomplete, stale, or mismatched.
    EvidenceCaptureUnverified,
    #[error("Android cleanup read-back evidence was incomplete or mismatched")]
    /// Cleanup read-back lacks the evidence required to make a disposition.
    CleanupReadBackMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Lifecycle state of an Android Device Session.
pub enum DeviceSessionState {
    /// Session is preparing to connect.
    Preparing,
    /// Session is connected under current authority.
    Connected,
    /// Session has only a subset of expected capability available.
    PartiallyAvailable,
    /// Session is rebinding after a connection change.
    Recovering,
    /// Session is disconnected.
    Disconnected,
    /// Session authority has expired.
    Expired,
    /// Session is performing close/cleanup work.
    Closing,
    /// Session is independently verified closed.
    Closed,
    /// Session failed and must not be returned available.
    Failed,
}

#[derive(Debug)]
/// Inputs required to open a leased and fenced Android Device Session.
pub struct DeviceSessionRequest<'a> {
    /// Workspace that owns the session.
    pub workspace_ref: EntityRef,
    /// Current C08 Device record.
    pub device: &'a DeviceRecord,
    /// Current C08 Device interface record.
    pub interface: &'a DeviceInterfaceRecord,
    /// Current C08 Device lease.
    pub lease: &'a DeviceLease,
    /// Fence token observed for the current lease.
    pub observed_fence_token: u64,
    /// Capability snapshot used for this operation.
    pub capability_snapshot_ref: EntityRef,
    /// Privacy policies governing the session or evidence.
    pub privacy_policy_refs: Vec<EntityRef>,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Session start timestamp.
    pub started_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Current Android Device Session bound to Device, Provider, connection epoch, and lease authority.
pub struct DeviceSession {
    /// Stable session identity.
    pub session_ref: EntityRef,
    /// Workspace that owns the session.
    pub workspace_ref: EntityRef,
    /// Stable Device identity.
    pub device_ref: EntityRef,
    /// Device profile revision active for the session.
    pub device_profile_revision_ref: EntityRef,
    /// Interface identity bound to the session.
    pub interface_ref: EntityRef,
    /// Connection identity bound to the session.
    pub connection_ref: EntityRef,
    /// Provider instance serving the connection.
    pub provider_instance_ref: EntityRef,
    /// Provider generation bound to the observation.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to the observation.
    pub connection_epoch: u64,
    /// Lease identity authorizing the session.
    pub lease_ref: EntityRef,
    /// Capability snapshot used for this operation.
    pub capability_snapshot_ref: EntityRef,
    /// Privacy policies governing the session or evidence.
    pub privacy_policy_refs: Vec<EntityRef>,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Monotonic count of successful session recoveries.
    pub recovery_generation: u64,
    /// Session start timestamp.
    pub started_at: String,
    /// Current lifecycle state.
    pub state: DeviceSessionState,
}

/// Open an Android Device Session under current C08 lease and fence authority.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn open_device_session(
    request: DeviceSessionRequest<'_>,
) -> Result<DeviceSession, AndroidRuntimeError> {
    if !matches!(
        request.device.device_kind,
        DeviceKind::PhysicalAndroid | DeviceKind::AndroidEmulator
    ) {
        return Err(AndroidRuntimeError::UnsupportedDeviceKind);
    }
    if request.interface.device_ref != request.device.device_ref {
        return Err(AndroidRuntimeError::SessionContextMismatch);
    }
    if request.evidence_refs.is_empty() {
        return Err(AndroidRuntimeError::MissingEvidence);
    }
    if request.privacy_policy_refs.is_empty() {
        return Err(AndroidRuntimeError::MissingPrivacyPolicy);
    }
    if request.started_at.trim().is_empty() {
        return Err(AndroidRuntimeError::EmptyTimestamp);
    }
    request.lease.fence(
        request.interface,
        request.observed_fence_token,
        "android.session.control",
    )?;
    Ok(DeviceSession {
        session_ref: EntityRef::new("device.session")?,
        workspace_ref: request.workspace_ref,
        device_ref: request.device.device_ref.clone(),
        device_profile_revision_ref: request.device.current_profile_revision_ref.clone(),
        interface_ref: request.interface.interface_ref.clone(),
        connection_ref: request.interface.connection_ref.clone(),
        provider_instance_ref: request.interface.provider_instance_ref.clone(),
        provider_generation: request.interface.provider_generation,
        connection_epoch: request.interface.connection_epoch,
        lease_ref: request.lease.lease_ref.clone(),
        capability_snapshot_ref: request.capability_snapshot_ref,
        privacy_policy_refs: request.privacy_policy_refs,
        evidence_refs: request.evidence_refs,
        recovery_generation: 0,
        started_at: request.started_at,
        state: DeviceSessionState::Connected,
    })
}

#[derive(Debug)]
/// Inputs required to rebind an existing Device Session after reconnect.
pub struct DeviceSessionRecoveryRequest<'a> {
    /// Current Device Session.
    pub session: &'a DeviceSession,
    /// Current C08 Device record.
    pub device: &'a DeviceRecord,
    /// Current C08 Device interface record.
    pub interface: &'a DeviceInterfaceRecord,
    /// Current C08 Device lease.
    pub lease: &'a DeviceLease,
    /// Fence token observed for the current lease.
    pub observed_fence_token: u64,
    /// Capability snapshot used for this operation.
    pub capability_snapshot_ref: EntityRef,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Recovery observation timestamp.
    pub recovered_at: String,
}

/// Rebind an existing Device Session to a newer compatible interface and lease without rekeying the session.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn recover_device_session(
    request: DeviceSessionRecoveryRequest<'_>,
) -> Result<DeviceSession, AndroidRuntimeError> {
    if !matches!(
        request.device.device_kind,
        DeviceKind::PhysicalAndroid | DeviceKind::AndroidEmulator
    ) {
        return Err(AndroidRuntimeError::UnsupportedDeviceKind);
    }
    if request.session.device_ref != request.device.device_ref
        || request.interface.device_ref != request.device.device_ref
    {
        return Err(AndroidRuntimeError::SessionContextMismatch);
    }
    if request.evidence_refs.is_empty() {
        return Err(AndroidRuntimeError::MissingEvidence);
    }
    if request.recovered_at.trim().is_empty() {
        return Err(AndroidRuntimeError::EmptyTimestamp);
    }
    request.lease.fence(
        request.interface,
        request.observed_fence_token,
        "android.session.control",
    )?;
    let recovery_generation = request
        .session
        .recovery_generation
        .checked_add(1)
        .ok_or(AndroidRuntimeError::RecoveryGenerationOverflow)?;
    let mut evidence_refs = request.session.evidence_refs.clone();
    evidence_refs.extend(request.evidence_refs);
    Ok(DeviceSession {
        session_ref: request.session.session_ref.clone(),
        workspace_ref: request.session.workspace_ref.clone(),
        device_ref: request.session.device_ref.clone(),
        device_profile_revision_ref: request.device.current_profile_revision_ref.clone(),
        interface_ref: request.interface.interface_ref.clone(),
        connection_ref: request.interface.connection_ref.clone(),
        provider_instance_ref: request.interface.provider_instance_ref.clone(),
        provider_generation: request.interface.provider_generation,
        connection_epoch: request.interface.connection_epoch,
        lease_ref: request.lease.lease_ref.clone(),
        capability_snapshot_ref: request.capability_snapshot_ref,
        privacy_policy_refs: request.session.privacy_policy_refs.clone(),
        evidence_refs,
        recovery_generation,
        started_at: request.session.started_at.clone(),
        state: DeviceSessionState::Connected,
    })
}

#[derive(Debug)]
/// Authority and expected package identity required to admit an Android package installation.
pub struct PackageInstallRequest<'a> {
    /// Current Device Session.
    pub session: &'a DeviceSession,
    /// Current C08 Device interface record.
    pub interface: &'a DeviceInterfaceRecord,
    /// Current C08 Device lease.
    pub lease: &'a DeviceLease,
    /// Fence token observed for the current lease.
    pub observed_fence_token: u64,
    /// Object identity of the package artifact.
    pub package_object_ref: EntityRef,
    /// Exact package revision identity.
    pub package_revision_ref: EntityRef,
    /// Android package identifier.
    pub package_id: String,
    /// Exact version expected after installation.
    pub expected_version: String,
    /// Signer identity expected for the package.
    pub expected_signer: String,
    /// Evidence for the admitted command or backend request.
    pub command_evidence_refs: Vec<EntityRef>,
    /// Operation request timestamp.
    pub requested_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Unverified package-install attempt awaiting independent read-back.
pub struct PackageInstallAttempt {
    /// Installation attempt/receipt identity.
    pub installation_ref: EntityRef,
    /// Device session ref.
    pub device_session_ref: EntityRef,
    /// Object identity of the package artifact.
    pub package_object_ref: EntityRef,
    /// Exact package revision identity.
    pub package_revision_ref: EntityRef,
    /// Android package identifier.
    pub package_id: String,
    /// Exact version expected after installation.
    pub expected_version: String,
    /// Signer identity expected for the package.
    pub expected_signer: String,
    /// Provider generation bound to the observation.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to the observation.
    pub connection_epoch: u64,
    /// Evidence for the admitted command or backend request.
    pub command_evidence_refs: Vec<EntityRef>,
    /// Operation request timestamp.
    pub requested_at: String,
    /// Whether the attempt itself has been promoted to verified proof.
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Independent Android package-state read-back used to verify an installation.
pub struct PackageReadBack {
    /// Provider generation that produced the package read-back.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch that produced the package read-back.
    pub connection_epoch: u64,
    /// Android package identifier.
    pub package_id: String,
    /// Version independently observed after installation.
    pub installed_version: String,
    /// Independent package signature observations.
    pub signatures: Vec<SignatureObservation>,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Read-back observation timestamp.
    pub observed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Package installation proven by exact version and independently verified signer evidence.
pub struct VerifiedPackageInstallation {
    /// Installation attempt/receipt identity.
    pub installation_ref: EntityRef,
    /// Device session ref.
    pub device_session_ref: EntityRef,
    /// Object identity of the package artifact.
    pub package_object_ref: EntityRef,
    /// Exact package revision identity.
    pub package_revision_ref: EntityRef,
    /// Android package identifier.
    pub package_id: String,
    /// Version independently observed after installation.
    pub installed_version: String,
    /// Signer identity independently verified for the package.
    pub verified_signer: String,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Verification timestamp.
    pub verified_at: String,
}

fn require_current_session_binding(
    session: &DeviceSession,
    interface: &DeviceInterfaceRecord,
    lease: &DeviceLease,
) -> Result<(), AndroidRuntimeError> {
    if session.device_ref != interface.device_ref
        || session.interface_ref != interface.interface_ref
        || session.connection_ref != interface.connection_ref
        || session.provider_instance_ref != interface.provider_instance_ref
        || session.provider_generation != interface.provider_generation
        || session.connection_epoch != interface.connection_epoch
        || session.lease_ref != lease.lease_ref
    {
        return Err(AndroidRuntimeError::PackageSessionMismatch);
    }
    Ok(())
}

/// Admit a package-install command without treating command acceptance as installation proof.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn admit_package_install(
    request: PackageInstallRequest<'_>,
) -> Result<PackageInstallAttempt, AndroidRuntimeError> {
    require_current_session_binding(request.session, request.interface, request.lease)?;
    request.lease.fence(
        request.interface,
        request.observed_fence_token,
        "android.package.install",
    )?;
    if request.package_id.trim().is_empty()
        || request.expected_version.trim().is_empty()
        || request.expected_signer.trim().is_empty()
        || request.command_evidence_refs.is_empty()
    {
        return Err(AndroidRuntimeError::PackageReadBackMismatch);
    }
    if request.requested_at.trim().is_empty() {
        return Err(AndroidRuntimeError::EmptyTimestamp);
    }
    Ok(PackageInstallAttempt {
        installation_ref: EntityRef::new("application.installation")?,
        device_session_ref: request.session.session_ref.clone(),
        package_object_ref: request.package_object_ref,
        package_revision_ref: request.package_revision_ref,
        package_id: request.package_id,
        expected_version: request.expected_version,
        expected_signer: request.expected_signer,
        provider_generation: request.interface.provider_generation,
        connection_epoch: request.interface.connection_epoch,
        command_evidence_refs: request.command_evidence_refs,
        requested_at: request.requested_at,
        verified: false,
    })
}

/// Verify an installation by exact package/version read-back and independently verified signer evidence.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn verify_package_install(
    attempt: &PackageInstallAttempt,
    read_back: PackageReadBack,
) -> Result<VerifiedPackageInstallation, AndroidRuntimeError> {
    if read_back.provider_generation != attempt.provider_generation
        || read_back.connection_epoch != attempt.connection_epoch
        || read_back.package_id != attempt.package_id
        || read_back.installed_version != attempt.expected_version
        || read_back.evidence_refs.is_empty()
        || read_back.observed_at.trim().is_empty()
    {
        return Err(AndroidRuntimeError::PackageReadBackMismatch);
    }
    let verified_signer = read_back
        .signatures
        .iter()
        .find_map(|signature| {
            (signature.status == SignatureStatus::Verified
                && signature.signer.as_deref() == Some(attempt.expected_signer.as_str()))
            .then(|| attempt.expected_signer.clone())
        })
        .ok_or(AndroidRuntimeError::PackageSignatureUnverified)?;
    Ok(VerifiedPackageInstallation {
        installation_ref: attempt.installation_ref.clone(),
        device_session_ref: attempt.device_session_ref.clone(),
        package_object_ref: attempt.package_object_ref.clone(),
        package_revision_ref: attempt.package_revision_ref.clone(),
        package_id: read_back.package_id,
        installed_version: read_back.installed_version,
        verified_signer,
        evidence_refs: read_back.evidence_refs,
        verified_at: read_back.observed_at,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Lifecycle state of a C10 Android Application Session.
pub enum ApplicationSessionState {
    /// Application package installation is in progress.
    Installing,
    /// Application package is installed.
    Installed,
    /// Application launch is in progress.
    Launching,
    /// Application has verified visible and semantic readiness.
    Visible,
    /// Application is running in the background.
    Backgrounded,
    /// Application is suspended.
    Suspended,
    /// Application stop has been independently verified.
    Stopped,
    /// Application terminated unexpectedly.
    Crashed,
    /// Session is rebinding after a connection change.
    Recovering,
    /// Session is independently verified closed.
    Closed,
}

#[derive(Debug)]
/// Inputs required to admit launch of a verified Android package installation.
pub struct ApplicationLaunchRequest<'a> {
    /// Current Device Session.
    pub session: &'a DeviceSession,
    /// Current C08 Device interface record.
    pub interface: &'a DeviceInterfaceRecord,
    /// Current C08 Device lease.
    pub lease: &'a DeviceLease,
    /// Fence token observed for the current lease.
    pub observed_fence_token: u64,
    /// Verified package installation being launched.
    pub installation: &'a VerifiedPackageInstallation,
    /// Stable application identity.
    pub application_ref: EntityRef,
    /// Exact application revision identity.
    pub application_revision_ref: EntityRef,
    /// Evidence for the admitted command or backend request.
    pub command_evidence_refs: Vec<EntityRef>,
    /// Operation request timestamp.
    pub requested_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Unverified application-launch attempt awaiting visible and semantic read-back.
pub struct ApplicationLaunchAttempt {
    /// Application launch-attempt identity.
    pub launch_ref: EntityRef,
    /// Device session ref.
    pub device_session_ref: EntityRef,
    /// Installation attempt/receipt identity.
    pub installation_ref: EntityRef,
    /// Stable application identity.
    pub application_ref: EntityRef,
    /// Exact application revision identity.
    pub application_revision_ref: EntityRef,
    /// Android package identifier.
    pub package_id: String,
    /// Version independently observed after installation.
    pub installed_version: String,
    /// Signer identity independently verified for the package.
    pub verified_signer: String,
    /// Provider instance serving the connection.
    pub provider_instance_ref: EntityRef,
    /// Provider generation bound to the observation.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to the observation.
    pub connection_epoch: u64,
    /// Evidence for the admitted command or backend request.
    pub command_evidence_refs: Vec<EntityRef>,
    /// Operation request timestamp.
    pub requested_at: String,
    /// Whether the attempt itself has been promoted to verified proof.
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Independent process, activity, frame, and semantic evidence for application launch.
pub struct ApplicationLaunchReadBack {
    /// Provider generation that produced the launch read-back.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch that produced the launch read-back.
    pub connection_epoch: u64,
    /// Android package identifier.
    pub package_id: String,
    /// Observed process aliases supporting application state.
    pub process_aliases: Vec<String>,
    /// Observed foreground Android activity or equivalent runtime context.
    pub activity_or_context: String,
    /// Evidence reference for the first verified visible frame.
    pub visible_frame_ref: Option<EntityRef>,
    /// Evidence reference for semantic UI readiness.
    pub semantic_context_ref: Option<EntityRef>,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Read-back observation timestamp.
    pub observed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Verified Android application runtime projection within a Device Session.
pub struct ApplicationSession {
    /// Stable session identity.
    pub session_ref: EntityRef,
    /// Device session ref.
    pub device_session_ref: EntityRef,
    /// Installation attempt/receipt identity.
    pub installation_ref: EntityRef,
    /// Stable application identity.
    pub application_ref: EntityRef,
    /// Exact application revision identity.
    pub application_revision_ref: EntityRef,
    /// Android package identifier.
    pub package_id: String,
    /// Version independently observed after installation.
    pub installed_version: String,
    /// Signer identity independently verified for the package.
    pub verified_signer: String,
    /// Provider instance serving the connection.
    pub provider_instance_ref: EntityRef,
    /// Provider generation bound to the observation.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to the observation.
    pub connection_epoch: u64,
    /// Observed process aliases supporting application state.
    pub process_aliases: Vec<String>,
    /// Observed foreground Android activity or equivalent runtime context.
    pub activity_or_context: String,
    /// Evidence reference for the first verified visible frame.
    pub visible_frame_ref: EntityRef,
    /// Evidence reference for semantic UI readiness.
    pub semantic_context_ref: EntityRef,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Session start timestamp.
    pub started_at: String,
    /// Current lifecycle state.
    pub state: ApplicationSessionState,
}

/// Admit launch of a verified package under the current Device Session authority.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn admit_application_launch(
    request: ApplicationLaunchRequest<'_>,
) -> Result<ApplicationLaunchAttempt, AndroidRuntimeError> {
    require_current_session_binding(request.session, request.interface, request.lease)?;
    request.lease.fence(
        request.interface,
        request.observed_fence_token,
        "android.application.launch",
    )?;
    if request.installation.device_session_ref != request.session.session_ref
        || request.command_evidence_refs.is_empty()
    {
        return Err(AndroidRuntimeError::ApplicationReadBackMismatch);
    }
    if request.requested_at.trim().is_empty() {
        return Err(AndroidRuntimeError::EmptyTimestamp);
    }
    Ok(ApplicationLaunchAttempt {
        launch_ref: EntityRef::new("application.launch_attempt")?,
        device_session_ref: request.session.session_ref.clone(),
        installation_ref: request.installation.installation_ref.clone(),
        application_ref: request.application_ref,
        application_revision_ref: request.application_revision_ref,
        package_id: request.installation.package_id.clone(),
        installed_version: request.installation.installed_version.clone(),
        verified_signer: request.installation.verified_signer.clone(),
        provider_instance_ref: request.interface.provider_instance_ref.clone(),
        provider_generation: request.interface.provider_generation,
        connection_epoch: request.interface.connection_epoch,
        command_evidence_refs: request.command_evidence_refs,
        requested_at: request.requested_at,
        verified: false,
    })
}

/// Promote a launch attempt only after process/activity, visible-frame, and semantic-readiness evidence exists.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn verify_application_launch(
    attempt: &ApplicationLaunchAttempt,
    read_back: ApplicationLaunchReadBack,
) -> Result<ApplicationSession, AndroidRuntimeError> {
    if read_back.provider_generation != attempt.provider_generation
        || read_back.connection_epoch != attempt.connection_epoch
        || read_back.package_id != attempt.package_id
        || read_back.process_aliases.is_empty()
        || read_back.activity_or_context.trim().is_empty()
        || read_back.visible_frame_ref.is_none()
        || read_back.semantic_context_ref.is_none()
        || read_back.evidence_refs.is_empty()
        || read_back.observed_at.trim().is_empty()
    {
        return Err(AndroidRuntimeError::ApplicationReadBackMismatch);
    }
    Ok(ApplicationSession {
        session_ref: EntityRef::new("application.session")?,
        device_session_ref: attempt.device_session_ref.clone(),
        installation_ref: attempt.installation_ref.clone(),
        application_ref: attempt.application_ref.clone(),
        application_revision_ref: attempt.application_revision_ref.clone(),
        package_id: attempt.package_id.clone(),
        installed_version: attempt.installed_version.clone(),
        verified_signer: attempt.verified_signer.clone(),
        provider_instance_ref: attempt.provider_instance_ref.clone(),
        provider_generation: attempt.provider_generation,
        connection_epoch: attempt.connection_epoch,
        process_aliases: read_back.process_aliases,
        activity_or_context: read_back.activity_or_context,
        visible_frame_ref: read_back
            .visible_frame_ref
            .ok_or(AndroidRuntimeError::ApplicationReadBackMismatch)?,
        semantic_context_ref: read_back
            .semantic_context_ref
            .ok_or(AndroidRuntimeError::ApplicationReadBackMismatch)?,
        evidence_refs: read_back.evidence_refs,
        started_at: read_back.observed_at,
        state: ApplicationSessionState::Visible,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Backend-neutral semantic UI node observed in a Screen Context.
pub struct SemanticNode {
    /// Backend-local node alias; never treated as stable identity.
    pub backend_node_alias: String,
    /// Optional Android resource identifier.
    pub resource_id: Option<String>,
    /// Optional visible text selector value.
    pub text: Option<String>,
    /// Optional accessibility/content description.
    pub description: Option<String>,
    /// Optional Android widget class name.
    pub class_name: Option<String>,
    /// Whether the current node can accept interaction.
    pub interactive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Stable semantic attributes used to locate a current UI target.
pub struct SemanticSelector {
    /// Optional Android resource identifier.
    pub resource_id: Option<String>,
    /// Optional visible text selector value.
    pub text: Option<String>,
    /// Optional accessibility/content description.
    pub description: Option<String>,
    /// Optional Android widget class name.
    pub class_name: Option<String>,
}

#[derive(Debug)]
/// Inputs required to capture a fenced semantic Screen Context.
pub struct ScreenContextRequest<'a> {
    /// Current Device Session.
    pub session: &'a DeviceSession,
    /// Current verified Application Session.
    pub application: &'a ApplicationSession,
    /// Current C08 Device interface record.
    pub interface: &'a DeviceInterfaceRecord,
    /// Current C08 Device lease.
    pub lease: &'a DeviceLease,
    /// Fence token observed for the current lease.
    pub observed_fence_token: u64,
    /// Monotonic Screen Context capture sequence.
    pub capture_sequence: u64,
    /// Backend that produced the observation.
    pub backend_source: String,
    /// Version of the producing backend.
    pub backend_version: String,
    /// Semantic nodes observed in the context.
    pub nodes: Vec<SemanticNode>,
    /// Optional screenshot/frame evidence bound to the context.
    pub screenshot_ref: Option<EntityRef>,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Screen Context capture timestamp.
    pub captured_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Versioned semantic/screenshot context bound to one Application Session and connection epoch.
pub struct ScreenContext {
    /// Stable Screen Context identity.
    pub context_ref: EntityRef,
    /// Device session ref.
    pub device_session_ref: EntityRef,
    /// Application Session identity bound to the observation.
    pub application_session_ref: EntityRef,
    /// Provider generation bound to the observation.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to the observation.
    pub connection_epoch: u64,
    /// Monotonic Screen Context capture sequence.
    pub capture_sequence: u64,
    /// Backend that produced the observation.
    pub backend_source: String,
    /// Version of the producing backend.
    pub backend_version: String,
    /// Semantic nodes observed in the context.
    pub nodes: Vec<SemanticNode>,
    /// Optional screenshot/frame evidence bound to the context.
    pub screenshot_ref: Option<EntityRef>,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Screen Context capture timestamp.
    pub captured_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Resolved semantic target bound to the exact Screen Context that produced it.
pub struct SemanticTarget {
    /// Stable semantic-target identity.
    pub target_ref: EntityRef,
    /// Stable Screen Context identity.
    pub context_ref: EntityRef,
    /// Application Session identity bound to the observation.
    pub application_session_ref: EntityRef,
    /// Stable semantic selector retained for reacquisition.
    pub selector: SemanticSelector,
    /// Backend-local node alias; never treated as stable identity.
    pub backend_node_alias: String,
    /// Whether the current node can accept interaction.
    pub interactive: bool,
    /// Connection epoch bound to the observation.
    pub connection_epoch: u64,
    /// Monotonic Screen Context capture sequence.
    pub capture_sequence: u64,
}

/// Capture a fenced semantic Screen Context for the current Application Session.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn capture_screen_context(
    request: ScreenContextRequest<'_>,
) -> Result<ScreenContext, AndroidRuntimeError> {
    require_current_session_binding(request.session, request.interface, request.lease)?;
    request.lease.fence(
        request.interface,
        request.observed_fence_token,
        "android.semantic.read",
    )?;
    if request.application.device_session_ref != request.session.session_ref
        || request.application.provider_generation != request.interface.provider_generation
        || request.application.connection_epoch != request.interface.connection_epoch
        || request.backend_source.trim().is_empty()
        || request.backend_version.trim().is_empty()
        || request.capture_sequence == 0
        || request.evidence_refs.is_empty()
        || request.captured_at.trim().is_empty()
    {
        return Err(AndroidRuntimeError::ScreenContextMismatch);
    }
    Ok(ScreenContext {
        context_ref: EntityRef::new("device.screen_context")?,
        device_session_ref: request.session.session_ref.clone(),
        application_session_ref: request.application.session_ref.clone(),
        provider_generation: request.interface.provider_generation,
        connection_epoch: request.interface.connection_epoch,
        capture_sequence: request.capture_sequence,
        backend_source: request.backend_source,
        backend_version: request.backend_version,
        nodes: request.nodes,
        screenshot_ref: request.screenshot_ref,
        evidence_refs: request.evidence_refs,
        captured_at: request.captured_at,
    })
}

fn selector_matches(selector: &SemanticSelector, node: &SemanticNode) -> bool {
    selector
        .resource_id
        .as_ref()
        .is_none_or(|value| node.resource_id.as_ref() == Some(value))
        && selector
            .text
            .as_ref()
            .is_none_or(|value| node.text.as_ref() == Some(value))
        && selector
            .description
            .as_ref()
            .is_none_or(|value| node.description.as_ref() == Some(value))
        && selector
            .class_name
            .as_ref()
            .is_none_or(|value| node.class_name.as_ref() == Some(value))
}

/// Resolve exactly one current semantic target from a Screen Context.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn resolve_semantic_target(
    context: &ScreenContext,
    selector: SemanticSelector,
) -> Result<SemanticTarget, AndroidRuntimeError> {
    if selector.resource_id.is_none()
        && selector.text.is_none()
        && selector.description.is_none()
        && selector.class_name.is_none()
    {
        return Err(AndroidRuntimeError::SemanticTargetNotFound);
    }
    let mut matches = context
        .nodes
        .iter()
        .filter(|node| selector_matches(&selector, node));
    let node = matches
        .next()
        .ok_or(AndroidRuntimeError::SemanticTargetNotFound)?;
    if matches.next().is_some() {
        return Err(AndroidRuntimeError::SemanticTargetAmbiguous);
    }
    Ok(SemanticTarget {
        target_ref: EntityRef::new("application.semantic_target")?,
        context_ref: context.context_ref.clone(),
        application_session_ref: context.application_session_ref.clone(),
        selector,
        backend_node_alias: node.backend_node_alias.clone(),
        interactive: node.interactive,
        connection_epoch: context.connection_epoch,
        capture_sequence: context.capture_sequence,
    })
}

/// Reacquire a stale semantic target from a newer compatible Screen Context while preserving target identity.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn reacquire_semantic_target(
    stale: &SemanticTarget,
    context: &ScreenContext,
) -> Result<SemanticTarget, AndroidRuntimeError> {
    if stale.application_session_ref != context.application_session_ref
        || context.capture_sequence <= stale.capture_sequence
    {
        return Err(AndroidRuntimeError::StaleSemanticContext);
    }
    let mut current = resolve_semantic_target(context, stale.selector.clone())?;
    current.target_ref = stale.target_ref.clone();
    Ok(current)
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Android input operation admitted by C10.
pub enum InputAction {
    /// Tap a current semantic target.
    TapSemantic {
        /// Semantic target bound to the current context.
        target: SemanticTarget,
    },
    /// Scroll a current semantic target.
    ScrollSemantic {
        /// Semantic target bound to the current context.
        target: SemanticTarget,
        /// Signed vertical scroll delta.
        delta_y: i32,
    },
    /// Inject an Android key press.
    KeyPress {
        /// Android key code to inject.
        android_key_code: u32,
    },
    /// Type text while retaining only length and digest in the C10 record.
    TypeText {
        /// Semantic target bound to the current context.
        target: SemanticTarget,
        /// UTF-8 payload length retained without raw text.
        utf8_len: usize,
        /// Lowercase SHA-256 digest retained instead of raw typed text.
        text_sha256: String,
    },
    /// Set clipboard content while retaining only length and digest in the C10 record.
    ClipboardSet {
        /// UTF-8 payload length retained without raw text.
        utf8_len: usize,
        /// Lowercase SHA-256 digest retained instead of raw clipboard content.
        content_sha256: String,
    },
    /// Tap coordinates bound to an exact frame and display geometry.
    TapCoordinates {
        /// Exact frame evidence used for coordinate input.
        frame_ref: EntityRef,
        /// Display-geometry evidence used for coordinate input.
        geometry_ref: EntityRef,
        /// Horizontal coordinate in the bound viewport.
        x: u32,
        /// Vertical coordinate in the bound viewport.
        y: u32,
        /// Bound viewport width.
        viewport_width: u32,
        /// Bound viewport height.
        viewport_height: u32,
    },
}

#[derive(Debug)]
/// Authority, context, and evidence required to admit an Android input action.
pub struct InputActionRequest<'a> {
    /// Current Device Session.
    pub session: &'a DeviceSession,
    /// Current verified Application Session.
    pub application: &'a ApplicationSession,
    /// Current C08 Device interface record.
    pub interface: &'a DeviceInterfaceRecord,
    /// Current C08 Device lease.
    pub lease: &'a DeviceLease,
    /// Fence token observed for the current lease.
    pub observed_fence_token: u64,
    /// Pre-action Screen Context.
    pub context: &'a ScreenContext,
    /// Admitted input action.
    pub action: InputAction,
    /// Evidence for the admitted command or backend request.
    pub command_evidence_refs: Vec<EntityRef>,
    /// Operation request timestamp.
    pub requested_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Unverified Android input attempt bound to its pre-action Screen Context.
pub struct InputAttempt {
    /// Input-attempt identity.
    pub attempt_ref: EntityRef,
    /// Device session ref.
    pub device_session_ref: EntityRef,
    /// Application Session identity bound to the observation.
    pub application_session_ref: EntityRef,
    /// Stable Screen Context identity.
    pub context_ref: EntityRef,
    /// Monotonic Screen Context capture sequence.
    pub capture_sequence: u64,
    /// Connection epoch bound to the observation.
    pub connection_epoch: u64,
    /// Admitted input action.
    pub action: InputAction,
    /// Evidence for the admitted command or backend request.
    pub command_evidence_refs: Vec<EntityRef>,
    /// Operation request timestamp.
    pub requested_at: String,
    /// Whether the attempt itself has been promoted to verified proof.
    pub verified: bool,
}

#[derive(Debug)]
/// Post-action Screen Context and evidence used to verify an input acknowledgement.
pub struct InputReadBack<'a> {
    /// Whether the backend acknowledged execution.
    pub backend_acknowledged: bool,
    /// Newer Screen Context used for post-condition verification.
    pub post_context: &'a ScreenContext,
    /// Optional semantic selector that must exist after the action.
    pub expected_selector: Option<SemanticSelector>,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Read-back observation timestamp.
    pub observed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Input action proven by a newer post-condition Screen Context.
pub struct VerifiedInputAction {
    /// Input-attempt identity.
    pub attempt_ref: EntityRef,
    /// Device session ref.
    pub device_session_ref: EntityRef,
    /// Application Session identity bound to the observation.
    pub application_session_ref: EntityRef,
    /// Screen Context identity before the action.
    pub pre_context_ref: EntityRef,
    /// Screen Context identity after the action.
    pub post_context_ref: EntityRef,
    /// Capture sequence before the action.
    pub pre_capture_sequence: u64,
    /// Capture sequence after the action.
    pub post_capture_sequence: u64,
    /// Admitted input action.
    pub action: InputAction,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Verification timestamp.
    pub verified_at: String,
}

fn current_interactive_target(
    target: &SemanticTarget,
    context: &ScreenContext,
    application: &ApplicationSession,
) -> bool {
    target.context_ref == context.context_ref
        && target.application_session_ref == application.session_ref
        && target.capture_sequence == context.capture_sequence
        && target.connection_epoch == context.connection_epoch
        && target.interactive
}

fn is_lower_hex_digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Admit an input action only when its Device/Application/Screen Context and lease authority are current.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn admit_input_action(
    request: InputActionRequest<'_>,
) -> Result<InputAttempt, AndroidRuntimeError> {
    require_current_session_binding(request.session, request.interface, request.lease)?;
    let required_scope = match request.action {
        InputAction::ClipboardSet { .. } => "android.clipboard",
        _ => "android.input",
    };
    request.lease.fence(
        request.interface,
        request.observed_fence_token,
        required_scope,
    )?;
    if request.application.device_session_ref != request.session.session_ref
        || request.context.device_session_ref != request.session.session_ref
        || request.context.application_session_ref != request.application.session_ref
        || request.context.provider_generation != request.interface.provider_generation
        || request.context.connection_epoch != request.interface.connection_epoch
        || request.command_evidence_refs.is_empty()
        || request.requested_at.trim().is_empty()
    {
        return Err(AndroidRuntimeError::InputContextMismatch);
    }
    match &request.action {
        InputAction::TapSemantic { target }
            if current_interactive_target(target, request.context, request.application) => {}
        InputAction::ScrollSemantic { target, delta_y }
            if current_interactive_target(target, request.context, request.application)
                && *delta_y != 0 => {}
        InputAction::KeyPress { android_key_code } if *android_key_code != 0 => {}
        InputAction::TypeText {
            target,
            utf8_len,
            text_sha256,
        } if current_interactive_target(target, request.context, request.application)
            && *utf8_len > 0
            && is_lower_hex_digest(text_sha256, 64) => {}
        InputAction::ClipboardSet {
            utf8_len,
            content_sha256,
        } if *utf8_len > 0 && is_lower_hex_digest(content_sha256, 64) => {}
        InputAction::TapCoordinates {
            frame_ref,
            x,
            y,
            viewport_width,
            viewport_height,
            ..
        } if request.context.screenshot_ref.as_ref() == Some(frame_ref)
            && *viewport_width > 0
            && *viewport_height > 0
            && *x < *viewport_width
            && *y < *viewport_height => {}
        _ => return Err(AndroidRuntimeError::InputContextMismatch),
    }
    Ok(InputAttempt {
        attempt_ref: EntityRef::new("application.semantic_action_attempt")?,
        device_session_ref: request.session.session_ref.clone(),
        application_session_ref: request.application.session_ref.clone(),
        context_ref: request.context.context_ref.clone(),
        capture_sequence: request.context.capture_sequence,
        connection_epoch: request.context.connection_epoch,
        action: request.action,
        command_evidence_refs: request.command_evidence_refs,
        requested_at: request.requested_at,
        verified: false,
    })
}

/// Verify an input acknowledgement from a newer post-condition Screen Context.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn verify_input_action(
    attempt: &InputAttempt,
    read_back: InputReadBack<'_>,
) -> Result<VerifiedInputAction, AndroidRuntimeError> {
    if !read_back.backend_acknowledged
        || read_back.post_context.application_session_ref != attempt.application_session_ref
        || read_back.post_context.connection_epoch != attempt.connection_epoch
        || read_back.post_context.capture_sequence <= attempt.capture_sequence
        || read_back.evidence_refs.is_empty()
        || read_back.observed_at.trim().is_empty()
    {
        return Err(AndroidRuntimeError::InputPostConditionUnverified);
    }
    if let Some(selector) = read_back.expected_selector {
        resolve_semantic_target(read_back.post_context, selector)
            .map_err(|_| AndroidRuntimeError::InputPostConditionUnverified)?;
    }
    Ok(VerifiedInputAction {
        attempt_ref: attempt.attempt_ref.clone(),
        device_session_ref: attempt.device_session_ref.clone(),
        application_session_ref: attempt.application_session_ref.clone(),
        pre_context_ref: attempt.context_ref.clone(),
        post_context_ref: read_back.post_context.context_ref.clone(),
        pre_capture_sequence: attempt.capture_sequence,
        post_capture_sequence: read_back.post_context.capture_sequence,
        action: attempt.action.clone(),
        evidence_refs: read_back.evidence_refs,
        verified_at: read_back.observed_at,
    })
}

#[derive(Debug)]
/// Inputs required to admit an Android application stop operation.
pub struct ApplicationStopRequest<'a> {
    /// Current Device Session.
    pub session: &'a DeviceSession,
    /// Current verified Application Session.
    pub application: &'a ApplicationSession,
    /// Current C08 Device interface record.
    pub interface: &'a DeviceInterfaceRecord,
    /// Current C08 Device lease.
    pub lease: &'a DeviceLease,
    /// Fence token observed for the current lease.
    pub observed_fence_token: u64,
    /// Evidence for the admitted command or backend request.
    pub command_evidence_refs: Vec<EntityRef>,
    /// Operation request timestamp.
    pub requested_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Unverified application-stop attempt retaining the original Application Session identity.
pub struct ApplicationStopAttempt {
    /// Application stop-attempt identity.
    pub stop_ref: EntityRef,
    /// Device session ref.
    pub device_session_ref: EntityRef,
    /// Application Session identity bound to the observation.
    pub application_session_ref: EntityRef,
    /// Android package identifier.
    pub package_id: String,
    /// Provider generation bound to the observation.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to the observation.
    pub connection_epoch: u64,
    /// Evidence for the admitted command or backend request.
    pub command_evidence_refs: Vec<EntityRef>,
    /// Operation request timestamp.
    pub requested_at: String,
    application_snapshot: ApplicationSession,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Independent process/activity absence read-back used to verify application stop.
pub struct ApplicationStopReadBack {
    /// Provider generation bound to the observation.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to the observation.
    pub connection_epoch: u64,
    /// Android package identifier.
    pub package_id: String,
    /// Observed process aliases supporting application state.
    pub process_aliases: Vec<String>,
    /// Observed foreground Android activity or equivalent runtime context.
    pub activity_or_context: Option<String>,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Read-back observation timestamp.
    pub observed_at: String,
}

/// Admit an application-stop command under the current Application Session authority.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn admit_application_stop(
    request: ApplicationStopRequest<'_>,
) -> Result<ApplicationStopAttempt, AndroidRuntimeError> {
    require_current_session_binding(request.session, request.interface, request.lease)?;
    request.lease.fence(
        request.interface,
        request.observed_fence_token,
        "android.application.stop",
    )?;
    if request.application.device_session_ref != request.session.session_ref
        || request.application.provider_generation != request.interface.provider_generation
        || request.application.connection_epoch != request.interface.connection_epoch
        || request.command_evidence_refs.is_empty()
    {
        return Err(AndroidRuntimeError::ApplicationStopUnverified);
    }
    if request.requested_at.trim().is_empty() {
        return Err(AndroidRuntimeError::EmptyTimestamp);
    }
    Ok(ApplicationStopAttempt {
        stop_ref: EntityRef::new("application.stop_attempt")?,
        device_session_ref: request.session.session_ref.clone(),
        application_session_ref: request.application.session_ref.clone(),
        package_id: request.application.package_id.clone(),
        provider_generation: request.interface.provider_generation,
        connection_epoch: request.interface.connection_epoch,
        command_evidence_refs: request.command_evidence_refs,
        requested_at: request.requested_at,
        application_snapshot: request.application.clone(),
    })
}

/// Verify application stop only after current-epoch read-back proves process and activity absence.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn verify_application_stop(
    attempt: &ApplicationStopAttempt,
    read_back: ApplicationStopReadBack,
) -> Result<ApplicationSession, AndroidRuntimeError> {
    if read_back.provider_generation != attempt.provider_generation
        || read_back.connection_epoch != attempt.connection_epoch
        || read_back.package_id != attempt.package_id
        || !read_back.process_aliases.is_empty()
        || read_back.activity_or_context.is_some()
        || read_back.evidence_refs.is_empty()
        || read_back.observed_at.trim().is_empty()
    {
        return Err(AndroidRuntimeError::ApplicationStopUnverified);
    }
    let mut stopped = attempt.application_snapshot.clone();
    stopped.process_aliases.clear();
    stopped.activity_or_context.clear();
    stopped.evidence_refs.extend(read_back.evidence_refs);
    stopped.state = ApplicationSessionState::Stopped;
    Ok(stopped)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Privacy-governed Android evidence artifact class.
pub enum EvidenceCaptureKind {
    /// Single-frame screenshot artifact.
    Screenshot,
    /// Time-bounded screen recording artifact.
    Recording,
    /// Time-bounded Android log artifact.
    LogSegment,
}

#[derive(Debug)]
/// Inputs required to admit screenshot, recording, or log capture.
pub struct EvidenceCaptureRequest<'a> {
    /// Current Device Session.
    pub session: &'a DeviceSession,
    /// Current C08 Device interface record.
    pub interface: &'a DeviceInterfaceRecord,
    /// Current C08 Device lease.
    pub lease: &'a DeviceLease,
    /// Fence token observed for the current lease.
    pub observed_fence_token: u64,
    /// Evidence artifact class.
    pub kind: EvidenceCaptureKind,
    /// Backend that produced the evidence artifact.
    pub producer_backend: String,
    /// Producer backend version.
    pub producer_version: String,
    /// Privacy classification applied to captured evidence.
    pub privacy_class: String,
    /// Retention policy governing the captured artifact.
    pub retention_policy_ref: EntityRef,
    /// Evidence for the admitted command or backend request.
    pub command_evidence_refs: Vec<EntityRef>,
    /// Operation request timestamp.
    pub requested_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Unverified evidence-capture attempt bound to current Provider generation and connection epoch.
pub struct EvidenceCaptureAttempt {
    /// Evidence-capture attempt identity.
    pub capture_ref: EntityRef,
    /// Device session ref.
    pub device_session_ref: EntityRef,
    /// Evidence artifact class.
    pub kind: EvidenceCaptureKind,
    /// Backend that produced the evidence artifact.
    pub producer_backend: String,
    /// Producer backend version.
    pub producer_version: String,
    /// Privacy classification applied to captured evidence.
    pub privacy_class: String,
    /// Retention policy governing the captured artifact.
    pub retention_policy_ref: EntityRef,
    /// Provider generation bound to the observation.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to the observation.
    pub connection_epoch: u64,
    /// Evidence for the admitted command or backend request.
    pub command_evidence_refs: Vec<EntityRef>,
    /// Operation request timestamp.
    pub requested_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Artifact read-back used to verify an evidence capture against its originating epoch.
pub struct EvidenceCaptureReadBack {
    /// Provider generation bound to the observation.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to the observation.
    pub connection_epoch: u64,
    /// Verified captured artifact identity.
    pub artifact_ref: Option<EntityRef>,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Read-back observation timestamp.
    pub observed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Verified privacy-governed screenshot, recording, or log artifact.
pub struct VerifiedEvidenceCapture {
    /// Evidence-capture attempt identity.
    pub capture_ref: EntityRef,
    /// Device session ref.
    pub device_session_ref: EntityRef,
    /// Evidence artifact class.
    pub kind: EvidenceCaptureKind,
    /// Verified captured artifact identity.
    pub artifact_ref: EntityRef,
    /// Backend that produced the evidence artifact.
    pub producer_backend: String,
    /// Producer backend version.
    pub producer_version: String,
    /// Privacy classification applied to captured evidence.
    pub privacy_class: String,
    /// Retention policy governing the captured artifact.
    pub retention_policy_ref: EntityRef,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Verification timestamp.
    pub verified_at: String,
}

/// Admit privacy-governed screenshot, recording, or log capture under the evidence-capture lease scope.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn admit_evidence_capture(
    request: EvidenceCaptureRequest<'_>,
) -> Result<EvidenceCaptureAttempt, AndroidRuntimeError> {
    require_current_session_binding(request.session, request.interface, request.lease)?;
    request.lease.fence(
        request.interface,
        request.observed_fence_token,
        "android.evidence.capture",
    )?;
    if request.session.privacy_policy_refs.is_empty()
        || request.producer_backend.trim().is_empty()
        || request.producer_version.trim().is_empty()
        || request.privacy_class.trim().is_empty()
        || request.command_evidence_refs.is_empty()
    {
        return Err(AndroidRuntimeError::EvidenceCaptureUnverified);
    }
    if request.requested_at.trim().is_empty() {
        return Err(AndroidRuntimeError::EmptyTimestamp);
    }
    Ok(EvidenceCaptureAttempt {
        capture_ref: EntityRef::new("proof.evidence_capture")?,
        device_session_ref: request.session.session_ref.clone(),
        kind: request.kind,
        producer_backend: request.producer_backend,
        producer_version: request.producer_version,
        privacy_class: request.privacy_class,
        retention_policy_ref: request.retention_policy_ref,
        provider_generation: request.interface.provider_generation,
        connection_epoch: request.interface.connection_epoch,
        command_evidence_refs: request.command_evidence_refs,
        requested_at: request.requested_at,
    })
}

/// Verify a captured artifact only when read-back belongs to the originating Provider generation and connection epoch.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn verify_evidence_capture(
    attempt: &EvidenceCaptureAttempt,
    read_back: EvidenceCaptureReadBack,
) -> Result<VerifiedEvidenceCapture, AndroidRuntimeError> {
    if read_back.provider_generation != attempt.provider_generation
        || read_back.connection_epoch != attempt.connection_epoch
    {
        return Err(AndroidRuntimeError::EvidenceCaptureUnverified);
    }
    let artifact_ref = read_back
        .artifact_ref
        .ok_or(AndroidRuntimeError::EvidenceCaptureUnverified)?;
    if read_back.evidence_refs.is_empty() || read_back.observed_at.trim().is_empty() {
        return Err(AndroidRuntimeError::EvidenceCaptureUnverified);
    }
    Ok(VerifiedEvidenceCapture {
        capture_ref: attempt.capture_ref.clone(),
        device_session_ref: attempt.device_session_ref.clone(),
        kind: attempt.kind,
        artifact_ref,
        producer_backend: attempt.producer_backend.clone(),
        producer_version: attempt.producer_version.clone(),
        privacy_class: attempt.privacy_class.clone(),
        retention_policy_ref: attempt.retention_policy_ref.clone(),
        evidence_refs: read_back.evidence_refs,
        verified_at: read_back.observed_at,
    })
}

#[derive(Debug)]
/// Inputs required to admit end-of-session Android cleanup.
pub struct DeviceCleanupRequest<'a> {
    /// Current Device Session.
    pub session: &'a DeviceSession,
    /// Current C08 Device interface record.
    pub interface: &'a DeviceInterfaceRecord,
    /// Current C08 Device lease.
    pub lease: &'a DeviceLease,
    /// Fence token observed for the current lease.
    pub observed_fence_token: u64,
    /// Cleanup recipe executed for the session.
    pub cleanup_recipe_ref: EntityRef,
    /// Evidence for the admitted command or backend request.
    pub command_evidence_refs: Vec<EntityRef>,
    /// Operation request timestamp.
    pub requested_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Unverified cleanup attempt bound to current Device Session authority.
pub struct DeviceCleanupAttempt {
    /// Cleanup-attempt identity.
    pub cleanup_ref: EntityRef,
    /// Device session ref.
    pub device_session_ref: EntityRef,
    /// Cleanup recipe executed for the session.
    pub cleanup_recipe_ref: EntityRef,
    /// Provider generation bound to the observation.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to the observation.
    pub connection_epoch: u64,
    /// Evidence for the admitted command or backend request.
    pub command_evidence_refs: Vec<EntityRef>,
    /// Operation request timestamp.
    pub requested_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Independent cleanup read-back describing residual device state.
pub struct DeviceCleanupReadBack {
    /// Provider generation bound to the observation.
    pub provider_generation: ProviderGeneration,
    /// Connection epoch bound to the observation.
    pub connection_epoch: u64,
    /// Whether the backend acknowledged execution.
    pub backend_acknowledged: bool,
    /// Evidence references for residual state remaining after cleanup.
    pub residual_state_refs: Vec<EntityRef>,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Read-back observation timestamp.
    pub observed_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Disposition assigned after independent cleanup verification.
pub enum CleanupDisposition {
    /// Cleanup was independently verified with no residual state.
    Verified,
    /// Cleanup could not be verified; Device must remain unavailable.
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Cleanup result that either closes the session or quarantines it.
pub struct DeviceCleanupReceipt {
    /// Cleanup-attempt identity.
    pub cleanup_ref: EntityRef,
    /// Device session ref.
    pub device_session_ref: EntityRef,
    /// Cleanup recipe executed for the session.
    pub cleanup_recipe_ref: EntityRef,
    /// Verified-clean or quarantined cleanup disposition.
    pub disposition: CleanupDisposition,
    /// Session state resulting from cleanup verification.
    pub session_state: DeviceSessionState,
    /// Evidence references for residual state remaining after cleanup.
    pub residual_state_refs: Vec<EntityRef>,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Verification timestamp.
    pub verified_at: String,
}

/// Admit end-of-session cleanup under the dedicated cleanup lease scope.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn admit_device_cleanup(
    request: DeviceCleanupRequest<'_>,
) -> Result<DeviceCleanupAttempt, AndroidRuntimeError> {
    require_current_session_binding(request.session, request.interface, request.lease)?;
    request.lease.fence(
        request.interface,
        request.observed_fence_token,
        "android.session.cleanup",
    )?;
    if request.command_evidence_refs.is_empty() {
        return Err(AndroidRuntimeError::CleanupReadBackMismatch);
    }
    if request.requested_at.trim().is_empty() {
        return Err(AndroidRuntimeError::EmptyTimestamp);
    }
    Ok(DeviceCleanupAttempt {
        cleanup_ref: EntityRef::new("device.cleanup_attempt")?,
        device_session_ref: request.session.session_ref.clone(),
        cleanup_recipe_ref: request.cleanup_recipe_ref,
        provider_generation: request.interface.provider_generation,
        connection_epoch: request.interface.connection_epoch,
        command_evidence_refs: request.command_evidence_refs,
        requested_at: request.requested_at,
    })
}

/// Verify cleanup independently; stale, negative, or residual-state read-back is quarantined rather than returned available.
///
/// # Errors
/// Returns [`AndroidRuntimeError`] when authority, context, evidence, or read-back validation fails.
pub fn verify_device_cleanup(
    attempt: &DeviceCleanupAttempt,
    read_back: DeviceCleanupReadBack,
) -> Result<DeviceCleanupReceipt, AndroidRuntimeError> {
    if read_back.evidence_refs.is_empty() || read_back.observed_at.trim().is_empty() {
        return Err(AndroidRuntimeError::CleanupReadBackMismatch);
    }
    let disposition = if read_back.provider_generation == attempt.provider_generation
        && read_back.connection_epoch == attempt.connection_epoch
        && read_back.backend_acknowledged
        && read_back.residual_state_refs.is_empty()
    {
        CleanupDisposition::Verified
    } else {
        CleanupDisposition::Quarantined
    };
    let session_state = match disposition {
        CleanupDisposition::Verified => DeviceSessionState::Closed,
        CleanupDisposition::Quarantined => DeviceSessionState::Failed,
    };
    Ok(DeviceCleanupReceipt {
        cleanup_ref: attempt.cleanup_ref.clone(),
        device_session_ref: attempt.device_session_ref.clone(),
        cleanup_recipe_ref: attempt.cleanup_recipe_ref.clone(),
        disposition,
        session_state,
        residual_state_refs: read_back.residual_state_refs,
        evidence_refs: read_back.evidence_refs,
        verified_at: read_back.observed_at,
    })
}
