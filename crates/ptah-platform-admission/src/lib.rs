#![forbid(unsafe_code)]
//! E05 Platform Node admission policy.
//!
//! E05 consumes exact current E01/A02 evidence and answers one bounded question:
//! whether that evidence satisfies an explicit platform-admission profile.
//! Admission is evidence, never Reservation, Lease, Fence or dispatch authority.

use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::{
    AdvisoryWorkState, Architecture, DiagnosticAdvisory, NodeAgentError, NodeCapabilitySnapshot,
    NodeHealth, NodeLifecycleState, NodeReachability, NodeStateProjection, OsFamily,
    SnapshotOutcome,
};
use ptah_node_link::SessionBinding;

/// Roadmap-ordered E05 platform classes.
///
/// These are implementation-level admission classes, not new canonical entity identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformNodeClass {
    /// Always-on Linux Node such as the mini-PC orchestration role.
    AlwaysOnLinux,
    /// Linux workstation Node with explicitly evidenced GPU/workstation capability.
    WorkstationGpu,
    /// Windows Node.
    Windows,
    /// macOS Node.
    Macos,
    /// Android endpoint participating as a Platform Node.
    AndroidDevice,
}

impl PlatformNodeClass {
    /// Return the A02 operating-system family required by this platform class.
    #[must_use]
    pub const fn expected_os_family(self) -> OsFamily {
        match self {
            Self::AlwaysOnLinux | Self::WorkstationGpu => OsFamily::Linux,
            Self::Windows => OsFamily::Windows,
            Self::Macos => OsFamily::Macos,
            Self::AndroidDevice => OsFamily::Android,
        }
    }

    /// Return a stable machine-readable class name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AlwaysOnLinux => "always_on_linux",
            Self::WorkstationGpu => "workstation_gpu",
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::AndroidDevice => "android_device",
        }
    }
}

/// Explicit caller/policy requirements for one E05 admission evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformAdmissionProfile {
    platform_class: PlatformNodeClass,
    required_capability_refs: Vec<EntityRef>,
    required_provider_revision_refs: Vec<EntityRef>,
    allowed_architectures: Vec<Architecture>,
    allow_degraded_health: bool,
}

impl PlatformAdmissionProfile {
    /// Construct one explicit E05 platform-admission profile.
    #[must_use]
    pub fn new(
        platform_class: PlatformNodeClass,
        required_capability_refs: Vec<EntityRef>,
        required_provider_revision_refs: Vec<EntityRef>,
        allowed_architectures: Vec<Architecture>,
        allow_degraded_health: bool,
    ) -> Self {
        Self {
            platform_class,
            required_capability_refs,
            required_provider_revision_refs,
            allowed_architectures,
            allow_degraded_health,
        }
    }

    /// Required roadmap platform class.
    #[must_use]
    pub const fn platform_class(&self) -> PlatformNodeClass {
        self.platform_class
    }

    /// Explicit capability references required for admission.
    #[must_use]
    pub fn required_capability_refs(&self) -> &[EntityRef] {
        &self.required_capability_refs
    }

    /// Explicit Provider Revision references required for admission.
    #[must_use]
    pub fn required_provider_revision_refs(&self) -> &[EntityRef] {
        &self.required_provider_revision_refs
    }

    /// Explicit allowed architecture set. An empty set means no architecture restriction.
    #[must_use]
    pub fn allowed_architectures(&self) -> &[Architecture] {
        &self.allowed_architectures
    }

    /// Whether degraded A02 health is explicitly admissible.
    #[must_use]
    pub const fn allow_degraded_health(&self) -> bool {
        self.allow_degraded_health
    }
}

/// Stable fail-closed E05 admission rejection classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformAdmissionRejection {
    /// A02 state/snapshot canonical Node identity differs from the E01 session.
    NodeIdentityMismatch,
    /// A02 state/snapshot Node Generation differs from the E01 session.
    NodeGenerationMismatch,
    /// A02 state/snapshot Connection Epoch differs from the E01 session.
    ConnectionEpochMismatch,
    /// The current A02 state does not reference the exact capability snapshot.
    CapabilitySnapshotNotCurrent,
    /// The Node lifecycle is not Active.
    NodeNotActive,
    /// The Node is not currently Online.
    NodeNotOnline,
    /// Current Node health is unknown.
    NodeHealthUnknown,
    /// Current Node health is unhealthy.
    NodeHealthUnhealthy,
    /// Current Node health is degraded and policy did not explicitly allow it.
    NodeHealthDegraded,
    /// The A02 capability snapshot is partial or failed.
    SnapshotIncomplete,
    /// The platform OS family differs from the selected E05 class.
    OperatingSystemMismatch,
    /// The architecture is outside the profile's explicit allowed set.
    ArchitectureMismatch,
    /// A required verified capability reference is absent.
    MissingCapability,
    /// Capability claims exist without A02 verification references.
    MissingCapabilityVerification,
    /// A required Provider Revision reference is absent.
    MissingProviderRevision,
    /// Required supporting evidence is absent.
    MissingEvidence,
}

impl PlatformAdmissionRejection {
    /// Return a stable machine-readable rejection code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NodeIdentityMismatch => "node_identity_mismatch",
            Self::NodeGenerationMismatch => "node_generation_mismatch",
            Self::ConnectionEpochMismatch => "connection_epoch_mismatch",
            Self::CapabilitySnapshotNotCurrent => "capability_snapshot_not_current",
            Self::NodeNotActive => "node_not_active",
            Self::NodeNotOnline => "node_not_online",
            Self::NodeHealthUnknown => "node_health_unknown",
            Self::NodeHealthUnhealthy => "node_health_unhealthy",
            Self::NodeHealthDegraded => "node_health_degraded",
            Self::SnapshotIncomplete => "snapshot_incomplete",
            Self::OperatingSystemMismatch => "operating_system_mismatch",
            Self::ArchitectureMismatch => "architecture_mismatch",
            Self::MissingCapability => "missing_capability",
            Self::MissingCapabilityVerification => "missing_capability_verification",
            Self::MissingProviderRevision => "missing_provider_revision",
            Self::MissingEvidence => "missing_evidence",
        }
    }
}

/// Evidence-bound E05 admission result.
///
/// This result grants no execution authority. E02 remains the sole owner of
/// Reservation, Lease, Fence and `DispatchAuthority` issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformAdmissionDecision {
    platform_class: PlatformNodeClass,
    node_id: NodeId,
    node_generation: NodeGeneration,
    connection_epoch: ConnectionEpoch,
    capability_snapshot_ref: EntityRef,
    evidence_refs: Vec<EntityRef>,
    limitations: Vec<String>,
}

impl PlatformAdmissionDecision {
    /// Admitted platform class.
    #[must_use]
    pub const fn platform_class(&self) -> PlatformNodeClass {
        self.platform_class
    }

    /// Stable canonical Node identity.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Exact admitted Node Generation.
    #[must_use]
    pub const fn node_generation(&self) -> NodeGeneration {
        self.node_generation
    }

    /// Exact admitted Connection Epoch.
    #[must_use]
    pub const fn connection_epoch(&self) -> ConnectionEpoch {
        self.connection_epoch
    }

    /// Exact A02 capability snapshot that earned this decision.
    #[must_use]
    pub const fn capability_snapshot_ref(&self) -> &EntityRef {
        &self.capability_snapshot_ref
    }

    /// Evidence retained by the decision.
    #[must_use]
    pub fn evidence_refs(&self) -> &[EntityRef] {
        &self.evidence_refs
    }

    /// Explicit limitations retained by the admission.
    #[must_use]
    pub fn limitations(&self) -> &[String] {
        &self.limitations
    }

    /// Recheck exact session/snapshot binding before composing this evidence elsewhere.
    #[must_use]
    pub fn matches(
        &self,
        session: &SessionBinding,
        snapshot: &NodeCapabilitySnapshot,
        platform_class: PlatformNodeClass,
    ) -> bool {
        self.platform_class == platform_class
            && self.node_id == session.node_id
            && self.node_generation == session.node_generation
            && self.connection_epoch == session.connection_epoch
            && self.capability_snapshot_ref == snapshot.snapshot_ref
    }
}

/// Evaluate exact current E01/A02 evidence against an explicit E05 admission profile.
///
/// # Errors
///
/// Fails closed for any stale/foreign binding, non-current Node state,
/// incomplete evidence, platform mismatch, or missing explicit requirement.
pub fn evaluate_platform_admission(
    session: &SessionBinding,
    state: &NodeStateProjection,
    capabilities: &NodeCapabilitySnapshot,
    profile: &PlatformAdmissionProfile,
) -> Result<PlatformAdmissionDecision, PlatformAdmissionRejection> {
    validate_state_binding(session, state)?;
    validate_capability_binding(session, capabilities)?;

    if !state
        .capability_snapshot_refs
        .contains(&capabilities.snapshot_ref)
    {
        return Err(PlatformAdmissionRejection::CapabilitySnapshotNotCurrent);
    }

    if state.lifecycle != NodeLifecycleState::Active {
        return Err(PlatformAdmissionRejection::NodeNotActive);
    }
    if state.current_reachability != NodeReachability::Online {
        return Err(PlatformAdmissionRejection::NodeNotOnline);
    }

    let mut limitations = Vec::new();
    match state.current_health {
        NodeHealth::Healthy => {}
        NodeHealth::Degraded if profile.allow_degraded_health => {
            limitations.push(String::from(
                "node health is degraded under explicit admission policy",
            ));
        }
        NodeHealth::Degraded => return Err(PlatformAdmissionRejection::NodeHealthDegraded),
        NodeHealth::Unknown => return Err(PlatformAdmissionRejection::NodeHealthUnknown),
        NodeHealth::Unhealthy => return Err(PlatformAdmissionRejection::NodeHealthUnhealthy),
    }

    if capabilities.snapshot_outcome != SnapshotOutcome::Complete {
        return Err(PlatformAdmissionRejection::SnapshotIncomplete);
    }
    if capabilities.platform.os_family != profile.platform_class.expected_os_family() {
        return Err(PlatformAdmissionRejection::OperatingSystemMismatch);
    }
    if !profile.allowed_architectures.is_empty()
        && !profile
            .allowed_architectures
            .contains(&capabilities.platform.architecture)
    {
        return Err(PlatformAdmissionRejection::ArchitectureMismatch);
    }
    if profile
        .required_capability_refs
        .iter()
        .any(|required| !capabilities.capability_claim_refs.contains(required))
    {
        return Err(PlatformAdmissionRejection::MissingCapability);
    }
    if !capabilities.capability_claim_refs.is_empty()
        && capabilities.capability_verification_refs.is_empty()
    {
        return Err(PlatformAdmissionRejection::MissingCapabilityVerification);
    }
    if profile
        .required_provider_revision_refs
        .iter()
        .any(|required| !capabilities.provider_revision_refs.contains(required))
    {
        return Err(PlatformAdmissionRejection::MissingProviderRevision);
    }
    if state.observation_refs.is_empty()
        || capabilities.observation_refs.is_empty()
        || capabilities.receipt_refs.is_empty()
    {
        return Err(PlatformAdmissionRejection::MissingEvidence);
    }

    limitations.extend(capabilities.limitations.iter().cloned());

    let mut evidence_refs = Vec::new();
    push_unique(&mut evidence_refs, capabilities.snapshot_ref.clone());
    extend_unique(&mut evidence_refs, &state.observation_refs);
    extend_unique(&mut evidence_refs, &capabilities.observation_refs);
    extend_unique(&mut evidence_refs, &capabilities.receipt_refs);
    extend_unique(
        &mut evidence_refs,
        &capabilities.capability_verification_refs,
    );
    extend_unique(&mut evidence_refs, &capabilities.provider_revision_refs);

    Ok(PlatformAdmissionDecision {
        platform_class: profile.platform_class,
        node_id: session.node_id,
        node_generation: session.node_generation,
        connection_epoch: session.connection_epoch,
        capability_snapshot_ref: capabilities.snapshot_ref.clone(),
        evidence_refs,
        limitations,
    })
}

/// Project one failed E05 admission through the existing A02 diagnostic-advisory boundary.
///
/// The returned View cannot approve or perform an upgrade; those fields remain
/// false by construction in A02.
///
/// # Errors
///
/// Propagates the existing A02 advisory validation/identifier failures when the
/// supplied owner evidence is insufficient to build a diagnostic View.
pub fn diagnostic_advisory_for_rejection(
    state: &NodeStateProjection,
    capabilities: &NodeCapabilitySnapshot,
    profile: &PlatformAdmissionProfile,
    rejection: PlatformAdmissionRejection,
) -> Result<DiagnosticAdvisory, NodeAgentError> {
    let mut evidence_refs = Vec::new();
    push_unique(&mut evidence_refs, capabilities.snapshot_ref.clone());
    extend_unique(&mut evidence_refs, &state.observation_refs);
    extend_unique(&mut evidence_refs, &capabilities.observation_refs);
    extend_unique(&mut evidence_refs, &capabilities.receipt_refs);
    extend_unique(
        &mut evidence_refs,
        &capabilities.capability_verification_refs,
    );
    extend_unique(&mut evidence_refs, &capabilities.provider_revision_refs);

    let observed_condition = format!("platform admission rejected: {}", rejection.code());
    let expected_condition = format!(
        "current evidence satisfies E05 {} admission profile",
        profile.platform_class.code()
    );
    let uncertainty = if capabilities.limitations.is_empty() {
        String::from("no additional capability-snapshot limitation was retained")
    } else {
        format!(
            "capability snapshot limitations: {}",
            capabilities.limitations.join("; ")
        )
    };

    DiagnosticAdvisory::new(
        state.node_ref.clone(),
        evidence_refs,
        observed_condition,
        expected_condition,
        "requested platform-node admission is blocked",
        uncertainty,
        None,
        "authorized caller must decide whether to refresh evidence, continue degraded work, or submit a separate upgrade/change Activity",
        AdvisoryWorkState::Blocked,
    )
}

fn validate_state_binding(
    session: &SessionBinding,
    state: &NodeStateProjection,
) -> Result<(), PlatformAdmissionRejection> {
    if state.node_ref.entity_id != session.node_id.entity_id() {
        return Err(PlatformAdmissionRejection::NodeIdentityMismatch);
    }
    if state.node_generation != session.node_generation
        || state.node_ref.node_generation != Some(session.node_generation.value())
    {
        return Err(PlatformAdmissionRejection::NodeGenerationMismatch);
    }
    if state.connection_epoch != session.connection_epoch
        || state.node_ref.connection_epoch != Some(session.connection_epoch.value())
    {
        return Err(PlatformAdmissionRejection::ConnectionEpochMismatch);
    }
    Ok(())
}

fn validate_capability_binding(
    session: &SessionBinding,
    capabilities: &NodeCapabilitySnapshot,
) -> Result<(), PlatformAdmissionRejection> {
    if capabilities.node_ref.entity_id != session.node_id.entity_id() {
        return Err(PlatformAdmissionRejection::NodeIdentityMismatch);
    }
    if capabilities.node_generation != session.node_generation
        || capabilities.node_ref.node_generation != Some(session.node_generation.value())
    {
        return Err(PlatformAdmissionRejection::NodeGenerationMismatch);
    }
    if capabilities.connection_epoch != session.connection_epoch
        || capabilities.node_ref.connection_epoch != Some(session.connection_epoch.value())
    {
        return Err(PlatformAdmissionRejection::ConnectionEpochMismatch);
    }
    Ok(())
}

fn extend_unique(target: &mut Vec<EntityRef>, values: &[EntityRef]) {
    for value in values {
        push_unique(target, value.clone());
    }
}

fn push_unique(target: &mut Vec<EntityRef>, value: EntityRef) {
    if !target.contains(&value) {
        target.push(value);
    }
}
