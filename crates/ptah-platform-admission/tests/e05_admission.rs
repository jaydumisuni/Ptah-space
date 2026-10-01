//! E05 pure platform-admission acceptance tests.

use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::{
    Architecture, NodeCapabilitySnapshot, NodeHealth, NodeLifecycleState, NodeReachability,
    NodeStateProjection, OsFamily, PlatformFacts, SnapshotOutcome,
};
use ptah_node_link::{CredentialFingerprint, ProtocolVersion, SessionBinding};
use ptah_platform_admission::{
    diagnostic_advisory_for_rejection, evaluate_platform_admission, PlatformAdmissionProfile,
    PlatformAdmissionRejection, PlatformNodeClass,
};

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid entity kind")
}

fn binding(node_id: NodeId, generation: NodeGeneration, epoch: ConnectionEpoch) -> SessionBinding {
    SessionBinding {
        node_id,
        node_generation: generation,
        connection_epoch: epoch,
        enrollment_ref: entity("runtime.node_enrollment"),
        credential_fingerprint: CredentialFingerprint::from_der(b"e05-admission-test"),
        negotiated_protocol: ProtocolVersion { major: 1, minor: 0 },
    }
}

fn capability(
    session: &SessionBinding,
    os_family: OsFamily,
    architecture: Architecture,
    outcome: SnapshotOutcome,
    claims: Vec<EntityRef>,
    providers: Vec<EntityRef>,
) -> NodeCapabilitySnapshot {
    NodeCapabilitySnapshot::new(
        session
            .node_id
            .entity_ref(session.node_generation, session.connection_epoch),
        session.node_generation,
        session.connection_epoch,
        outcome,
        "e05-test-agent",
        PlatformFacts {
            os_family,
            os_name: None,
            os_version: None,
            kernel_name: None,
            kernel_version: None,
            architecture,
            architecture_detail: None,
        },
        claims,
        vec![entity("runtime.capability_verification")],
        providers,
        vec![entity("runtime.node_observation")],
        vec![entity("activity.receipt")],
        Vec::new(),
    )
    .expect("capability snapshot")
}

fn state(
    session: &SessionBinding,
    capability: &NodeCapabilitySnapshot,
    lifecycle: NodeLifecycleState,
    reachability: NodeReachability,
    health: NodeHealth,
) -> NodeStateProjection {
    NodeStateProjection {
        node_ref: session
            .node_id
            .entity_ref(session.node_generation, session.connection_epoch),
        lifecycle,
        node_generation: session.node_generation,
        connection_epoch: session.connection_epoch,
        current_reachability: reachability,
        current_health: health,
        capability_snapshot_refs: vec![capability.snapshot_ref.clone()],
        resource_snapshot_refs: Vec::new(),
        observation_refs: vec![entity("runtime.node_observation")],
    }
}

fn strict_profile(
    class: PlatformNodeClass,
    capability_ref: EntityRef,
    provider_ref: EntityRef,
) -> PlatformAdmissionProfile {
    PlatformAdmissionProfile::new(
        class,
        vec![capability_ref],
        vec![provider_ref],
        vec![Architecture::X86_64],
        false,
    )
}

fn admitted(class: PlatformNodeClass, os_family: OsFamily) {
    let node_id = NodeId::new();
    let generation = NodeGeneration::new(7);
    let epoch = ConnectionEpoch::new(11);
    let session = binding(node_id, generation, epoch);
    let required_capability = entity("runtime.capability");
    let provider = entity("runtime.provider_revision");
    let snapshot = capability(
        &session,
        os_family,
        Architecture::X86_64,
        SnapshotOutcome::Complete,
        vec![required_capability.clone()],
        vec![provider.clone()],
    );
    let state = state(
        &session,
        &snapshot,
        NodeLifecycleState::Active,
        NodeReachability::Online,
        NodeHealth::Healthy,
    );

    let decision = evaluate_platform_admission(
        &session,
        &state,
        &snapshot,
        &strict_profile(class, required_capability, provider),
    )
    .expect("exact current platform must admit");

    assert_eq!(decision.platform_class(), class);
    assert_eq!(decision.node_id(), node_id);
    assert_eq!(decision.node_generation(), generation);
    assert_eq!(decision.connection_epoch(), epoch);
    assert_eq!(decision.capability_snapshot_ref(), &snapshot.snapshot_ref);
    assert!(!decision.evidence_refs().is_empty());
}

#[test]
fn all_five_roadmap_platform_classes_admit_from_exact_current_evidence() {
    admitted(PlatformNodeClass::AlwaysOnLinux, OsFamily::Linux);
    admitted(PlatformNodeClass::WorkstationGpu, OsFamily::Linux);
    admitted(PlatformNodeClass::Windows, OsFamily::Windows);
    admitted(PlatformNodeClass::Macos, OsFamily::Macos);
    admitted(PlatformNodeClass::AndroidDevice, OsFamily::Android);
}

#[test]
fn foreign_node_fails_closed() {
    let generation = NodeGeneration::new(3);
    let epoch = ConnectionEpoch::new(5);
    let session = binding(NodeId::new(), generation, epoch);
    let other = binding(NodeId::new(), generation, epoch);
    let cap_ref = entity("runtime.capability");
    let provider = entity("runtime.provider_revision");
    let snapshot = capability(
        &other,
        OsFamily::Linux,
        Architecture::X86_64,
        SnapshotOutcome::Complete,
        vec![cap_ref.clone()],
        vec![provider.clone()],
    );
    let state = state(
        &other,
        &snapshot,
        NodeLifecycleState::Active,
        NodeReachability::Online,
        NodeHealth::Healthy,
    );

    assert_eq!(
        evaluate_platform_admission(
            &session,
            &state,
            &snapshot,
            &strict_profile(PlatformNodeClass::AlwaysOnLinux, cap_ref, provider),
        ),
        Err(PlatformAdmissionRejection::NodeIdentityMismatch)
    );
}

#[test]
fn stale_generation_and_connection_epoch_fail_closed() {
    let node_id = NodeId::new();
    let current = binding(node_id, NodeGeneration::new(4), ConnectionEpoch::new(9));
    let cap_ref = entity("runtime.capability");
    let provider = entity("runtime.provider_revision");

    let stale_generation = binding(node_id, NodeGeneration::new(3), ConnectionEpoch::new(9));
    let snapshot = capability(
        &stale_generation,
        OsFamily::Linux,
        Architecture::X86_64,
        SnapshotOutcome::Complete,
        vec![cap_ref.clone()],
        vec![provider.clone()],
    );
    let stale_generation_state = state(
        &stale_generation,
        &snapshot,
        NodeLifecycleState::Active,
        NodeReachability::Online,
        NodeHealth::Healthy,
    );
    assert_eq!(
        evaluate_platform_admission(
            &current,
            &stale_generation_state,
            &snapshot,
            &strict_profile(
                PlatformNodeClass::AlwaysOnLinux,
                cap_ref.clone(),
                provider.clone()
            ),
        ),
        Err(PlatformAdmissionRejection::NodeGenerationMismatch)
    );

    let stale_epoch = binding(node_id, NodeGeneration::new(4), ConnectionEpoch::new(8));
    let snapshot = capability(
        &stale_epoch,
        OsFamily::Linux,
        Architecture::X86_64,
        SnapshotOutcome::Complete,
        vec![cap_ref.clone()],
        vec![provider.clone()],
    );
    let stale_epoch_state = state(
        &stale_epoch,
        &snapshot,
        NodeLifecycleState::Active,
        NodeReachability::Online,
        NodeHealth::Healthy,
    );
    assert_eq!(
        evaluate_platform_admission(
            &current,
            &stale_epoch_state,
            &snapshot,
            &strict_profile(PlatformNodeClass::AlwaysOnLinux, cap_ref, provider),
        ),
        Err(PlatformAdmissionRejection::ConnectionEpochMismatch)
    );
}

#[test]
fn non_active_or_non_online_node_is_not_admitted() {
    let session = binding(
        NodeId::new(),
        NodeGeneration::new(2),
        ConnectionEpoch::new(2),
    );
    let cap_ref = entity("runtime.capability");
    let provider = entity("runtime.provider_revision");
    let snapshot = capability(
        &session,
        OsFamily::Linux,
        Architecture::X86_64,
        SnapshotOutcome::Complete,
        vec![cap_ref.clone()],
        vec![provider.clone()],
    );
    let profile = strict_profile(
        PlatformNodeClass::AlwaysOnLinux,
        cap_ref.clone(),
        provider.clone(),
    );

    let draining = state(
        &session,
        &snapshot,
        NodeLifecycleState::Draining,
        NodeReachability::Online,
        NodeHealth::Healthy,
    );
    assert_eq!(
        evaluate_platform_admission(&session, &draining, &snapshot, &profile),
        Err(PlatformAdmissionRejection::NodeNotActive)
    );

    let offline = state(
        &session,
        &snapshot,
        NodeLifecycleState::Active,
        NodeReachability::Offline,
        NodeHealth::Healthy,
    );
    assert_eq!(
        evaluate_platform_admission(&session, &offline, &snapshot, &profile),
        Err(PlatformAdmissionRejection::NodeNotOnline)
    );
}

#[test]
fn health_is_strict_unless_degraded_is_explicitly_allowed() {
    let session = binding(
        NodeId::new(),
        NodeGeneration::new(2),
        ConnectionEpoch::new(3),
    );
    let cap_ref = entity("runtime.capability");
    let provider = entity("runtime.provider_revision");
    let snapshot = capability(
        &session,
        OsFamily::Linux,
        Architecture::X86_64,
        SnapshotOutcome::Complete,
        vec![cap_ref.clone()],
        vec![provider.clone()],
    );
    let degraded = state(
        &session,
        &snapshot,
        NodeLifecycleState::Active,
        NodeReachability::Online,
        NodeHealth::Degraded,
    );

    assert_eq!(
        evaluate_platform_admission(
            &session,
            &degraded,
            &snapshot,
            &strict_profile(
                PlatformNodeClass::AlwaysOnLinux,
                cap_ref.clone(),
                provider.clone()
            ),
        ),
        Err(PlatformAdmissionRejection::NodeHealthDegraded)
    );

    let profile = PlatformAdmissionProfile::new(
        PlatformNodeClass::AlwaysOnLinux,
        vec![cap_ref],
        vec![provider],
        vec![Architecture::X86_64],
        true,
    );
    let decision = evaluate_platform_admission(&session, &degraded, &snapshot, &profile)
        .expect("degraded health is admitted only by explicit policy");
    assert!(decision
        .limitations()
        .iter()
        .any(|item| item.contains("degraded")));
}

#[test]
fn incomplete_snapshot_and_wrong_os_fail_closed() {
    let session = binding(
        NodeId::new(),
        NodeGeneration::new(5),
        ConnectionEpoch::new(6),
    );
    let cap_ref = entity("runtime.capability");
    let provider = entity("runtime.provider_revision");
    let partial = capability(
        &session,
        OsFamily::Linux,
        Architecture::X86_64,
        SnapshotOutcome::Partial,
        vec![cap_ref.clone()],
        vec![provider.clone()],
    );
    let partial_state = state(
        &session,
        &partial,
        NodeLifecycleState::Active,
        NodeReachability::Online,
        NodeHealth::Healthy,
    );
    let profile = strict_profile(
        PlatformNodeClass::AlwaysOnLinux,
        cap_ref.clone(),
        provider.clone(),
    );
    assert_eq!(
        evaluate_platform_admission(&session, &partial_state, &partial, &profile),
        Err(PlatformAdmissionRejection::SnapshotIncomplete)
    );

    let windows = capability(
        &session,
        OsFamily::Windows,
        Architecture::X86_64,
        SnapshotOutcome::Complete,
        vec![cap_ref],
        vec![provider],
    );
    let windows_state = state(
        &session,
        &windows,
        NodeLifecycleState::Active,
        NodeReachability::Online,
        NodeHealth::Healthy,
    );
    assert_eq!(
        evaluate_platform_admission(&session, &windows_state, &windows, &profile),
        Err(PlatformAdmissionRejection::OperatingSystemMismatch)
    );
}

#[test]
fn profile_requirements_are_explicit_and_fail_closed() {
    let session = binding(
        NodeId::new(),
        NodeGeneration::new(8),
        ConnectionEpoch::new(8),
    );
    let required_capability = entity("runtime.capability");
    let required_provider = entity("runtime.provider_revision");
    let snapshot = capability(
        &session,
        OsFamily::Linux,
        Architecture::Aarch64,
        SnapshotOutcome::Complete,
        Vec::new(),
        Vec::new(),
    );
    let state = state(
        &session,
        &snapshot,
        NodeLifecycleState::Active,
        NodeReachability::Online,
        NodeHealth::Healthy,
    );

    assert_eq!(
        evaluate_platform_admission(
            &session,
            &state,
            &snapshot,
            &strict_profile(
                PlatformNodeClass::AlwaysOnLinux,
                required_capability.clone(),
                required_provider.clone()
            ),
        ),
        Err(PlatformAdmissionRejection::ArchitectureMismatch)
    );

    let profile = PlatformAdmissionProfile::new(
        PlatformNodeClass::AlwaysOnLinux,
        vec![required_capability],
        vec![required_provider],
        vec![Architecture::Aarch64],
        false,
    );
    assert_eq!(
        evaluate_platform_admission(&session, &state, &snapshot, &profile),
        Err(PlatformAdmissionRejection::MissingCapability)
    );
}

#[test]
fn state_must_name_the_exact_capability_snapshot() {
    let session = binding(
        NodeId::new(),
        NodeGeneration::new(9),
        ConnectionEpoch::new(2),
    );
    let cap_ref = entity("runtime.capability");
    let provider = entity("runtime.provider_revision");
    let snapshot = capability(
        &session,
        OsFamily::Linux,
        Architecture::X86_64,
        SnapshotOutcome::Complete,
        vec![cap_ref.clone()],
        vec![provider.clone()],
    );
    let mut state = state(
        &session,
        &snapshot,
        NodeLifecycleState::Active,
        NodeReachability::Online,
        NodeHealth::Healthy,
    );
    state.capability_snapshot_refs.clear();

    assert_eq!(
        evaluate_platform_admission(
            &session,
            &state,
            &snapshot,
            &strict_profile(PlatformNodeClass::AlwaysOnLinux, cap_ref, provider),
        ),
        Err(PlatformAdmissionRejection::CapabilitySnapshotNotCurrent)
    );
}

#[test]
fn unknown_and_unhealthy_health_fail_closed() {
    let session = binding(
        NodeId::new(),
        NodeGeneration::new(4),
        ConnectionEpoch::new(4),
    );
    let cap_ref = entity("runtime.capability");
    let provider = entity("runtime.provider_revision");
    let snapshot = capability(
        &session,
        OsFamily::Linux,
        Architecture::X86_64,
        SnapshotOutcome::Complete,
        vec![cap_ref.clone()],
        vec![provider.clone()],
    );
    let profile = strict_profile(PlatformNodeClass::AlwaysOnLinux, cap_ref, provider);

    let unknown = state(
        &session,
        &snapshot,
        NodeLifecycleState::Active,
        NodeReachability::Online,
        NodeHealth::Unknown,
    );
    assert_eq!(
        evaluate_platform_admission(&session, &unknown, &snapshot, &profile),
        Err(PlatformAdmissionRejection::NodeHealthUnknown)
    );

    let unhealthy = state(
        &session,
        &snapshot,
        NodeLifecycleState::Active,
        NodeReachability::Online,
        NodeHealth::Unhealthy,
    );
    assert_eq!(
        evaluate_platform_admission(&session, &unhealthy, &snapshot, &profile),
        Err(PlatformAdmissionRejection::NodeHealthUnhealthy)
    );
}

#[test]
fn missing_provider_revision_fails_closed() {
    let session = binding(
        NodeId::new(),
        NodeGeneration::new(5),
        ConnectionEpoch::new(5),
    );
    let cap_ref = entity("runtime.capability");
    let required_provider = entity("runtime.provider_revision");
    let snapshot = capability(
        &session,
        OsFamily::Linux,
        Architecture::X86_64,
        SnapshotOutcome::Complete,
        vec![cap_ref.clone()],
        Vec::new(),
    );
    let state = state(
        &session,
        &snapshot,
        NodeLifecycleState::Active,
        NodeReachability::Online,
        NodeHealth::Healthy,
    );

    assert_eq!(
        evaluate_platform_admission(
            &session,
            &state,
            &snapshot,
            &strict_profile(PlatformNodeClass::AlwaysOnLinux, cap_ref, required_provider,),
        ),
        Err(PlatformAdmissionRejection::MissingProviderRevision)
    );
}

#[test]
fn capability_claims_without_verification_fail_closed() {
    let session = binding(
        NodeId::new(),
        NodeGeneration::new(6),
        ConnectionEpoch::new(6),
    );
    let cap_ref = entity("runtime.capability");
    let provider = entity("runtime.provider_revision");
    let mut snapshot = capability(
        &session,
        OsFamily::Linux,
        Architecture::X86_64,
        SnapshotOutcome::Complete,
        vec![cap_ref.clone()],
        vec![provider.clone()],
    );
    snapshot.capability_verification_refs.clear();
    let state = state(
        &session,
        &snapshot,
        NodeLifecycleState::Active,
        NodeReachability::Online,
        NodeHealth::Healthy,
    );

    assert_eq!(
        evaluate_platform_admission(
            &session,
            &state,
            &snapshot,
            &strict_profile(PlatformNodeClass::AlwaysOnLinux, cap_ref, provider),
        ),
        Err(PlatformAdmissionRejection::MissingCapabilityVerification)
    );
}

#[test]
fn rejected_admission_projects_only_an_evidence_bound_non_authorizing_advisory() {
    let session = binding(
        NodeId::new(),
        NodeGeneration::new(7),
        ConnectionEpoch::new(7),
    );
    let required_capability = entity("runtime.capability");
    let provider = entity("runtime.provider_revision");
    let snapshot = capability(
        &session,
        OsFamily::Linux,
        Architecture::X86_64,
        SnapshotOutcome::Complete,
        Vec::new(),
        vec![provider.clone()],
    );
    let state = state(
        &session,
        &snapshot,
        NodeLifecycleState::Active,
        NodeReachability::Online,
        NodeHealth::Healthy,
    );
    let profile = strict_profile(
        PlatformNodeClass::WorkstationGpu,
        required_capability,
        provider,
    );
    let rejection = evaluate_platform_admission(&session, &state, &snapshot, &profile)
        .expect_err("missing explicit GPU/workstation capability must reject");
    assert_eq!(rejection, PlatformAdmissionRejection::MissingCapability);

    let advisory = diagnostic_advisory_for_rejection(&state, &snapshot, &profile, rejection)
        .expect("rejection should project through the existing A02 advisory boundary");

    assert_eq!(advisory.view_kind, "platform_diagnostic_advisory");
    assert_eq!(advisory.affected_node_ref, state.node_ref);
    assert!(!advisory.evidence_refs.is_empty());
    assert!(!advisory.automatic_upgrade_authorized);
    assert!(!advisory.self_approved);
    assert!(advisory.required_caller_decision.contains("caller"));
}
