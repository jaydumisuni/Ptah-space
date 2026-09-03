//! D08 Application platform expansion acceptance proof.

use native_process::{
    DisconnectPolicy, ProcessMode, ProcessRecord, ProcessSpec, ProcessState, StreamTopology,
};
use ptah_activity_runtime::AttemptContext;
use ptah_application_runtime::{
    APPLICATION_COMPATIBILITY_SCHEMA_ID, APPLICATION_REVISION_SCHEMA_ID, APPLICATION_SCHEMA_ID,
    APPLICATION_SESSION_LIFECYCLE, APPLICATION_SESSION_SCHEMA_ID, APPLICATION_WINDOW_LIFECYCLE,
    APPLICATION_WINDOW_OBSERVATION_SCHEMA_ID, APPLICATION_WINDOW_SCHEMA_ID, ApplicationAvailability,
    ApplicationOperation, ApplicationSessionLifecycle, ApplicationWindowProjection,
    CompatibilityDecision, CompatibilityRequirement, D08Error, DISPLAY_OBSERVATION_SCHEMA_ID,
    DISPLAY_SESSION_LIFECYCLE, DISPLAY_SESSION_SCHEMA_ID, DisplayLifecycle, DisplayObservation,
    DisplaySessionProjection, DisplaySessionRequest, ExecutionDisposition, InputCapability,
    LaunchMode, LocalLaunchRequest, LocalReadBack, NodeLocalCompatibility, PlatformClass,
    RequirementOutcome, SessionLocality, WindowLifecycle, WindowObservation, WindowStateClaim,
    apply_display_observation, apply_window_observation, create_application_window,
    prepare_display_session, prepare_local_application_session, verify_local_application_session,
};
use ptah_contracts::generated;
use ptah_identifiers::EntityRef;
use ptah_provider_api::{EndpointAlias, EndpointAliasType, ProviderGeneration};
use std::collections::BTreeMap;

fn entity(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("test entity kind must be valid")
}

fn requirement(outcome: RequirementOutcome) -> CompatibilityRequirement {
    CompatibilityRequirement {
        key: String::from("application.launch.graphical"),
        mandatory: true,
        outcome,
        condition_refs: Vec::new(),
        evidence_refs: vec![entity("proof.evidence")],
        reason: None,
    }
}

fn compatibility() -> NodeLocalCompatibility {
    NodeLocalCompatibility {
        compatibility_ref: entity("application.compatibility"),
        application_revision_ref: entity("application.revision"),
        operation: ApplicationOperation::LaunchGraphical,
        provider_revision_ref: entity("runtime.provider_revision"),
        provider_instance_ref: entity("runtime.provider_instance"),
        provider_generation: ProviderGeneration::new(7).expect("positive generation"),
        node_ref: entity("core.node"),
        node_generation: 4,
        node_capability_snapshot_ref: entity("runtime.node_capability_snapshot"),
        node_resource_snapshot_ref: entity("runtime.node_resource_snapshot"),
        requirements: vec![requirement(RequirementOutcome::Satisfied)],
        decision: CompatibilityDecision::Compatible,
        condition_refs: Vec::new(),
        evaluated_at: String::from("2026-09-03T12:00:00Z"),
        valid_until: String::from("2026-09-03T14:00:00Z"),
        evidence_refs: vec![entity("proof.evidence")],
        limitations: Vec::new(),
    }
}

fn attempt_context(compatibility: &NodeLocalCompatibility) -> AttemptContext {
    AttemptContext {
        node_ref: compatibility.node_ref.clone(),
        node_generation: compatibility.node_generation,
        provider_ref: compatibility.provider_instance_ref.clone(),
        provider_generation: compatibility.provider_generation.value(),
        workload_generation: 2,
        connection_epoch: 3,
        facility_ref: entity("runtime.facility"),
        producer_instance_ref: entity("runtime.producer_instance"),
        producer_version: String::from("d08-test"),
    }
}

fn local_request<'a>(
    compatibility: &NodeLocalCompatibility,
    context: &'a AttemptContext,
    mode: LaunchMode,
) -> LocalLaunchRequest<'a> {
    LocalLaunchRequest {
        workspace_ref: entity("core.workspace"),
        workspace_revision_ref: entity("core.workspace_revision"),
        materialization_ref: entity("storage.materialization"),
        materialization_generation: 5,
        application_ref: entity("application.application"),
        application_revision_ref: compatibility.application_revision_ref.clone(),
        installation_ref: entity("application.installation"),
        activity_ref: entity("core.activity"),
        operation_ref: entity("core.operation"),
        attempt_ref: entity("core.attempt"),
        attempt_context: context,
        privacy_policy_refs: vec![entity("policy.privacy")],
        command_evidence_refs: vec![entity("proof.command_evidence")],
        requested_at: String::from("2026-09-03T13:00:00Z"),
        mode,
    }
}

fn preparing_graphical() -> ptah_application_runtime::ApplicationSessionProjection {
    let compatibility = compatibility();
    let context = attempt_context(&compatibility);
    prepare_local_application_session(
        local_request(&compatibility, &context, LaunchMode::Graphical),
        &compatibility,
        "2026-09-03T13:00:00Z",
    )
    .expect("valid graphical preparation")
}

fn process_for(
    session: &ptah_application_runtime::ApplicationSessionProjection,
) -> ProcessRecord {
    ProcessRecord {
        process_ref: entity("runtime.native_process"),
        terminal_ref: None,
        provider_revision_ref: entity("runtime.provider_revision"),
        provider_instance_ref: session.provider_instance_ref.clone(),
        provider_generation: session.provider_generation,
        node_ref: session.node_ref.clone().expect("node-local session"),
        node_generation: session.node_generation.expect("node-local generation"),
        aliases: vec![EndpointAlias::process_id(
            4242,
            "2026-09-03T13:01:00Z",
        )],
        spec: ProcessSpec {
            program: String::from("/usr/bin/d08-test-app"),
            args: Vec::new(),
            env: BTreeMap::new(),
            clear_env: false,
            cwd: None,
            mode: ProcessMode::Pipes,
            max_stream_bytes: 4096,
            disconnect_policy: DisconnectPolicy::Retain,
        },
        stream_topology: StreamTopology::SeparatedStdoutStderr,
        state: ProcessState::Running,
        exit: None,
        started_at: String::from("2026-09-03T13:01:00Z"),
        limitations: Vec::new(),
    }
}

fn window_alias() -> EndpointAlias {
    EndpointAlias {
        alias_type: EndpointAliasType::Other,
        value: String::from("0x00c0ffee"),
        scope: String::from("x11.window_handle"),
        observed_at: String::from("2026-09-03T13:02:00Z"),
        valid_until: Some(String::from("2026-09-03T13:10:00Z")),
    }
}

fn visible_window(
    session: &ptah_application_runtime::ApplicationSessionProjection,
) -> ApplicationWindowProjection {
    let window = create_application_window(
        session,
        vec![window_alias()],
        vec![entity("proof.window_created")],
    )
    .expect("window creation should bind to preparing session");
    apply_window_observation(
        window,
        WindowObservation {
            provider_generation: session.provider_generation,
            state_claims: vec![WindowStateClaim::Visible],
            evidence_refs: vec![entity("proof.window_visible")],
            observed_at: String::from("2026-09-03T13:03:00Z"),
            valid_until: String::from("2026-09-03T13:10:00Z"),
        },
        "2026-09-03T13:04:00Z",
    )
    .expect("fresh visible observation should promote window")
}

fn display_request(
    session: &ptah_application_runtime::ApplicationSessionProjection,
    surface_ref: EntityRef,
) -> DisplaySessionRequest {
    DisplaySessionRequest {
        application_session_ref: session.session_ref.clone(),
        provider_instance_ref: session.provider_instance_ref.clone(),
        provider_generation: session.provider_generation,
        locality: SessionLocality::NodeLocal,
        node_ref: session.node_ref.clone(),
        node_generation: session.node_generation,
        connection_epoch: session.connection_epoch,
        device_session_ref: None,
        surface_refs: vec![surface_ref],
        input_capabilities: vec![InputCapability::ObserveOnly],
        privacy_policy_refs: session.privacy_policy_refs.clone(),
        evidence_refs: vec![entity("proof.display_prepared")],
        started_at: String::from("2026-09-03T13:02:00Z"),
    }
}

fn streaming_display(
    session: &ptah_application_runtime::ApplicationSessionProjection,
) -> DisplaySessionProjection {
    let surface_ref = entity("application.display_surface");
    let display = prepare_display_session(session, display_request(session, surface_ref.clone()))
        .expect("display preparation should accept exact session binding");
    apply_display_observation(
        display,
        DisplayObservation {
            observation_ref: entity("application.display_observation"),
            provider_generation: session.provider_generation,
            surface_ref,
            frame_evidence_ref: entity("proof.frame"),
            evidence_refs: vec![entity("proof.display_observation")],
            observed_at: String::from("2026-09-03T13:03:00Z"),
            valid_until: String::from("2026-09-03T13:10:00Z"),
        },
        "2026-09-03T13:04:00Z",
    )
    .expect("fresh frame observation should stream")
}

#[test]
fn d08_01_frozen_application_contract_and_lifecycle_ids_are_exact() {
    for schema in [
        APPLICATION_SCHEMA_ID,
        APPLICATION_REVISION_SCHEMA_ID,
        APPLICATION_COMPATIBILITY_SCHEMA_ID,
        APPLICATION_SESSION_SCHEMA_ID,
        APPLICATION_WINDOW_SCHEMA_ID,
        APPLICATION_WINDOW_OBSERVATION_SCHEMA_ID,
        DISPLAY_SESSION_SCHEMA_ID,
        DISPLAY_OBSERVATION_SCHEMA_ID,
    ] {
        assert!(
            generated::schema_by_id(schema).is_some(),
            "missing {schema}"
        );
    }
    for machine in [
        APPLICATION_SESSION_LIFECYCLE,
        APPLICATION_WINDOW_LIFECYCLE,
        DISPLAY_SESSION_LIFECYCLE,
    ] {
        assert!(
            generated::state_machine(machine, "0.1.0").is_some(),
            "missing {machine}"
        );
    }
}

#[test]
fn d08_02_node_local_compatibility_requires_current_evidence() {
    let mut candidate = compatibility();
    candidate.evidence_refs.clear();
    assert_eq!(
        candidate.validate_at("2026-09-03T13:00:00Z"),
        Err(D08Error::MissingCompatibilityEvidence)
    );
}

#[test]
fn d08_03_expired_compatibility_cannot_admit_new_work() {
    let candidate = compatibility();
    assert_eq!(
        candidate.validate_at("2026-09-03T14:00:00Z"),
        Err(D08Error::StaleCompatibility)
    );
}

#[test]
fn d08_04_compatible_with_conditions_requires_condition_evidence() {
    let mut candidate = compatibility();
    candidate.decision = CompatibilityDecision::CompatibleWithConditions;
    candidate.requirements[0].outcome = RequirementOutcome::SatisfiedWithConditions;
    assert_eq!(
        candidate.validate_at("2026-09-03T13:00:00Z"),
        Err(D08Error::MissingCompatibilityConditions)
    );
}

#[test]
fn d08_05_mandatory_unsatisfied_requirement_rejects_compatible_decision() {
    let mut candidate = compatibility();
    candidate.requirements[0].outcome = RequirementOutcome::Unsatisfied;
    assert_eq!(
        candidate.validate_at("2026-09-03T13:00:00Z"),
        Err(D08Error::MandatoryRequirementUnsatisfied)
    );
}

#[test]
fn d08_06_linux_native_graphical_can_be_node_local_ready() {
    let disposition = ExecutionDisposition::for_platform(
        PlatformClass::LinuxNative,
        ApplicationOperation::LaunchGraphical,
        Some(compatibility()),
        Vec::new(),
        "2026-09-03T13:00:00Z",
    )
    .expect("current Linux compatibility should be usable");
    assert!(matches!(
        disposition,
        ExecutionDisposition::NodeLocalReady(_)
    ));
}

#[test]
fn d08_07_linux_packaged_graphical_can_be_node_local_ready() {
    let disposition = ExecutionDisposition::for_platform(
        PlatformClass::LinuxPackaged,
        ApplicationOperation::LaunchGraphical,
        Some(compatibility()),
        Vec::new(),
        "2026-09-03T13:00:00Z",
    )
    .expect("current packaged Linux compatibility should be usable");
    assert!(matches!(
        disposition,
        ExecutionDisposition::NodeLocalReady(_)
    ));
}

#[test]
fn d08_08_windows_node_is_explicitly_remote_node_dependent() {
    let disposition = ExecutionDisposition::for_platform(
        PlatformClass::WindowsNode,
        ApplicationOperation::LaunchGraphical,
        None,
        vec![entity("proof.evidence")],
        "2026-09-03T13:00:00Z",
    )
    .expect("remote dependency should be representable");
    let ExecutionDisposition::RequiresRemoteNode(requirement) = disposition else {
        panic!("Windows Node must remain remote-node dependent");
    };
    assert_eq!(requirement.roadmap_dependency, "Programme E");
    assert!(
        requirement
            .required_capabilities
            .iter()
            .any(|v| v == "windows")
    );
}

#[test]
fn d08_09_windows_vm_retains_virtualization_requirement() {
    let disposition = ExecutionDisposition::for_platform(
        PlatformClass::WindowsVm,
        ApplicationOperation::LaunchGraphical,
        None,
        vec![entity("proof.evidence")],
        "2026-09-03T13:00:00Z",
    )
    .expect("remote dependency should be representable");
    let ExecutionDisposition::RequiresRemoteNode(requirement) = disposition else {
        panic!("Windows VM must remain remote-node dependent");
    };
    assert!(
        requirement
            .required_capabilities
            .iter()
            .any(|v| v == "virtualization")
    );
}

#[test]
fn d08_10_macos_node_is_explicitly_remote_node_dependent() {
    let disposition = ExecutionDisposition::for_platform(
        PlatformClass::MacOsNode,
        ApplicationOperation::LaunchGraphical,
        None,
        vec![entity("proof.evidence")],
        "2026-09-03T13:00:00Z",
    )
    .expect("remote dependency should be representable");
    let ExecutionDisposition::RequiresRemoteNode(requirement) = disposition else {
        panic!("macOS must remain remote-node dependent");
    };
    assert!(
        requirement
            .required_capabilities
            .iter()
            .any(|v| v == "macos")
    );
}

#[test]
fn d08_11_ios_simulator_requires_macos_xcode_and_graphical_display() {
    let disposition = ExecutionDisposition::for_platform(
        PlatformClass::IosSimulator,
        ApplicationOperation::LaunchGraphical,
        None,
        vec![entity("proof.evidence")],
        "2026-09-03T13:00:00Z",
    )
    .expect("remote dependency should be representable");
    let ExecutionDisposition::RequiresRemoteNode(requirement) = disposition else {
        panic!("iOS Simulator must remain remote-node dependent");
    };
    for required in ["macos", "xcode_simulator", "graphical_display"] {
        assert!(
            requirement
                .required_capabilities
                .iter()
                .any(|value| value == required),
            "missing {required}"
        );
    }
}

#[test]
fn d08_12_remote_node_requirement_cannot_be_used_as_node_local_authority() {
    let disposition = ExecutionDisposition::for_platform(
        PlatformClass::WindowsNode,
        ApplicationOperation::RemoteDisplay,
        None,
        vec![entity("proof.evidence")],
        "2026-09-03T13:00:00Z",
    )
    .expect("remote dependency should be representable");
    assert_eq!(
        disposition.require_node_local().map(|_| ()),
        Err(D08Error::RemoteNodeRequired)
    );
}

#[test]
fn d08_13_local_preparation_binds_exact_context_and_mints_one_preparing_session() {
    let compatibility = compatibility();
    let context = attempt_context(&compatibility);
    let request = local_request(&compatibility, &context, LaunchMode::Graphical);
    let expected_workspace = request.workspace_ref.clone();
    let expected_revision = request.application_revision_ref.clone();
    let expected_attempt = request.attempt_ref.clone();

    let session = prepare_local_application_session(
        request,
        &compatibility,
        "2026-09-03T13:00:00Z",
    )
    .expect("exact current compatibility should prepare a session");

    assert_eq!(session.workspace_ref, expected_workspace);
    assert_eq!(session.application_revision_ref, expected_revision);
    assert_eq!(session.attempt_ref, expected_attempt);
    assert_eq!(session.locality, SessionLocality::NodeLocal);
    assert_eq!(session.launch_mode, LaunchMode::Graphical);
    assert_eq!(session.lifecycle, ApplicationSessionLifecycle::Preparing);
    assert_eq!(session.availability, ApplicationAvailability::Unavailable);
    assert!(session.process_refs.is_empty());
    assert!(session.window_refs.is_empty());
    assert!(session.display_session_refs.is_empty());
}

#[test]
fn d08_14_non_admissible_or_foreign_compatibility_is_rejected_before_execution() {
    let mut incompatible = compatibility();
    incompatible.decision = CompatibilityDecision::Incompatible;
    let incompatible_context = attempt_context(&incompatible);
    assert_eq!(
        prepare_local_application_session(
            local_request(&incompatible, &incompatible_context, LaunchMode::Graphical),
            &incompatible,
            "2026-09-03T13:00:00Z",
        ),
        Err(D08Error::CompatibilityNotAdmitted)
    );

    let mut stale = compatibility();
    stale.valid_until = String::from("2026-09-03T12:30:00Z");
    let stale_context = attempt_context(&stale);
    assert_eq!(
        prepare_local_application_session(
            local_request(&stale, &stale_context, LaunchMode::Graphical),
            &stale,
            "2026-09-03T13:00:00Z",
        ),
        Err(D08Error::StaleCompatibility)
    );

    let compatibility = compatibility();
    let context = attempt_context(&compatibility);
    let mut foreign_request = local_request(&compatibility, &context, LaunchMode::Graphical);
    foreign_request.application_revision_ref = entity("application.foreign_revision");
    assert_eq!(
        prepare_local_application_session(
            foreign_request,
            &compatibility,
            "2026-09-03T13:00:00Z",
        ),
        Err(D08Error::ApplicationRevisionMismatch)
    );
}

#[test]
fn d08_15_running_process_without_graphical_window_and_display_is_not_readiness() {
    let preparing = preparing_graphical();
    let process = process_for(&preparing);
    let original_ref = preparing.session_ref.clone();

    assert_eq!(
        verify_local_application_session(
            preparing.clone(),
            LocalReadBack {
                process: &process,
                window: None,
                display: None,
                readiness_evidence_refs: vec![entity("proof.process_readback")],
                observed_at: String::from("2026-09-03T13:04:00Z"),
            },
        ),
        Err(D08Error::GraphicalReadinessMissing)
    );
    assert_eq!(preparing.session_ref, original_ref);
    assert_eq!(preparing.lifecycle, ApplicationSessionLifecycle::Preparing);
    assert_eq!(preparing.availability, ApplicationAvailability::Unavailable);
}

#[test]
fn d08_16_foreign_a05_node_or_provider_generation_rejects_verification() {
    let preparing = preparing_graphical();
    let mut process = process_for(&preparing);
    process.node_generation += 1;
    assert_eq!(
        verify_local_application_session(
            preparing,
            LocalReadBack {
                process: &process,
                window: None,
                display: None,
                readiness_evidence_refs: vec![entity("proof.process_readback")],
                observed_at: String::from("2026-09-03T13:04:00Z"),
            },
        ),
        Err(D08Error::ProcessContextMismatch)
    );
}

#[test]
fn d08_17_current_process_visible_window_and_streaming_display_promote_same_session() {
    let preparing = preparing_graphical();
    let original_ref = preparing.session_ref.clone();
    let process = process_for(&preparing);
    let window = visible_window(&preparing);
    let display = streaming_display(&preparing);

    let running = verify_local_application_session(
        preparing,
        LocalReadBack {
            process: &process,
            window: Some(&window),
            display: Some(&display),
            readiness_evidence_refs: vec![entity("proof.application_ready")],
            observed_at: String::from("2026-09-03T13:04:00Z"),
        },
    )
    .expect("full current graphical read-back should promote the same session");

    assert_eq!(running.session_ref, original_ref);
    assert_eq!(running.lifecycle, ApplicationSessionLifecycle::Running);
    assert_eq!(running.availability, ApplicationAvailability::Full);
    assert_eq!(running.process_refs, vec![process.process_ref]);
    assert_eq!(running.window_refs, vec![window.window_ref]);
    assert_eq!(
        running.display_session_refs,
        vec![display.display_session_ref]
    );
}

#[test]
fn d08_18_backend_pid_and_window_handle_aliases_never_become_canonical_identity() {
    let preparing = preparing_graphical();
    let process = process_for(&preparing);
    let first = create_application_window(
        &preparing,
        vec![window_alias()],
        vec![entity("proof.window_created")],
    )
    .expect("first window");
    let second = create_application_window(
        &preparing,
        vec![window_alias()],
        vec![entity("proof.window_created")],
    )
    .expect("second window");

    assert_ne!(first.window_ref, second.window_ref);
    assert_eq!(first.aliases[0].value, second.aliases[0].value);
    assert_eq!(process.aliases[0].value, "4242");
    assert_ne!(process.process_ref, entity("runtime.backend_pid_4242"));
}

#[test]
fn d08_23_display_preparation_requires_exact_session_provider_surface_and_privacy() {
    let preparing = preparing_graphical();
    let surface = entity("application.display_surface");

    let mut foreign_session = display_request(&preparing, surface.clone());
    foreign_session.application_session_ref = entity("application.foreign_session");
    assert_eq!(
        prepare_display_session(&preparing, foreign_session),
        Err(D08Error::SessionBindingMismatch)
    );

    let mut foreign_provider = display_request(&preparing, surface.clone());
    foreign_provider.provider_generation = ProviderGeneration::new(8).expect("positive generation");
    assert_eq!(
        prepare_display_session(&preparing, foreign_provider),
        Err(D08Error::ProviderContextMismatch)
    );

    let mut no_surface = display_request(&preparing, surface.clone());
    no_surface.surface_refs.clear();
    assert_eq!(
        prepare_display_session(&preparing, no_surface),
        Err(D08Error::MissingDisplaySurface)
    );

    let mut no_privacy = display_request(&preparing, surface);
    no_privacy.privacy_policy_refs.clear();
    assert_eq!(
        prepare_display_session(&preparing, no_privacy),
        Err(D08Error::MissingPrivacyPolicy)
    );
}

#[test]
fn d08_24_stale_or_foreign_display_observation_cannot_stream() {
    let preparing = preparing_graphical();
    let surface = entity("application.display_surface");
    let display = prepare_display_session(
        &preparing,
        display_request(&preparing, surface.clone()),
    )
    .expect("display preparation");
    assert_eq!(display.lifecycle, DisplayLifecycle::Preparing);

    let foreign = DisplayObservation {
        observation_ref: entity("application.display_observation"),
        provider_generation: ProviderGeneration::new(8).expect("positive generation"),
        surface_ref: surface.clone(),
        frame_evidence_ref: entity("proof.frame"),
        evidence_refs: vec![entity("proof.display_observation")],
        observed_at: String::from("2026-09-03T13:03:00Z"),
        valid_until: String::from("2026-09-03T13:10:00Z"),
    };
    assert_eq!(
        apply_display_observation(display.clone(), foreign, "2026-09-03T13:04:00Z"),
        Err(D08Error::ProviderContextMismatch)
    );

    let stale = DisplayObservation {
        observation_ref: entity("application.display_observation"),
        provider_generation: preparing.provider_generation,
        surface_ref: surface,
        frame_evidence_ref: entity("proof.frame"),
        evidence_refs: vec![entity("proof.display_observation")],
        observed_at: String::from("2026-09-03T13:00:00Z"),
        valid_until: String::from("2026-09-03T13:01:00Z"),
    };
    assert_eq!(
        apply_display_observation(display, stale, "2026-09-03T13:04:00Z"),
        Err(D08Error::StaleObservation)
    );
}
