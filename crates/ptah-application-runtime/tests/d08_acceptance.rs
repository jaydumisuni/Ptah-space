//! D08 Application platform expansion acceptance proof.

use ptah_application_runtime::{
    APPLICATION_COMPATIBILITY_SCHEMA_ID, APPLICATION_REVISION_SCHEMA_ID, APPLICATION_SCHEMA_ID,
    APPLICATION_SESSION_LIFECYCLE, APPLICATION_SESSION_SCHEMA_ID, APPLICATION_WINDOW_LIFECYCLE,
    APPLICATION_WINDOW_OBSERVATION_SCHEMA_ID, APPLICATION_WINDOW_SCHEMA_ID,
    ApplicationOperation, CompatibilityDecision, CompatibilityRequirement, D08Error,
    DISPLAY_OBSERVATION_SCHEMA_ID, DISPLAY_SESSION_LIFECYCLE, DISPLAY_SESSION_SCHEMA_ID,
    ExecutionDisposition, NodeLocalCompatibility, PlatformClass, RequirementOutcome,
};
use ptah_contracts::generated;
use ptah_identifiers::EntityRef;
use ptah_provider_api::ProviderGeneration;

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
        assert!(generated::schema_by_id(schema).is_some(), "missing {schema}");
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
    assert!(matches!(disposition, ExecutionDisposition::NodeLocalReady(_)));
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
    assert!(matches!(disposition, ExecutionDisposition::NodeLocalReady(_)));
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
    assert!(requirement.required_capabilities.iter().any(|v| v == "windows"));
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
    assert!(requirement.required_capabilities.iter().any(|v| v == "macos"));
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
