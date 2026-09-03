//! D08 read-only Application platform projection into the D01 shell.

use ptah_application_runtime::{
    ApplicationPlatformSnapshot, ApplicationSessionProjection, RemoteNodeRequirement,
};
use ptah_control::{
    HumanSnapshot, build_workspace_shell_v2_projection, project_application_platform_views,
};
use serde_json::{Value, json};

fn snapshot() -> HumanSnapshot {
    serde_json::from_str(include_str!("fixtures/a14_snapshot.json"))
        .expect("A14 snapshot fixture must remain valid")
}

fn entity(kind: &str, suffix: u16) -> Value {
    json!({
        "entity_id": format!("0199a000-0000-7000-8000-{suffix:012x}"),
        "entity_kind": kind,
    })
}

fn session(lifecycle: &str, availability: &str) -> ApplicationSessionProjection {
    serde_json::from_value(json!({
        "session_ref": entity("application.session", 1),
        "workspace_ref": entity("core.workspace", 2),
        "workspace_revision_ref": entity("core.workspace_revision", 3),
        "materialization_ref": entity("storage.materialization", 4),
        "materialization_generation": 2,
        "application_ref": entity("application.application", 5),
        "application_revision_ref": entity("application.revision", 6),
        "installation_ref": entity("application.installation", 7),
        "compatibility_ref": entity("application.compatibility", 8),
        "provider_instance_ref": entity("runtime.provider_instance", 9),
        "provider_generation": 3,
        "locality": "node_local",
        "node_ref": entity("core.node", 10),
        "node_generation": 4,
        "connection_epoch": null,
        "device_session_ref": null,
        "activity_ref": entity("core.activity", 11),
        "operation_ref": entity("core.operation", 12),
        "attempt_ref": entity("core.attempt", 13),
        "process_refs": [entity("runtime.process", 14)],
        "window_refs": [],
        "display_session_refs": [],
        "semantic_context_refs": [],
        "availability": availability,
        "privacy_policy_refs": [entity("policy.privacy", 15)],
        "lifecycle": lifecycle,
        "launch_mode": "graphical",
        "evidence_refs": [entity("proof.evidence", 16)],
        "limitations": [],
        "started_at": "2026-09-03T12:00:00Z"
    }))
    .expect("valid D08 session fixture")
}

fn remote_requirement() -> RemoteNodeRequirement {
    serde_json::from_value(json!({
        "platform": "windows_node",
        "operation": "remote_display",
        "required_execution_class": "remote_windows_node",
        "required_capabilities": ["graphical_display", "remote_application_display"],
        "roadmap_dependency": "programme_e.remote_node",
        "evidence_refs": [entity("proof.evidence", 17)],
        "limitations": ["remote execution is deferred until Programme E"]
    }))
    .expect("valid remote requirement")
}

#[test]
fn validated_session_projections_render_without_adding_launch_authority() {
    let mut shell = build_workspace_shell_v2_projection(&snapshot()).expect("D01 projection");
    let authority = shell.authority.clone();
    let operations = shell.operations.clone();
    let running = ApplicationPlatformSnapshot::Session {
        platform: ptah_application_runtime::PlatformClass::LinuxNative,
        session: session("running", "full"),
        display: None,
    };
    let degraded = ApplicationPlatformSnapshot::Session {
        platform: ptah_application_runtime::PlatformClass::LinuxPackaged,
        session: session("degraded", "headless_only"),
        display: None,
    };

    project_application_platform_views(&mut shell, &[running, degraded]);

    assert_eq!(shell.applications.len(), 2);
    assert_eq!(shell.applications[0].disposition, "session");
    assert_eq!(shell.applications[0].lifecycle.as_deref(), Some("running"));
    assert_eq!(shell.applications[0].availability, "full");
    assert_eq!(shell.applications[1].availability, "headless_only");
    assert_eq!(shell.authority, authority);
    assert_eq!(shell.operations, operations);
}

#[test]
fn remote_requirement_renders_a_blocker_without_session_or_display_identity() {
    let mut shell = build_workspace_shell_v2_projection(&snapshot()).expect("D01 projection");
    let blocker = ApplicationPlatformSnapshot::RemoteRequirement {
        application_ref: serde_json::from_value(entity("application.application", 18))
            .expect("application ref"),
        application_revision_ref: serde_json::from_value(entity("application.revision", 19))
            .expect("application revision ref"),
        requirement: remote_requirement(),
    };

    project_application_platform_views(&mut shell, &[blocker]);

    assert_eq!(shell.applications.len(), 1);
    let view = &shell.applications[0];
    assert_eq!(view.disposition, "requires_remote_node");
    assert_eq!(view.platform, "windows_node");
    assert_eq!(view.session_id, None);
    assert_eq!(view.display_session_id, None);
    assert_eq!(view.availability, "unavailable");
    assert!(!view.limitations.is_empty());
}

#[test]
fn absent_or_preparing_backing_stays_unavailable_and_cannot_change_d01_authority() {
    let mut shell = build_workspace_shell_v2_projection(&snapshot()).expect("D01 projection");
    let authority = shell.authority.clone();
    let operations = shell.operations.clone();
    assert!(shell.applications.is_empty());

    project_application_platform_views(
        &mut shell,
        &[ApplicationPlatformSnapshot::Session {
            platform: ptah_application_runtime::PlatformClass::LinuxNative,
            session: session("preparing", "unavailable"),
            display: None,
        }],
    );

    assert_eq!(shell.applications.len(), 1);
    assert_eq!(shell.applications[0].availability, "unavailable");
    assert_eq!(
        shell.applications[0].lifecycle.as_deref(),
        Some("preparing")
    );
    assert_eq!(shell.authority, authority);
    assert_eq!(shell.operations, operations);
}
