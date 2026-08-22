use ptah_control::{
    AcceptanceState, ClientReopenState, ControlError, ControlKind, HumanControlRequest,
    HumanSnapshot, SubmissionState, Viewport, authorize_control, reconcile_reopen_state,
    responsive_projection, validate_snapshot,
};
use serde_json::json;
use std::collections::BTreeSet;

fn snapshot() -> HumanSnapshot {
    serde_json::from_str(include_str!("fixtures/a14_snapshot.json"))
        .expect("A14 snapshot fixture must be valid")
}

fn request(snapshot: &HumanSnapshot, kind: ControlKind, target: &str) -> HumanControlRequest {
    HumanControlRequest {
        request_id: String::from("request-1"),
        kind,
        target_id: String::from(target),
        expected: snapshot.authority.clone(),
        provider_id: None,
        expected_provider_generation: None,
        approval_id: None,
        payload: json!({}),
    }
}

#[test]
fn human_shell_exposes_the_a14_vertical_slice_without_ai() {
    let html = include_str!("../web/index.html");
    for required in [
        "Current state",
        "Activity Centre",
        "Objects & Artifacts",
        "Terminals",
        "Transfers",
        "Browser",
        "Node / Provider health",
        "Diagnostics",
        "Workers & acceptance",
        "Checkpoint / recovery",
        "Evidence & limitations",
    ] {
        assert!(
            html.contains(required),
            "missing A14 human panel: {required}"
        );
    }
    assert!(!html.to_ascii_lowercase().contains("ai required"));
}

#[test]
fn stale_projection_cannot_issue_a_protected_control() {
    let current = snapshot();
    let mut control = request(&current, ControlKind::CheckpointRequest, "workspace-alpha");
    control.expected.workspace_revision -= 1;
    assert_eq!(
        authorize_control(&current, control),
        Err(ControlError::StaleWorkspaceRevision)
    );
}

#[test]
fn reopen_uses_fresh_canonical_identity_not_cached_authority() {
    let fresh = snapshot();
    let cached = ClientReopenState {
        selected_workspace_id: String::from("workspace-stale"),
        selected_session_id: String::from("session-stale"),
        selected_panel: String::from("terminals"),
        expanded_panels: BTreeSet::from([String::from("terminals")]),
    };
    let reconciled = reconcile_reopen_state(&cached, &fresh);
    assert_eq!(reconciled.selected_workspace_id, "workspace-alpha");
    assert_eq!(reconciled.selected_session_id, "session-human");
    assert_eq!(reconciled.selected_panel, "home");
}

#[test]
fn mobile_and_tablet_preserve_critical_approval_and_recovery_controls() {
    let expected = vec![
        ControlKind::CheckpointRequest,
        ControlKind::WorkspaceReconnect,
        ControlKind::SubmitUpgradeActivity,
        ControlKind::AcceptWorkerResult,
    ];
    for viewport in [Viewport::Desktop, Viewport::Tablet, Viewport::Mobile] {
        let projection = responsive_projection(viewport);
        assert_eq!(projection.critical_controls, expected);
        for panel in [
            "activities",
            "diagnostics",
            "workers",
            "recovery",
            "evidence",
        ] {
            assert!(projection.panels.iter().any(|value| value == panel));
        }
    }

    let css = include_str!("../web/styles.css");
    assert!(css.contains("@media(max-width:900px)"));
    assert!(css.contains("@media(max-width:560px)"));
    assert!(css.contains(".critical{display:block!important}"));
}

#[test]
fn observed_facts_and_upgrade_suggestions_remain_structurally_separate() {
    let current = snapshot();
    validate_snapshot(&current).expect("well-evidenced advisory is valid");
    let advisory = &current.advisories[0];
    assert_eq!(advisory.observed_facts, ["optional capability is absent"]);
    assert_eq!(
        advisory.suggestions,
        ["submit an upgrade Activity if the caller wants that capability"]
    );
    assert!(!advisory.evidence.is_empty());
}

#[test]
fn worker_completion_does_not_imply_caller_acceptance() {
    let current = snapshot();
    assert!(current.activities[0].worker_completion);
    assert_eq!(current.activities[0].acceptance, AcceptanceState::Pending);
    assert!(current.workers[0].completed);
    assert_eq!(current.workers[0].acceptance, AcceptanceState::Pending);

    let app = include_str!("../web/app.js");
    assert!(app.contains("Worker completion:"));
    assert!(app.contains("Caller/reviewer acceptance:"));
}

#[test]
fn advisory_cannot_authorize_its_own_upgrade() {
    let current = snapshot();
    let no_approval = request(&current, ControlKind::SubmitUpgradeActivity, "advisory-1");
    assert_eq!(
        authorize_control(&current, no_approval),
        Err(ControlError::ApprovalRequired)
    );

    let mut approved = request(&current, ControlKind::SubmitUpgradeActivity, "advisory-1");
    approved.approval_id = Some(String::from("caller-approval-1"));
    let submission = authorize_control(&current, approved).expect("caller approved submission");
    assert_eq!(submission.state, SubmissionState::AuthorizedForDispatch);

    let app = include_str!("../web/app.js");
    assert!(app.contains("this is not completion"));
}

#[test]
fn corrupt_cached_presentation_is_removed_before_app_boot() {
    let preflight = include_str!("../web/preflight.js");
    let html = include_str!("../web/index.html");
    let preflight_position = html.find("/preflight.js").expect("preflight script");
    let app_position = html.find("/app.js").expect("application script");
    assert!(preflight_position < app_position);
    assert!(preflight.contains("localStorage.removeItem('ptah.presentation')"));
}
