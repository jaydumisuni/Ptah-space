//! D01 Human Workspace shell v2 acceptance proof.

use ptah_control::{
    ActivityResultState, AvailabilityState, HumanSnapshot, OperationEffectClass,
    ProviderPermissionRelation, RequirementState, TimingMode, build_workspace_shell_v2_projection,
};

fn snapshot() -> HumanSnapshot {
    serde_json::from_str(include_str!("fixtures/a14_snapshot.json"))
        .expect("A14 snapshot fixture must remain valid")
}

#[test]
fn d01_exposes_the_mature_workspace_surface_without_replacing_a14_authority() {
    let html = include_str!("../web/index.html");
    for required in [
        "Operations",
        "Availability & materialization",
        "Results & partials",
        "Schedules",
        "Conflicts & preconditions",
        "Views & limits",
        "Editor",
        "Applications & Devices",
        "Media & Documents",
        "Approvals & control transfer",
    ] {
        assert!(
            html.contains(required),
            "missing D01 shell panel: {required}"
        );
    }
    assert!(html.contains("Projection only"));
}

#[test]
fn operation_catalog_exposes_effect_and_approval_as_separate_mechanical_facts() {
    let projection = build_workspace_shell_v2_projection(&snapshot()).expect("D01 projection");
    let upgrade = projection
        .operations
        .iter()
        .find(|item| item.id == "submit_upgrade_activity")
        .expect("upgrade operation descriptor");
    assert_eq!(upgrade.effect, OperationEffectClass::Mutate);
    assert_eq!(upgrade.grant_requirement, RequirementState::NotExposed);
    assert_eq!(upgrade.grant_state, "not_exposed_by_a14_projection");
    assert_eq!(upgrade.confirmation_requirement, RequirementState::Required);
    assert_eq!(upgrade.confirmation_state, "explicit_reference_required");
    assert_eq!(
        upgrade.provider_permission_relation,
        ProviderPermissionRelation::Separate
    );
    assert_eq!(
        upgrade.materialization_requirement,
        RequirementState::NotExposed
    );
    assert_eq!(
        upgrade.provider_access_state,
        "provider_specific_not_exposed_by_a14_projection"
    );
    assert!(
        upgrade
            .limits
            .iter()
            .any(|item| item.contains("not completion"))
    );

    let navigate = projection
        .operations
        .iter()
        .find(|item| item.id == "browser_navigate")
        .expect("browser operation descriptor");
    assert_eq!(navigate.effect, OperationEffectClass::ExternalSideEffect);
    assert_eq!(
        navigate.confirmation_requirement,
        RequirementState::NotRequired
    );
}

#[test]
fn materialization_truth_is_parsed_from_canonical_object_state_without_path_invention() {
    let projection = build_workspace_shell_v2_projection(&snapshot()).expect("D01 projection");
    assert_eq!(projection.availability.len(), 2);
    assert_eq!(
        projection.availability[0].state,
        AvailabilityState::MaterializedCopy
    );
    assert_eq!(
        projection.availability[1].state,
        AvailabilityState::GeneratedArtifact
    );
    assert!(
        projection
            .availability
            .iter()
            .all(|item| item.local_path.is_none())
    );
}

#[test]
fn unknown_materialization_state_fails_closed() {
    let mut current = snapshot();
    current.objects[0].materialization_state = String::from("magic_local_file");
    assert!(build_workspace_shell_v2_projection(&current).is_err());
}

#[test]
fn stable_result_handles_do_not_convert_completion_into_acceptance() {
    let projection = build_workspace_shell_v2_projection(&snapshot()).expect("D01 projection");
    let result = projection
        .results
        .iter()
        .find(|item| item.activity_id == "activity-1")
        .expect("activity result handle");
    assert_eq!(result.handle, "activity:activity-1");
    assert_eq!(result.final_state, Some(ActivityResultState::Succeeded));
    assert_eq!(result.acceptance, "pending");
    assert_eq!(result.partial_retained, None);
    assert!(!result.pageable);
    assert!(!result.searchable);
    assert!(
        result
            .limitations
            .iter()
            .any(|item| item.contains("not exposed"))
    );
}

#[test]
fn worker_conflicts_are_visible_and_never_reconciled_by_ptah() {
    let projection = build_workspace_shell_v2_projection(&snapshot()).expect("D01 projection");
    assert_eq!(projection.conflicts.len(), 1);
    assert_eq!(projection.conflicts[0].target_id, "worker-1");
    assert_eq!(projection.conflicts[0].state, "unresolved");
    assert!(projection.conflicts[0].caller_resolution_required);
}

#[test]
fn timing_modes_are_declared_without_manufacturing_schedule_instances() {
    let projection = build_workspace_shell_v2_projection(&snapshot()).expect("D01 projection");
    assert_eq!(
        projection.supported_timing_modes,
        vec![
            TimingMode::Exact,
            TimingMode::Flexible,
            TimingMode::Condition
        ]
    );
    assert!(projection.schedules.is_empty());
}

#[test]
fn typed_views_remain_replaceable_non_authoritative_projections() {
    let projection = build_workspace_shell_v2_projection(&snapshot()).expect("D01 projection");
    assert!(!projection.views.is_empty());
    assert!(projection.views.iter().all(|item| item.replaceable));
    assert!(projection.views.iter().all(|item| !item.authoritative));
}

#[test]
fn responsive_shell_keeps_critical_d01_truth_panels_visible() {
    let css = include_str!("../web/styles.css");
    assert!(css.contains("@media(max-width:900px)"));
    assert!(css.contains("@media(max-width:560px)"));
    let app = include_str!("../web/app.js");
    for function in [
        "renderOperations",
        "renderAvailability",
        "renderResults",
        "renderSchedules",
        "renderConflicts",
        "renderViewsAndLimits",
    ] {
        assert!(app.contains(function), "missing D01 renderer {function}");
    }
}

#[test]
fn d01_profile_identity_is_exact_and_non_semantic() {
    let projection = build_workspace_shell_v2_projection(&snapshot()).expect("D01 projection");
    assert_eq!(projection.profile_id, "ptah.workspace.operations.v2");
    assert!(!projection.context_selection_authority);
    assert!(!projection.approval_authority);
    assert!(!projection.next_action_authority);
}

#[test]
fn d01_layout_persistence_contains_presentation_only_identifiers() {
    let html = include_str!("../web/index.html");
    assert!(html.contains("id=\"layout-mode\""));
    assert!(html.contains("id=\"reset-layout\""));
    assert!(html.contains("class=\"skip-link\""));

    let app = include_str!("../web/app.js");
    assert!(app.contains("ptah.layout.v2"));
    assert!(app.contains("panel_order"));
    assert!(app.contains("layout_mode"));
    assert!(app.contains("applyLayoutPresentation"));
    assert!(app.contains("persistLayoutPresentation"));
    assert!(!app.contains("layout.authority"));
    assert!(!app.contains("layout.fence"));

    let preflight = include_str!("../web/preflight.js");
    assert!(preflight.contains("ptah.layout.v2"));
    assert!(preflight.contains("localStorage.removeItem('ptah.layout.v2')"));
}

#[test]
fn d01_absent_specialized_backing_state_is_reported_instead_of_invented() {
    let app = include_str!("../web/app.js");
    assert!(app.contains("No canonical editor session exists"));
    assert!(app.contains("must be projected by its owning session"));
    assert!(app.contains("Viewer chrome is available only when canonical typed Objects/Artifacts"));
}

#[test]
fn d01_accessibility_and_layout_controls_do_not_hide_critical_actions() {
    let css = include_str!("../web/styles.css");
    assert!(css.contains(".skip-link"));
    assert!(css.contains(":focus-visible"));
    assert!(css.contains(".layout-single"));
    assert!(css.contains(".critical{display:block!important}"));
    let html = include_str!("../web/index.html");
    assert!(html.contains("aria-label=\"Workspace layout\""));
    assert!(html.contains("aria-live=\"polite\""));
}
