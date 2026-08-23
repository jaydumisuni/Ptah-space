use ptah_control::{
    AcceptanceState, AdvisoryState, ControlError, ControlKind, HumanControlRequest, HumanSnapshot,
    SnapshotError, SubmissionState, authorize_control, validate_snapshot,
};
use serde_json::json;
use std::collections::BTreeSet;

fn snapshot() -> HumanSnapshot {
    serde_json::from_str(include_str!("fixtures/a14_snapshot.json"))
        .expect("A14 qualification snapshot must remain valid")
}

fn request(snapshot: &HumanSnapshot, kind: ControlKind, target: &str) -> HumanControlRequest {
    HumanControlRequest {
        request_id: String::from("a15-request"),
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
fn green_acceptance_without_retained_evidence_is_rejected() {
    let mut current = snapshot();
    current.activities[0].acceptance = AcceptanceState::Accepted;
    current.activities[0].evidence.clear();
    assert_eq!(
        validate_snapshot(&current),
        Err(SnapshotError::AcceptedResultMissingEvidence(String::from(
            "activity-1"
        )))
    );
}

#[test]
fn evidence_backed_advisory_keeps_observation_and_suggestion_separate() {
    let current = snapshot();
    validate_snapshot(&current).expect("qualification advisory must be structurally valid");
    let advisory = &current.advisories[0];
    assert!(!advisory.observed_facts.is_empty());
    assert!(!advisory.evidence.is_empty());
    assert!(!advisory.suggestions.is_empty());
    assert_eq!(advisory.state, AdvisoryState::Open);
}

#[test]
fn false_positive_advisory_still_has_no_upgrade_authority() {
    let mut current = snapshot();
    current.advisories[0].observed_facts = vec![String::from(
        "qualification deliberately supplies a possibly false missing-capability observation",
    )];
    current.advisories[0].uncertainty = Some(String::from(
        "the caller or independent evidence must resolve this observation",
    ));
    let control = request(&current, ControlKind::SubmitUpgradeActivity, "advisory-1");
    assert_eq!(
        authorize_control(&current, control),
        Err(ControlError::ApprovalRequired)
    );
    assert_eq!(current.advisories[0].state, AdvisoryState::Open);
}

#[test]
fn stale_advisory_evidence_cannot_cross_the_current_control_fence() {
    let current = snapshot();
    let mut control = request(&current, ControlKind::SubmitUpgradeActivity, "advisory-1");
    control.expected.fence = String::from("stale-advisory-fence");
    control.approval_id = Some(String::from("caller-approval-a15"));
    assert_eq!(
        authorize_control(&current, control),
        Err(ControlError::StaleFence)
    );
}

#[test]
fn caller_approved_upgrade_is_dispatch_authorization_not_upgrade_completion() {
    let current = snapshot();
    let mut control = request(&current, ControlKind::SubmitUpgradeActivity, "advisory-1");
    control.approval_id = Some(String::from("caller-approval-a15"));
    let submission = authorize_control(&current, control).expect("explicit caller approval");
    assert_eq!(submission.state, SubmissionState::AuthorizedForDispatch);
    assert_eq!(current.advisories[0].state, AdvisoryState::Open);
    assert_eq!(current.activities[0].acceptance, AcceptanceState::Pending);
}

#[test]
fn hunter_handoff_keeps_semantic_and_review_authority_outside_ptah() {
    let bridge = include_str!("../../../design/candidates/HUNTER-PTAH-WORKSPACE-BRIDGE.md");
    for required in [
        "Ptah does not interpret intent, select context, rank sources",
        "Ptah does not perform the review",
        "Ptah does not promote a candidate",
        "Ptah does not decide whether approval should be granted",
        "Hunter constructs its own bounded context packet",
        "Sergeant constructs a separate review packet",
    ] {
        assert!(bridge.contains(required), "Hunter/Ptah boundary drift: {required}");
    }
}

#[test]
fn ten_for_two_formation_is_bounded_distinct_recoverable_conflicted_and_unaccepted() {
    let mut current = snapshot();
    let template = current.workers[0].clone();
    current.workers = (0..20)
        .map(|index| {
            let mut worker = template.clone();
            worker.formation_id = String::from("formation-ten-for-two");
            worker.worker_id = format!("worker-{index:02}");
            worker.role = if index < 10 {
                format!("primary-lane-{index:02}")
            } else {
                format!("verifier-lane-{index:02}")
            };
            worker.checkpoint = Some(format!("checkpoint-{index:02}"));
            worker.partial_result = Some(format!("artifact:evidence-{index:02}"));
            worker.conflict = (index == 19).then(|| String::from("verifier conflict remains visible"));
            worker.completed = true;
            worker.acceptance = AcceptanceState::Pending;
            worker
        })
        .collect();

    assert_eq!(current.workers.len(), 20, "ten-for-two formation must stay bounded");
    let ids: BTreeSet<_> = current.workers.iter().map(|worker| &worker.worker_id).collect();
    let roles: BTreeSet<_> = current.workers.iter().map(|worker| &worker.role).collect();
    let checkpoints: BTreeSet<_> = current
        .workers
        .iter()
        .filter_map(|worker| worker.checkpoint.as_ref())
        .collect();
    let evidence: BTreeSet<_> = current
        .workers
        .iter()
        .filter_map(|worker| worker.partial_result.as_ref())
        .collect();
    assert_eq!(ids.len(), 20);
    assert_eq!(roles.len(), 20, "lanes must be distinct rather than duplicated");
    assert_eq!(checkpoints.len(), 20, "every lane must carry an independent checkpoint");
    assert_eq!(evidence.len(), 20, "every lane must retain an independently addressable result");
    assert!(current.workers.iter().any(|worker| worker.conflict.is_some()));
    assert!(
        current
            .workers
            .iter()
            .all(|worker| worker.acceptance == AcceptanceState::Pending),
        "worker completion must not become result acceptance"
    );
    assert_eq!(current.recovery.checkpoint_integrity, "verified");
    assert_eq!(current.recovery.restore_compatibility, "compatible");
    assert_eq!(current.recovery.recovery_verification, "verified");
}

#[test]
fn human_operator_snapshot_retains_evidence_for_visible_runtime_claims() {
    let current = snapshot();
    assert!(current.activities.iter().all(|item| !item.evidence.is_empty()));
    assert!(current.objects.iter().all(|item| !item.evidence.is_empty()));
    assert!(current.transfers.iter().all(|item| !item.evidence.is_empty()));
    assert!(current.nodes.iter().all(|item| !item.evidence.is_empty()));
    assert!(current.providers.iter().all(|item| !item.evidence.is_empty()));
    assert!(!current.evidence_links.is_empty());
}
