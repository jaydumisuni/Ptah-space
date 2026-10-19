use ptah_offline_intent::{
    durable::{DurableIntentError, DurableIntentJournal},
    reconciliation::ReconciliationFinding,
    reconnect::{check_reconnect, ReconnectCheck, ReconnectObservation},
    LocalSequence, QueuedIntent, ReconnectDependencies,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn temp_path() -> PathBuf {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("ptah-e06-reconnect-{}-{t}.db", std::process::id()))
}
fn clean(p: &Path) {
    for ext in ["", "-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{ext}", p.display()));
    }
}
fn intent() -> QueuedIntent {
    QueuedIntent::try_new(
        "id-one".into(),
        "ws-one".into(),
        "activity-one".into(),
        "operation-one".into(),
        "attempt-one".into(),
        LocalSequence {
            node_id: "node-a".into(),
            value: 1,
        },
        "prepare_local".into(),
        digest('a'),
    )
    .unwrap()
    .with_reconnect_dependencies(dependencies())
    .unwrap()
}
fn dependencies() -> ReconnectDependencies {
    ReconnectDependencies {
        created_at: "2026-10-20T00:34:00+02:00".into(),
        e01_session: Some("unverified-session-ref".into()),
        e02_fence: Some("unverified-fence-ref".into()),
        e03_object_digest: Some(digest('b')),
        e03_object_generation: Some("object-gen-7".into()),
        e04_checkpoint_digest: Some(digest('c')),
        e05_host_profile_digest: Some(digest('d')),
        e05_admission_generation: Some("host-gen-8".into()),
    }
}
fn digest(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}
fn observation<'a>(digest: &'a str) -> ReconnectObservation<'a> {
    ReconnectObservation {
        intent_id: "id-one",
        origin_node_id: "node-a",
        origin_sequence: 1,
        workspace_id: "ws-one",
        activity_id: "activity-one",
        operation_id: "operation-one",
        attempt_id: "attempt-one",
        canonical_input_digest: digest,
        created_at: "2026-10-20T00:34:00+02:00",
        e01_session: Some("unverified-session-ref"),
        e02_fence: Some("unverified-fence-ref"),
        e03_object_digest: Some(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        e03_object_generation: Some("object-gen-7"),
        e04_checkpoint_digest: Some(
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
        e05_host_profile_digest: Some(
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        ),
        e05_admission_generation: Some("host-gen-8"),
        uncertain_prior_effect: false,
    }
}
#[test]
fn matching_observation_is_never_execution_authority() {
    let d = digest('a');
    let check = check_reconnect(&intent(), &observation(&d));
    assert_eq!(check, ReconnectCheck::RequiresExternalOwnerReview);
    assert!(!check.authority_granted());
    assert!(!check.can_dispatch());
}
#[test]
fn missing_e01_e02_e03_e04_e05_are_distinct_fail_closed_findings() {
    let d = digest('a');
    let baseline = observation(&d);
    let cases = [
        (
            1,
            ReconnectCheck::Rejected(ReconciliationFinding::MissingE01),
        ),
        (
            2,
            ReconnectCheck::Rejected(ReconciliationFinding::MissingE02),
        ),
        (
            3,
            ReconnectCheck::Rejected(ReconciliationFinding::MissingE03),
        ),
        (
            4,
            ReconnectCheck::Rejected(ReconciliationFinding::MissingE04),
        ),
        (
            5,
            ReconnectCheck::Rejected(ReconciliationFinding::MissingE05),
        ),
    ];
    for (i, want) in cases {
        let mut o = baseline.clone();
        match i {
            1 => o.e01_session = None,
            2 => o.e02_fence = None,
            3 => o.e03_object_digest = None,
            4 => o.e04_checkpoint_digest = None,
            5 => o.e05_host_profile_digest = None,
            _ => unreachable!(),
        }
        assert_eq!(check_reconnect(&intent(), &o), want);
    }
}
#[test]
fn foreign_origin_sequence_workspace_activity_operation_and_attempt_rejected() {
    let d = digest('a');
    let base = observation(&d);
    for mutation in 0..7 {
        let mut o = base.clone();
        match mutation {
            0 => o.origin_node_id = "other-node",
            1 => o.origin_sequence = 2,
            2 => o.workspace_id = "different-ws",
            3 => o.activity_id = "different-activity",
            4 => o.operation_id = "different-op",
            5 => o.attempt_id = "different-attempt",
            6 => o.intent_id = "different-intent",
            _ => unreachable!(),
        }
        assert_eq!(
            check_reconnect(&intent(), &o),
            ReconnectCheck::Rejected(ReconciliationFinding::ConflictingEffect)
        );
    }
}
#[test]
fn changed_input_and_uncertain_prior_effect_never_replay() {
    let d = digest('b');
    let o = observation(&d);
    assert_eq!(
        check_reconnect(&intent(), &o),
        ReconnectCheck::Rejected(ReconciliationFinding::ChangedObject)
    );
    let a = digest('a');
    let mut prior = observation(&a);
    prior.uncertain_prior_effect = true;
    assert_eq!(
        check_reconnect(&intent(), &prior),
        ReconnectCheck::Rejected(ReconciliationFinding::UnknownOutcome)
    );
}
#[test]
fn malformed_digest_and_fake_epoch_are_not_admission() {
    let d = digest('a');
    let mut o = observation(&d);
    o.e01_session = Some(" \n untrusted \n ");
    assert_eq!(
        check_reconnect(&intent(), &o),
        ReconnectCheck::Rejected(ReconciliationFinding::MissingE01)
    );
    o = observation(&d);
    o.e03_object_digest = Some("sha256:FAKE");
    assert_eq!(
        check_reconnect(&intent(), &o),
        ReconnectCheck::Rejected(ReconciliationFinding::MissingE03)
    );
    o = observation("sha256:NOT-CANONICAL");
    assert_eq!(
        check_reconnect(&intent(), &o),
        ReconnectCheck::Rejected(ReconciliationFinding::ChangedObject)
    );
}
#[test]
fn untrusted_negative_does_not_poison_the_durable_queue() {
    let p = temp_path();
    let d = digest('a');
    {
        let mut journal = DurableIntentJournal::open(&p).unwrap();
        journal.append(&intent()).unwrap();
        let mut o = observation(&d);
        o.e02_fence = None;
        let first = journal.observe_reconnect(&o).unwrap();
        assert_eq!(
            first.check,
            ReconnectCheck::Rejected(ReconciliationFinding::MissingE02)
        );
        assert!(!first.authority_granted);
        assert!(first.requires_external_owner_verification);
        let replay = journal.observe_reconnect(&o).unwrap();
        assert_eq!(replay, first);
        assert!(journal.findings().unwrap().is_empty());
    }
    {
        let journal = DurableIntentJournal::open(&p).unwrap();
        assert!(journal.findings().unwrap().is_empty());
        assert_eq!(journal.history().unwrap().len(), 1);
        assert_eq!(
            journal.observe_reconnect(&observation(&d)).unwrap().check,
            ReconnectCheck::RequiresExternalOwnerReview
        );
        assert!(journal.history().unwrap()[0].revalidate_required);
    }
    clean(&p);
}
#[test]
fn owner_controlled_finding_is_retained_and_cannot_be_cleared_by_observer() {
    let p = temp_path();
    let d = digest('a');
    let mut journal = DurableIntentJournal::open(&p).unwrap();
    journal.append(&intent()).unwrap();
    // Owner-only route is separately gated; this simulates its durable record.
    journal
        .record_finding("id-one", ReconciliationFinding::StaleFence, &digest('f'))
        .unwrap();
    assert!(matches!(
        journal.observe_reconnect(&observation(&d)),
        Err(DurableIntentError::Conflict(_))
    ));
    assert_eq!(journal.findings().unwrap().len(), 1);
    drop(journal);
    clean(&p);
}
#[test]
fn no_observation_even_a_conflict_can_persist_without_external_owner() {
    let p = temp_path();
    let d = digest('a');
    let mut journal = DurableIntentJournal::open(&p).unwrap();
    journal.append(&intent()).unwrap();
    let mut o = observation(&d);
    o.intent_id = "not-in-journal";
    assert!(matches!(
        journal.observe_reconnect(&o),
        Err(DurableIntentError::Conflict(_))
    ));
    o.intent_id = "id-one";
    o.origin_node_id = "other-node";
    assert_eq!(
        journal.observe_reconnect(&o).unwrap().check,
        ReconnectCheck::Rejected(ReconciliationFinding::ConflictingEffect)
    );
    assert!(journal.findings().unwrap().is_empty());
    drop(journal);
    clean(&p);
}

#[test]
fn stale_reconnect_versions_cannot_be_manufactured_from_fresh_observations() {
    let d = digest('a');
    let baseline = observation(&d);
    for mutation in 0..8 {
        let mut current = baseline.clone();
        let expected = match mutation {
            0 => {
                current.e01_session = Some("new-session");
                ReconciliationFinding::StaleE01
            }
            1 => {
                current.e02_fence = Some("new-fence");
                ReconciliationFinding::StaleFence
            }
            2 => {
                current.e03_object_digest =
                    Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
                ReconciliationFinding::ChangedObject
            }
            3 => {
                current.e03_object_generation = Some("new-object-generation");
                ReconciliationFinding::ChangedObject
            }
            4 => {
                current.e04_checkpoint_digest =
                    Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
                ReconciliationFinding::ConflictingEffect
            }
            5 => {
                current.e05_host_profile_digest =
                    Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
                ReconciliationFinding::ConflictingEffect
            }
            6 => {
                current.e05_admission_generation = Some("new-host-generation");
                ReconciliationFinding::ConflictingEffect
            }
            7 => {
                current.created_at = "new-timestamp";
                ReconciliationFinding::ConflictingEffect
            }
            _ => unreachable!(),
        };
        assert_eq!(
            check_reconnect(&intent(), &current),
            ReconnectCheck::Rejected(expected)
        );
    }
}
#[test]
fn legacy_unbound_queue_never_accepts_a_fully_populated_observation() {
    let d = digest('a');
    let unbound = QueuedIntent::try_new(
        "id-one".into(),
        "ws-one".into(),
        "activity-one".into(),
        "operation-one".into(),
        "attempt-one".into(),
        LocalSequence {
            node_id: "node-a".into(),
            value: 1,
        },
        "prepare_local".into(),
        d.clone(),
    )
    .unwrap();
    assert_eq!(
        check_reconnect(&unbound, &observation(&d)),
        ReconnectCheck::Rejected(ReconciliationFinding::MissingE01)
    );
}

#[test]
fn unknown_prior_effect_outweighs_changed_or_malformed_input() {
    for input in [digest('f'), "sha256:NONCANONICAL".to_owned()] {
        let mut observed = observation(&input);
        observed.uncertain_prior_effect = true;
        assert_eq!(
            check_reconnect(&intent(), &observed),
            ReconnectCheck::Rejected(ReconciliationFinding::UnknownOutcome)
        );
    }
    let d = digest('a');
    let mut observed = observation(&d);
    observed.uncertain_prior_effect = true;
    observed.e02_fence = Some("fence-stale");
    assert_eq!(
        check_reconnect(&intent(), &observed),
        ReconnectCheck::Rejected(ReconciliationFinding::UnknownOutcome)
    );
}
