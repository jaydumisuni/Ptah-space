use ptah_offline_intent::{
    durable::{DurableIntentError, DurableIntentJournal},
    reconciliation::ReconciliationFinding,
    reconnect::{check_reconnect, ReconnectCheck, ReconnectObservation},
    LocalSequence, QueuedIntent,
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
        e01_session: Some("unverified-session-ref"),
        e02_fence: Some("unverified-fence-ref"),
        e03_object_digest: Some(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        e04_checkpoint_digest: Some(
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
        e05_host_profile_digest: Some(
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        ),
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
