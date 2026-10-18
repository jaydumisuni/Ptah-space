use ptah_offline_intent::{
    degraded::{DegradedProjection, DegradedState},
    durable::{DurableIntentError, DurableIntentJournal},
    reconciliation::{valid_evidence_digest, ReconciliationFinding},
    LocalSequence, QueuedIntent, ReplayDisposition,
};
use rusqlite::Connection;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn scratch() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ptah-e06-receipts-{}-{nonce}.sqlite",
        std::process::id()
    ))
}
fn clean(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
fn intent(node: &str, id: &str, sequence: u64) -> QueuedIntent {
    QueuedIntent::try_new(
        id.into(),
        "workspace".into(),
        "activity".into(),
        format!("op-{id}"),
        format!("attempt-{id}"),
        LocalSequence {
            node_id: node.into(),
            value: sequence,
        },
        "offline_prepare".into(),
        format!("sha256:{}", "a".repeat(64)),
    )
    .unwrap()
}
fn digest() -> String {
    format!("sha256:{}", "b".repeat(64))
}

#[test]
fn receipt_survives_reopen_without_granting_authority() {
    let path = scratch();
    {
        let mut journal = DurableIntentJournal::open(&path).unwrap();
        journal.append(&intent("node-a", "i1", 1)).unwrap();
        assert_eq!(
            DegradedProjection::from_queue(&journal).unwrap().state,
            DegradedState::QueuedNotAuthorized
        );
        let (receipt, result) = journal
            .record_finding("i1", ReconciliationFinding::StaleFence, &digest())
            .unwrap();
        assert_eq!(result, ReplayDisposition::Distinct);
        assert!(!receipt.authority_granted());
        assert_eq!(receipt.origin.value, 1);
        assert_eq!(
            DegradedProjection::from_queue(&journal).unwrap().state,
            DegradedState::Conflict
        );
    }
    {
        let journal = DurableIntentJournal::open(&path).unwrap();
        assert_eq!(journal.findings().unwrap().len(), 1);
        assert!(journal.history().unwrap()[0].revalidate_required);
        assert!(
            !DegradedProjection::from_queue(&journal)
                .unwrap()
                .authority_granted
        );
        assert_eq!(
            DegradedProjection::from_queue(&journal).unwrap().state,
            DegradedState::Conflict
        );
    }
    clean(&path);
}
#[test]
fn duplicate_is_idempotent_but_changed_finding_or_digest_is_rejected() {
    let path = scratch();
    let mut journal = DurableIntentJournal::open(&path).unwrap();
    journal.append(&intent("node-a", "i1", 1)).unwrap();
    journal
        .record_finding("i1", ReconciliationFinding::MissingE01, &digest())
        .unwrap();
    assert_eq!(
        journal
            .record_finding("i1", ReconciliationFinding::MissingE01, &digest())
            .unwrap()
            .1,
        ReplayDisposition::Idempotent
    );
    assert!(matches!(
        journal.record_finding("i1", ReconciliationFinding::StaleE01, &digest()),
        Err(DurableIntentError::Conflict(_))
    ));
    assert!(matches!(
        journal.record_finding(
            "i1",
            ReconciliationFinding::MissingE01,
            &format!("sha256:{}", "c".repeat(64))
        ),
        Err(DurableIntentError::Conflict(_))
    ));
    assert_eq!(journal.findings().unwrap().len(), 1);
    drop(journal);
    clean(&path);
}
#[test]
fn unknown_identity_and_invalid_digest_do_not_create_receipts() {
    let path = scratch();
    let mut journal = DurableIntentJournal::open(&path).unwrap();
    journal.append(&intent("node-a", "i1", 1)).unwrap();
    assert!(matches!(
        journal.record_finding("missing", ReconciliationFinding::UnknownOutcome, &digest()),
        Err(DurableIntentError::Conflict(_))
    ));
    for bad in [
        "",
        "sha256:ABC",
        "sha256:",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaZ",
    ] {
        assert!(!valid_evidence_digest(bad));
        assert!(matches!(
            journal.record_finding("i1", ReconciliationFinding::UnknownOutcome, bad),
            Err(DurableIntentError::Integrity(_))
        ));
    }
    assert!(journal.findings().unwrap().is_empty());
    drop(journal);
    clean(&path);
}
#[test]
fn node_scoped_findings_preserve_queue_sequence_and_exact_identity() {
    let path = scratch();
    let mut journal = DurableIntentJournal::open(&path).unwrap();
    journal.append(&intent("node-a", "a1", 1)).unwrap();
    journal.append(&intent("node-b", "b1", 1)).unwrap();
    journal.append(&intent("node-a", "a2", 2)).unwrap();
    journal
        .record_finding("a2", ReconciliationFinding::ChangedObject, &digest())
        .unwrap();
    journal
        .record_finding("b1", ReconciliationFinding::ConflictingEffect, &digest())
        .unwrap();
    let receipts = journal.findings().unwrap();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].origin.node_id, "node-a");
    assert_eq!(receipts[0].origin.value, 2);
    assert_eq!(receipts[1].origin.node_id, "node-b");
    assert_eq!(receipts[1].origin.value, 1);
    assert_eq!(journal.history().unwrap().len(), 3);
    drop(journal);
    clean(&path);
}
#[test]
fn tampered_finding_and_orphaned_identity_fail_closed_on_reopen() {
    let path = scratch();
    let mut journal = DurableIntentJournal::open(&path).unwrap();
    journal.append(&intent("node-a", "i1", 1)).unwrap();
    journal
        .record_finding("i1", ReconciliationFinding::UnknownOutcome, &digest())
        .unwrap();
    drop(journal);
    {
        let db = Connection::open(&path).unwrap();
        db.execute(
            "UPDATE reconciliation_findings SET finding='approved' WHERE intent_id='i1'",
            [],
        )
        .unwrap();
    }
    assert!(matches!(
        DurableIntentJournal::open(&path),
        Err(DurableIntentError::Integrity(_))
    ));
    {
        let db = Connection::open(&path).unwrap();
        db.execute("UPDATE reconciliation_findings SET finding='unknown_outcome', intent_id='forged' WHERE intent_id='i1'",[]).unwrap();
    }
    assert!(matches!(
        DurableIntentJournal::open(&path),
        Err(DurableIntentError::Integrity(_))
    ));
    clean(&path);
}
#[test]
fn every_supported_finding_is_a_negative_closed_vocabulary() {
    let variants = [
        ReconciliationFinding::MissingE01,
        ReconciliationFinding::StaleE01,
        ReconciliationFinding::MissingE02,
        ReconciliationFinding::StaleFence,
        ReconciliationFinding::MissingE03,
        ReconciliationFinding::MissingE04,
        ReconciliationFinding::MissingE05,
        ReconciliationFinding::ChangedObject,
        ReconciliationFinding::ConflictingEffect,
        ReconciliationFinding::InterruptedReconnect,
        ReconciliationFinding::UnknownOutcome,
    ];
    for finding in variants {
        assert_eq!(
            ReconciliationFinding::from_strict(finding.as_str()),
            Some(finding)
        );
    }
    assert_eq!(ReconciliationFinding::from_strict("approved"), None);
    assert_eq!(ReconciliationFinding::from_strict("ready_to_apply"), None);
}
