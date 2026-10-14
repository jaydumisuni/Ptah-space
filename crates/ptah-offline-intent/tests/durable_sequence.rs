use ptah_offline_intent::{
    durable::{DurableIntentError, DurableIntentJournal},
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
        "ptah-e06-test-{}-{nonce}.sqlite",
        std::process::id()
    ))
}
fn clean(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
fn intent(node: &str, sequence: u64, key: &str) -> QueuedIntent {
    QueuedIntent::try_new(
        key.into(),
        "workspace-1".into(),
        "activity-1".into(),
        format!("operation-{key}"),
        format!("attempt-{key}"),
        LocalSequence {
            node_id: node.into(),
            value: sequence,
        },
        "prepare_offline".into(),
        format!("sha256:{}", "c".repeat(64)),
    )
    .unwrap()
}

#[test]
fn atomic_append_and_reopen_with_interleaved_nodes() {
    let path = scratch();
    let mut j = DurableIntentJournal::open(&path).unwrap();
    for (node, n, key) in [
        ("n1", 1, "n1-1"),
        ("n2", 1, "n2-1"),
        ("n1", 2, "n1-2"),
        ("n2", 2, "n2-2"),
        ("n1", 3, "n1-3"),
    ] {
        assert_eq!(
            j.append(&intent(node, n, key)).unwrap(),
            ReplayDisposition::Distinct
        );
    }
    assert_eq!(
        j.append(&intent("n1", 3, "n1-3")).unwrap(),
        ReplayDisposition::Idempotent
    );
    assert_eq!(j.history().unwrap().len(), 5);
    drop(j);
    let again = DurableIntentJournal::open(&path).unwrap();
    again.verify().unwrap();
    assert!(again
        .history()
        .unwrap()
        .iter()
        .all(|i| i.revalidate_required));
    drop(again);
    clean(&path);
}
#[test]
fn missing_successor_and_modified_replay_fail_without_cursor_progress() {
    let path = scratch();
    let mut j = DurableIntentJournal::open(&path).unwrap();
    j.append(&intent("n1", 1, "one")).unwrap();
    assert!(j.append(&intent("n1", 3, "three")).is_err());
    assert!(j.append(&intent("n1", 1, "different")).is_err());
    let mut tampered = intent("n1", 1, "one");
    tampered.action = "not-the-same-action".into();
    assert!(j.append(&tampered).is_err());
    j.append(&intent("n1", 2, "two")).unwrap();
    assert_eq!(j.history().unwrap().len(), 2);
    drop(j);
    clean(&path);
}
#[test]
fn lost_interior_record_is_detected_even_when_cursor_matches_tail() {
    let path = scratch();
    let mut j = DurableIntentJournal::open(&path).unwrap();
    for n in 1..=3 {
        j.append(&intent("n1", n, &format!("n1-{n}"))).unwrap();
    }
    drop(j);
    let sql = Connection::open(&path).unwrap();
    sql.execute(
        "DELETE FROM queued_intents WHERE node='n1' AND sequence='00000000000000000002'",
        [],
    )
    .unwrap();
    drop(sql);
    assert!(matches!(
        DurableIntentJournal::open(&path),
        Err(DurableIntentError::Integrity(_))
    ));
    clean(&path);
}
#[test]
fn corrupt_cursor_is_not_recovered_as_authority() {
    let path = scratch();
    let mut j = DurableIntentJournal::open(&path).unwrap();
    j.append(&intent("n1", 1, "one")).unwrap();
    drop(j);
    let sql = Connection::open(&path).unwrap();
    sql.execute(
        "UPDATE origin_cursor SET sequence='00000000000000000002' WHERE node='n1'",
        [],
    )
    .unwrap();
    drop(sql);
    assert!(matches!(
        DurableIntentJournal::open(&path),
        Err(DurableIntentError::Integrity(_))
    ));
    clean(&path);
}
#[test]
fn cursor_update_failure_rolls_back_both_sequence_and_record() {
    let path = scratch();
    let mut j = DurableIntentJournal::open(&path).unwrap();
    j.append(&intent("n1", 1, "one")).unwrap();
    let sql = Connection::open(&path).unwrap();
    sql.execute_batch(
        "CREATE TRIGGER block_cursor BEFORE UPDATE ON origin_cursor
     BEGIN SELECT RAISE(ABORT,'injected cursor failure'); END;",
    )
    .unwrap();
    drop(sql);
    assert!(j.append(&intent("n1", 2, "two")).is_err());
    drop(j);
    let again = DurableIntentJournal::open(&path).unwrap();
    assert_eq!(again.history().unwrap().len(), 1);
    again.verify().unwrap();
    drop(again);
    clean(&path);
}
#[test]
fn two_connection_writers_serialize_and_preserve_contiguity() {
    let path = scratch();
    let mut a = DurableIntentJournal::open(&path).unwrap();
    let mut b = DurableIntentJournal::open(&path).unwrap();
    a.append(&intent("n1", 1, "one")).unwrap();
    b.append(&intent("n1", 2, "two")).unwrap();
    assert!(a.append(&intent("n1", 2, "other")).is_err());
    a.append(&intent("n2", 1, "independent")).unwrap();
    drop(a);
    drop(b);
    assert_eq!(
        DurableIntentJournal::open(&path)
            .unwrap()
            .history()
            .unwrap()
            .len(),
        3
    );
    clean(&path);
}

fn draft(node: &str, key: &str) -> ptah_offline_intent::durable::IntentDraft {
    ptah_offline_intent::durable::IntentDraft {
        intent_id: key.into(),
        node_id: node.into(),
        workspace_id: "workspace-1".into(),
        activity_id: "activity-1".into(),
        operation_id: format!("operation-{key}"),
        attempt_id: format!("attempt-{key}"),
        action: "prepare_offline".into(),
        canonical_input_digest: format!("sha256:{}", "c".repeat(64)),
    }
}
#[test]
fn enqueue_allocates_sequence_after_commit_with_two_writers() {
    let path = scratch();
    let mut a = DurableIntentJournal::open(&path).unwrap();
    let mut b = DurableIntentJournal::open(&path).unwrap();
    let (one, first) = a.enqueue(&draft("node-a", "first")).unwrap();
    let (other, _) = b.enqueue(&draft("node-b", "independent")).unwrap();
    let (two, _) = b.enqueue(&draft("node-a", "second")).unwrap();
    let (replayed, last) = a.enqueue(&draft("node-a", "first")).unwrap();
    assert_eq!(first, ReplayDisposition::Distinct);
    assert_eq!(last, ReplayDisposition::Idempotent);
    assert_eq!(one, replayed);
    assert_eq!(one.origin.value, 1);
    assert_eq!(other.origin.value, 1);
    assert_eq!(two.origin.value, 2);
    drop(a);
    drop(b);
    let recovered = DurableIntentJournal::open(&path).unwrap();
    assert_eq!(recovered.history().unwrap().len(), 3);
    drop(recovered);
    clean(&path);
}
#[test]
fn idempotent_replay_rejects_corrupt_cursor_without_acknowledging_authority() {
    let path = scratch();
    let mut journal = DurableIntentJournal::open(&path).unwrap();
    journal.enqueue(&draft("n1", "one")).unwrap();

    let sql = Connection::open(&path).unwrap();
    sql.execute(
        "UPDATE origin_cursor SET sequence='00000000000000000002' WHERE node='n1'",
        [],
    )
    .unwrap();
    drop(sql);

    // An already-open journal must not acknowledge duplicate work when its
    // origin cursor no longer agrees with the immutable committed tail.
    assert!(journal.enqueue(&draft("n1", "one")).is_err());
    assert!(journal.append(&intent("n1", 1, "one")).is_err());

    let sql = Connection::open(&path).unwrap();
    sql.execute(
        "UPDATE origin_cursor SET sequence='00000000000000000001' WHERE node='n1'",
        [],
    )
    .unwrap();
    drop(sql);
    assert_eq!(
        journal.enqueue(&draft("n1", "one")).unwrap().1,
        ReplayDisposition::Idempotent
    );
    assert_eq!(
        journal.append(&intent("n1", 1, "one")).unwrap(),
        ReplayDisposition::Idempotent
    );
    drop(journal);
    clean(&path);
}

#[test]
fn failed_enqueue_cursor_transaction_never_reserves_a_sequence() {
    let path = scratch();
    let mut j = DurableIntentJournal::open(&path).unwrap();
    assert_eq!(j.enqueue(&draft("n1", "one")).unwrap().0.origin.value, 1);
    let sql = Connection::open(&path).unwrap();
    sql.execute_batch(
        "CREATE TRIGGER fail_all_cursor_updates
      BEFORE UPDATE ON origin_cursor
      BEGIN SELECT RAISE(ABORT,'deliberate failure'); END;",
    )
    .unwrap();
    drop(sql);
    assert!(j.enqueue(&draft("n1", "two")).is_err());
    drop(j);
    let sql = Connection::open(&path).unwrap();
    sql.execute_batch("DROP TRIGGER fail_all_cursor_updates")
        .unwrap();
    drop(sql);
    let mut recovered = DurableIntentJournal::open(&path).unwrap();
    assert_eq!(recovered.history().unwrap().len(), 1);
    assert_eq!(
        recovered
            .enqueue(&draft("n1", "next"))
            .unwrap()
            .0
            .origin
            .value,
        2
    );
    drop(recovered);
    clean(&path);
}

#[test]
#[ignore = "explicit opt-in physical KRATOS storage latency measurement"]
fn benchmark_atomic_enqueue_and_full_restart_validation() {
    let path = scratch();
    let mut j = DurableIntentJournal::open(&path).unwrap();
    let start = std::time::Instant::now();
    let count = 1000_u64;
    for i in 0..count {
        j.enqueue(&draft("kratos-e06-measure", &format!("bench-{i}")))
            .unwrap();
    }
    let append = start.elapsed();
    drop(j);
    let recovery_start = std::time::Instant::now();
    let recovered = DurableIntentJournal::open(&path).unwrap();
    let recovery = recovery_start.elapsed();
    assert_eq!(recovered.history().unwrap().len(), count as usize);
    println!(
        "PTAH_E06_BENCH_1000_APPENDS_MS={:.3}",
        append.as_secs_f64() * 1000.0
    );
    println!(
        "PTAH_E06_BENCH_RECOVERY_MS={:.3}",
        recovery.as_secs_f64() * 1000.0
    );
    println!(
        "PTAH_E06_BENCH_OPS_PER_SEC={:.2}",
        count as f64 / append.as_secs_f64()
    );
    drop(recovered);
    clean(&path);
}

#[cfg(unix)]
#[test]
fn unsafe_permissions_and_file_aliases_are_rejected() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let path = scratch();
    let mut journal = DurableIntentJournal::open(&path).unwrap();
    journal.enqueue(&draft("node", "secure")).unwrap();
    drop(journal);
    let meta = fs::metadata(&path).unwrap();
    assert_eq!(meta.permissions().mode() & 0o077, 0);
    let alias = path.with_extension("hardlink");
    fs::hard_link(&path, &alias).unwrap();
    assert!(DurableIntentJournal::open(&path).is_err());
    fs::remove_file(&alias).unwrap();
    let link = path.with_extension("symlink");
    symlink(&path, &link).unwrap();
    assert!(DurableIntentJournal::open(&link).is_err());
    fs::remove_file(&link).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(DurableIntentJournal::open(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(DurableIntentJournal::open(&path).is_ok());
    clean(&path);
}

#[test]
fn degraded_views_never_promote_offline_intents_to_authority() {
    use ptah_offline_intent::degraded::{DegradedProjection, DegradedState};
    let path = scratch();
    let mut journal = DurableIntentJournal::open(&path).unwrap();
    let empty = DegradedProjection::from_queue(&journal).unwrap();
    assert_eq!(empty.state, DegradedState::OfflineLocal);
    assert!(!empty.authority_granted && empty.revalidate_required);
    journal.enqueue(&draft("node", "queued")).unwrap();
    let queued = DegradedProjection::from_queue(&journal).unwrap();
    assert_eq!(queued.state.as_str(), "queued_not_authorized");
    assert_eq!(queued.pending_count, 1);
    for projection in [queued.clone().revalidating(), queued.conflict()] {
        assert!(!projection.authority_granted);
        assert!(projection.revalidate_required);
    }
    drop(journal);
    clean(&path);
}

#[test]
fn conflict_projection_cannot_be_downgraded_to_revalidating() {
    use ptah_offline_intent::degraded::{DegradedProjection, DegradedState};
    let path = scratch();
    let mut journal = DurableIntentJournal::open(&path).unwrap();
    journal.enqueue(&draft("node", "conflicted")).unwrap();
    let conflict = DegradedProjection::from_queue(&journal).unwrap().conflict();
    let attempted_retry = conflict.revalidating();
    assert_eq!(attempted_retry.state, DegradedState::Conflict);
    assert_eq!(attempted_retry.pending_count, 1);
    assert!(!attempted_retry.authority_granted);
    assert!(attempted_retry.revalidate_required);
    drop(journal);
    clean(&path);
}

#[test]
fn forged_degraded_projection_cannot_grant_authority() {
    use ptah_offline_intent::degraded::{DegradedProjection, DegradedState};
    let forged = DegradedProjection {
        state: DegradedState::OfflineLocal,
        pending_count: 1,
        authority_granted: true,
        revalidate_required: false,
    };
    for projected in [forged.clone().revalidating(), forged.conflict()] {
        assert!(!projected.authority_granted);
        assert!(projected.revalidate_required);
    }
}

#[test]
fn forged_persisted_revalidation_bit_is_rejected() {
    let path = scratch();
    let mut journal = DurableIntentJournal::open(&path).unwrap();
    journal.append(&intent("n1", 1, "one")).unwrap();
    drop(journal);
    let sql = Connection::open(&path).unwrap();
    sql.execute_batch(
        "PRAGMA ignore_check_constraints=ON;
         UPDATE queued_intents SET revalidate=0 WHERE intent_id='one';
         PRAGMA ignore_check_constraints=OFF;",
    )
    .unwrap();
    drop(sql);
    assert!(DurableIntentJournal::open(&path).is_err());
    clean(&path);
}

#[test]
fn duplicate_replay_rejects_matching_noncanonical_cursor_and_tail() {
    let path = scratch();
    let mut journal = DurableIntentJournal::open(&path).unwrap();
    journal.enqueue(&draft("n1", "one")).unwrap();
    journal.enqueue(&draft("n1", "two")).unwrap();

    // A matching cursor and tail are not sufficient when both are malformed.
    let sql = Connection::open(&path).unwrap();
    let malformed = "0000000000000000000x";
    sql.execute(
        "UPDATE queued_intents SET sequence=?1 WHERE intent_id='two'",
        [malformed],
    )
    .unwrap();
    sql.execute(
        "UPDATE origin_cursor SET sequence=?1 WHERE node='n1'",
        [malformed],
    )
    .unwrap();
    drop(sql);

    assert!(journal.enqueue(&draft("n1", "one")).is_err());
    assert!(journal.append(&intent("n1", 1, "one")).is_err());
    drop(journal);
    clean(&path);
}
