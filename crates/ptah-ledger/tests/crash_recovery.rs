//! Abrupt-process recovery proof for the A03 `SQLite` ledger boundary.
//!
//! The helper process stages a canonical write and aborts without unwinding so
//! reopening the same database must prove that uncommitted truth was not published.

use ptah_identifiers::{EntityId, EntityRef};
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger};
use serde_json::json;
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{self, Command},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_DB: AtomicU64 = AtomicU64::new(0);
const NODE_SCHEMA_ID: &str = "urn:ptah:schema:runtime:node:0.1.0";
const NODE_SCHEMA_VERSION: &str = "0.1.0";
const CRASH_DB_ENV: &str = "PTAH_A03_CRASH_HELPER_DB";
const CRASH_ENTITY_ENV: &str = "PTAH_A03_CRASH_HELPER_ENTITY";

struct TempDb(PathBuf);

impl TempDb {
    fn new() -> Self {
        let serial = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "ptah-a03-crash-test-{}-{serial}.sqlite3",
            process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        for suffix in ["-wal", "-shm"] {
            let mut sidecar: OsString = self.0.as_os_str().to_owned();
            sidecar.push(suffix);
            let _ = fs::remove_file(PathBuf::from(sidecar));
        }
    }
}

fn node_record(entity_id: EntityId) -> CanonicalRecord {
    CanonicalRecord::from_document(json!({
        "envelope": {
            "entity_id": entity_id.to_string(),
            "entity_kind": "core.node",
            "schema_id": NODE_SCHEMA_ID,
            "schema_version": NODE_SCHEMA_VERSION,
            "record_revision": 1,
            "authority_ref": EntityRef::new("identity.principal")
                .expect("canonical authority reference"),
        },
        "node_generation": 0,
        "test_payload": "abrupt-crash",
    }))
    .expect("canonical crash-test record")
}

#[test]
fn crash_writer_helper() {
    let Ok(path) = std::env::var(CRASH_DB_ENV) else {
        return;
    };
    let Ok(entity_id) = std::env::var(CRASH_ENTITY_ENV) else {
        return;
    };

    let entity_id = EntityId::from_str(&entity_id).expect("crash-helper entity identity");
    let mut ledger = Ledger::open(path).expect("open crash-helper ledger");
    let write = ledger.begin_write().expect("begin crash-helper write");
    write
        .insert(&node_record(entity_id))
        .expect("stage crash-helper record");

    // Deliberately bypass Rust unwinding and Drop so SQLite must recover the
    // uncommitted transaction after an abrupt process death.
    process::abort();
}

#[test]
fn committed_crash_writer_helper() {
    let Ok(path) = std::env::var(CRASH_DB_ENV) else {
        return;
    };
    let Ok(entity_id) = std::env::var(CRASH_ENTITY_ENV) else {
        return;
    };

    let entity_id = EntityId::from_str(&entity_id).expect("committed-crash entity identity");
    let mut ledger = Ledger::open(path).expect("open committed-crash ledger");
    let write = ledger.begin_write().expect("begin committed-crash write");
    write
        .insert(&node_record(entity_id))
        .expect("stage committed-crash record");
    write.commit().expect("commit WAL record before crash");

    // The commit must already be durable in WAL. Abort without destructors or an
    // explicit checkpoint so reopen has to recover the committed WAL truth.
    process::abort();
}

#[test]
fn abrupt_process_death_preserves_committed_wal_truth_without_checkpoint() {
    let db = TempDb::new();
    let entity_id = EntityId::new_v7();
    drop(Ledger::open(db.path()).expect("initialize committed-crash ledger"));

    let status =
        Command::new(std::env::current_exe().expect("current integration-test executable"))
            .arg("--exact")
            .arg("committed_crash_writer_helper")
            .arg("--nocapture")
            .current_dir(std::env::temp_dir())
            .env(CRASH_DB_ENV, db.path())
            .env(CRASH_ENTITY_ENV, entity_id.to_string())
            .status()
            .expect("launch committed-crash child");
    assert!(
        !status.success(),
        "committed-crash helper must terminate abruptly rather than return normally"
    );

    let mut wal_path: OsString = db.path().as_os_str().to_owned();
    wal_path.push("-wal");
    let wal_path = PathBuf::from(wal_path);
    assert!(wal_path.is_file(), "committed WAL must exist before reopen");
    assert!(
        fs::metadata(&wal_path)
            .expect("committed WAL metadata")
            .len()
            > 0,
        "committed WAL must contain durable frames before reopen"
    );

    let ledger = Ledger::open(db.path()).expect("reopen ledger after committed process death");
    let observed = ledger
        .latest_record(entity_id)
        .expect("query committed record after process death")
        .expect("committed WAL record must survive abrupt process death");
    assert_eq!(observed.entity_id(), entity_id);
    assert_eq!(observed.record_revision().value(), 1);
    assert_eq!(
        observed
            .node_generation()
            .map(ptah_identifiers::NodeGeneration::value),
        Some(0)
    );
    assert_eq!(observed.document()["test_payload"], "abrupt-crash");
    assert_eq!(
        ledger
            .schema_version()
            .expect("schema version after committed crash"),
        2
    );
    assert_eq!(
        ledger
            .journal_mode()
            .expect("journal mode after committed crash"),
        "wal"
    );
}

#[test]
fn abrupt_process_death_does_not_publish_uncommitted_truth() {
    let db = TempDb::new();
    let entity_id = EntityId::new_v7();
    drop(Ledger::open(db.path()).expect("initialize crash-test ledger"));

    let status =
        Command::new(std::env::current_exe().expect("current integration-test executable"))
            .arg("--exact")
            .arg("crash_writer_helper")
            .arg("--nocapture")
            .current_dir(std::env::temp_dir())
            .env(CRASH_DB_ENV, db.path())
            .env(CRASH_ENTITY_ENV, entity_id.to_string())
            .status()
            .expect("launch abrupt-crash child");
    assert!(
        !status.success(),
        "crash-helper child must terminate abruptly rather than return normally"
    );

    let ledger = Ledger::open(db.path()).expect("reopen ledger after abrupt process death");
    assert!(
        ledger
            .latest_record(entity_id)
            .expect("query after abrupt process death")
            .is_none(),
        "an uncommitted canonical row must not survive process death"
    );
    assert_eq!(
        ledger.schema_version().expect("schema version after crash"),
        2
    );
    assert_eq!(
        ledger.journal_mode().expect("journal mode after crash"),
        "wal"
    );
}
