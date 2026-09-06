//! A03 entity-kind discovery proof required by E02 durable authority recovery.

use ptah_identifiers::{EntityId, EntityKind, EntityRef};
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger};
use serde_json::json;
use std::{fs, path::PathBuf, process};

fn temp_db() -> PathBuf {
    std::env::temp_dir().join(format!(
        "ptah-a03-kind-recovery-{}-{}.sqlite3",
        process::id(),
        EntityId::new_v7()
    ))
}

fn record(entity_id: EntityId, kind: &str, revision: u64, marker: &str) -> CanonicalRecord {
    CanonicalRecord::from_document(json!({
        "entity_id": entity_id.to_string(),
        "entity_kind": kind,
        "schema_id": "urn:ptah:schema:common:entity-envelope:0.1.0",
        "schema_version": "0.1.0",
        "record_revision": revision,
        "authority_ref": EntityRef::new("identity.principal").expect("authority"),
        "marker": marker,
    }))
    .expect("canonical record")
}

#[test]
fn latest_records_by_kind_discovers_one_latest_revision_per_entity_deterministically() {
    let path = temp_db();
    let mut ledger = Ledger::open(&path).expect("ledger");
    let first = EntityId::new_v7();
    let second = EntityId::new_v7();
    let other = EntityId::new_v7();

    {
        let write = ledger.begin_write().expect("write");
        write.insert(&record(first, "resource.reservation", 1, "old")).expect("first v1");
        write.insert(&record(first, "resource.reservation", 2, "new")).expect("first v2");
        write.insert(&record(second, "resource.reservation", 1, "second")).expect("second");
        write.insert(&record(other, "isolation.lease", 1, "other-kind")).expect("other");
        write.commit().expect("commit");
    }

    let kind = EntityKind::new("resource.reservation").expect("kind");
    let records = ledger.latest_records_by_kind(&kind).expect("kind query");
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| record.entity_kind() == &kind));
    assert!(records.iter().any(|record| record.entity_id() == first && record.record_revision().value() == 2 && record.document()["marker"] == "new"));
    assert!(records.iter().any(|record| record.entity_id() == second && record.record_revision().value() == 1));

    drop(ledger);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
    let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
}
