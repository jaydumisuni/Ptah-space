//! Canonical A03 persistence and store-boundary proof for D07.

use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use ptah_identifiers::EntityRef;
use ptah_security_evidence::{D07Error, SecurityEvidenceStore};
use serde_json::json;

static NEXT_DB: AtomicU64 = AtomicU64::new(0);

struct TempDb(PathBuf);
impl TempDb {
    fn new() -> Self {
        let n = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("ptah-d07-store-{}-{n}.sqlite3", process::id())))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        for suffix in ["-wal", "-shm"] {
            let mut side: OsString = self.0.as_os_str().to_owned();
            side.push(suffix);
            let _ = fs::remove_file(PathBuf::from(side));
        }
    }
}
fn er(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid kind")
}

#[test]
fn frozen_security_observation_round_trips_through_a03() {
    let db = TempDb::new();
    let mut store = SecurityEvidenceStore::open(db.path()).expect("open");
    let observation_ref = er("security.observation");
    let document = json!({
      "envelope":{"entity_id":observation_ref.entity_id,"entity_kind":observation_ref.entity_kind,"schema_id":"urn:ptah:schema:security:observation:0.1.0","schema_version":"0.1.0","record_revision":1,"authority_ref":er("identity.principal")},
      "observer_ref":er("identity.agent"),"observation_type":"static_scan","subject_refs":[er("core.object_revision")],
      "observed_facts":{"rule":"RULE-1","message":"bounded fact"},"confidence":0.8,"observed_at":"2026-09-03T00:00:00Z",
      "evidence_refs":[er("core.evidence")],"limitations":[],"extensions":{}
    });
    let stored = store.record_document(document.clone()).expect("persist");
    assert_eq!(stored, observation_ref);
    assert_eq!(store.read(&stored).expect("read"), document);
}

#[test]
fn non_wp12_canonical_document_is_rejected() {
    let db = TempDb::new();
    let mut store = SecurityEvidenceStore::open(db.path()).expect("open");
    let observation_ref = er("provenance.package_observation");
    let document = json!({
      "envelope":{"entity_id":observation_ref.entity_id,"entity_kind":observation_ref.entity_kind,"schema_id":"urn:ptah:schema:build:package-observation:0.1.0","schema_version":"0.1.0","record_revision":1,"authority_ref":er("identity.principal")},
      "subject_ref":er("core.object_revision"),"scanner_or_cataloguer_revision_ref":er("core.object_revision"),"package_name":"x","package_type":"cargo",
      "locations":[{"location_type":"path","locator":"/tmp/x"}],"confidence":1.0,"observed_at":"2026-09-03T00:00:00Z","evidence_refs":[er("core.evidence")],"extensions":{}
    });
    assert!(matches!(
        store.record_document(document),
        Err(D07Error::UnsupportedSecuritySchema)
    ));
}
