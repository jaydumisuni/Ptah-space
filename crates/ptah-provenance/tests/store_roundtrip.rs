//! Canonical A03 persistence proof for the bounded D06 WP07 store.

use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use ptah_identifiers::EntityRef;
use ptah_provenance::ProvenanceStore;
use serde_json::json;

static NEXT_DB: AtomicU64 = AtomicU64::new(0);

struct TempDb(PathBuf);

impl TempDb {
    fn new() -> Self {
        let serial = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "ptah-d06-store-test-{}-{serial}.sqlite3",
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

fn er(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid test entity kind")
}

#[test]
fn frozen_package_observation_round_trips_through_a03() {
    let db = TempDb::new();
    let mut store = ProvenanceStore::open(db.path()).expect("open D06 store");
    let observation_ref = er("provenance.package_observation");
    let document = json!({
        "envelope": {
            "entity_id": observation_ref.entity_id,
            "entity_kind": observation_ref.entity_kind,
            "schema_id": "urn:ptah:schema:build:package-observation:0.1.0",
            "schema_version": "0.1.0",
            "record_revision": 1,
            "authority_ref": er("identity.principal")
        },
        "subject_ref": er("core.object_revision"),
        "scanner_or_cataloguer_revision_ref": er("core.object_revision"),
        "package_name": "ptah-provenance",
        "package_type": "cargo",
        "locations": [{"location_type":"path","locator":"/workspace/Cargo.lock"}],
        "confidence": 1.0,
        "observed_at": "2026-09-02T20:00:00Z",
        "evidence_refs": [er("core.evidence")],
        "extensions": {}
    });
    let stored_ref = store
        .record_document(document.clone())
        .expect("persist canonical observation");
    assert_eq!(stored_ref, observation_ref);
    assert_eq!(
        store.read(&stored_ref).expect("read canonical observation"),
        document
    );
}
