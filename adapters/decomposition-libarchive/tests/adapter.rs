//! A12 libarchive adapter unit tests that do not require the physical helper.

use decomposition_libarchive::{LibarchiveBackend, LibarchiveConfig};
use ptah_identifiers::EntityRef;
use std::path::PathBuf;

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("ref")
}

#[test]
fn wrong_locked_version_is_rejected_before_execution() {
    let error = LibarchiveBackend::open(LibarchiveConfig {
        helper_path: PathBuf::from("missing"),
        expected_helper_sha256: "a".repeat(64),
        expected_source_sha256: "b".repeat(64),
        expected_version: "3.7.4".to_owned(),
        provider_ref: reference("runtime.provider"),
        provider_generation: 1,
        max_members: 10,
        max_member_bytes: 1024,
        max_total_bytes: 4096,
        max_path_bytes: 1024,
    })
    .err()
    .expect("must reject");
    assert!(error.to_string().contains("version"));
}
