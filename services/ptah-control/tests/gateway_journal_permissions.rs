//! Private creation of Ptah Control's optional native dispatch journal.
#[cfg(unix)]
#[test]
fn new_control_journal_is_private_and_matches_verified_readback_requirement() {
    use ptah_control::gateway_control_journal::ControlDispatchJournal;
    use ptah_identifiers::EntityId;
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
    let path = std::env::temp_dir().join(format!(
        "ptah-e07-private-journal-{}.sqlite3",
        EntityId::new_v7()
    ));
    let journal = ControlDispatchJournal::open(&path).expect("create journal");
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode & 0o077,
        0,
        "new Control journal cannot be group/world accessible"
    );
    let lock = PathBuf::from(format!("{}.lock", path.display()));
    let lock_mode = fs::metadata(&lock).unwrap().permissions().mode() & 0o777;
    assert_eq!(lock_mode & 0o077, 0, "the owner lock must also be private");
    drop(journal);
    for file in [
        path.clone(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
        lock,
    ] {
        let _ = fs::remove_file(file);
    }
}
