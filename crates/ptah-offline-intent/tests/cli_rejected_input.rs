//! Invalid CLI requests must not create a durable journal as a side effect.
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn rejected_cli_arguments_do_not_materialize_a_journal() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/ptah-e06-cli-negative")
        .join(format!("{}-{nonce}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let journal = dir.join("rejected.sqlite");
    for args in [
        vec!["unknown"],
        vec!["status", "unexpected"],
        vec!["enqueue", "only-node"],
        vec![
            "enqueue",
            "node",
            "intent",
            "workspace",
            "activity",
            "operation",
            "attempt",
            "prepare",
            "not-a-digest",
        ],
        vec![
            "enqueue",
            " ",
            "intent",
            "workspace",
            "activity",
            "operation",
            "attempt",
            "prepare",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_ptah-local-queue"))
            .arg(args[0])
            .arg(&journal)
            .args(&args[1..])
            .output()
            .unwrap();
        assert!(
            !result.status.success(),
            "invalid request was accepted: {args:?}"
        );
        assert!(
            !journal.exists(),
            "invalid request created a durable journal: {args:?}"
        );
        for suffix in ["-wal", "-shm"] {
            assert!(!dir.join(format!("rejected.sqlite{suffix}")).exists());
        }
    }
    fs::remove_dir(&dir).unwrap();
}
