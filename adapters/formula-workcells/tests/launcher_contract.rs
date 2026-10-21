//! Negative and positive tests for the custody-bound native Ptah launcher.
#![cfg(unix)]
use std::{path::PathBuf, process::Command};
const MANIFEST: &str = "sha256:778e11206defae987198ad7174606ab063a64855a4d0775a10bce66087e2ec07";
const CELL: &str = "sha256:d156d75e30f1da5b7fc32e1a5f55fec0f126c0b11ae0cd361ea1b925071a8d09";
const AUTH: &str = "sha256:f849d67325facf04177bc663b2dc544051831c589ef581d412f2eba44834e77c";
fn command(control: &str, authority: &str) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ptah-formula-control"));
    let packet = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/formula-generated-handoff.json");
    c.args([
        "--control-bin",
        control,
        "--formula-handoff",
        packet.to_str().unwrap(),
        "--formula-work-cell",
        CELL,
        "--formula-authority",
        authority,
        "--request-digest",
        MANIFEST,
        "--listen",
        "127.0.0.1:47826",
        "--server-cert",
        "server.pem",
        "--server-key",
        "server.key",
        "--client-ca",
        "ca.pem",
        "--enrollments",
        "enrollments.json",
        "--journal",
        "journal.sqlite3",
    ]);
    c
}
#[test]
fn real_formula_packet_has_custody_and_delegates_native_control() {
    assert!(command("/usr/bin/true", AUTH).status().unwrap().success());
    assert_eq!(
        command("/usr/bin/false", AUTH).status().unwrap().code(),
        Some(1)
    );
}
#[test]
fn incorrect_mathematical_authority_denied_before_launch() {
    let denied = command(
        "/usr/bin/true",
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
    .output()
    .unwrap();
    assert_eq!(denied.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&denied.stderr).contains("Formula custody denied"));
}

#[test]
fn symlink_handoff_fails_before_launch() {
    use std::{ffi::OsString, fs, os::unix::fs::symlink};
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/formula-generated-handoff.json");
    let link = std::env::temp_dir().join(format!("p13-link-{}", std::process::id()));
    symlink(&source, &link).unwrap();
    let base = command("/usr/bin/true", AUTH);
    let mut args: Vec<OsString> = base.get_args().map(OsString::from).collect();
    let index = args.iter().position(|a| a == "--formula-handoff").unwrap();
    args[index + 1] = link.as_os_str().to_os_string();
    let result = Command::new(env!("CARGO_BIN_EXE_ptah-formula-control"))
        .args(args)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    fs::remove_file(link).unwrap();
}

#[test]
fn oversized_handoff_is_rejected_without_unbounded_allocation() {
    use std::{ffi::OsString, fs};
    let path = std::env::temp_dir().join(format!("p13-large-{}", std::process::id()));
    fs::write(&path, vec![b'X'; 1_048_577]).unwrap();
    let base = command("/usr/bin/true", AUTH);
    let mut args: Vec<OsString> = base.get_args().map(OsString::from).collect();
    let index = args.iter().position(|a| a == "--formula-handoff").unwrap();
    args[index + 1] = path.as_os_str().to_os_string();
    let result = Command::new(env!("CARGO_BIN_EXE_ptah-formula-control"))
        .args(args)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    fs::remove_file(path).unwrap();
}
