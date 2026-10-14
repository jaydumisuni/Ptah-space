#![cfg(unix)]
#![forbid(unsafe_code)]
//! Black-box E01 production-entry negative admission: never manufacture credentials.
use ptah_identifiers::EntityRef;
use ptah_node_agent::NodeAgent;
use std::{fs, process::Command};

fn entry() -> &'static str {
    env!("CARGO_BIN_EXE_ptah-e01-node-client")
}

#[test]
fn binary_without_approved_deployment_configuration_fails_closed() {
    let output = Command::new(entry()).output().expect("run compiled binary");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("missing --endpoint"),
        "missing identity should not attempt network connections"
    );
}

#[test]
fn missing_production_certificate_never_consumes_retained_node_generation() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!(
        "ptah-e01-external-{}",
        ptah_identifiers::EntityId::new_v7()
    ));
    fs::create_dir(&dir).expect("isolated test dir");
    let seed = dir.join("node-seed.json");
    let initial = NodeAgent::bootstrap().expect("test-only bootstrap");
    let bytes = serde_json::to_vec(&initial.restart_seed()).unwrap();
    fs::write(&seed, &bytes).unwrap();
    fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).unwrap();
    let enrollment =
        serde_json::to_string(&EntityRef::new("core.node_enrollment").unwrap()).unwrap();
    let output = Command::new(entry())
        .args([
            "--endpoint",
            "127.0.0.1:9201",
            "--server-name",
            "control.invalid",
            "--client-cert",
            dir.join("nonexistent-cert.pem").to_str().unwrap(),
            "--client-key",
            dir.join("nonexistent-key.pem").to_str().unwrap(),
            "--control-ca",
            dir.join("nonexistent-ca.pem").to_str().unwrap(),
            "--node-seed",
            seed.to_str().unwrap(),
            "--enrollment-ref-json",
            &enrollment,
            "--seconds",
            "2",
        ])
        .output()
        .expect("execute negative admission");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read(&seed).unwrap(), bytes, "no generation consumed");
    assert!(!dir.join("node-seed.e01.lock").exists());
    let _ = fs::remove_file(seed);
    let _ = fs::remove_dir(dir);
}
