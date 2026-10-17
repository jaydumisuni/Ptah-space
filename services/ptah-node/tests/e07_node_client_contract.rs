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

const FIXTURE_CA_DER: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/ca.cert.der");
const FIXTURE_SERVER_DER: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.cert.der");
const FIXTURE_SERVER_KEY_DER: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.key.der");
const FIXTURE_CLIENT_DER: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.cert.der");
const FIXTURE_CLIENT_KEY_DER: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.key.der");

fn openssl_fixture_to_pem(
    directory: &std::path::Path,
    name: &str,
    input: &[u8],
    key: bool,
) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let der = directory.join(format!("{name}.der"));
    let pem = directory.join(format!("{name}.pem"));
    fs::write(&der, input).unwrap();
    let args = if key {
        vec!["pkey", "-inform", "DER", "-in"]
    } else {
        vec!["x509", "-inform", "DER", "-in"]
    };
    let output = Command::new("openssl")
        .args(args)
        .arg(&der)
        .args(["-outform", "PEM", "-out"])
        .arg(&pem)
        .output()
        .expect("OpenSSL fixture conversion");
    assert!(
        output.status.success(),
        "OpenSSL fixture DER invalid: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if key {
        fs::set_permissions(&pem, fs::Permissions::from_mode(0o600)).unwrap();
    }
    pem
}

#[tokio::test(flavor = "multi_thread")]
async fn real_binary_authenticates_to_control_and_closes_bounded_tls_session() {
    use ptah_control::{
        gateway_session::handle, node_link::NodeLinkControl, placement::PlacementAuthorityOwner,
    };
    use ptah_node_link::{
        ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle, ProtocolVersion,
        TlsIdentity, TlsServerConfig, TlsTrustRoots,
    };
    use std::{sync::Arc, time::Duration};
    use tokio::{net::TcpListener, sync::Mutex};

    let dir = std::env::temp_dir().join(format!(
        "ptah-e01-socket-test-{}",
        ptah_identifiers::EntityId::new_v7()
    ));
    fs::create_dir(&dir).unwrap();
    let ca = openssl_fixture_to_pem(&dir, "ca", FIXTURE_CA_DER, false);
    let client_cert = openssl_fixture_to_pem(&dir, "client", FIXTURE_CLIENT_DER, false);
    let client_key = openssl_fixture_to_pem(&dir, "client-key", FIXTURE_CLIENT_KEY_DER, true);
    let node = NodeAgent::bootstrap().unwrap();
    let enrollment_ref = EntityRef::new("core.node_enrollment").unwrap();
    let seed = dir.join("node-state.json");
    fs::write(&seed, serde_json::to_vec(&node.restart_seed()).unwrap()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let enrollment = ApprovedNodeEnrollment::new(
        enrollment_ref.clone(),
        node.node_id(),
        EnrollmentLifecycle::Approved,
        vec!["node.connect".to_owned()],
        vec![CredentialFingerprint::from_der(FIXTURE_CLIENT_DER)],
        None,
    )
    .unwrap();
    let owner = Arc::new(Mutex::new(PlacementAuthorityOwner::new(
        NodeLinkControl::new(ProtocolVersion { major: 1, minor: 0 }, vec![enrollment]),
    )));
    let tls = TlsServerConfig::new(
        TlsIdentity::from_der(
            vec![FIXTURE_SERVER_DER.to_vec()],
            FIXTURE_SERVER_KEY_DER.to_vec(),
        )
        .unwrap(),
        TlsTrustRoots::from_der(vec![FIXTURE_CA_DER.to_vec()]).unwrap(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        handle(socket, &tls, &owner, 1_800_000_000, Duration::from_secs(7)).await
    });
    let enrollment_json = serde_json::to_string(&enrollment_ref).unwrap();
    let client = tokio::task::spawn_blocking(move || {
        Command::new(entry())
            .args([
                "--endpoint",
                &port.to_string(),
                "--server-name",
                "localhost",
                "--client-cert",
                client_cert.to_str().unwrap(),
                "--client-key",
                client_key.to_str().unwrap(),
                "--control-ca",
                ca.to_str().unwrap(),
                "--node-seed",
                seed.to_str().unwrap(),
                "--enrollment-ref-json",
                &enrollment_json,
                "--seconds",
                "2",
            ])
            .output()
            .expect("run actual Node E01 client")
    });
    let output = tokio::time::timeout(Duration::from_secs(15), client)
        .await
        .expect("client duration bound")
        .expect("client subprocess");
    assert!(
        output.status.success(),
        "E01 client: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    tokio::time::timeout(Duration::from_secs(8), server)
        .await
        .expect("Control retained channel timeout")
        .expect("Control task")
        .expect("authenticated Hello, fresh heartbeats, bounded Close");
    let state: ptah_node_agent::NodeRestartSeed =
        serde_json::from_slice(&fs::read(dir.join("node-state.json")).unwrap()).unwrap();
    assert_eq!(state.node_id, node.node_id());
    assert!(state.generation.value() > node.generation().value());
    assert!(state.connection_epoch.value() > node.connection_epoch().value());
    let _ = fs::remove_dir_all(dir);
}
