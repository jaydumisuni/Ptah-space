//! Optional E01 mutual-TLS admission endpoint.
//! Read-only authenticated enrollment only. No dispatch or authority minting.
//! Must be provisioned with deployment-owned certificates and canonical
//! approved enrollment projections. Cannot start without them.
#![forbid(unsafe_code)]

use ptah_control::gateway_session::handle;
use ptah_control::node_link::NodeLinkControl;
use ptah_control::placement::PlacementAuthorityOwner;
use ptah_identifiers::{EntityRef, NodeId};
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle, ProtocolVersion,
    TlsIdentity, TlsServerConfig, TlsTrustRoots,
};
use serde::Deserialize;
use std::sync::Arc;
use std::{
    collections::HashSet,
    env, fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRow {
    enrollment_ref: EntityRef,
    node_id: NodeId,
    lifecycle: EnrollmentLifecycle,
    approved_role_keys: Vec<String>,
    credential_fingerprints: Vec<String>,
    expires_at_epoch_seconds: Option<u64>,
}
struct Config {
    listen: SocketAddr,
    server_cert: PathBuf,
    server_key: PathBuf,
    client_ca: PathBuf,
    enrollment_path: PathBuf,
}
fn config_from_args() -> Result<Config, String> {
    config_from_iter(env::args().skip(1))
}
fn allowed_bind(ip: IpAddr, allow_private: bool) -> bool {
    if ip.is_loopback() {
        return true;
    }
    if !allow_private {
        return false;
    }
    match ip {
        IpAddr::V4(addr) => {
            let o = addr.octets();
            o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(_) => false,
    }
}
fn config_from_iter(args: impl IntoIterator<Item = String>) -> Result<Config, String> {
    let mut allow_private = false;
    let mut entries = std::collections::BTreeMap::new();
    let mut it = args.into_iter();
    while let Some(key) = it.next() {
        if key == "--allow-private-lan" {
            if allow_private {
                return Err("duplicate private-LAN option".into());
            }
            allow_private = true;
            continue;
        }
        if ![
            "--listen",
            "--server-cert",
            "--server-key",
            "--client-ca",
            "--enrollments",
        ]
        .contains(&key.as_str())
        {
            return Err(format!("unsupported option: {key}"));
        }
        let value = it.next().ok_or("missing option value")?;
        if entries.insert(key.clone(), value).is_some() {
            return Err(format!("repeated option: {key}"));
        }
    }
    let mut val = |key: &str| {
        entries
            .remove(key)
            .ok_or_else(|| format!("missing required {key}"))
    };
    let listen: SocketAddr = val("--listen")?
        .parse()
        .map_err(|_| "invalid bind address")?;
    if !allowed_bind(listen.ip(), allow_private) {
        return Err(String::from(
            "listener must be loopback, or explicit private RFC1918 address with --allow-private-lan",
        ));
    }
    let config = Config {
        listen,
        server_cert: PathBuf::from(val("--server-cert")?),
        server_key: PathBuf::from(val("--server-key")?),
        client_ca: PathBuf::from(val("--client-ca")?),
        enrollment_path: PathBuf::from(val("--enrollments")?),
    };
    Ok(config)
}
fn read_owned(path: &PathBuf, sensitive: bool) -> Result<Vec<u8>, String> {
    let metadata = path
        .symlink_metadata()
        .map_err(|e| format!("missing configured file: {e}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(String::from(
            "configured file must be a regular non-symlink",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if sensitive && metadata.permissions().mode() & 0o077 != 0 {
            return Err(String::from(
                "private key/enrollment file is group/world accessible",
            ));
        }
    }
    // Windows ACL validation is not yet qualified. Do not permit a private
    // key/enrollment file to be loaded merely because the path exists.
    #[cfg(windows)]
    if sensitive {
        return Err(String::from(
            "Windows sensitive-file ACL admission is not qualified",
        ));
    }
    fs::read(path).map_err(|e| format!("cannot read configured file: {e}"))
}
fn canonical_enrollments(input: &[u8]) -> Result<Vec<ApprovedNodeEnrollment>, String> {
    let rows: Vec<AdmissionRow> = serde_json::from_slice(input)
        .map_err(|e| format!("malformed enrollment projection: {e}"))?;
    if rows.is_empty() {
        return Err(String::from("no approved enrollments"));
    }
    let mut used = HashSet::new();
    rows.into_iter()
        .map(|row| {
            if !used.insert(row.node_id) {
                return Err(String::from("duplicate canonical Node"));
            }
            if row.lifecycle != EnrollmentLifecycle::Approved
                || !row
                    .approved_role_keys
                    .iter()
                    .any(|role| role == "node.connect")
            {
                return Err(String::from("enrollment is not approved for node.connect"));
            }
            let mut fp = Vec::new();
            for input in &row.credential_fingerprints {
                fp.push(CredentialFingerprint::from_str(input).map_err(|e| e.to_string())?);
            }
            ApprovedNodeEnrollment::new(
                row.enrollment_ref,
                row.node_id,
                row.lifecycle,
                row.approved_role_keys,
                fp,
                row.expires_at_epoch_seconds,
            )
            .map_err(|e| e.to_string())
        })
        .collect()
}
async fn serve(config: Config) -> Result<(), String> {
    let cert = read_owned(&config.server_cert, false)?;
    let key = read_owned(&config.server_key, true)?;
    let ca = read_owned(&config.client_ca, false)?;
    let rows = read_owned(&config.enrollment_path, true)?;
    let approved = canonical_enrollments(&rows)?;
    let tls = TlsServerConfig::new(
        TlsIdentity::from_pem(&cert, &key).map_err(|e| e.to_string())?,
        TlsTrustRoots::from_pem(&ca).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let owner = Arc::new(Mutex::new(PlacementAuthorityOwner::new(
        NodeLinkControl::new(ProtocolVersion { major: 1, minor: 0 }, approved),
    )));
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|e| e.to_string())?;
    eprintln!(
        "ptah-enrollment-gateway: mutual-TLS E01 admission-only endpoint on {}",
        config.listen
    );
    let slots = Arc::new(Semaphore::new(16));
    loop {
        let (socket, _peer) = listener.accept().await.map_err(|e| e.to_string())?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            // Fail closed under overload. Never queue unbounded sockets.
            drop(socket);
            continue;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let shared_owner = owner.clone();
        let tls_config = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle(
                socket,
                &tls_config,
                &shared_owner,
                now,
                Duration::from_secs(30),
            )
            .await
            {
                eprintln!("ptah-enrollment-gateway: E01 connection rejected/closed: {error}");
            }
        });
    }
}
#[tokio::main]
async fn main() {
    let result = match config_from_args() {
        Ok(config) => serve(config).await,
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        eprintln!("ptah-enrollment-gateway: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptah_node_agent::NodeAgent;
    use serde_json::json;
    fn row(lifecycle: &str, fingerprint: &str) -> serde_json::Value {
        let node = NodeAgent::bootstrap().expect("test Node");
        json!({
            "enrollment_ref":EntityRef::new("core.node_enrollment").expect("ref"),
            "node_id":node.node_id(),
            "lifecycle":lifecycle,
            "approved_role_keys":["node.connect"],
            "credential_fingerprints":[fingerprint],
            "expires_at_epoch_seconds":null
        })
    }

    fn listener_args(endpoint: &str, opt_in: bool) -> Vec<String> {
        let mut v = vec![
            "--listen".to_string(),
            endpoint.to_string(),
            "--server-cert".to_string(),
            "server.pem".to_string(),
            "--server-key".to_string(),
            "key.pem".to_string(),
            "--client-ca".to_string(),
            "ca.pem".to_string(),
            "--enrollments".to_string(),
            "approved.json".to_string(),
        ];
        if opt_in {
            v.push("--allow-private-lan".to_string());
        }
        v
    }
    #[test]
    fn loopback_allowed_without_private_opt_in() {
        for endpoint in ["127.0.0.1:9238", "[::1]:9238"] {
            assert!(config_from_iter(listener_args(endpoint, false)).is_ok());
        }
        assert!(config_from_iter(listener_args("192.168.0.100:9238", false)).is_err());
    }
    #[test]
    fn only_specific_private_ipv4_bind_allowed_with_opt_in() {
        for endpoint in [
            "192.168.0.100:9238",
            "192.168.1.100:9238",
            "10.10.10.1:9238",
            "172.16.0.1:9238",
            "172.31.255.1:9238",
        ] {
            assert!(
                config_from_iter(listener_args(endpoint, true)).is_ok(),
                "{endpoint}"
            );
        }
        for endpoint in [
            "0.0.0.0:9238",
            "[::]:9238",
            "8.8.8.8:9238",
            "1.1.1.1:9238",
            "169.254.1.10:9238",
            "100.64.0.1:9238",
            "172.15.0.1:9238",
            "172.32.0.1:9238",
            "192.0.2.1:9238",
            "[fe80::1]:9238",
            "[fc00::1]:9238",
        ] {
            assert!(
                config_from_iter(listener_args(endpoint, true)).is_err(),
                "{endpoint}"
            );
        }
    }
    #[test]
    fn duplicate_private_bind_opt_in_is_refused() {
        let mut a = listener_args("192.168.0.100:9238", true);
        a.push("--allow-private-lan".to_string());
        assert!(config_from_iter(a).is_err());
        let mut b = listener_args("192.168.0.100:9238", true);
        b.push("--unsupported-option".to_string());
        assert!(config_from_iter(b).is_err());
    }

    #[test]
    fn enrollment_config_accepts_only_canonical_approved_entries() {
        let fingerprint = "a".repeat(64);
        let entry = row("approved", &fingerprint);
        let bytes = serde_json::to_vec(&vec![entry.clone()]).expect("serialize");
        assert_eq!(canonical_enrollments(&bytes).expect("approved").len(), 1);
        let duplicates = serde_json::to_vec(&vec![entry.clone(), entry]).expect("serialize");
        assert!(canonical_enrollments(&duplicates).is_err());
        let revoked = serde_json::to_vec(&vec![row("revoked", &fingerprint)]).expect("serialize");
        assert!(canonical_enrollments(&revoked).is_err());
        let malformed =
            serde_json::to_vec(&vec![row("approved", "not-a-fingerprint")]).expect("serialize");
        assert!(canonical_enrollments(&malformed).is_err());
    }
    #[cfg(windows)]
    #[test]
    fn windows_sensitive_file_requires_explicit_acl_qualification() {
        let path = std::env::temp_dir().join(format!(
            "ptah-win-secret-policy-{}.txt",
            ptah_identifiers::EntityId::new_v7()
        ));
        fs::write(&path, b"harmless-test-material").expect("fixture");
        assert!(read_owned(&path, true).is_err());
        assert_eq!(
            read_owned(&path, false).expect("public material"),
            b"harmless-test-material"
        );
        fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn server_refuses_missing_or_world_readable_secret_file() {
        let path = std::env::temp_dir().join(format!(
            "ptah-no-deploy-keys-{}.pem",
            ptah_identifiers::EntityId::new_v7()
        ));
        assert!(read_owned(&path, true).is_err());
        fs::write(&path, b"not-a-key").expect("create harmless fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("public");
            assert!(read_owned(&path, true).is_err());
        }
        let _ = fs::remove_file(path);
    }
}
