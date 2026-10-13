//! Optional E01 mutual-TLS admission endpoint.
//! Read-only authenticated enrollment only. No dispatch or authority minting.
//! Must be provisioned with deployment-owned certificates and canonical
//! approved enrollment projections. Cannot start without them.
#![forbid(unsafe_code)]

use ptah_control::gateway_enrollment::admit_authenticated_node;
use ptah_control::node_link::NodeLinkControl;
use ptah_control::placement::PlacementAuthorityOwner;
use ptah_identifiers::{EntityRef, NodeId};
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle, ProtocolVersion,
    TlsIdentity, TlsServerConfig, TlsTrustRoots,
};
use serde::Deserialize;
use std::{
    collections::HashSet,
    env, fs,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;

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
    let mut entries = std::collections::BTreeMap::new();
    let mut it = env::args().skip(1);
    while let Some(key) = it.next() {
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
    if !listen.ip().is_loopback() {
        return Err(String::from(
            "initial enrollment listener must bind to loopback",
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
    let mut owner = PlacementAuthorityOwner::new(NodeLinkControl::new(
        ProtocolVersion { major: 1, minor: 0 },
        approved,
    ));
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|e| e.to_string())?;
    eprintln!(
        "ptah-enrollment-gateway: mutual-TLS E01 admission-only endpoint on {}",
        config.listen
    );
    loop {
        let (socket, _peer) = listener.accept().await.map_err(|e| e.to_string())?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        if let Err(error) = admit_authenticated_node(socket, &tls, &mut owner, now).await {
            eprintln!("ptah-enrollment-gateway: admission rejected: {error}");
        }
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
