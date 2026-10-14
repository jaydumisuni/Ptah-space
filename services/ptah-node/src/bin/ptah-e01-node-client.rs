//! Explicit, deployment-provisioned E01 mutual-TLS Node client.
//! Admission-only: never issues Node identities, leases or process dispatch.
#![forbid(unsafe_code)]

use ptah_identifiers::EntityRef;
use ptah_node::{NodeLinkClientConfig, connect_node_link};
use ptah_node_agent::{NodeAgent, NodeRestartSeed};
use ptah_node_link::{
    Heartbeat, LinkMessage, ProtocolVersion, TlsClientConfig, TlsIdentity, TlsTrustRoots,
    write_frame,
};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Config {
    endpoint: SocketAddr,
    server_name: String,
    certificate: PathBuf,
    private_key: PathBuf,
    control_ca: PathBuf,
    node_seed: PathBuf,
    enrollment_ref: EntityRef,
    duration: Duration,
}

fn args_to_config(args: impl IntoIterator<Item = String>) -> Result<Config> {
    let mut options = BTreeMap::new();
    let mut args = args.into_iter();
    while let Some(key) = args.next() {
        if ![
            "--endpoint",
            "--server-name",
            "--client-cert",
            "--client-key",
            "--control-ca",
            "--node-seed",
            "--enrollment-ref-json",
            "--seconds",
        ]
        .contains(&key.as_str())
        {
            return Err(format!("unknown option: {key}").into());
        }
        let value = args.next().ok_or("missing option value")?;
        if options.insert(key, value).is_some() {
            return Err("duplicate option".into());
        }
    }
    let mut take = |key: &str| options.remove(key).ok_or(format!("missing {key}"));
    let endpoint: SocketAddr = take("--endpoint")?.parse()?;
    let server_name = take("--server-name")?;
    if server_name.is_empty() || server_name.len() > 253 {
        return Err("server name required and bounded".into());
    }
    let seconds: u64 = take("--seconds")?.parse()?;
    if !(2..=3_600).contains(&seconds) {
        return Err("duration must be between 2 and 3600 seconds".into());
    }
    let certificate = PathBuf::from(take("--client-cert")?);
    let private_key = PathBuf::from(take("--client-key")?);
    let control_ca = PathBuf::from(take("--control-ca")?);
    let node_seed = PathBuf::from(take("--node-seed")?);
    let enrollment_ref: EntityRef = serde_json::from_str(&take("--enrollment-ref-json")?)?;
    if enrollment_ref.entity_kind != "core.node_enrollment" {
        return Err("expected canonical core.node_enrollment reference".into());
    }
    Ok(Config {
        endpoint,
        server_name,
        certificate,
        private_key,
        control_ca,
        node_seed,
        enrollment_ref,
        duration: Duration::from_secs(seconds),
    })
}

fn read_regular_file(path: &Path, sensitive: bool) -> Result<Vec<u8>> {
    let meta = path.symlink_metadata()?;
    if !meta.file_type().is_file() || meta.file_type().is_symlink() {
        return Err("input must be a regular non-symlink file".into());
    }
    #[cfg(unix)]
    if sensitive {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.permissions().mode() & 0o077 != 0 || meta.nlink() != 1 {
            return Err("secret/Node state must be private and not hard-linked".into());
        }
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err("input must be nonempty and bounded".into());
    }
    Ok(bytes)
}

/// Retain one exclusive OS file lock and persist next-generation identity
/// atomically before attempting network I/O. Do not create a new Node identity.
fn advance_seed(seed_path: &Path) -> Result<(NodeAgent, File)> {
    let lock_path = seed_path.with_extension("e01.lock");
    if lock_path
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        return Err("Node lock symlink not permitted".into());
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(&lock_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if lock.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err("Node lock file must be private".into());
        }
    }
    lock.try_lock()?;
    // Read the seed only after acquiring the lock. A pre-lock read could
    // replay an obsolete Generation/Epoch after the previous writer exits.
    let data = read_regular_file(seed_path, true)?;
    let seed: NodeRestartSeed = serde_json::from_slice(&data)?;
    let agent = NodeAgent::restart(seed)?;
    let serialized = serde_json::to_vec_pretty(&agent.restart_seed())?;
    let temp_path = seed_path.with_extension(format!("epoch-{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp_path)?;
    file.write_all(&serialized)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp_path, seed_path)?;
    File::open(seed_path.parent().ok_or("seed parent missing")?)?.sync_all()?;
    Ok((agent, lock))
}

async fn session(config: &Config, agent: &NodeAgent, tls: TlsClientConfig) -> Result<()> {
    let client = NodeLinkClientConfig::new(
        config.endpoint,
        config.server_name.clone(),
        tls,
        config.enrollment_ref.clone(),
        "ptah-e07-node-enrollment/0.1".into(),
        ProtocolVersion { major: 1, minor: 0 },
    );
    let (_, mut connection) =
        tokio::time::timeout(Duration::from_secs(12), connect_node_link(agent, &client)).await??;
    if !connection.is_tls13() {
        return Err("TLS 1.3 required".into());
    }
    eprintln!("E01 mutual-TLS session accepted. No E02 execution capability.");
    let end = tokio::time::Instant::now() + config.duration;
    let mut sequence = 0_u64;
    while tokio::time::Instant::now() < end {
        tokio::time::sleep(Duration::from_secs(1)).await;
        sequence = sequence.checked_add(1).ok_or("sequence overflow")?;
        let heartbeat = LinkMessage::Heartbeat(Heartbeat {
            node_id: agent.node_id(),
            node_generation: agent.generation(),
            connection_epoch: agent.connection_epoch(),
            sequence,
        });
        tokio::time::timeout(
            Duration::from_secs(5),
            write_frame(connection.stream_mut(), &heartbeat),
        )
        .await??;
    }
    tokio::time::timeout(
        Duration::from_secs(5),
        write_frame(connection.stream_mut(), &LinkMessage::Close),
    )
    .await??;
    eprintln!("E01 enrollment-only connection closed; no production dispatch authorized");
    Ok(())
}

#[tokio::main]
async fn main() {
    let outcome = async {
        // Windows deployment requires independently audited private-key/state
        // ACLs and crash-durable state replacement; do not silently downgrade.
        #[cfg(not(unix))]
        return Err::<(), Box<dyn std::error::Error>>(
            "Windows E01 Node state custody is not qualified".into(),
        );
        let config = args_to_config(env::args().skip(1))?;
        let cert = read_regular_file(&config.certificate, false)?;
        let key = read_regular_file(&config.private_key, true)?;
        let ca = read_regular_file(&config.control_ca, false)?;
        // Invalid TLS configuration may not consume a canonical Node generation.
        let tls = TlsClientConfig::new(
            TlsIdentity::from_pem(&cert, &key)?,
            TlsTrustRoots::from_pem(&ca)?,
        )?;
        let (agent, _lock) = advance_seed(&config.node_seed)?;
        session(&config, &agent, tls).await
    }
    .await;
    if let Err(error) = outcome {
        eprintln!("ptah-e01-node-client: {error}");
        std::process::exit(2);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn empty_and_partial_options_are_not_admitted() {
        assert!(args_to_config(Vec::new()).is_err());
        assert!(args_to_config(vec!["--endpoint".into(), "127.0.0.1:9301".into()]).is_err());
    }

    #[test]
    fn world_readable_and_symlink_state_are_denied() {
        let path = std::env::temp_dir().join(format!(
            "ptah-e01-private-{}.json",
            ptah_identifiers::EntityId::new_v7()
        ));
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_regular_file(&path, true).is_err());
        let link = path.with_extension("link");
        symlink(&path, &link).unwrap();
        assert!(read_regular_file(&link, false).is_err());
        let _ = fs::remove_file(link);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = path.with_extension("hardlink");
        fs::hard_link(&path, &alias).unwrap();
        assert!(read_regular_file(&path, true).is_err());
        fs::remove_file(alias).unwrap();
        assert!(read_regular_file(&path, true).is_ok());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn repeat_start_mints_no_new_node_and_advances_generation() {
        let path = std::env::temp_dir().join(format!(
            "ptah-e01-seed-{}.json",
            ptah_identifiers::EntityId::new_v7()
        ));
        let initial = NodeAgent::bootstrap().unwrap();
        fs::write(&path, serde_json::to_vec(&initial.restart_seed()).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (first, writer) = advance_seed(&path).unwrap();
        assert!(
            advance_seed(&path).is_err(),
            "must not allow competing writer"
        );
        drop(writer);
        let (second, writer) = advance_seed(&path).unwrap();
        assert_eq!(first.node_id(), second.node_id());
        assert!(second.generation().value() > first.generation().value());
        assert!(second.connection_epoch().value() > first.connection_epoch().value());
        drop(writer);
        let _ = fs::remove_file(path.with_extension("e01.lock"));
        let _ = fs::remove_file(path);
    }
}
