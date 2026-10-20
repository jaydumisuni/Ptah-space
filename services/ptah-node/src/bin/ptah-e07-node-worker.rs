//! Optional native E07 Node worker: TLS E01 -> E02 -> durable A05 once.
//! Local process specification is provided by the caller on this Node.
//! This executable never approves a user and never accepts a program from the wire.
use native_process::{
    DisconnectPolicy, NativeProcessProvider, NativeProcessProviderConfig, ProcessMode, ProcessSpec,
};
use ptah_identifiers::EntityRef;
use ptah_node::{
    NodeLinkClientConfig, connect_node_link, gateway_e02_wire::receive_one,
    gateway_journal::GatewayJournal,
};
use ptah_node_agent::{NodeAgent, NodeRestartSeed};
use ptah_node_link::{
    LinkAck, LinkMessage, ProtocolVersion, TlsClientConfig, TlsIdentity, TlsTrustRoots, write_frame,
};
use ptah_provider_api::{
    ProviderGeneration, ProviderHealth, ProviderInstance, ProviderKind, ProviderReachability,
    ProviderReadiness, ProviderRevision,
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerConfig {
    control: SocketAddr,
    server_name: String,
    ca_pem: PathBuf,
    node_cert_pem: PathBuf,
    node_key_pem: PathBuf,
    enrollment_ref: EntityRef,
    node_seed: PathBuf,
    node_journal: PathBuf,
    program: String,
    args: Vec<String>,
    request_sha256: String,
}

fn entity(kind: &str) -> Result<EntityRef, String> {
    EntityRef::new(kind).map_err(|e| format!("identity error: {e:?}"))
}
fn durable_node(path: &Path) -> Result<NodeAgent, String> {
    use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
    if path
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        return Err("node identity path must not be a symlink".into());
    }
    // SQLite's atomic immediate transaction preserves one monotonic Node
    // generation even on Windows where std::fs::rename cannot replace a file.
    // A worker is never allowed to reuse the generation after process death.
    if !path.exists() {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let _file = opts.open(path).map_err(|e| format!("seed create: {e}"))?;
    }
    let mut db = Connection::open(path).map_err(|e| format!("seed database: {e}"))?;
    db.busy_timeout(Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    db.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS identity_seed(
            slot INTEGER PRIMARY KEY CHECK(slot=1), seed TEXT NOT NULL
        ) WITHOUT ROWID;",
    )
    .map_err(|e| format!("seed schema: {e}"))?;
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| format!("seed write owner: {e}"))?;
    let old: Option<String> = tx
        .query_row("SELECT seed FROM identity_seed WHERE slot=1", [], |r| {
            r.get(0)
        })
        .optional()
        .map_err(|e| format!("seed read: {e}"))?;
    let agent = if let Some(record) = old {
        let seed: NodeRestartSeed =
            serde_json::from_str(&record).map_err(|e| format!("invalid saved seed: {e}"))?;
        NodeAgent::restart(seed).map_err(|e| format!("advance generation: {e:?}"))?
    } else {
        let bootstrap = NodeAgent::bootstrap().map_err(|e| format!("bootstrap: {e:?}"))?;
        NodeAgent::restart(bootstrap.restart_seed())
            .map_err(|e| format!("first generation: {e:?}"))?
    };
    let serialized = serde_json::to_string(&agent.restart_seed()).map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO identity_seed(slot,seed) VALUES(1,?1)
        ON CONFLICT(slot) DO UPDATE SET seed=excluded.seed",
        params![serialized],
    )
    .map_err(|e| format!("seed commit: {e}"))?;
    tx.commit()
        .map_err(|e| format!("seed durable commit: {e}"))?;
    Ok(agent)
}
fn provider(agent: &NodeAgent) -> Result<NativeProcessProvider, String> {
    let revision_ref = entity("runtime.provider_revision")?;
    let revision = ProviderRevision {
        revision_ref: revision_ref.clone(),
        provider_ref: entity("runtime.provider")?,
        provider_kind: ProviderKind::Process,
        implementation_name: "native-process".into(),
        implementation_version: "0.1.0".into(),
        build_or_package_digest: "sha256:e07-ptah-native-process".into(),
        configuration_digest: "sha256:e07-caller-local-process-profile".into(),
        supported_facility_refs: vec![entity("runtime.facility")?],
        capability_claim_refs: vec![],
        dependency_refs: vec![],
        node_requirements: vec![],
        security_requirements: vec![],
        known_limitations: vec![],
    };
    let instance = ProviderInstance {
        instance_ref: entity("runtime.provider_instance")?,
        provider_revision_ref: revision_ref,
        node_ref: agent
            .node_id()
            .entity_ref(agent.generation(), agent.connection_epoch()),
        node_generation: agent.generation().value(),
        provider_generation: ProviderGeneration::new(1).map_err(|e| format!("{e:?}"))?,
        connection_epoch: agent.connection_epoch().value(),
        reachability: ProviderReachability::Reachable,
        readiness: ProviderReadiness::Ready,
        health: ProviderHealth::Healthy,
        endpoint_aliases: vec![],
        process_or_service_refs: vec![],
        observation_refs: vec![entity("proof.evidence")?],
        started_at: "2026-10-20T00:00:00Z".into(),
        limitations: vec![],
    };
    NativeProcessProvider::new(NativeProcessProviderConfig {
        revision,
        instance,
        clock: Arc::new(|| "2026-10-20T00:00:00Z".into()),
    })
    .map_err(|e| format!("native process provider: {e:?}"))
}

async fn run(config: WorkerConfig) -> Result<(), String> {
    let agent = durable_node(&config.node_seed)?;
    let key = fs::read(&config.node_key_pem).map_err(|e| e.to_string())?;
    let cert = fs::read(&config.node_cert_pem).map_err(|e| e.to_string())?;
    let ca = fs::read(&config.ca_pem).map_err(|e| e.to_string())?;
    let tls = TlsClientConfig::new(
        TlsIdentity::from_pem(&cert, &key).map_err(|e| format!("{e:?}"))?,
        TlsTrustRoots::from_pem(&ca).map_err(|e| format!("{e:?}"))?,
    )
    .map_err(|e| format!("{e:?}"))?;
    let connection = NodeLinkClientConfig::new(
        config.control,
        config.server_name,
        tls,
        config.enrollment_ref,
        "e07-native-worker-v1".into(),
        ProtocolVersion { major: 1, minor: 0 },
    );
    let (_, mut stream) = tokio::time::timeout(
        Duration::from_secs(10),
        connect_node_link(&agent, &connection),
    )
    .await
    .map_err(|_| "remote E01 timeout".to_string())?
    .map_err(|e| format!("remote E01: {e:?}"))?;
    let (guard, dispatch) = receive_one(&agent, &mut stream)
        .await
        .map_err(|e| format!("remote E02: {e:?}"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let digest = config.request_sha256;
    if digest.len() != 71
        || !digest.starts_with("sha256:")
        || !digest[7..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("invalid configured request digest".into());
    }
    let provider = provider(&agent)?;
    let expected = provider
        .attempt_context(1, entity("runtime.facility")?)
        .map_err(|e| format!("provider context: {e:?}"))?;
    let mut journal = GatewayJournal::open(&config.node_journal)
        .map_err(|e| format!("durable Node journal: {e:?}"))?;
    let spec = ProcessSpec {
        program: config.program,
        args: config.args,
        env: BTreeMap::new(),
        clear_env: false,
        cwd: None,
        mode: ProcessMode::Pipes,
        max_stream_bytes: 16384,
        disconnect_policy: DisconnectPolicy::Retain,
    };
    let pid = journal
        .spawn_once(
            &agent, &guard, &dispatch, now, &digest, &provider, &expected, spec,
        )
        .map_err(|e| format!("A05 native process: {e:?}"))?;
    let _ = provider
        .wait_for_exit(pid, Duration::from_secs(30))
        .map_err(|e| format!("A05 exit: {e:?}"))?;
    let output_digest = journal
        .complete_from_process(&agent, &dispatch, &digest, &provider, pid)
        .map_err(|e| format!("A05 durable exit: {e:?}"))?;
    let record = journal
        .get(&dispatch)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("missing durable completion")?;
    // This acknowledgement is liveness-only. The durable Node record is
    // independent completion evidence; Control does not infer effect proof.
    write_frame(
        stream.stream_mut(),
        &LinkMessage::Ack(LinkAck { message_id: 1 }),
    )
    .await
    .map_err(|e| format!("A05 completion acknowledgment: {e:?}"))?;
    println!(
        "{}",
        serde_json::json!({
            "event":"ptah.native_e07.a05_completed",
            "node_id":agent.node_id(),
            "generation":agent.generation(),
            "epoch":agent.connection_epoch(),
            "dispatch":dispatch.dispatch_ref,
            "attempt":dispatch.attempt_ref,
            "phase":record.phase,"exit_code":record.exit_code,
            "stdout_sha256":output_digest,"remote_tls_e02":true,
            "additional_ptah_user_approval":false
        })
    );
    Ok(())
}
/// Keep caller-selected Ptah Node capability alive across disconnected Control
/// sessions. Normal workspace tools do not depend on this optional service.
async fn serve_config(config_path: &Path) -> Result<(), String> {
    let mut consecutive_failures: u32 = 0;
    println!(
        "{}",
        serde_json::json!({
            "event": "ptah.native_e07.node_worker_started",
            "persistent": true,
            "task_selection_by_ptah": false,
            "second_ptah_user_approval": false
        })
    );
    loop {
        let outcome = fs::read(config_path)
            .map_err(|e| format!("read worker config: {e}"))
            .and_then(|raw| {
                serde_json::from_slice::<WorkerConfig>(&raw)
                    .map_err(|e| format!("invalid worker config: {e}"))
            });
        let result = match outcome {
            Ok(config) => run(config).await,
            Err(error) => Err(error),
        };
        let delay = match result {
            Ok(()) => {
                consecutive_failures = 0;
                Duration::from_secs(4)
            }
            Err(error) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                eprintln!("ptah-e07-node-worker: capability error: {error}");
                Duration::from_secs(
                    (8_u64)
                        .saturating_mul(1_u64 << consecutive_failures.min(4))
                        .min(120),
                )
            }
        };
        tokio::time::sleep(delay).await;
    }
}
#[tokio::main]
async fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() == 3 && args[1] == "--init" {
        match durable_node(Path::new(&args[2])) {
            Ok(agent) => {
                println!(
                    "{}",
                    serde_json::json!({
                        "node_id":agent.node_id(),
                        "enrollment_ref":EntityRef::new("core.node_enrollment").unwrap(),
                        "node_generation":agent.generation(),
                        "node_seed":args[2]
                    })
                );
                return;
            }
            Err(error) => {
                eprintln!("ptah-e07-node-worker init: {error}");
                std::process::exit(2);
            }
        }
    }
    if args.len() == 3 && args[1] == "--serve-config" {
        if let Err(error) = serve_config(Path::new(&args[2])).await {
            eprintln!("ptah-e07-node-worker service: {error}");
            std::process::exit(2);
        }
        return;
    }
    let result = if args.len() == 3 && args[1] == "--config" {
        fs::read(&args[2])
            .map_err(|e| e.to_string())
            .and_then(|raw| serde_json::from_slice::<WorkerConfig>(&raw).map_err(|e| e.to_string()))
    } else {
        Err("usage: ptah-e07-node-worker --config <caller-owned.json> | --serve-config <caller-owned.json> | --init <seed.sqlite3>".into())
    };
    let outcome = match result {
        Ok(config) => run(config).await,
        Err(error) => Err(error),
    };
    if let Err(error) = outcome {
        eprintln!("ptah-e07-node-worker: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persistent_node_identity_advances_before_every_new_connection() {
        let file = std::env::temp_dir().join(format!(
            "ptah-e07-node-seed-{}.sqlite3",
            ptah_identifiers::EntityId::new_v7()
        ));
        let first = durable_node(&file).expect("bootstrap durable seed");
        let second = durable_node(&file).expect("new connection advances generation");
        let third = durable_node(&file).expect("subsequent reconnect advances again");
        assert_eq!(first.node_id(), second.node_id());
        assert_eq!(second.node_id(), third.node_id());
        assert_eq!(second.generation(), first.generation().next().unwrap());
        assert_eq!(third.generation(), second.generation().next().unwrap());
        assert_eq!(
            second.connection_epoch(),
            first.connection_epoch().next().unwrap()
        );
        let db = rusqlite::Connection::open(&file).unwrap();
        let integrity: String = db
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        drop(db);
        let _ = fs::remove_file(&file);
    }
    #[test]
    fn invalid_existing_seed_never_creates_new_identity() {
        let file = std::env::temp_dir().join(format!(
            "ptah-e07-corrupt-seed-{}.sqlite3",
            ptah_identifiers::EntityId::new_v7()
        ));
        fs::write(&file, b"not-a-sqlite-database").unwrap();
        assert!(durable_node(&file).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"not-a-sqlite-database");
        let _ = fs::remove_file(&file);
    }
}
