//! Optional native E07 Control single-dispatch gateway.
//! Read-only authenticated enrollment only. No dispatch or authority minting.
//! Must be provisioned with deployment-owned certificates and canonical
//! approved enrollment projections. Cannot start without them.
#![forbid(unsafe_code)]

use ptah_control::gateway_control_journal::ControlDispatchJournal;
use ptah_control::gateway_session::establish;
use ptah_control::node_link::DispatchAuthorityFrames;
use ptah_control::node_link::NodeLinkControl;
use ptah_control::placement::PlacementAuthorityOwner;
use ptah_identifiers::{EntityRef, NodeId};
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, DispatchLeaseFrame, DispatchRequestFrame,
    DispatchReservationFrame, EnrollmentLifecycle, LinkMessage, ProtocolVersion, TlsIdentity,
    TlsServerConfig, TlsTrustRoots, read_frame,
    roaming::{self, RelayRole},
    write_frame,
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
use tokio::{net::TcpListener, sync::Mutex};

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
    listen: Option<SocketAddr>,
    relay: Option<(SocketAddr, String)>,
    server_cert: PathBuf,
    server_key: PathBuf,
    client_ca: PathBuf,
    enrollment_path: PathBuf,
    journal_path: PathBuf,
    request_digest: String,
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
            "--journal",
            "--request-digest",
            "--relay",
            "--relay-route",
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
    let relay = match (entries.remove("--relay"), entries.remove("--relay-route")) {
        (Some(endpoint), Some(route)) => {
            let addr: SocketAddr = endpoint.parse().map_err(|_| "invalid relay address")?;
            if !roaming::valid_route_id(&route) {
                return Err("invalid relay route".into());
            }
            Some((addr, route))
        }
        (None, None) => None,
        _ => return Err("relay and relay-route must be supplied together".into()),
    };
    let listen = match (entries.remove("--listen"), relay.as_ref()) {
        (Some(ip), None) => {
            let bind: SocketAddr = ip.parse().map_err(|_| "invalid bind address")?;
            if !allowed_bind(bind.ip(), allow_private) {
                return Err("listen must be loopback or explicitly allowed private LAN".into());
            }
            Some(bind)
        }
        (None, Some(_)) => None,
        _ => return Err("select exactly one: --listen or --relay and --relay-route".into()),
    };
    let mut val = |key: &str| {
        entries
            .remove(key)
            .ok_or_else(|| format!("missing required {key}"))
    };
    let config = Config {
        listen,
        relay,
        server_cert: PathBuf::from(val("--server-cert")?),
        server_key: PathBuf::from(val("--server-key")?),
        client_ca: PathBuf::from(val("--client-ca")?),
        enrollment_path: PathBuf::from(val("--enrollments")?),
        journal_path: PathBuf::from(val("--journal")?),
        request_digest: val("--request-digest")?,
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
/// Caller-selected single dispatch. No autonomous retries, access decisions
/// or remote executable selection. The Node binds its own local A05 profile.
// The single-dispatch path is deliberately linear: TLS establishment,
// durable stage, wire send, advisory acknowledgement. No implicit retry.
#[allow(clippy::too_many_lines)]
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
    // Both route types produce one unmodified TCP byte stream for the
    // existing E01 mutual TLS server. No relay identity or grant is trusted.
    let socket = if let Some((address, route)) = config.relay.as_ref() {
        roaming::connect(*address, RelayRole::Control, route)
            .await
            .map_err(|e| format!("outbound roaming relay: {e}"))?
    } else {
        let listener = TcpListener::bind(config.listen.ok_or("missing listener")?)
            .await
            .map_err(|e| e.to_string())?;
        eprintln!(
            "ptah-e07-control-dispatch: listening on {}",
            listener.local_addr().map_err(|e| e.to_string())?
        );
        // Node worker normally retries within 120 seconds.
        tokio::time::timeout(Duration::from_mins(4), listener.accept())
            .await
            .map_err(|_| "waiting for Node timed out")?
            .map_err(|e| e.to_string())?
            .0
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let (binding, mut stream) = establish(socket, &tls, &owner, now)
        .await
        .map_err(|e| format!("E01 handshake: {e:?}"))?;
    // The peer identity and epoch are taken exclusively from the authenticated
    // current session. Fresh dispatch references are Control-created.
    let mut journal = ControlDispatchJournal::open(&config.journal_path)
        .map_err(|e| format!("Control journal: {e:?}"))?;
    let next_fence = journal
        .unresolved()
        .map_err(|e| format!("{e:?}"))?
        .iter()
        .map(|r| r.fence)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or("fence overflow")?;
    if !owner.lock().await.is_current_session(&binding) {
        return Err("stale E01 session".into());
    }
    let attempt = EntityRef::new("activity.attempt").map_err(|e| format!("{e:?}"))?;
    let reservation = EntityRef::new("resource.reservation").map_err(|e| format!("{e:?}"))?;
    let lease = EntityRef::new("isolation.lease").map_err(|e| format!("{e:?}"))?;
    let frame = DispatchAuthorityFrames {
        reservation: DispatchReservationFrame {
            reservation_ref: reservation.clone(),
            attempt_ref: attempt.clone(),
            node_id: binding.node_id,
            node_generation: binding.node_generation,
            connection_epoch: binding.connection_epoch,
            expires_at_unix_seconds: now + 90,
        },
        lease: DispatchLeaseFrame {
            lease_ref: lease.clone(),
            reservation_ref: reservation.clone(),
            attempt_ref: attempt.clone(),
            node_id: binding.node_id,
            node_generation: binding.node_generation,
            connection_epoch: binding.connection_epoch,
            fence: next_fence,
            expires_at_unix_seconds: now + 75,
        },
        request: DispatchRequestFrame {
            dispatch_ref: EntityRef::new("runtime.dispatch").map_err(|e| format!("{e:?}"))?,
            operation_ref: EntityRef::new("activity.operation").map_err(|e| format!("{e:?}"))?,
            attempt_ref: attempt,
            reservation_ref: reservation,
            lease_ref: lease,
            node_id: binding.node_id,
            node_generation: binding.node_generation,
            connection_epoch: binding.connection_epoch,
            fence: next_fence,
        },
    };
    journal
        .stage_issued(&frame, &config.request_digest)
        .map_err(|e| format!("durable dispatch: {e:?}"))?;
    for msg in [
        LinkMessage::DispatchReservation(Box::new(frame.reservation.clone())),
        LinkMessage::DispatchLease(Box::new(frame.lease.clone())),
        LinkMessage::DispatchRequest(Box::new(frame.request.clone())),
    ] {
        tokio::time::timeout(
            Duration::from_secs(5),
            write_frame(stream.stream_mut(), &msg),
        )
        .await
        .map_err(|_| "E02 transport timeout")?
        .map_err(|e| format!("E02 transport: {e:?}"))?;
    }
    journal
        .mark_sent(&frame)
        .map_err(|e| format!("dispatch sent: {e:?}"))?;
    let ack = tokio::time::timeout(Duration::from_secs(45), read_frame(stream.stream_mut()))
        .await
        .map_err(|_| "Node completion acknowledgement timeout")?
        .map_err(|e| format!("Node response: {e:?}"))?;
    if !matches!(ack,LinkMessage::Ack(ref ack) if ack.message_id==1) {
        return Err("Node did not acknowledge observed local completion".into());
    }
    // An Ack is never signed independent A05 effect proof. The Node's durable
    // journal is the source of real local process completion evidence.
    println!(
        "{}",
        serde_json::json!({
            "result":"e07_e02_frames_sent_node_a05_completion_acknowledged",
            "node":binding.node_id,"fence":next_fence,
            "attempt":frame.request.attempt_ref,
            "dispatch":frame.request.dispatch_ref,
            "control_journal_phase":"sent_unconfirmed",
            "independent_effect_witness":false,
            "second_ptah_user_approval":false
        })
    );
    owner.lock().await.end_session_if_current(&binding);
    Ok(())
}
#[tokio::main]
async fn main() {
    let result = match config_from_args() {
        Ok(config) => serve(config).await,
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        eprintln!("ptah-e07-control-dispatch: {error}");
        std::process::exit(2);
    }
}
