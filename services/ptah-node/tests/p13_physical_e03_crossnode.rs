//! Explicit opt-in, two-host E03 physical qualification.
//! This is a temporary test harness around *native* E01/E03, not a new
//! transport/protocol. All keys are the repository's TEST fixture PKI.
//! It does NOT certify production E01 enrollment or independent witness.
use ptah_control::{
    node_link::NodeLinkControl,
    transfer::{TransferAuthorityOwner, TransferTicketSpec},
};
use ptah_identifiers::EntityRef;
use ptah_node_agent::NodeAgent;
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle, NodeHello, ProtocolVersion,
    TlsClientConfig, TlsIdentity, TlsServerConfig, TlsTrustRoots, accept_tls, connect_tls,
};
use ptah_node_transfer::{DirectSourceSession, DirectTargetSession, ExactRangeSource};
use ptah_transfer::{DownloadCursor, TransferRouteCandidate, TransferRouteKind, TransferTicket};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{Read, Seek, SeekFrom},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::{TcpListener, TcpStream};

const CA: &[u8] = include_bytes!("../../../crates/ptah-node-link/tests/fixtures/ca.cert.der");
const SERVER: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.cert.der");
const SERVER_KEY: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.key.der");
const CLIENT: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.cert.der");
const CLIENT_KEY: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.key.der");
const CANDIDATE: &[u8] = b"9\n";
const PORT: u16 = 48956;

#[derive(Serialize, Deserialize)]
struct Plan {
    ticket: TransferTicket,
    candidate: Vec<u8>,
    source_host: String,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn entity(value: &str) -> EntityRef {
    EntityRef::new(value).unwrap()
}
fn fingerprint(cert: &[u8]) -> CredentialFingerprint {
    CredentialFingerprint::from_der(cert)
}
fn enrollment(agent: &NodeAgent, cert: &[u8]) -> ApprovedNodeEnrollment {
    ApprovedNodeEnrollment::new(
        entity("core.node_enrollment"),
        agent.node_id(),
        EnrollmentLifecycle::Approved,
        vec!["node.connect".into()],
        vec![fingerprint(cert)],
        None,
    )
    .unwrap()
}
fn hello(agent: &NodeAgent, enrollment_ref: EntityRef) -> NodeHello {
    NodeHello {
        supported_major: 1,
        minimum_minor: 0,
        maximum_minor: 0,
        node_id: agent.node_id(),
        node_generation: agent.generation(),
        connection_epoch: agent.connection_epoch(),
        enrollment_ref,
        agent_revision: "p13-physical-fixture-crosshost".into(),
        capability_snapshot_ref: None,
    }
}
fn plan_file() -> PathBuf {
    PathBuf::from(env::var("P13_PLAN").expect("P13_PLAN required"))
}
fn proof_file() -> PathBuf {
    PathBuf::from(env::var("P13_EVIDENCE").expect("P13_EVIDENCE required"))
}
fn server_config() -> TlsServerConfig {
    TlsServerConfig::new(
        TlsIdentity::from_der(vec![SERVER.to_vec()], SERVER_KEY.to_vec()).unwrap(),
        TlsTrustRoots::from_der(vec![CA.to_vec()]).unwrap(),
    )
    .unwrap()
}
fn client_config() -> TlsClientConfig {
    TlsClientConfig::new(
        TlsIdentity::from_der(vec![CLIENT.to_vec()], CLIENT_KEY.to_vec()).unwrap(),
        TlsTrustRoots::from_der(vec![CA.to_vec()]).unwrap(),
    )
    .unwrap()
}
struct Source {
    file: fs::File,
    sha: String,
    len: u64,
}
impl Source {
    fn open(bytes: &[u8], path: &Path) -> Self {
        assert_eq!(
            fs::read(path).unwrap(),
            bytes,
            "source candidate unexpectedly changed"
        );
        let mut file = fs::File::open(path).unwrap();
        let len = file.metadata().unwrap().len();
        let sha = format!("{:x}", Sha256::digest(bytes));
        file.seek(SeekFrom::Start(0)).unwrap();
        Self { file, sha, len }
    }
}
impl ExactRangeSource for Source {
    fn len(&self) -> u64 {
        self.len
    }
    fn canonical_sha256(&self) -> &str {
        &self.sha
    }
    fn read_exact_range(&mut self, start: u64, len: u64) -> Result<Vec<u8>, String> {
        let end = start.checked_add(len).ok_or("range overflow")?;
        if end > self.len || len > ptah_node_transfer::MAX_RANGE_BYTES as u64 {
            return Err("range not in ticket".into());
        }
        self.file
            .seek(SeekFrom::Start(start))
            .map_err(|e| e.to_string())?;
        let mut bytes = vec![0; usize::try_from(len).map_err(|e| e.to_string())?];
        self.file
            .read_exact(&mut bytes)
            .map_err(|e| e.to_string())?;
        Ok(bytes)
    }
}
fn setup() {
    let source = NodeAgent::bootstrap().unwrap();
    let target = NodeAgent::bootstrap().unwrap();
    let s = enrollment(&source, SERVER);
    let t = enrollment(&target, CLIENT);
    let sid = s.enrollment_ref().clone();
    let tid = t.enrollment_ref().clone();
    let mut control = TransferAuthorityOwner::new(NodeLinkControl::new(
        ProtocolVersion { major: 1, minor: 0 },
        vec![s, t],
    ));
    let time = now();
    control
        .accept_hello(&hello(&source, sid), fingerprint(SERVER), time)
        .unwrap();
    control
        .accept_hello(&hello(&target, tid), fingerprint(CLIENT), time)
        .unwrap();
    let source_host = env::var("P13_SOURCE_HOST").expect("source LAN hostname required");
    let ticket = control
        .issue_ticket(
            TransferTicketSpec {
                request_ref: entity("transfer.request"),
                run_ref: entity("transfer.run"),
                attempt_ref: entity("activity.attempt"),
                source_node_id: source.node_id(),
                target_node_id: target.node_id(),
                content_ref: Some(entity("storage.content")),
                artifact_ref: None,
                expected_size: CANDIDATE.len() as u64,
                canonical_sha256: format!("{:x}", Sha256::digest(CANDIDATE)),
                range_size: 1,
                routes: vec![TransferRouteCandidate {
                    kind: TransferRouteKind::Direct,
                    endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), PORT),
                    server_name: "localhost".into(),
                    expected_peer_fingerprint: *fingerprint(SERVER).as_bytes(),
                    relay_ref: None,
                }],
                expires_at_unix_seconds: time + 1200,
            },
            time,
        )
        .unwrap();
    control.assert_current(&ticket).unwrap();
    let plan = Plan {
        ticket,
        candidate: CANDIDATE.to_vec(),
        source_host,
    };
    // Fixture PKI and E01 agents are constructed strictly inside this test.
    fs::write(plan_file(), serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
    println!("PHYSICAL_P13_PLAN_PREPARED");
}
async fn serve() {
    let plan: Plan = serde_json::from_slice(&fs::read(plan_file()).unwrap()).unwrap();
    assert_eq!(plan.candidate, CANDIDATE);
    let source = proof_file().with_extension("source");
    fs::write(&source, CANDIDATE).unwrap();
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), PORT);
    let listener = TcpListener::bind(socket).await.unwrap();
    println!("PHYSICAL_P13_E03_SOURCE_LISTENING {PORT}");
    for pass in [1, 2] {
        let (tcp, addr) =
            tokio::time::timeout(std::time::Duration::from_secs(110), listener.accept())
                .await
                .unwrap()
                .unwrap();
        println!("PHYSICAL_P13_SOURCE_ACCEPTED {addr}");
        let mut tls = accept_tls(tcp, &server_config()).await.unwrap();
        assert!(tls.is_tls13());
        assert_eq!(tls.peer_fingerprint(), fingerprint(CLIENT));
        let fp = tls.peer_fingerprint();
        let mut source_handle = Source::open(&plan.candidate, &source);
        DirectSourceSession::serve(
            tls.stream_mut(),
            &plan.ticket,
            fp,
            &mut source_handle,
            1,
            Some(pass),
        )
        .await
        .unwrap();
    }
    let evidence = serde_json::json!({"role":"source","passes":2,
        "size":CANDIDATE.len(),
        "sha256":format!("{:x}",Sha256::digest(CANDIDATE)),
        "data":"native Ptah E03 TLS 1.3; TEST fixture PKI"});
    fs::write(proof_file(), serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    println!("PHYSICAL_P13_E03_SOURCE_COMPLETED");
}
async fn target() {
    let plan: Plan = serde_json::from_slice(&fs::read(plan_file()).unwrap()).unwrap();
    let partial = proof_file().with_extension("candidate");
    let mut cursor = DownloadCursor::default();
    let mut observations = vec![];
    for (pass, limit) in [(1, 1), (2, 2)] {
        let addr = format!("{}:{}", plan.source_host, PORT);
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = connect_tls(tcp, "localhost", &client_config())
            .await
            .unwrap();
        assert!(tls.is_tls13());
        assert_eq!(tls.peer_fingerprint(), fingerprint(SERVER));
        let fp = tls.peer_fingerprint();
        let report = DirectTargetSession::pull_missing_ranges(
            tls.stream_mut(),
            &plan.ticket,
            fp,
            &partial,
            &mut cursor,
            1,
            Some(limit),
        )
        .await
        .unwrap();
        observations.push((
            pass,
            report.network_bytes,
            report.resumed_ranges,
            report.whole_sha256,
        ));
    }
    assert_eq!(observations[0].1, 1);
    assert_eq!(observations[1].1, 1);
    assert_eq!(observations[1].2, 1);
    assert_eq!(
        observations[1].3.as_deref(),
        Some(plan.ticket.canonical_sha256())
    );
    let returned = fs::read(&partial).unwrap();
    assert_eq!(returned, plan.candidate);
    let evidence = serde_json::json!({
        "role":"target","host":env::var("COMPUTERNAME").unwrap_or_default(),
        "size":returned.len(),"sha256":format!("{:x}",Sha256::digest(&returned)),
        "passes":observations.iter().map(|(pass,net,resumed,sha)|serde_json::json!({
            "pass":pass,"network_bytes":net,"resumed_ranges":resumed,"whole_sha256":sha
        })).collect::<Vec<_>>(),
        "test_fixture_pki":true,"native_e03":true,
        "mathematical_authority":false
    });
    fs::write(proof_file(), serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    println!("PHYSICAL_P13_E03_TARGET_PASS {}", evidence["sha256"]);
}
#[tokio::test]
async fn p13_physical_e03_native() {
    let Ok(role) = env::var("P13_ROLE") else {
        return;
    };
    match role.as_str() {
        "prepare" => setup(),
        "source" => serve().await,
        "target" => target().await,
        _ => panic!("unsupported explicit P13 role"),
    }
}
