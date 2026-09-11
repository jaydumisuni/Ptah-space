//! E03 node-level direct interruption/resume proof over the real TLS 1.3 data plane.

use ptah_identifiers::EntityRef;
use ptah_node_link::{
    CredentialFingerprint, TlsClientConfig, TlsIdentity, TlsServerConfig, TlsTrustRoots, accept_tls,
    connect_tls,
};
use ptah_node_transfer::{DirectSourceSession, DirectTargetSession, ExactRangeSource, MAX_RANGE_BYTES};
use ptah_transfer::{
    DownloadCursor, TransferPeerBinding, TransferRouteCandidate, TransferRouteKind, TransferTicket,
};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream};

const CA_CERT: &[u8] = include_bytes!("../../../crates/ptah-node-link/tests/fixtures/ca.cert.der");
const SERVER_CERT: &[u8] = include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.cert.der");
const SERVER_KEY: &[u8] = include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.key.der");
const CLIENT_CERT: &[u8] = include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.cert.der");
const CLIENT_KEY: &[u8] = include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.key.der");

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("reference")
}

fn roots() -> TlsTrustRoots {
    TlsTrustRoots::from_der(vec![CA_CERT.to_vec()]).expect("roots")
}

fn server_config() -> TlsServerConfig {
    TlsServerConfig::new(
        TlsIdentity::from_der(vec![SERVER_CERT.to_vec()], SERVER_KEY.to_vec()).expect("server id"),
        roots(),
    )
    .expect("server tls")
}

fn client_config() -> TlsClientConfig {
    TlsClientConfig::new(
        TlsIdentity::from_der(vec![CLIENT_CERT.to_vec()], CLIENT_KEY.to_vec()).expect("client id"),
        roots(),
    )
    .expect("client tls")
}

fn binding(fingerprint: CredentialFingerprint) -> TransferPeerBinding {
    use ptah_identifiers::{ConnectionEpoch, NodeGeneration, NodeId};
    TransferPeerBinding {
        node_id: NodeId::new(),
        node_generation: NodeGeneration::INITIAL,
        connection_epoch: ConnectionEpoch::INITIAL,
        credential_fingerprint: *fingerprint.as_bytes(),
    }
}

fn ticket(bytes: &[u8]) -> TransferTicket {
    let source_fp = CredentialFingerprint::from_der(SERVER_CERT);
    let target_fp = CredentialFingerprint::from_der(CLIENT_CERT);
    TransferTicket::new(
        reference("transfer.ticket"),
        reference("transfer.request"),
        reference("transfer.run"),
        reference("activity.attempt"),
        binding(source_fp),
        binding(target_fp),
        Some(reference("storage.content")),
        None,
        bytes.len() as u64,
        format!("{:x}", Sha256::digest(bytes)),
        MAX_RANGE_BYTES as u64,
        vec![TransferRouteCandidate {
            kind: TransferRouteKind::Direct,
            endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7443),
            server_name: String::from("localhost"),
            expected_peer_fingerprint: *source_fp.as_bytes(),
            relay_ref: None,
        }],
        1,
        100,
        1,
    )
    .expect("ticket")
}

struct BytesSource {
    bytes: Vec<u8>,
    sha256: String,
}

impl ExactRangeSource for BytesSource {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn canonical_sha256(&self) -> &str {
        &self.sha256
    }

    fn read_exact_range(&mut self, start: u64, len: u64) -> Result<Vec<u8>, String> {
        let start = usize::try_from(start).map_err(|_| String::from("start"))?;
        let len = usize::try_from(len).map_err(|_| String::from("len"))?;
        let end = start.checked_add(len).ok_or_else(|| String::from("overflow"))?;
        self.bytes
            .get(start..end)
            .map(ToOwned::to_owned)
            .ok_or_else(|| String::from("range"))
    }
}

async fn transfer_pass(
    bytes: Vec<u8>,
    ticket: &TransferTicket,
    partial_path: &std::path::Path,
    cursor: &mut DownloadCursor,
    stop_after_ranges: usize,
) -> ptah_node_transfer::DirectTransferReport {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let server_ticket = ticket.clone();
    let source_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = accept_tls(tcp, &server_config()).await.expect("server tls");
        let peer_fingerprint = tls.peer_fingerprint();
        let mut source = BytesSource {
            bytes,
            sha256: source_sha256,
        };
        DirectSourceSession::serve(
            tls.stream_mut(),
            &server_ticket,
            peer_fingerprint,
            &mut source,
            1,
            Some(stop_after_ranges),
        )
        .await
        .expect("serve pass");
    });

    let tcp = TcpStream::connect(address).await.expect("connect");
    let mut tls = connect_tls(tcp, "localhost", &client_config())
        .await
        .expect("client tls");
    let peer_fingerprint = tls.peer_fingerprint();
    let report = DirectTargetSession::pull_missing_ranges(
        tls.stream_mut(),
        ticket,
        peer_fingerprint,
        partial_path,
        cursor,
        1,
        Some(stop_after_ranges),
    )
    .await
    .expect("pull pass");
    server.await.expect("server join");
    report
}

#[tokio::test]
async fn direct_transfer_resumes_only_missing_ranges_after_interruption() {
    let bytes: Vec<u8> = (0..(5 * MAX_RANGE_BYTES + 123))
        .map(|index| (index % 251) as u8)
        .collect();
    let source_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let ticket = ticket(&bytes);
    let destination = std::env::temp_dir().join(format!(
        "ptah-e03-node-direct-resume-{}.part",
        ticket.ticket_ref().entity_id
    ));
    let _ = std::fs::remove_file(&destination);
    let mut cursor = DownloadCursor::default();

    let first = transfer_pass(bytes.clone(), &ticket, &destination, &mut cursor, 2).await;
    assert_eq!(first.network_bytes, (2 * MAX_RANGE_BYTES) as u64);

    let second = transfer_pass(bytes.clone(), &ticket, &destination, &mut cursor, 4).await;
    assert_eq!(second.resumed_ranges, 2);
    assert_eq!(second.network_bytes, bytes.len() as u64 - first.network_bytes);
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(std::fs::read(&destination).expect("read destination"))
        ),
        source_sha256
    );
    assert!(bytes.len() > ptah_node_link::MAX_FRAME_BYTES);

    let _ = std::fs::remove_file(destination);
}
