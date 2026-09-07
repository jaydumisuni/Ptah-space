//! E03 direct transport over the existing E01 TLS 1.3 PKI.

use ptah_identifiers::EntityRef;
use ptah_node_link::{
    CredentialFingerprint, TlsClientConfig, TlsIdentity, TlsServerConfig, TlsTrustRoots, accept_tls,
    connect_tls,
};
use ptah_node_transfer::{DirectSourceSession, DirectTargetSession, ExactRangeSource};
use ptah_transfer::{
    DownloadCursor, TransferPeerBinding, TransferRouteCandidate, TransferRouteKind, TransferTicket,
};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream};

const CA_CERT: &[u8] = include_bytes!("../../ptah-node-link/tests/fixtures/ca.cert.der");
const SERVER_CERT: &[u8] = include_bytes!("../../ptah-node-link/tests/fixtures/server.cert.der");
const SERVER_KEY: &[u8] = include_bytes!("../../ptah-node-link/tests/fixtures/server.key.der");
const CLIENT_CERT: &[u8] = include_bytes!("../../ptah-node-link/tests/fixtures/client.cert.der");
const CLIENT_KEY: &[u8] = include_bytes!("../../ptah-node-link/tests/fixtures/client.key.der");

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

fn binding(fingerprint: CredentialFingerprint, seed: u8) -> TransferPeerBinding {
    use ptah_identifiers::{ConnectionEpoch, NodeGeneration, NodeId};
    let _ = seed;
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
        binding(source_fp, 1),
        binding(target_fp, 2),
        Some(reference("storage.content")),
        None,
        bytes.len() as u64,
        format!("{:x}", Sha256::digest(bytes)),
        1024,
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

#[tokio::test]
async fn direct_session_uses_existing_tls13_and_ticket_bound_peer_fingerprints() {
    let bytes = b"authenticated direct e03 payload".to_vec();
    let ticket = ticket(&bytes);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let server_ticket = ticket.clone();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = accept_tls(tcp, &server_config()).await.expect("server tls");
        assert!(tls.is_tls13());
        assert_eq!(tls.peer_fingerprint(), CredentialFingerprint::from_der(CLIENT_CERT));
        let mut source = BytesSource {
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            bytes,
        };
        DirectSourceSession::serve(
            tls.stream_mut(),
            &server_ticket,
            tls.peer_fingerprint(),
            &mut source,
            2,
            Some(0),
        )
        .await
        .expect("serve")
    });

    let tcp = TcpStream::connect(address).await.expect("connect");
    let mut tls = connect_tls(tcp, "localhost", &client_config())
        .await
        .expect("client tls");
    assert!(tls.is_tls13());
    assert_eq!(tls.peer_fingerprint(), CredentialFingerprint::from_der(SERVER_CERT));
    let temp = std::env::temp_dir().join(format!("ptah-e03-direct-{}.part", ticket.ticket_ref().entity_id));
    let mut cursor = DownloadCursor::default();
    let report = DirectTargetSession::pull_missing_ranges(
        tls.stream_mut(),
        &ticket,
        tls.peer_fingerprint(),
        &temp,
        &mut cursor,
        2,
        Some(0),
    )
    .await
    .expect("pull handshake");
    assert_eq!(report.network_bytes, 0);
    assert_eq!(report.requested_ranges, 0);
    server.await.expect("server join");
    let _ = std::fs::remove_file(temp);
}
