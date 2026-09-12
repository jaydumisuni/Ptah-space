//! E03 node-level direct-failure to explicit relay continuation proof.

use ptah_identifiers::EntityRef;
use ptah_node_link::{
    CredentialFingerprint, TlsClientConfig, TlsIdentity, TlsServerConfig, TlsTrustRoots,
    accept_tls, connect_tls,
};
use ptah_node_transfer::{
    DirectSourceSession, DirectTargetSession, ExactRangeSource, MAX_RANGE_BYTES, RangeDataHeader,
    RangeRequest, RelayBroker, RouteFailure,
};
use ptah_transfer::{
    DownloadCursor, TransferPeerBinding, TransferRouteCandidate, TransferRouteKind, TransferTicket,
    VerifiedRange,
};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tokio::net::{TcpListener, TcpStream};

const CA_CERT: &[u8] = include_bytes!("../../../crates/ptah-node-link/tests/fixtures/ca.cert.der");
const SERVER_CERT: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.cert.der");
const SERVER_KEY: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.key.der");
const CLIENT_CERT: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.cert.der");
const CLIENT_KEY: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.key.der");
const RELAY_FINGERPRINT: [u8; 32] = [0x33; 32];

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

fn ticket(bytes: &[u8]) -> (TransferTicket, TransferRouteCandidate) {
    let source_fp = CredentialFingerprint::from_der(SERVER_CERT);
    let target_fp = CredentialFingerprint::from_der(CLIENT_CERT);
    let relay = TransferRouteCandidate {
        kind: TransferRouteKind::Relay,
        endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9443),
        server_name: String::from("relay.localhost"),
        expected_peer_fingerprint: RELAY_FINGERPRINT,
        relay_ref: Some(reference("relay.authorized")),
    };
    let ticket = TransferTicket::new(
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
        vec![
            TransferRouteCandidate {
                kind: TransferRouteKind::Direct,
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7443),
                server_name: String::from("localhost"),
                expected_peer_fingerprint: *source_fp.as_bytes(),
                relay_ref: None,
            },
            relay.clone(),
        ],
        1,
        100,
        1,
    )
    .expect("ticket");
    (ticket, relay)
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
        let end = start
            .checked_add(len)
            .ok_or_else(|| String::from("overflow"))?;
        self.bytes
            .get(start..end)
            .map(ToOwned::to_owned)
            .ok_or_else(|| String::from("range"))
    }
}

async fn direct_first_range(
    bytes: Vec<u8>,
    ticket: &TransferTicket,
    partial_path: &std::path::Path,
    cursor: &mut DownloadCursor,
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
            Some(1),
        )
        .await
        .expect("serve first range");
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
        Some(1),
    )
    .await
    .expect("pull first range");
    server.await.expect("server join");
    report
}

fn persist_relay_range(
    partial_path: &std::path::Path,
    forwarded: &ptah_node_transfer::RelayForwardedRange,
) -> VerifiedRange {
    assert_eq!(
        format!("{:x}", Sha256::digest(&forwarded.payload)),
        forwarded.header.sha256
    );

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(partial_path)
        .expect("open partial");
    file.seek(SeekFrom::Start(forwarded.header.start))
        .expect("seek write");
    file.write_all(&forwarded.payload).expect("write range");
    file.flush().expect("flush range");
    file.sync_data().expect("sync range");
    file.seek(SeekFrom::Start(forwarded.header.start))
        .expect("seek verify");
    let mut reread = vec![0_u8; forwarded.payload.len()];
    file.read_exact(&mut reread).expect("reread range");
    assert_eq!(
        format!("{:x}", Sha256::digest(&reread)),
        forwarded.header.sha256
    );

    VerifiedRange {
        start: forwarded.header.start,
        len: forwarded.header.len,
        sha256: forwarded.header.sha256.clone(),
    }
}

#[tokio::test]
async fn direct_failure_continues_only_missing_ranges_through_explicit_relay() {
    let bytes: Vec<u8> = (0..(5 * MAX_RANGE_BYTES + 123))
        .map(|index| u8::try_from(index % 251).expect("index modulo 251 fits u8"))
        .collect();
    let source_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let (ticket, relay_route) = ticket(&bytes);
    let destination = std::env::temp_dir().join(format!(
        "ptah-e03-node-relay-resume-{}.part",
        ticket.ticket_ref().entity_id
    ));
    let _ = std::fs::remove_file(&destination);
    let mut cursor = DownloadCursor::default();

    let mut report = direct_first_range(bytes.clone(), &ticket, &destination, &mut cursor).await;
    assert_eq!(report.network_bytes, MAX_RANGE_BYTES as u64);
    report.failures.push(RouteFailure {
        kind: TransferRouteKind::Direct,
        error: String::from("connection_lost"),
    });

    let mut broker = RelayBroker::new(vec![ticket.clone()]);
    broker
        .register_source(
            ticket.ticket_ref(),
            &relay_route,
            ticket.source(),
            RELAY_FINGERPRINT,
            11,
        )
        .expect("relay source");
    broker
        .register_target(
            ticket.ticket_ref(),
            &relay_route,
            ticket.target(),
            RELAY_FINGERPRINT,
            11,
        )
        .expect("relay target");

    let mut start = MAX_RANGE_BYTES as u64;
    let mut relay_network_bytes = 0_u64;
    while start < bytes.len() as u64 {
        let len = (bytes.len() as u64 - start).min(MAX_RANGE_BYTES as u64);
        let start_usize = usize::try_from(start).expect("start usize");
        let len_usize = usize::try_from(len).expect("len usize");
        let payload = bytes[start_usize..start_usize + len_usize].to_vec();
        let request = RangeRequest {
            ticket_ref: ticket.ticket_ref().clone(),
            start,
            len,
        };
        let header = RangeDataHeader {
            ticket_ref: ticket.ticket_ref().clone(),
            start,
            len,
            sha256: format!("{:x}", Sha256::digest(&payload)),
        };
        let forwarded = broker
            .forward_range(ticket.ticket_ref(), request, header, &payload)
            .expect("forward relay range");
        let verified = persist_relay_range(&destination, &forwarded);
        cursor.mark_verified(verified);
        relay_network_bytes = relay_network_bytes
            .checked_add(len)
            .expect("relay bytes overflow");
        start = start.checked_add(len).expect("range start overflow");
    }

    assert_eq!(
        relay_network_bytes,
        bytes.len() as u64 - report.network_bytes
    );
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(std::fs::read(&destination).expect("read destination"))
        ),
        source_sha256
    );
    assert_eq!(
        report.failures,
        vec![RouteFailure {
            kind: TransferRouteKind::Direct,
            error: String::from("connection_lost"),
        }]
    );
    assert!(bytes.len() > ptah_node_link::MAX_FRAME_BYTES);

    let _ = std::fs::remove_file(destination);
}
