//! E01 physical loopback TLS 1.3 mutual-authentication tests.

use ptah_identifiers::EntityRef;
use ptah_node_agent::NodeAgent;
use ptah_node_link::{
    CredentialFingerprint, LinkMessage, NodeHello, TlsClientConfig, TlsIdentity, TlsServerConfig,
    TlsTrustRoots, accept_tls, connect_tls, read_frame, write_frame,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const CA_CERT: &[u8] = include_bytes!("fixtures/ca.cert.der");
const SERVER_CERT: &[u8] = include_bytes!("fixtures/server.cert.der");
const SERVER_KEY: &[u8] = include_bytes!("fixtures/server.key.der");
const CLIENT_CERT: &[u8] = include_bytes!("fixtures/client.cert.der");
const CLIENT_KEY: &[u8] = include_bytes!("fixtures/client.key.der");
const WRONG_CA_CERT: &[u8] = include_bytes!("fixtures/wrong-ca.cert.der");
const WRONG_CLIENT_CERT: &[u8] = include_bytes!("fixtures/wrong-client.cert.der");
const WRONG_CLIENT_KEY: &[u8] = include_bytes!("fixtures/wrong-client.key.der");

fn server_identity() -> TlsIdentity {
    TlsIdentity::from_der(vec![SERVER_CERT.to_vec()], SERVER_KEY.to_vec()).expect("server identity")
}

fn client_identity() -> TlsIdentity {
    TlsIdentity::from_der(vec![CLIENT_CERT.to_vec()], CLIENT_KEY.to_vec()).expect("client identity")
}

fn wrong_client_identity() -> TlsIdentity {
    TlsIdentity::from_der(
        vec![WRONG_CLIENT_CERT.to_vec()],
        WRONG_CLIENT_KEY.to_vec(),
    )
    .expect("wrong client identity")
}

fn roots(cert: &[u8]) -> TlsTrustRoots {
    TlsTrustRoots::from_der(vec![cert.to_vec()]).expect("trust roots")
}

fn hello_message() -> LinkMessage {
    let agent = NodeAgent::bootstrap().expect("bootstrap");
    LinkMessage::Hello(Box::new(NodeHello {
        supported_major: 1,
        minimum_minor: 0,
        maximum_minor: 0,
        node_id: agent.node_id(),
        node_generation: agent.generation(),
        connection_epoch: agent.connection_epoch(),
        enrollment_ref: EntityRef::new("core.node_enrollment").expect("enrollment ref"),
        agent_revision: String::from("e01-tls-test"),
        capability_snapshot_ref: None,
    }))
}

#[tokio::test]
async fn mutual_tls13_round_trips_protocol_and_extracts_client_fingerprint() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("listener address");
    let server_config = TlsServerConfig::new(server_identity(), roots(CA_CERT)).expect("server config");
    let client_config = TlsClientConfig::new(client_identity(), roots(CA_CERT)).expect("client config");
    let expected = hello_message();
    let expected_for_server = expected.clone();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept tcp");
        let mut tls = accept_tls(tcp, &server_config).await.expect("accept mTLS");
        assert!(tls.is_tls13());
        assert_eq!(
            tls.peer_fingerprint(),
            CredentialFingerprint::from_der(CLIENT_CERT)
        );
        let message = read_frame(tls.stream_mut()).await.expect("read hello");
        assert_eq!(message, expected_for_server);
        write_frame(tls.stream_mut(), &LinkMessage::Close)
            .await
            .expect("write close");
    });

    let tcp = TcpStream::connect(address).await.expect("connect tcp");
    let mut tls = connect_tls(tcp, "localhost", &client_config)
        .await
        .expect("connect mTLS");
    assert!(tls.is_tls13());
    write_frame(tls.stream_mut(), &expected).await.expect("write hello");
    assert_eq!(
        read_frame(tls.stream_mut()).await.expect("read close"),
        LinkMessage::Close
    );
    server.await.expect("server join");
}

#[tokio::test]
async fn wrong_server_trust_root_fails_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("listener address");
    let server_config = TlsServerConfig::new(server_identity(), roots(CA_CERT)).expect("server config");
    let client_config =
        TlsClientConfig::new(client_identity(), roots(WRONG_CA_CERT)).expect("client config");

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept tcp");
        accept_tls(tcp, &server_config).await
    });
    let tcp = TcpStream::connect(address).await.expect("connect tcp");
    assert!(connect_tls(tcp, "localhost", &client_config).await.is_err());
    assert!(server.await.expect("server join").is_err());
}

#[tokio::test]
async fn client_signed_by_wrong_ca_fails_server_authentication() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("listener address");
    let server_config = TlsServerConfig::new(server_identity(), roots(CA_CERT)).expect("server config");
    let client_config =
        TlsClientConfig::new(wrong_client_identity(), roots(CA_CERT)).expect("client config");

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept tcp");
        accept_tls(tcp, &server_config).await
    });
    let tcp = TcpStream::connect(address).await.expect("connect tcp");
    let client_result = connect_tls(tcp, "localhost", &client_config).await;
    let server_result = server.await.expect("server join");
    assert!(server_result.is_err());

    if let Ok(mut tls) = client_result {
        assert!(read_frame(tls.stream_mut()).await.is_err());
    }
}

#[tokio::test]
async fn plaintext_cannot_downgrade_tls_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("listener address");
    let server_config = TlsServerConfig::new(server_identity(), roots(CA_CERT)).expect("server config");

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept tcp");
        accept_tls(tcp, &server_config).await
    });
    let mut tcp = TcpStream::connect(address).await.expect("connect tcp");
    tcp.write_all(b"plaintext is not an E01 secure link")
        .await
        .expect("write plaintext");
    tcp.shutdown().await.expect("shutdown plaintext");
    assert!(server.await.expect("server join").is_err());
}

#[test]
fn tls_identity_debug_never_exposes_private_key() {
    let identity = client_identity();
    let debug = format!("{identity:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains(&format!("{:02x}", CLIENT_KEY[0])) || !debug.contains("private_key_der"));
}
