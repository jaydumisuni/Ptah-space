//! Real TLS 1.3 transport + certificate-bound E01 owner tests.
//! Cryptographic keys here are repository test fixtures, never deployment keys.
use ptah_control::gateway_enrollment::admit_authenticated_node;
use ptah_control::node_link::NodeLinkControl;
use ptah_control::placement::PlacementAuthorityOwner;
use ptah_identifiers::EntityRef;
use ptah_node_agent::NodeAgent;
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle, LinkError, LinkMessage,
    NodeHello, ProtocolVersion, TlsClientConfig, TlsIdentity, TlsServerConfig, TlsTrustRoots,
    connect_tls, read_frame, write_frame,
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

fn ref_id(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("canonical ref")
}
fn tls_server() -> TlsServerConfig {
    TlsServerConfig::new(
        TlsIdentity::from_der(vec![SERVER.to_vec()], SERVER_KEY.to_vec()).expect("server identity"),
        TlsTrustRoots::from_der(vec![CA.to_vec()]).expect("trusted CA"),
    )
    .expect("TLS 1.3 server")
}
fn tls_client() -> TlsClientConfig {
    TlsClientConfig::new(
        TlsIdentity::from_der(vec![CLIENT.to_vec()], CLIENT_KEY.to_vec()).expect("client identity"),
        TlsTrustRoots::from_der(vec![CA.to_vec()]).expect("trusted CA"),
    )
    .expect("TLS 1.3 client")
}

async fn exchange(fingerprint: CredentialFingerprint) -> Result<(), LinkError> {
    let agent = NodeAgent::bootstrap().expect("Node");
    let enrollment_ref = ref_id("core.node_enrollment");
    let enrollment = ApprovedNodeEnrollment::new(
        enrollment_ref.clone(),
        agent.node_id(),
        EnrollmentLifecycle::Approved,
        vec![String::from("node.connect")],
        vec![fingerprint],
        None,
    )
    .expect("approved test projection");
    let owner = PlacementAuthorityOwner::new(NodeLinkControl::new(
        ProtocolVersion { major: 1, minor: 0 },
        vec![enrollment],
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let target = listener.local_addr().expect("address");
    let config = tls_server();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let mut owner = owner;
        admit_authenticated_node(socket, &config, &mut owner, 1_800_000_000).await
    });
    let socket = TcpStream::connect(target).await.expect("connect");
    let mut client = connect_tls(socket, "localhost", &tls_client())
        .await
        .expect("mutual TLS");
    assert!(client.is_tls13());
    write_frame(
        client.stream_mut(),
        &LinkMessage::Hello(Box::new(NodeHello {
            supported_major: 1,
            minimum_minor: 0,
            maximum_minor: 0,
            node_id: agent.node_id(),
            node_generation: agent.generation(),
            connection_epoch: agent.connection_epoch(),
            enrollment_ref,
            agent_revision: String::from("real-certificate-test"),
            capability_snapshot_ref: None,
        })),
    )
    .await
    .expect("Hello");
    let accepted = server.await.expect("server task");
    if accepted.is_ok() {
        let reply = read_frame(client.stream_mut()).await.expect("ack");
        assert!(matches!(reply, LinkMessage::HelloAck(_)));
    }
    accepted.map(|_| ())
}
#[tokio::test]
async fn actual_client_certificate_is_bound_to_e01_canonical_node() {
    exchange(CredentialFingerprint::from_der(CLIENT))
        .await
        .expect("bound certificate admitted");
}
#[tokio::test]
async fn valid_ca_client_but_unenrolled_fingerprint_is_denied() {
    let result = exchange(CredentialFingerprint::from_der(b"wrong-end-entity"));
    assert!(matches!(result.await, Err(LinkError::CredentialNotBound)));
}
