//! E01 Node-side secure-link orchestration test.

use ptah_identifiers::EntityRef;
use ptah_node::{NodeLinkClientConfig, run_node_link_client};
use ptah_node_agent::NodeAgent;
use ptah_node_link::{
    HelloAck, LinkMessage, ProtocolVersion, TlsClientConfig, TlsIdentity, TlsServerConfig,
    TlsTrustRoots, accept_tls, read_frame, write_frame,
};
use tokio::net::TcpListener;

const CA_CERT: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/ca.cert.der");
const SERVER_CERT: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.cert.der");
const SERVER_KEY: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.key.der");
const CLIENT_CERT: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.cert.der");
const CLIENT_KEY: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.key.der");

fn identity(cert: &[u8], key: &[u8]) -> TlsIdentity {
    TlsIdentity::from_der(vec![cert.to_vec()], key.to_vec()).expect("TLS identity")
}

fn roots() -> TlsTrustRoots {
    TlsTrustRoots::from_der(vec![CA_CERT.to_vec()]).expect("trust roots")
}

#[tokio::test]
async fn node_client_sends_current_a02_identity_and_accepts_matching_ack() {
    let agent = NodeAgent::bootstrap().expect("node agent");
    let enrollment_ref = EntityRef::new("core.node_enrollment").expect("enrollment ref");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let endpoint = listener.local_addr().expect("address");
    let server_config =
        TlsServerConfig::new(identity(SERVER_CERT, SERVER_KEY), roots()).expect("server config");
    let client_config =
        TlsClientConfig::new(identity(CLIENT_CERT, CLIENT_KEY), roots()).expect("client config");
    let expected_node_id = agent.node_id();
    let expected_generation = agent.generation();
    let expected_epoch = agent.connection_epoch();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = accept_tls(tcp, &server_config).await.expect("TLS accept");
        let LinkMessage::Hello(hello) = read_frame(tls.stream_mut()).await.expect("hello") else {
            panic!("expected hello");
        };
        assert_eq!(hello.node_id, expected_node_id);
        assert_eq!(hello.node_generation, expected_generation);
        assert_eq!(hello.connection_epoch, expected_epoch);
        write_frame(
            tls.stream_mut(),
            &LinkMessage::HelloAck(HelloAck {
                selected_version: ProtocolVersion { major: 1, minor: 0 },
                node_id: hello.node_id,
                node_generation: hello.node_generation,
                connection_epoch: hello.connection_epoch,
            }),
        )
        .await
        .expect("ack");
    });

    let config = NodeLinkClientConfig::new(
        endpoint,
        String::from("localhost"),
        client_config,
        enrollment_ref,
        String::from("e01-node-test"),
        ProtocolVersion { major: 1, minor: 0 },
    );
    let ack = run_node_link_client(&agent, &config)
        .await
        .expect("node link client");
    assert_eq!(ack.node_id, agent.node_id());
    assert_eq!(ack.node_generation, agent.generation());
    assert_eq!(ack.connection_epoch, agent.connection_epoch());
    server.await.expect("server join");
}
