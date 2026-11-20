//! Retained TLS 1.3 E01 channel tests. Certificates are test fixtures.
use ptah_control::{
    gateway_session, node_link::NodeLinkControl, placement::PlacementAuthorityOwner,
};
use ptah_identifiers::EntityRef;
use ptah_node_agent::NodeAgent;
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle, Heartbeat, LinkMessage,
    NodeHello, ProtocolVersion, TlsClientConfig, TlsIdentity, TlsServerConfig, TlsTrustRoots,
    connect_tls, read_frame, write_frame,
};
use std::{sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
const CA: &[u8] = include_bytes!("../../../crates/ptah-node-link/tests/fixtures/ca.cert.der");
const SERVER: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.cert.der");
const SERVER_KEY: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/server.key.der");
const CLIENT: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.cert.der");
const CLIENT_KEY: &[u8] =
    include_bytes!("../../../crates/ptah-node-link/tests/fixtures/client.key.der");
fn config() -> (TlsServerConfig, TlsClientConfig) {
    let roots = || TlsTrustRoots::from_der(vec![CA.to_vec()]).unwrap();
    (
        TlsServerConfig::new(
            TlsIdentity::from_der(vec![SERVER.to_vec()], SERVER_KEY.to_vec()).unwrap(),
            roots(),
        )
        .unwrap(),
        TlsClientConfig::new(
            TlsIdentity::from_der(vec![CLIENT.to_vec()], CLIENT_KEY.to_vec()).unwrap(),
            roots(),
        )
        .unwrap(),
    )
}
async fn exchange(case: u8) -> (bool, bool) {
    let agent = NodeAgent::bootstrap().unwrap();
    let enrolled = EntityRef::new("core.node_enrollment").unwrap();
    let owner = Arc::new(Mutex::new(PlacementAuthorityOwner::new(
        NodeLinkControl::new(
            ProtocolVersion { major: 1, minor: 0 },
            vec![
                ApprovedNodeEnrollment::new(
                    enrolled.clone(),
                    agent.node_id(),
                    EnrollmentLifecycle::Approved,
                    vec!["node.connect".to_owned()],
                    vec![CredentialFingerprint::from_der(CLIENT)],
                    None,
                )
                .unwrap(),
            ],
        ),
    )));
    let (tls, client_tls) = config();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cloned = owner.clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        gateway_session::handle(
            socket,
            &tls,
            &cloned,
            1_800_000_000,
            Duration::from_millis(250),
        )
        .await
    });
    let socket = TcpStream::connect(addr).await.unwrap();
    let mut client = connect_tls(socket, "localhost", &client_tls).await.unwrap();
    let hello = NodeHello {
        supported_major: 1,
        minimum_minor: 0,
        maximum_minor: 0,
        node_id: agent.node_id(),
        node_generation: agent.generation(),
        connection_epoch: agent.connection_epoch(),
        enrollment_ref: enrolled,
        agent_revision: "retained-session-test".into(),
        capability_snapshot_ref: None,
    };
    write_frame(
        client.stream_mut(),
        &LinkMessage::Hello(Box::new(hello.clone())),
    )
    .await
    .unwrap();
    assert!(matches!(
        read_frame(client.stream_mut()).await.unwrap(),
        LinkMessage::HelloAck(_)
    ));

    let heartbeat = |sequence| {
        LinkMessage::Heartbeat(Heartbeat {
            node_id: agent.node_id(),
            node_generation: agent.generation(),
            connection_epoch: agent.connection_epoch(),
            sequence,
        })
    };
    let messages = match case {
        0 => vec![heartbeat(1), heartbeat(2), LinkMessage::Close],
        1 => vec![heartbeat(1), heartbeat(1)],
        2 => vec![LinkMessage::Hello(Box::new(hello))],
        3 => vec![],
        _ => panic!("unknown test case"),
    };
    for msg in messages {
        write_frame(client.stream_mut(), &msg).await.unwrap();
    }

    let passed = server.await.unwrap().is_ok();
    let ended = owner
        .lock()
        .await
        .is_current_session(&ptah_node_link::SessionBinding {
            node_id: agent.node_id(),
            node_generation: agent.generation(),
            connection_epoch: agent.connection_epoch(),
            enrollment_ref: EntityRef::new("core.node_enrollment").unwrap(),
            negotiated_protocol: ProtocolVersion { major: 1, minor: 0 },
            credential_fingerprint: CredentialFingerprint::from_der(CLIENT),
        });
    (passed, !ended)
}

#[tokio::test]
async fn close_after_two_heartbeats_clears_current_session() {
    assert_eq!(exchange(0).await, (true, true));
}
#[tokio::test]
async fn replayed_heartbeat_is_rejected_and_fenced() {
    assert_eq!(exchange(1).await, (false, true));
}
#[tokio::test]
async fn non_heartbeat_message_is_rejected_and_fenced() {
    assert_eq!(exchange(2).await, (false, true));
}
#[tokio::test]
async fn idle_session_times_out_and_is_fenced() {
    assert_eq!(exchange(3).await, (false, true));
}
