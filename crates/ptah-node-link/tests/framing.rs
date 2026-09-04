//! E01 bounded framing tests over a transport-neutral async stream.

use ptah_identifiers::EntityRef;
use ptah_node_agent::NodeAgent;
use ptah_node_link::{LinkError, LinkMessage, MAX_FRAME_BYTES, NodeHello, read_frame, write_frame};
use tokio::io::{AsyncWriteExt, duplex};

fn hello_message() -> LinkMessage {
    let agent = NodeAgent::bootstrap().expect("bootstrap node");
    LinkMessage::Hello(Box::new(NodeHello {
        supported_major: 1,
        minimum_minor: 0,
        maximum_minor: 0,
        node_id: agent.node_id(),
        node_generation: agent.generation(),
        connection_epoch: agent.connection_epoch(),
        enrollment_ref: EntityRef::new("core.node_enrollment").expect("enrollment ref"),
        agent_revision: String::from("e01-framing-test"),
        capability_snapshot_ref: None,
    }))
}

#[tokio::test]
async fn frame_round_trip_is_transport_neutral() {
    let (mut left, mut right) = duplex(16 * 1024);
    let expected = hello_message();
    let sender = tokio::spawn(async move { write_frame(&mut left, &expected).await.map(|()| expected) });
    let received = read_frame(&mut right).await.expect("read frame");
    let sent = sender.await.expect("sender join").expect("write frame");
    assert_eq!(received, sent);
}

#[tokio::test]
async fn oversized_declared_frame_fails_before_payload_read() {
    let (mut left, mut right) = duplex(64);
    let declared = MAX_FRAME_BYTES + 1;
    let declared_u32 = u32::try_from(declared).expect("E01 frame test bound fits u32");
    left.write_all(&declared_u32.to_be_bytes())
        .await
        .expect("write length");
    left.flush().await.expect("flush length");

    assert_eq!(
        read_frame(&mut right).await,
        Err(LinkError::FrameTooLarge { declared })
    );
}

#[tokio::test]
async fn zero_length_frame_is_malformed() {
    let (mut left, mut right) = duplex(64);
    left.write_all(&0_u32.to_be_bytes()).await.expect("write length");
    left.flush().await.expect("flush length");

    assert_eq!(
        read_frame(&mut right).await,
        Err(LinkError::MalformedFrame(String::from("zero-length frame")))
    );
}
