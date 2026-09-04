//! E01 protocol identity and negotiation tests.

use ptah_identifiers::EntityRef;
use ptah_node_agent::NodeAgent;
use ptah_node_link::{LinkError, LinkMessage, MAX_FRAME_BYTES, NodeHello, PROTOCOL_ID, ProtocolVersion, negotiate_version};

#[test]
fn hello_preserves_a02_node_identity() {
    let agent = NodeAgent::bootstrap().expect("bootstrap node");
    let enrollment_ref = EntityRef::new("core.node_enrollment").expect("enrollment ref");
    let hello = NodeHello {
        supported_major: 1,
        minimum_minor: 0,
        maximum_minor: 0,
        node_id: agent.node_id(),
        node_generation: agent.generation(),
        connection_epoch: agent.connection_epoch(),
        enrollment_ref,
        agent_revision: String::from("e01-test"),
        capability_snapshot_ref: None,
    };

    assert_eq!(PROTOCOL_ID, "ptah.node.link.v1");
    assert_eq!(MAX_FRAME_BYTES, 1_048_576);
    assert_eq!(hello.node_id, agent.node_id());
    assert_eq!(hello.node_generation, agent.generation());
    assert_eq!(hello.connection_epoch, agent.connection_epoch());
    assert_eq!(LinkMessage::Hello(hello).kind(), "hello");
}

#[test]
fn incompatible_major_fails_closed() {
    let local = ProtocolVersion { major: 1, minor: 0 };
    let remote = ProtocolVersion { major: 2, minor: 0 };
    assert_eq!(
        negotiate_version(local, remote),
        Err(LinkError::ProtocolIncompatible {
            local_major: 1,
            remote_major: 2,
        })
    );
}
