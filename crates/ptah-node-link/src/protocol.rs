use crate::LinkError;
use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::NodeCapabilitySnapshot;
use serde::{Deserialize, Serialize};

/// One negotiated E01 application-protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    /// Protocol major version. A mismatch fails closed.
    pub major: u16,
    /// Protocol minor version.
    pub minor: u16,
}

/// Negotiate one exact protocol version.
///
/// E01 has one major version. Peers with different majors are incompatible;
/// compatible peers use the lower minor version.
pub fn negotiate_version(
    local: ProtocolVersion,
    remote: ProtocolVersion,
) -> Result<ProtocolVersion, LinkError> {
    if local.major != remote.major {
        return Err(LinkError::ProtocolIncompatible {
            local_major: local.major,
            remote_major: remote.major,
        });
    }
    Ok(ProtocolVersion {
        major: local.major,
        minor: local.minor.min(remote.minor),
    })
}

/// First authenticated application message sent by a Node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeHello {
    /// Supported E01 protocol major.
    pub supported_major: u16,
    /// Lowest supported minor version.
    pub minimum_minor: u16,
    /// Highest supported minor version.
    pub maximum_minor: u16,
    /// Stable canonical Node identity.
    pub node_id: NodeId,
    /// Exact current Node Generation.
    pub node_generation: NodeGeneration,
    /// Requested exact ConnectionEpoch.
    pub connection_epoch: ConnectionEpoch,
    /// Exact enrollment record reference.
    pub enrollment_ref: EntityRef,
    /// Exact Node-agent revision.
    pub agent_revision: String,
    /// Optional current capability snapshot reference.
    pub capability_snapshot_ref: Option<EntityRef>,
}

/// Control-plane acknowledgement of one accepted Node hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    /// Exact selected protocol version.
    pub selected_version: ProtocolVersion,
    /// Stable Node identity accepted by the control plane.
    pub node_id: NodeId,
    /// Accepted Generation.
    pub node_generation: NodeGeneration,
    /// Accepted ConnectionEpoch.
    pub connection_epoch: ConnectionEpoch,
}

/// Evidence-bound capability snapshot carried over an authenticated session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityAnnouncement {
    /// Existing A02 capability snapshot. E01 does not redefine capability truth.
    pub snapshot: NodeCapabilitySnapshot,
}

/// Constant-space liveness message bound to one exact session authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Stable Node identity.
    pub node_id: NodeId,
    /// Exact Node Generation.
    pub node_generation: NodeGeneration,
    /// Exact ConnectionEpoch.
    pub connection_epoch: ConnectionEpoch,
    /// Monotonic sender-local heartbeat sequence.
    pub sequence: u64,
}

/// Generic positive acknowledgement for one message identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkAck {
    /// Sender-selected bounded message identifier.
    pub message_id: u64,
}

/// Bounded error projection returned across the E01 link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkErrorFrame {
    /// Stable machine-readable error code.
    pub code: String,
    /// Bounded human-readable detail.
    pub detail: String,
}

/// Versioned E01 application message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum LinkMessage {
    /// Node handshake projection.
    Hello(NodeHello),
    /// Accepted-handshake projection.
    HelloAck(HelloAck),
    /// Evidence-bound capability announcement.
    CapabilityAnnouncement(CapabilityAnnouncement),
    /// Liveness projection.
    Heartbeat(Heartbeat),
    /// Generic acknowledgement.
    Ack(LinkAck),
    /// Stable error projection.
    Error(LinkErrorFrame),
    /// Graceful close request.
    Close,
}

impl LinkMessage {
    /// Stable wire message-kind name.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Hello(_) => "hello",
            Self::HelloAck(_) => "hello_ack",
            Self::CapabilityAnnouncement(_) => "capability_announcement",
            Self::Heartbeat(_) => "heartbeat",
            Self::Ack(_) => "ack",
            Self::Error(_) => "error",
            Self::Close => "close",
        }
    }
}
