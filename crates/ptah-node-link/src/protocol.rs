use crate::LinkError;
use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::{NodeCapabilitySnapshot, ResourceUnit};
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
///
/// # Errors
///
/// Returns [`LinkError::ProtocolIncompatible`] when the major versions differ.
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
    /// Requested exact `ConnectionEpoch`.
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
    /// Accepted `ConnectionEpoch`.
    pub connection_epoch: ConnectionEpoch,
}

/// Evidence-bound capability snapshot carried over an authenticated session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityAnnouncement {
    /// Existing A02 capability snapshot. E01 does not redefine capability truth.
    pub snapshot: NodeCapabilitySnapshot,
}

/// One bounded advisory resource quantity published by a Node offer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OfferedResource {
    /// Stable A02 resource key.
    pub resource_key: String,
    /// Frozen A02 resource unit.
    pub unit: ResourceUnit,
    /// Advisory quantity currently offered by the Node.
    pub quantity: f64,
}

/// Short-lived advisory E02 offer transported over the authenticated E01 link.
///
/// This frame carries decision input only. It cannot mint Reservation, Lease,
/// Fence or dispatch authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeOfferFrame {
    /// Unique canonical offer identity.
    pub offer_ref: EntityRef,
    /// Stable canonical Node identity.
    pub node_id: NodeId,
    /// Exact Node Generation that published the offer.
    pub node_generation: NodeGeneration,
    /// Exact authenticated E01 Connection Epoch.
    pub connection_epoch: ConnectionEpoch,
    /// Exact capability-snapshot evidence reference.
    pub capability_snapshot_ref: EntityRef,
    /// Exact resource-snapshot evidence reference.
    pub resource_snapshot_ref: EntityRef,
    /// Bounded advisory resource quantities.
    pub offered_resources: Vec<OfferedResource>,
    /// Optional normalized Node load score.
    pub load_score: Option<u16>,
    /// Optional bounded locality label used only for scoring.
    pub locality: Option<String>,
    /// Unix-second instant after which this offer is stale.
    pub valid_until_unix_seconds: u64,
    /// Positive sender-local nonce identifying this offer instance.
    pub nonce: u64,
}

/// Control-issued Reservation authority projected onto the authenticated E01 link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchReservationFrame {
    /// Canonical Reservation identity.
    pub reservation_ref: EntityRef,
    /// Canonical A04 Attempt identity.
    pub attempt_ref: EntityRef,
    /// Stable canonical target Node identity.
    pub node_id: NodeId,
    /// Exact target Node Generation.
    pub node_generation: NodeGeneration,
    /// Exact authenticated E01 Connection Epoch.
    pub connection_epoch: ConnectionEpoch,
    /// Fixed Reservation expiry instant.
    pub expires_at_unix_seconds: u64,
}

/// Control-issued Lease/Fence authority projected onto the authenticated E01 link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchLeaseFrame {
    /// Canonical Lease identity.
    pub lease_ref: EntityRef,
    /// Canonical Reservation identity held by this Lease.
    pub reservation_ref: EntityRef,
    /// Canonical A04 Attempt identity.
    pub attempt_ref: EntityRef,
    /// Stable canonical target Node identity.
    pub node_id: NodeId,
    /// Exact target Node Generation.
    pub node_generation: NodeGeneration,
    /// Exact authenticated E01 Connection Epoch.
    pub connection_epoch: ConnectionEpoch,
    /// Positive monotonic ownership Fence allocated by control.
    pub fence: u64,
    /// Fixed Lease expiry instant.
    pub expires_at_unix_seconds: u64,
}

/// Execution-changing request carrying the exact authority selected by control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchRequestFrame {
    /// Unique dispatch request identity.
    pub dispatch_ref: EntityRef,
    /// Existing A04 Operation identity to invoke after authority admission.
    pub operation_ref: EntityRef,
    /// Canonical A04 Attempt identity.
    pub attempt_ref: EntityRef,
    /// Canonical Reservation identity.
    pub reservation_ref: EntityRef,
    /// Canonical Lease identity.
    pub lease_ref: EntityRef,
    /// Stable canonical target Node identity.
    pub node_id: NodeId,
    /// Exact target Node Generation.
    pub node_generation: NodeGeneration,
    /// Exact authenticated E01 Connection Epoch.
    pub connection_epoch: ConnectionEpoch,
    /// Exact current control-issued ownership Fence.
    pub fence: u64,
}

/// Constant-space liveness message bound to one exact session authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Stable Node identity.
    pub node_id: NodeId,
    /// Exact Node Generation.
    pub node_generation: NodeGeneration,
    /// Exact `ConnectionEpoch`.
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
    Hello(Box<NodeHello>),
    /// Accepted-handshake projection.
    HelloAck(HelloAck),
    /// Evidence-bound capability announcement.
    CapabilityAnnouncement(Box<CapabilityAnnouncement>),
    /// Advisory E02 Node offer.
    NodeOffer(Box<NodeOfferFrame>),
    /// Control-issued E02 Reservation authority.
    DispatchReservation(Box<DispatchReservationFrame>),
    /// Control-issued E02 Lease/Fence authority.
    DispatchLease(Box<DispatchLeaseFrame>),
    /// Execution-changing E02 request admitted only after Node-side authority validation.
    DispatchRequest(Box<DispatchRequestFrame>),
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
            Self::NodeOffer(_) => "node_offer",
            Self::DispatchReservation(_) => "dispatch_reservation",
            Self::DispatchLease(_) => "dispatch_lease",
            Self::DispatchRequest(_) => "dispatch_request",
            Self::Heartbeat(_) => "heartbeat",
            Self::Ack(_) => "ack",
            Self::Error(_) => "error",
            Self::Close => "close",
        }
    }
}
