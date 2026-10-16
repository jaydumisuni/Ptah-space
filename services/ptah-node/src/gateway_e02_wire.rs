//! Node-side E02 control-wire ingress over an already authenticated TLS E01
//! connection. No arbitrary program or shell command arrives over the wire.
use crate::{NodeDispatchError, NodeDispatchGuard};
use ptah_node_agent::NodeAgent;
use ptah_node_link::{
    AuthenticatedClientStream, DispatchRequestFrame, LinkError, LinkMessage, read_frame,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Typed failure of the strictly bounded E02 wire-authority sequence.
#[derive(Debug)]
pub enum E02WireError {
    /// TLS/framing or peer disconnect failed.
    Link(LinkError),
    /// Node Generation, epoch, fence or E02 authority invalid.
    Authority(NodeDispatchError),
    /// Wrong frame or ordering; E02 messages may not create new authority.
    Protocol(&'static str),
}
impl From<LinkError> for E02WireError {
    fn from(value: LinkError) -> Self {
        Self::Link(value)
    }
}
impl From<NodeDispatchError> for E02WireError {
    fn from(value: NodeDispatchError) -> Self {
        Self::Authority(value)
    }
}

/// Receive exactly one Control-issued Reservation, Lease and `DispatchRequest`.
/// The Node's own E02 guard admits all three and checks expiry at receive time.
/// The resulting request is NOT executed here; the caller must separately use
/// a pinned, local, approved A05 provider and the durable `GatewayJournal`.
///
/// # Errors
///
/// Denies wire timeout, reordered/missing frames, stale identity, lease expiry,
/// stale/future fence, or unexpected authority messages.
pub async fn receive_one(
    agent: &NodeAgent,
    stream: &mut AuthenticatedClientStream,
) -> Result<(NodeDispatchGuard, DispatchRequestFrame), E02WireError> {
    let mut guard = NodeDispatchGuard::for_agent(agent);
    for phase in 0..3_u8 {
        let msg = tokio::time::timeout(Duration::from_secs(5), read_frame(stream.stream_mut()))
            .await
            .map_err(|_| E02WireError::Protocol("E02 frame timeout"))??;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| E02WireError::Protocol("invalid system time"))?
            .as_secs();
        match (phase, msg) {
            (0, LinkMessage::DispatchReservation(frame)) => {
                guard.accept_reservation(agent, &frame, now)?;
            }
            (1, LinkMessage::DispatchLease(frame)) => guard.accept_lease(agent, &frame, now)?,
            (2, LinkMessage::DispatchRequest(frame)) => {
                guard.invoke_if_authorized(agent, &frame, now, || ())?;
                return Ok((guard, *frame));
            }
            _ => return Err(E02WireError::Protocol("unexpected or reordered E02 frame")),
        }
    }
    Err(E02WireError::Protocol("no dispatch request"))
}
