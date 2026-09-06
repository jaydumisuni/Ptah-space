#![forbid(unsafe_code)]
//! E01 secure Node client plus E02 fail-closed dispatch authority guard.

use native_process::{NativeProcessError, NativeProcessProvider, ProcessSpec};
use ptah_activity_runtime::AttemptContext;
use ptah_identifiers::{ConnectionEpoch, EntityId, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::NodeAgent;
use ptah_node_link::{
    DispatchLeaseFrame, DispatchRequestFrame, DispatchReservationFrame, HelloAck, LinkError,
    LinkMessage, NodeHello, ProtocolVersion, TlsClientConfig, connect_tls, read_frame, write_frame,
};
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Deployment-provided connection facts for one E01 Node-link attempt.
#[derive(Clone, Debug)]
pub struct NodeLinkClientConfig {
    endpoint: SocketAddr,
    server_name: String,
    tls: TlsClientConfig,
    enrollment_ref: EntityRef,
    agent_revision: String,
    protocol: ProtocolVersion,
}

impl NodeLinkClientConfig {
    /// Construct one Node-link client configuration without changing canonical Node identity.
    #[must_use]
    pub fn new(
        endpoint: SocketAddr,
        server_name: String,
        tls: TlsClientConfig,
        enrollment_ref: EntityRef,
        agent_revision: String,
        protocol: ProtocolVersion,
    ) -> Self {
        Self {
            endpoint,
            server_name,
            tls,
            enrollment_ref,
            agent_revision,
            protocol,
        }
    }

    fn hello(&self, agent: &NodeAgent) -> NodeHello {
        NodeHello {
            supported_major: self.protocol.major,
            minimum_minor: self.protocol.minor,
            maximum_minor: self.protocol.minor,
            node_id: agent.node_id(),
            node_generation: agent.generation(),
            connection_epoch: agent.connection_epoch(),
            enrollment_ref: self.enrollment_ref.clone(),
            agent_revision: self.agent_revision.clone(),
            capability_snapshot_ref: None,
        }
    }
}

/// Stable Node-side E02 dispatch rejection classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeDispatchError {
    /// The Node's live E01 Generation/epoch no longer matches this guard.
    SupersededSession,
    /// Wire authority targets another stable Node.
    NodeIdentityMismatch,
    /// Wire authority targets another Node Generation.
    NodeGenerationMismatch,
    /// Wire authority targets another E01 Connection Epoch.
    ConnectionEpochMismatch,
    /// Reservation identity is unknown locally.
    UnknownReservation,
    /// Reservation validity has ended.
    ExpiredReservation,
    /// Attempt binding differs from the accepted Reservation/Lease.
    AttemptMismatch,
    /// Lease authority has not been accepted for this Attempt.
    MissingCurrentLease,
    /// Lease identity differs from current accepted authority.
    LeaseMismatch,
    /// Lease validity has ended.
    ExpiredLease,
    /// Fence zero is never valid execution authority.
    InvalidFence,
    /// Fence is lower than the permanently accepted current Fence.
    StaleFence,
    /// Fence is greater than the Fence accepted from control.
    FutureFence,
    /// Reservation binding differs from the accepted Lease.
    ReservationMismatch,
    /// Reservation identity was accepted more than once.
    DuplicateReservation,
    /// Lease identity was accepted more than once.
    DuplicateLease,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FenceState {
    attempt_ref: EntityRef,
    highest: u64,
}

/// Node-local E02 authority state. This guard contains no scheduling policy and
/// cannot mint authority; it only accepts and validates control-issued frames.
#[derive(Debug, Clone)]
pub struct NodeDispatchGuard {
    node_id: NodeId,
    node_generation: NodeGeneration,
    connection_epoch: ConnectionEpoch,
    reservations: Vec<DispatchReservationFrame>,
    leases: Vec<DispatchLeaseFrame>,
    fences: Vec<FenceState>,
}

impl NodeDispatchGuard {
    /// Bind one guard to the exact live A02/E01 Node session.
    #[must_use]
    pub fn for_agent(agent: &NodeAgent) -> Self {
        Self {
            node_id: agent.node_id(),
            node_generation: agent.generation(),
            connection_epoch: agent.connection_epoch(),
            reservations: Vec::new(),
            leases: Vec::new(),
            fences: Vec::new(),
        }
    }

    /// Accept one control-issued Reservation authority for this exact live session.
    ///
    /// # Errors
    ///
    /// Rejects superseded/wrong session authority, duplicate identity, or expiry.
    pub fn accept_reservation(
        &mut self,
        agent: &NodeAgent,
        frame: &DispatchReservationFrame,
        now_unix_seconds: u64,
    ) -> Result<(), NodeDispatchError> {
        self.assert_live_session(agent)?;
        self.assert_frame_session(frame.node_id, frame.node_generation, frame.connection_epoch)?;
        if frame.expires_at_unix_seconds <= now_unix_seconds {
            return Err(NodeDispatchError::ExpiredReservation);
        }
        if self
            .reservations
            .iter()
            .any(|accepted| accepted.reservation_ref == frame.reservation_ref)
        {
            return Err(NodeDispatchError::DuplicateReservation);
        }
        self.reservations.push(frame.clone());
        Ok(())
    }

    /// Accept one control-issued Lease/Fence only against a known live Reservation.
    ///
    /// # Errors
    ///
    /// Rejects missing/mismatched/expired Reservation or Lease authority, duplicate
    /// Lease identity, non-positive Fence, and every Fence that does not advance the
    /// Attempt's permanently retained Node-local Fence history.
    pub fn accept_lease(
        &mut self,
        agent: &NodeAgent,
        frame: &DispatchLeaseFrame,
        now_unix_seconds: u64,
    ) -> Result<(), NodeDispatchError> {
        self.assert_live_session(agent)?;
        self.assert_frame_session(frame.node_id, frame.node_generation, frame.connection_epoch)?;
        if frame.fence == 0 {
            return Err(NodeDispatchError::InvalidFence);
        }
        if frame.expires_at_unix_seconds <= now_unix_seconds {
            return Err(NodeDispatchError::ExpiredLease);
        }
        if self
            .leases
            .iter()
            .any(|accepted| accepted.lease_ref == frame.lease_ref)
        {
            return Err(NodeDispatchError::DuplicateLease);
        }
        let reservation = self
            .reservations
            .iter()
            .find(|accepted| accepted.reservation_ref == frame.reservation_ref)
            .ok_or(NodeDispatchError::UnknownReservation)?;
        if reservation.expires_at_unix_seconds <= now_unix_seconds {
            return Err(NodeDispatchError::ExpiredReservation);
        }
        if reservation.attempt_ref != frame.attempt_ref {
            return Err(NodeDispatchError::AttemptMismatch);
        }
        if frame.expires_at_unix_seconds > reservation.expires_at_unix_seconds {
            return Err(NodeDispatchError::ReservationMismatch);
        }
        if let Some(fence) = self
            .fences
            .iter()
            .find(|fence| fence.attempt_ref == frame.attempt_ref)
            && frame.fence <= fence.highest
        {
            return Err(NodeDispatchError::StaleFence);
        }
        if let Some(fence) = self
            .fences
            .iter_mut()
            .find(|fence| fence.attempt_ref == frame.attempt_ref)
        {
            fence.highest = frame.fence;
        } else {
            self.fences.push(FenceState {
                attempt_ref: frame.attempt_ref.clone(),
                highest: frame.fence,
            });
        }
        self.leases.push(frame.clone());
        Ok(())
    }

    /// Validate one execution-changing dispatch and invoke the supplied callback
    /// only after every Node/session/Reservation/Lease/Fence check succeeds.
    ///
    /// # Errors
    ///
    /// Returns a typed [`NodeDispatchError`] without invoking `invoke` whenever
    /// authority is missing, expired, mismatched, superseded, stale or future.
    pub fn invoke_if_authorized<T, F>(
        &self,
        agent: &NodeAgent,
        frame: &DispatchRequestFrame,
        now_unix_seconds: u64,
        invoke: F,
    ) -> Result<T, NodeDispatchError>
    where
        F: FnOnce() -> T,
    {
        self.assert_live_session(agent)?;
        self.assert_frame_session(frame.node_id, frame.node_generation, frame.connection_epoch)?;
        let reservation = self
            .reservations
            .iter()
            .find(|accepted| accepted.reservation_ref == frame.reservation_ref)
            .ok_or(NodeDispatchError::UnknownReservation)?;
        if reservation.attempt_ref != frame.attempt_ref {
            return Err(NodeDispatchError::AttemptMismatch);
        }
        if reservation.expires_at_unix_seconds <= now_unix_seconds {
            return Err(NodeDispatchError::ExpiredReservation);
        }
        let highest = self
            .fences
            .iter()
            .find(|fence| fence.attempt_ref == frame.attempt_ref)
            .map(|fence| fence.highest)
            .ok_or(NodeDispatchError::MissingCurrentLease)?;
        if frame.fence < highest {
            return Err(NodeDispatchError::StaleFence);
        }
        if frame.fence > highest {
            return Err(NodeDispatchError::FutureFence);
        }
        let lease = self
            .leases
            .iter()
            .find(|accepted| accepted.lease_ref == frame.lease_ref)
            .ok_or(NodeDispatchError::LeaseMismatch)?;
        if lease.attempt_ref != frame.attempt_ref {
            return Err(NodeDispatchError::AttemptMismatch);
        }
        if lease.reservation_ref != frame.reservation_ref {
            return Err(NodeDispatchError::ReservationMismatch);
        }
        if lease.fence != frame.fence {
            return if lease.fence < highest {
                Err(NodeDispatchError::StaleFence)
            } else {
                Err(NodeDispatchError::FutureFence)
            };
        }
        if lease.expires_at_unix_seconds <= now_unix_seconds {
            return Err(NodeDispatchError::ExpiredLease);
        }
        Ok(invoke())
    }

    fn assert_live_session(&self, agent: &NodeAgent) -> Result<(), NodeDispatchError> {
        if agent.node_id() != self.node_id
            || agent.generation() != self.node_generation
            || agent.connection_epoch() != self.connection_epoch
        {
            return Err(NodeDispatchError::SupersededSession);
        }
        Ok(())
    }

    fn assert_frame_session(
        &self,
        node_id: NodeId,
        node_generation: NodeGeneration,
        connection_epoch: ConnectionEpoch,
    ) -> Result<(), NodeDispatchError> {
        if node_id != self.node_id {
            return Err(NodeDispatchError::NodeIdentityMismatch);
        }
        if node_generation != self.node_generation {
            return Err(NodeDispatchError::NodeGenerationMismatch);
        }
        if connection_epoch != self.connection_epoch {
            return Err(NodeDispatchError::ConnectionEpochMismatch);
        }
        Ok(())
    }
}

/// Failures from the narrow E02-to-A05 native Provider dispatch boundary.
#[derive(Debug)]
pub enum NodeProviderDispatchError {
    /// E02 Node/session/Reservation/Lease/Fence authority rejected dispatch.
    Authority(NodeDispatchError),
    /// The real A05 Provider context no longer matches the A04 Attempt context.
    ProviderContextMismatch,
    /// The native A05 Provider rejected or failed mechanical execution.
    Provider(NativeProcessError),
}

/// Spawn through the real A05 native-process Provider only after E02 authority
/// admission and exact A04/A05 Provider-context currentness validation.
///
/// E02 does not copy or replace Provider identity/generation truth. The current
/// Provider derives an [`AttemptContext`] from A05 and that context must equal the
/// already selected A04 context before the Provider can execute.
///
/// # Errors
///
/// Returns [`NodeProviderDispatchError::Authority`] before entering Provider code
/// for stale E02 authority, [`NodeProviderDispatchError::ProviderContextMismatch`]
/// for stale A05 context, or [`NodeProviderDispatchError::Provider`] for an
/// admitted Provider execution failure.
pub fn spawn_native_process_if_authorized(
    guard: &NodeDispatchGuard,
    agent: &NodeAgent,
    frame: &DispatchRequestFrame,
    now_unix_seconds: u64,
    provider: &NativeProcessProvider,
    expected_attempt: &AttemptContext,
    spec: ProcessSpec,
) -> Result<EntityId, NodeProviderDispatchError> {
    guard
        .invoke_if_authorized(agent, frame, now_unix_seconds, || {
            let current = provider
                .attempt_context(
                    expected_attempt.workload_generation,
                    expected_attempt.facility_ref.clone(),
                )
                .map_err(NodeProviderDispatchError::Provider)?;
            if current != *expected_attempt {
                return Err(NodeProviderDispatchError::ProviderContextMismatch);
            }
            provider
                .spawn(spec)
                .map_err(NodeProviderDispatchError::Provider)
        })
        .map_err(NodeProviderDispatchError::Authority)?
}

/// Connect one Node to the E01 control plane, send its current A02 identity, and accept a matching hello acknowledgement.
///
/// This helper does not mutate Node Generation/epoch, persist capability truth,
/// or implement scheduling/placement/transfer semantics.
///
/// # Errors
///
/// Returns an E01 [`LinkError`] for TCP/TLS/framing failures, incompatible
/// protocol selection, or any acknowledgement that does not match the exact
/// Node identity, Generation, and epoch sent in the hello.
pub async fn run_node_link_client(
    agent: &NodeAgent,
    config: &NodeLinkClientConfig,
) -> Result<HelloAck, LinkError> {
    let tcp = TcpStream::connect(config.endpoint).await?;
    let mut tls = connect_tls(tcp, &config.server_name, &config.tls).await?;
    let hello = config.hello(agent);
    write_frame(
        tls.stream_mut(),
        &LinkMessage::Hello(Box::new(hello.clone())),
    )
    .await?;

    let LinkMessage::HelloAck(ack) = read_frame(tls.stream_mut()).await? else {
        return Err(LinkError::MalformedFrame(String::from(
            "expected hello_ack after node hello",
        )));
    };

    if ack.selected_version.major != config.protocol.major {
        return Err(LinkError::ProtocolIncompatible {
            local_major: config.protocol.major,
            remote_major: ack.selected_version.major,
        });
    }
    if ack.selected_version.minor != config.protocol.minor {
        return Err(LinkError::ProtocolMinorIncompatible {
            local_minor: config.protocol.minor,
            remote_min: ack.selected_version.minor,
            remote_max: ack.selected_version.minor,
        });
    }
    if ack.node_id != hello.node_id {
        return Err(LinkError::NodeIdentityMismatch);
    }
    if ack.node_generation != hello.node_generation {
        return Err(LinkError::StaleNodeGeneration {
            current: hello.node_generation.value(),
            requested: ack.node_generation.value(),
        });
    }
    if ack.connection_epoch != hello.connection_epoch {
        return Err(LinkError::StaleConnectionEpoch {
            current: hello.connection_epoch.value(),
            requested: ack.connection_epoch.value(),
        });
    }
    Ok(ack)
}
