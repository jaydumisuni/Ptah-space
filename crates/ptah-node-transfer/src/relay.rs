use crate::{MAX_RANGE_BYTES, RangeDataHeader, RangeRequest};
use ptah_identifiers::EntityRef;
use ptah_transfer::{
    E03TransferError, TransferPeerBinding, TransferPeerRole, TransferRouteCandidate,
    TransferRouteKind, TransferTicket,
};
use thiserror::Error;

/// Stable relay admission failures for the bounded single-hop E03 broker.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RelayAdmissionError {
    /// The presented ticket reference is not present in this broker registry.
    #[error("E03 relay ticket is unknown")]
    UnknownTicket,
    /// The route is not the exact relay candidate authorized by the ticket.
    #[error("E03 relay route is not authorized by the ticket")]
    UnauthorizedRelayRoute,
    /// The authenticated relay credential differs from the route fingerprint.
    #[error("E03 relay TLS credential fingerprint mismatch")]
    RelayFingerprintMismatch,
    /// The source or target projection does not belong to this exact ticket.
    #[error("E03 relay peer does not match ticket authority")]
    TicketPeerMismatch,
    /// A source is already paired to this ticket.
    #[error("E03 relay source already registered for ticket")]
    SourceAlreadyRegistered,
    /// A target is already paired to this ticket.
    #[error("E03 relay target already registered for ticket")]
    TargetAlreadyRegistered,
    /// The short-lived ticket is no longer live.
    #[error("E03 relay ticket expired")]
    ExpiredTicket,
}

/// Stable failures for bounded single-hop relay range forwarding.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RelayForwardError {
    /// The presented ticket is not registered with this broker.
    #[error("E03 relay ticket is unknown")]
    UnknownTicket,
    /// Both exact ticket peers have not completed relay admission.
    #[error("E03 relay source and target are not both paired")]
    PeersNotPaired,
    /// Request or payload metadata references a different ticket.
    #[error("E03 relay range ticket does not match paired ticket")]
    TicketMismatch,
    /// Range request, header, and payload lengths or offsets disagree.
    #[error("E03 relay range metadata is inconsistent")]
    RangeMetadataMismatch,
    /// The requested range exceeds the frozen E03 per-frame bound.
    #[error("E03 relay range exceeds the bounded frame limit")]
    RangeTooLarge,
}

/// One bounded range frame forwarded without creating relay storage authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayForwardedRange {
    /// Exact target-issued request being forwarded.
    pub request: RangeRequest,
    /// Exact source-produced range header being forwarded.
    pub header: RangeDataHeader,
    /// The single bounded in-flight payload; this is not canonical storage.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
struct RelayTicketState {
    ticket: TransferTicket,
    source_registered: bool,
    target_registered: bool,
}

/// Bounded single-hop relay authority for already-issued E03 tickets.
///
/// The broker cannot mint or mutate transfer authority. It keeps only one
/// source/target pairing bitset per supplied ticket. Forwarding is added only
/// after this admission boundary is independently proven.
#[derive(Debug, Clone)]
pub struct RelayBroker {
    tickets: Vec<RelayTicketState>,
}

impl RelayBroker {
    /// Construct a broker from the caller-owned live ticket registry snapshot.
    #[must_use]
    pub fn new(ticket_registry: Vec<TransferTicket>) -> Self {
        Self {
            tickets: ticket_registry
                .into_iter()
                .map(|ticket| RelayTicketState {
                    ticket,
                    source_registered: false,
                    target_registered: false,
                })
                .collect(),
        }
    }

    /// Admit the one source peer for an exact ticket and relay route.
    ///
    /// # Errors
    ///
    /// Fails closed for unknown/expired tickets, non-exact relay candidates,
    /// relay TLS fingerprint mismatch, ticket-peer mismatch, or a second source.
    pub fn register_source(
        &mut self,
        ticket_ref: &EntityRef,
        route: &TransferRouteCandidate,
        presented_source: &TransferPeerBinding,
        relay_tls_fingerprint: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<(), RelayAdmissionError> {
        self.register_peer(
            ticket_ref,
            route,
            presented_source,
            relay_tls_fingerprint,
            now_unix_seconds,
            TransferPeerRole::Source,
        )
    }

    /// Admit the one target peer for an exact ticket and relay route.
    ///
    /// # Errors
    ///
    /// Fails closed for unknown/expired tickets, non-exact relay candidates,
    /// relay TLS fingerprint mismatch, ticket-peer mismatch, or a second target.
    pub fn register_target(
        &mut self,
        ticket_ref: &EntityRef,
        route: &TransferRouteCandidate,
        presented_target: &TransferPeerBinding,
        relay_tls_fingerprint: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<(), RelayAdmissionError> {
        self.register_peer(
            ticket_ref,
            route,
            presented_target,
            relay_tls_fingerprint,
            now_unix_seconds,
            TransferPeerRole::Target,
        )
    }

    /// Forward one exact bounded range only after both ticket peers are paired.
    ///
    /// The relay retains no canonical object state; the returned payload is the
    /// single bounded in-flight range and the target remains responsible for
    /// digest verification and destination persistence.
    ///
    /// # Errors
    ///
    /// Fails closed when the ticket is unknown, both exact peers are not paired,
    /// ticket identities differ, range metadata is inconsistent, or the range
    /// exceeds the frozen E03 per-frame bound.
    pub fn forward_range(
        &self,
        ticket_ref: &EntityRef,
        request: RangeRequest,
        header: RangeDataHeader,
        payload: &[u8],
    ) -> Result<RelayForwardedRange, RelayForwardError> {
        let state = self
            .tickets
            .iter()
            .find(|state| state.ticket.ticket_ref() == ticket_ref)
            .ok_or(RelayForwardError::UnknownTicket)?;

        if !state.source_registered || !state.target_registered {
            return Err(RelayForwardError::PeersNotPaired);
        }
        if request.ticket_ref != *ticket_ref || header.ticket_ref != *ticket_ref {
            return Err(RelayForwardError::TicketMismatch);
        }
        if request.start != header.start
            || request.len != header.len
            || request.len != payload.len() as u64
        {
            return Err(RelayForwardError::RangeMetadataMismatch);
        }
        if request.len > MAX_RANGE_BYTES as u64 {
            return Err(RelayForwardError::RangeTooLarge);
        }

        Ok(RelayForwardedRange {
            request,
            header,
            payload: payload.to_vec(),
        })
    }

    fn register_peer(
        &mut self,
        ticket_ref: &EntityRef,
        route: &TransferRouteCandidate,
        presented_peer: &TransferPeerBinding,
        relay_tls_fingerprint: [u8; 32],
        now_unix_seconds: u64,
        role: TransferPeerRole,
    ) -> Result<(), RelayAdmissionError> {
        let state = self
            .tickets
            .iter_mut()
            .find(|state| state.ticket.ticket_ref() == ticket_ref)
            .ok_or(RelayAdmissionError::UnknownTicket)?;

        if now_unix_seconds >= state.ticket.expires_at_unix_seconds() {
            return Err(RelayAdmissionError::ExpiredTicket);
        }
        if route.kind != TransferRouteKind::Relay
            || route.relay_ref.is_none()
            || state.ticket.authorize_route(route).is_err()
        {
            return Err(RelayAdmissionError::UnauthorizedRelayRoute);
        }
        if relay_tls_fingerprint != route.expected_peer_fingerprint {
            return Err(RelayAdmissionError::RelayFingerprintMismatch);
        }
        match state
            .ticket
            .authorize_peer(role, presented_peer, now_unix_seconds)
        {
            Ok(()) => {}
            Err(E03TransferError::ExpiredTicket) => {
                return Err(RelayAdmissionError::ExpiredTicket);
            }
            Err(_) => return Err(RelayAdmissionError::TicketPeerMismatch),
        }

        let registered = match role {
            TransferPeerRole::Source => &mut state.source_registered,
            TransferPeerRole::Target => &mut state.target_registered,
        };
        if *registered {
            return Err(match role {
                TransferPeerRole::Source => RelayAdmissionError::SourceAlreadyRegistered,
                TransferPeerRole::Target => RelayAdmissionError::TargetAlreadyRegistered,
            });
        }
        *registered = true;
        Ok(())
    }
}
