use crate::node_link::NodeLinkControl;
use ptah_identifiers::{EntityRef, NodeId};
use ptah_node_link::{CredentialFingerprint, LinkError, NodeHello, SessionBinding};
use ptah_transfer::{
    E03TransferError, TransferPeerBinding, TransferRouteCandidate, TransferTicket,
};
use std::collections::HashMap;

/// Caller-supplied immutable facts required to issue one E03 transfer ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferTicketSpec {
    /// Exact A08 transfer request.
    pub request_ref: EntityRef,
    /// Exact A08 transfer run.
    pub run_ref: EntityRef,
    /// Exact activity attempt.
    pub attempt_ref: EntityRef,
    /// Stable source Node identity. Current E01 binding is resolved by control.
    pub source_node_id: NodeId,
    /// Stable target Node identity. Current E01 binding is resolved by control.
    pub target_node_id: NodeId,
    /// Optional expected canonical content reference.
    pub content_ref: Option<EntityRef>,
    /// Optional expected canonical artifact reference.
    pub artifact_ref: Option<EntityRef>,
    /// Exact expected complete byte count.
    pub expected_size: u64,
    /// Canonical SHA-256 of the complete byte sequence.
    pub canonical_sha256: String,
    /// Exact range geometry used for resumable transfer.
    pub range_size: u64,
    /// Explicit caller-selected routes. Control does not discover or expand these.
    pub routes: Vec<TransferRouteCandidate>,
    /// Absolute short-lived ticket expiry.
    pub expires_at_unix_seconds: u64,
}

/// Stable failures from the sole control-side E03 ticket authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferAuthorityError {
    /// Source and target must be different stable Nodes for Node-to-Node transfer.
    SameNode,
    /// No current E01 source session exists.
    SourceSessionNotCurrent,
    /// No current E01 target session exists.
    TargetSessionNotCurrent,
    /// Requested expiry is not strictly in the future.
    InvalidExpiry,
    /// A canonical ticket identifier could not be allocated.
    InvalidIdentifier,
    /// The monotonic issuance nonce cannot advance safely.
    NonceExhausted,
    /// Mechanical E03 ticket validation failed.
    Ticket(E03TransferError),
    /// The supplied ticket is not one issued by this owner in its current process lifetime.
    UnknownTicket,
    /// The ticket was explicitly revoked.
    RevokedTicket,
    /// Source E01 authority was superseded or revoked after ticket issuance.
    SupersededSourceSession,
    /// Target E01 authority was superseded or revoked after ticket issuance.
    SupersededTargetSession,
}

impl From<E03TransferError> for TransferAuthorityError {
    fn from(value: E03TransferError) -> Self {
        Self::Ticket(value)
    }
}

#[derive(Debug, Clone)]
struct IssuedTicketState {
    ticket: TransferTicket,
    source_session: SessionBinding,
    target_session: SessionBinding,
    revoked: bool,
}

/// Sole control-plane owner for short-lived E03 transfer-ticket issuance/currentness.
///
/// The wrapped [`NodeLinkControl`] remains the sole E01 current-session authority;
/// this type keeps only ephemeral E03 ticket state and never creates a second
/// Node/session registry or A07 storage truth.
#[derive(Debug)]
pub struct TransferAuthorityOwner {
    node_link: NodeLinkControl,
    tickets: HashMap<EntityRef, IssuedTicketState>,
    next_nonce: u64,
}

impl TransferAuthorityOwner {
    /// Wrap the existing E01 control authority with empty E03 ticket state.
    #[must_use]
    pub fn new(node_link: NodeLinkControl) -> Self {
        Self {
            node_link,
            tickets: HashMap::new(),
            next_nonce: 1,
        }
    }

    /// Accept one E01 hello through the existing authoritative secure-link owner.
    ///
    /// # Errors
    ///
    /// Propagates existing E01 enrollment, protocol and replay/currentness failures.
    pub fn accept_hello(
        &mut self,
        hello: &NodeHello,
        credential_fingerprint: CredentialFingerprint,
        now_epoch_seconds: u64,
    ) -> Result<SessionBinding, LinkError> {
        self.node_link
            .accept_hello(hello, credential_fingerprint, now_epoch_seconds)
    }

    /// Issue one short-lived ticket from exact current E01 source/target sessions.
    ///
    /// Route candidates are preserved exactly as supplied. No discovery, route
    /// expansion, relay selection or A07 acceptance occurs here.
    ///
    /// # Errors
    ///
    /// Fails closed for same-Node transfers, absent current sessions, invalid
    /// expiry/identifier/nonce state, or invalid mechanical ticket facts.
    pub fn issue_ticket(
        &mut self,
        spec: TransferTicketSpec,
        now_unix_seconds: u64,
    ) -> Result<TransferTicket, TransferAuthorityError> {
        if spec.source_node_id == spec.target_node_id {
            return Err(TransferAuthorityError::SameNode);
        }
        if spec.expires_at_unix_seconds <= now_unix_seconds {
            return Err(TransferAuthorityError::InvalidExpiry);
        }

        let source_session = self
            .node_link
            .current_session(spec.source_node_id)
            .cloned()
            .ok_or(TransferAuthorityError::SourceSessionNotCurrent)?;
        let target_session = self
            .node_link
            .current_session(spec.target_node_id)
            .cloned()
            .ok_or(TransferAuthorityError::TargetSessionNotCurrent)?;

        let ticket_ref = EntityRef::new("transfer.ticket")
            .map_err(|_| TransferAuthorityError::InvalidIdentifier)?;
        let nonce = self.next_nonce;
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or(TransferAuthorityError::NonceExhausted)?;

        let source = binding_from_session(&source_session);
        let target = binding_from_session(&target_session);
        let ticket = TransferTicket::new(
            ticket_ref.clone(),
            spec.request_ref,
            spec.run_ref,
            spec.attempt_ref,
            source,
            target,
            spec.content_ref,
            spec.artifact_ref,
            spec.expected_size,
            spec.canonical_sha256,
            spec.range_size,
            spec.routes,
            now_unix_seconds,
            spec.expires_at_unix_seconds,
            nonce,
        )?;

        self.tickets.insert(
            ticket_ref,
            IssuedTicketState {
                ticket: ticket.clone(),
                source_session,
                target_session,
                revoked: false,
            },
        );
        Ok(ticket)
    }

    /// Recheck that a ticket remains the exact issued value and both E01 session
    /// bindings frozen at issuance are still current.
    ///
    /// # Errors
    ///
    /// Rejects unknown/mutated, revoked, source-superseded or target-superseded tickets.
    pub fn assert_current(
        &self,
        ticket: &TransferTicket,
    ) -> Result<(), TransferAuthorityError> {
        let state = self
            .tickets
            .get(ticket.ticket_ref())
            .ok_or(TransferAuthorityError::UnknownTicket)?;
        if &state.ticket != ticket {
            return Err(TransferAuthorityError::UnknownTicket);
        }
        if state.revoked {
            return Err(TransferAuthorityError::RevokedTicket);
        }
        if self
            .node_link
            .current_session(state.source_session.node_id)
            != Some(&state.source_session)
        {
            return Err(TransferAuthorityError::SupersededSourceSession);
        }
        if self
            .node_link
            .current_session(state.target_session.node_id)
            != Some(&state.target_session)
        {
            return Err(TransferAuthorityError::SupersededTargetSession);
        }
        Ok(())
    }

    /// Explicitly revoke one ticket issued by this owner.
    ///
    /// Returns `true` only when a known non-revoked ticket was transitioned to revoked.
    pub fn revoke_ticket(&mut self, ticket_ref: &EntityRef) -> bool {
        self.tickets.get_mut(ticket_ref).is_some_and(|state| {
            if state.revoked {
                false
            } else {
                state.revoked = true;
                true
            }
        })
    }
}

fn binding_from_session(session: &SessionBinding) -> TransferPeerBinding {
    TransferPeerBinding {
        node_id: session.node_id,
        node_generation: session.node_generation,
        connection_epoch: session.connection_epoch,
        credential_fingerprint: *session.credential_fingerprint.as_bytes(),
    }
}
