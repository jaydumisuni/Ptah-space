use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::NodeAgent;
use ptah_node_link::CredentialFingerprint;
use ptah_transfer::{TransferPeerRole, TransferTicket};

/// Stable Node-local E03 transfer admission failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeTransferError {
    /// The live Node identity/Generation/epoch no longer matches this guard.
    SupersededSession,
    /// The ticket role presented to this Node belongs to the other ticket peer.
    WrongRole,
    /// The ticket was not previously admitted by this guard, or differs from the admitted value.
    UnknownTicket,
    /// The authenticated transport peer fingerprint does not match the opposite ticket peer.
    PeerFingerprintMismatch,
    /// The short-lived transfer ticket has expired.
    ExpiredTicket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AcceptedTicket {
    role: TransferPeerRole,
    ticket: TransferTicket,
}

/// Node-local E03 ticket admission state.
///
/// This guard cannot mint authority and contains no E02 Reservation, Lease,
/// Fence, placement, scheduling or discovery policy. It only admits exact
/// control-issued E03 tickets against the live [`NodeAgent`] session.
#[derive(Debug, Clone)]
pub struct NodeTransferGuard {
    node_id: NodeId,
    node_generation: NodeGeneration,
    connection_epoch: ConnectionEpoch,
    tickets: Vec<AcceptedTicket>,
}

impl NodeTransferGuard {
    /// Bind one E03 guard to the exact current A02/E01 Node session.
    #[must_use]
    pub fn for_agent(agent: &NodeAgent) -> Self {
        Self {
            node_id: agent.node_id(),
            node_generation: agent.generation(),
            connection_epoch: agent.connection_epoch(),
            tickets: Vec::new(),
        }
    }

    /// Admit one control-issued ticket only for this Node's exact ticket side.
    ///
    /// # Errors
    ///
    /// Rejects a superseded live Node session, wrong ticket role, stale ticket
    /// binding, expiry, or a conflicting ticket value for an already-admitted
    /// ticket reference.
    pub fn accept_ticket(
        &mut self,
        agent: &NodeAgent,
        role: TransferPeerRole,
        ticket: &TransferTicket,
        now_unix_seconds: u64,
    ) -> Result<(), NodeTransferError> {
        self.assert_live_session(agent)?;
        if now_unix_seconds >= ticket.expires_at_unix_seconds() {
            return Err(NodeTransferError::ExpiredTicket);
        }

        let local = match role {
            TransferPeerRole::Source => ticket.source(),
            TransferPeerRole::Target => ticket.target(),
        };
        if local.node_id != self.node_id {
            return Err(NodeTransferError::WrongRole);
        }
        if local.node_generation != self.node_generation
            || local.connection_epoch != self.connection_epoch
        {
            return Err(NodeTransferError::SupersededSession);
        }

        if let Some(accepted) = self
            .tickets
            .iter()
            .find(|accepted| accepted.ticket.ticket_ref() == ticket.ticket_ref())
        {
            if accepted.role == role && accepted.ticket == *ticket {
                return Ok(());
            }
            return Err(NodeTransferError::UnknownTicket);
        }

        self.tickets.push(AcceptedTicket {
            role,
            ticket: ticket.clone(),
        });
        Ok(())
    }

    /// Authorize the authenticated opposite transport peer for an admitted ticket.
    ///
    /// # Errors
    ///
    /// Rejects superseded local session state, unknown/mutated tickets, expiry,
    /// or a peer certificate fingerprint that differs from the exact opposite
    /// ticket-bound E01 credential.
    pub fn authorize_peer(
        &self,
        agent: &NodeAgent,
        ticket: &TransferTicket,
        peer_fingerprint: CredentialFingerprint,
        now_unix_seconds: u64,
    ) -> Result<(), NodeTransferError> {
        self.assert_live_session(agent)?;
        let accepted = self
            .tickets
            .iter()
            .find(|accepted| accepted.ticket.ticket_ref() == ticket.ticket_ref())
            .ok_or(NodeTransferError::UnknownTicket)?;
        if accepted.ticket != *ticket {
            return Err(NodeTransferError::UnknownTicket);
        }
        if now_unix_seconds >= ticket.expires_at_unix_seconds() {
            return Err(NodeTransferError::ExpiredTicket);
        }

        let expected_peer = match accepted.role {
            TransferPeerRole::Source => ticket.target(),
            TransferPeerRole::Target => ticket.source(),
        };
        if expected_peer.credential_fingerprint != *peer_fingerprint.as_bytes() {
            return Err(NodeTransferError::PeerFingerprintMismatch);
        }
        Ok(())
    }

    /// Return one exact ticket admitted by this guard.
    #[must_use]
    pub fn ticket(&self, ticket_ref: &EntityRef) -> Option<&TransferTicket> {
        self.tickets
            .iter()
            .find(|accepted| accepted.ticket.ticket_ref() == ticket_ref)
            .map(|accepted| &accepted.ticket)
    }

    fn assert_live_session(&self, agent: &NodeAgent) -> Result<(), NodeTransferError> {
        if agent.node_id() != self.node_id
            || agent.generation() != self.node_generation
            || agent.connection_epoch() != self.connection_epoch
        {
            return Err(NodeTransferError::SupersededSession);
        }
        Ok(())
    }
}
