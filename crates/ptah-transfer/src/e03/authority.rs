use super::E03TransferError;
use crate::model::TransferMode;
use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// E03 role held by one exact ticket-bound Node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferPeerRole {
    /// Node supplying exact source ranges.
    Source,
    /// Node receiving and verifying exact destination ranges.
    Target,
}

/// Exact current E01 peer authority projected into an E03 ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferPeerBinding {
    /// Stable canonical Node identity.
    pub node_id: NodeId,
    /// Exact current Node Generation.
    pub node_generation: NodeGeneration,
    /// Exact current E01 ConnectionEpoch.
    pub connection_epoch: ConnectionEpoch,
    /// SHA-256 bytes of the authenticated E01 end-entity credential.
    pub credential_fingerprint: [u8; 32],
}

/// Explicit E03 transport route kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferRouteKind {
    /// Source connects to target directly.
    Direct,
    /// Source and target use one explicitly authorized relay.
    Relay,
}

/// One explicit transport route frozen into a ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferRouteCandidate {
    /// Route class.
    pub kind: TransferRouteKind,
    /// Deployment-supplied transport endpoint; never canonical Node identity.
    pub endpoint: SocketAddr,
    /// TLS server name expected at the route endpoint.
    pub server_name: String,
    /// Exact authenticated endpoint credential fingerprint.
    pub expected_peer_fingerprint: [u8; 32],
    /// Canonical relay reference for relay routes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_ref: Option<EntityRef>,
}

/// Short-lived control-issued authority for one exact A08 Node-to-Node transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferTicket {
    ticket_ref: EntityRef,
    request_ref: EntityRef,
    run_ref: EntityRef,
    attempt_ref: EntityRef,
    source: TransferPeerBinding,
    target: TransferPeerBinding,
    content_ref: Option<EntityRef>,
    artifact_ref: Option<EntityRef>,
    expected_size: u64,
    canonical_sha256: String,
    range_size: u64,
    routes: Vec<TransferRouteCandidate>,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    nonce: u64,
}

impl TransferTicket {
    /// Construct one mechanically valid E03 ticket from already-authorized facts.
    ///
    /// This constructor does not choose peers, discover routes or authorize A07 truth.
    ///
    /// # Errors
    ///
    /// Rejects invalid byte geometry, digest/lifetime shape, empty routes or duplicates.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ticket_ref: EntityRef,
        request_ref: EntityRef,
        run_ref: EntityRef,
        attempt_ref: EntityRef,
        source: TransferPeerBinding,
        target: TransferPeerBinding,
        content_ref: Option<EntityRef>,
        artifact_ref: Option<EntityRef>,
        expected_size: u64,
        canonical_sha256: String,
        range_size: u64,
        routes: Vec<TransferRouteCandidate>,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
        nonce: u64,
    ) -> Result<Self, E03TransferError> {
        if expected_size == 0 || range_size == 0 {
            return Err(E03TransferError::InvalidGeometry);
        }
        if !is_canonical_sha256(&canonical_sha256) {
            return Err(E03TransferError::InvalidCanonicalDigest);
        }
        if issued_at_unix_seconds >= expires_at_unix_seconds {
            return Err(E03TransferError::InvalidLifetime);
        }
        if routes.is_empty() {
            return Err(E03TransferError::NoAuthorizedRoute);
        }
        if routes
            .iter()
            .enumerate()
            .any(|(index, route)| routes[..index].contains(route))
        {
            return Err(E03TransferError::DuplicateRoute);
        }

        Ok(Self {
            ticket_ref,
            request_ref,
            run_ref,
            attempt_ref,
            source,
            target,
            content_ref,
            artifact_ref,
            expected_size,
            canonical_sha256,
            range_size,
            routes,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            nonce,
        })
    }

    /// E03 tickets always authorize the frozen A08 Node-to-Node transfer mode.
    #[must_use]
    pub const fn transfer_mode(&self) -> TransferMode {
        TransferMode::NodeToNode
    }

    pub(super) const fn expected_size(&self) -> u64 {
        self.expected_size
    }

    pub(super) fn canonical_sha256(&self) -> &str {
        &self.canonical_sha256
    }

    pub(super) const fn range_size(&self) -> u64 {
        self.range_size
    }

    pub(super) fn content_ref(&self) -> Option<&EntityRef> {
        self.content_ref.as_ref()
    }

    /// Validate one presented peer against the exact ticket-bound E01 authority.
    ///
    /// # Errors
    ///
    /// Rejects identity, Generation, epoch, credential or expiry mismatch.
    pub fn authorize_peer(
        &self,
        role: TransferPeerRole,
        presented: &TransferPeerBinding,
        now_unix_seconds: u64,
    ) -> Result<(), E03TransferError> {
        let expected = match role {
            TransferPeerRole::Source => &self.source,
            TransferPeerRole::Target => &self.target,
        };
        if presented.node_id != expected.node_id {
            return Err(E03TransferError::NodeIdentityMismatch);
        }
        if presented.node_generation != expected.node_generation {
            return Err(E03TransferError::NodeGenerationMismatch);
        }
        if presented.connection_epoch != expected.connection_epoch {
            return Err(E03TransferError::ConnectionEpochMismatch);
        }
        if presented.credential_fingerprint != expected.credential_fingerprint {
            return Err(E03TransferError::CredentialFingerprintMismatch);
        }
        if now_unix_seconds >= self.expires_at_unix_seconds {
            return Err(E03TransferError::ExpiredTicket);
        }
        Ok(())
    }

    /// Validate that one exact route was explicitly frozen into this ticket.
    ///
    /// # Errors
    ///
    /// Returns [`E03TransferError::UnauthorizedRoute`] for ambient or mutated routes.
    pub fn authorize_route(
        &self,
        candidate: &TransferRouteCandidate,
    ) -> Result<(), E03TransferError> {
        if self.routes.contains(candidate) {
            Ok(())
        } else {
            Err(E03TransferError::UnauthorizedRoute)
        }
    }
}

fn is_canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
