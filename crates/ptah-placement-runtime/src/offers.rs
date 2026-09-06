use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::{NodeCapabilitySnapshot, NodeResourceSnapshot};
use ptah_node_link::{NodeOfferFrame, OfferedResource, SessionBinding};
use thiserror::Error;

const MAX_OFFERED_RESOURCES: usize = 64;
const MAX_RESOURCE_KEY_BYTES: usize = 128;
const MAX_LOCALITY_BYTES: usize = 128;

/// Stable fail-closed errors from advisory Node-offer validation.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum OfferError {
    /// Offer stable Node identity differs from the authenticated session.
    #[error("offer node identity does not match current session")]
    NodeIdentityMismatch,
    /// Offer or evidence Node Generation differs from the authenticated session.
    #[error("offer node generation does not match current session")]
    NodeGenerationMismatch,
    /// Offer or evidence Connection Epoch differs from the authenticated session.
    #[error("offer connection epoch does not match current session")]
    ConnectionEpochMismatch,
    /// Offer references capability evidence other than the supplied current snapshot.
    #[error("offer capability evidence does not match current snapshot")]
    CapabilityEvidenceMismatch,
    /// Offer references resource evidence other than the supplied current snapshot.
    #[error("offer resource evidence does not match current snapshot")]
    ResourceEvidenceMismatch,
    /// Offer validity ended at or before the validation instant.
    #[error("offer is expired")]
    Expired,
    /// Offer nonce must be positive.
    #[error("offer nonce must be positive")]
    InvalidNonce,
    /// Offered resource list or quantity is malformed or unsupported by current evidence.
    #[error("offered resource is invalid")]
    InvalidOfferedResource,
    /// Optional locality input exceeds the bounded wire-policy limit.
    #[error("offer locality exceeds bounded limit")]
    LocalityTooLong,
}

impl OfferError {
    /// Return a stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NodeIdentityMismatch => "node_identity_mismatch",
            Self::NodeGenerationMismatch => "node_generation_mismatch",
            Self::ConnectionEpochMismatch => "connection_epoch_mismatch",
            Self::CapabilityEvidenceMismatch => "capability_evidence_mismatch",
            Self::ResourceEvidenceMismatch => "resource_evidence_mismatch",
            Self::Expired => "expired",
            Self::InvalidNonce => "invalid_nonce",
            Self::InvalidOfferedResource => "invalid_offered_resource",
            Self::LocalityTooLong => "locality_too_long",
        }
    }
}

/// Validated short-lived advisory Node offer.
///
/// A `NodeOffer` is a deterministic placement input only. It never grants
/// Reservation, Lease, Fence or execution-changing dispatch authority.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeOffer {
    offer_ref: EntityRef,
    node_id: NodeId,
    node_generation: NodeGeneration,
    connection_epoch: ConnectionEpoch,
    capability_snapshot_ref: EntityRef,
    resource_snapshot_ref: EntityRef,
    offered_resources: Vec<OfferedResource>,
    load_score: Option<u16>,
    locality: Option<String>,
    valid_until_unix_seconds: u64,
    nonce: u64,
}

impl NodeOffer {
    /// Return the unique canonical offer reference.
    #[must_use]
    pub const fn offer_ref(&self) -> &EntityRef {
        &self.offer_ref
    }

    /// Return the stable canonical Node identity.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Return the exact Node Generation.
    #[must_use]
    pub const fn node_generation(&self) -> NodeGeneration {
        self.node_generation
    }

    /// Return the exact E01 Connection Epoch.
    #[must_use]
    pub const fn connection_epoch(&self) -> ConnectionEpoch {
        self.connection_epoch
    }

    /// Return the exact capability-snapshot evidence reference.
    #[must_use]
    pub const fn capability_snapshot_ref(&self) -> &EntityRef {
        &self.capability_snapshot_ref
    }

    /// Return the exact resource-snapshot evidence reference.
    #[must_use]
    pub const fn resource_snapshot_ref(&self) -> &EntityRef {
        &self.resource_snapshot_ref
    }

    /// Return the validated advisory resource quantities.
    #[must_use]
    pub fn offered_resources(&self) -> &[OfferedResource] {
        &self.offered_resources
    }

    /// Return the optional normalized load score.
    #[must_use]
    pub const fn load_score(&self) -> Option<u16> {
        self.load_score
    }

    /// Return the optional locality scoring fact.
    #[must_use]
    pub fn locality(&self) -> Option<&str> {
        self.locality.as_deref()
    }

    /// Return the offer expiry instant in Unix seconds.
    #[must_use]
    pub const fn valid_until_unix_seconds(&self) -> u64 {
        self.valid_until_unix_seconds
    }

    /// Return the positive sender-local offer nonce.
    #[must_use]
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Offers are advisory and can never authorize execution-changing dispatch.
    #[must_use]
    pub const fn authorizes_dispatch(&self) -> bool {
        false
    }
}

/// Validate one advisory Node offer against the authenticated E01 session and
/// the exact current A02 capability/resource snapshots it claims to represent.
///
/// # Errors
///
/// Returns [`OfferError`] for stale/cross-session identity, stale evidence,
/// expiry, invalid nonce, unbounded fields or a resource quantity not supported
/// by the supplied current resource snapshot.
pub fn validate_offer(
    session: &SessionBinding,
    offer: &NodeOfferFrame,
    capabilities: &NodeCapabilitySnapshot,
    resources: &NodeResourceSnapshot,
    now_unix_seconds: u64,
) -> Result<NodeOffer, OfferError> {
    validate_offer_session(session, offer)?;
    validate_evidence_session(session, capabilities, resources)?;

    if offer.capability_snapshot_ref != capabilities.snapshot_ref {
        return Err(OfferError::CapabilityEvidenceMismatch);
    }
    if offer.resource_snapshot_ref != resources.snapshot_ref {
        return Err(OfferError::ResourceEvidenceMismatch);
    }
    if offer.valid_until_unix_seconds <= now_unix_seconds {
        return Err(OfferError::Expired);
    }
    if offer.nonce == 0 {
        return Err(OfferError::InvalidNonce);
    }
    if offer.offered_resources.is_empty()
        || offer.offered_resources.len() > MAX_OFFERED_RESOURCES
        || offer
            .offered_resources
            .iter()
            .any(|offered| !offered_resource_is_current(offered, resources))
    {
        return Err(OfferError::InvalidOfferedResource);
    }
    if offer
        .locality
        .as_ref()
        .is_some_and(|value| value.len() > MAX_LOCALITY_BYTES)
    {
        return Err(OfferError::LocalityTooLong);
    }

    Ok(NodeOffer {
        offer_ref: offer.offer_ref.clone(),
        node_id: offer.node_id,
        node_generation: offer.node_generation,
        connection_epoch: offer.connection_epoch,
        capability_snapshot_ref: offer.capability_snapshot_ref.clone(),
        resource_snapshot_ref: offer.resource_snapshot_ref.clone(),
        offered_resources: offer.offered_resources.clone(),
        load_score: offer.load_score,
        locality: offer.locality.clone(),
        valid_until_unix_seconds: offer.valid_until_unix_seconds,
        nonce: offer.nonce,
    })
}

fn validate_offer_session(
    session: &SessionBinding,
    offer: &NodeOfferFrame,
) -> Result<(), OfferError> {
    if offer.node_id != session.node_id {
        return Err(OfferError::NodeIdentityMismatch);
    }
    if offer.node_generation != session.node_generation {
        return Err(OfferError::NodeGenerationMismatch);
    }
    if offer.connection_epoch != session.connection_epoch {
        return Err(OfferError::ConnectionEpochMismatch);
    }
    Ok(())
}

fn validate_evidence_session(
    session: &SessionBinding,
    capabilities: &NodeCapabilitySnapshot,
    resources: &NodeResourceSnapshot,
) -> Result<(), OfferError> {
    if capabilities.node_ref.entity_id != session.node_id.entity_id()
        || resources.node_ref.entity_id != session.node_id.entity_id()
    {
        return Err(OfferError::NodeIdentityMismatch);
    }
    if capabilities.node_generation != session.node_generation
        || resources.node_generation != session.node_generation
        || capabilities.node_ref.node_generation != Some(session.node_generation.value())
        || resources.node_ref.node_generation != Some(session.node_generation.value())
    {
        return Err(OfferError::NodeGenerationMismatch);
    }
    if capabilities.connection_epoch != session.connection_epoch
        || resources.connection_epoch != session.connection_epoch
        || capabilities.node_ref.connection_epoch != Some(session.connection_epoch.value())
        || resources.node_ref.connection_epoch != Some(session.connection_epoch.value())
    {
        return Err(OfferError::ConnectionEpochMismatch);
    }
    Ok(())
}

fn offered_resource_is_current(
    offered: &OfferedResource,
    resources: &NodeResourceSnapshot,
) -> bool {
    if offered.resource_key.is_empty()
        || offered.resource_key.len() > MAX_RESOURCE_KEY_BYTES
        || !offered.quantity.is_finite()
        || offered.quantity <= 0.0
    {
        return false;
    }

    resources.resources.iter().any(|current| {
        current.resource_key == offered.resource_key
            && current.unit == offered.unit
            && offered.quantity <= current.currently_available
            && offered.quantity <= current.administratively_allocatable
    })
}
