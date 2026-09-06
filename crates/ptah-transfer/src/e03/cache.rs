use super::{E03TransferError, TransferTicket};
use ptah_identifiers::EntityRef;

/// E03 cache policy chosen by the caller before any route is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferCachePolicy {
    /// Ignore local cache evidence and perform the authorized network transfer.
    RequireNetworkTransfer,
    /// Reuse exact verified local content when its identity matches the ticket.
    ReuseVerifiedLocalContent,
}

/// Exact local cache evidence presented for E03 reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCacheEvidence {
    /// Canonical Content identity already accepted by A07.
    pub content_ref: EntityRef,
    /// Canonical verified Storage Location identity already accepted by A07.
    pub location_ref: EntityRef,
    /// Exact byte size of the retained local content.
    pub size: u64,
    /// Canonical SHA-256 of the retained local content.
    pub canonical_sha256: String,
    /// Whether the local evidence is already independently verified.
    pub verified: bool,
}

/// Mechanical E03 cache decision. This never creates A07 truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheDecision {
    /// Route bytes over the authorized E03 data plane.
    NetworkTransfer,
    /// Reuse an already-verified A07 Content/Location pair locally.
    ReuseVerified {
        /// Existing canonical Content reference.
        content_ref: EntityRef,
        /// Existing canonical verified Storage Location reference.
        location_ref: EntityRef,
    },
}

/// Decide whether E03 may reuse exact verified local content.
///
/// # Errors
///
/// Returns an explicit error when cache reuse was requested but the supplied
/// evidence is unverified or does not match the ticket's exact content identity.
pub fn decide_cache(
    ticket: &TransferTicket,
    policy: TransferCachePolicy,
    evidence: Option<&VerifiedCacheEvidence>,
) -> Result<CacheDecision, E03TransferError> {
    if policy == TransferCachePolicy::RequireNetworkTransfer {
        return Ok(CacheDecision::NetworkTransfer);
    }

    let Some(evidence) = evidence else {
        return Ok(CacheDecision::NetworkTransfer);
    };
    if !evidence.verified {
        return Err(E03TransferError::UnverifiedCacheEvidence);
    }
    if evidence.size != ticket.expected_size()
        || evidence.canonical_sha256 != ticket.canonical_sha256()
        || ticket
            .content_ref()
            .is_some_and(|expected| expected != &evidence.content_ref)
    {
        return Err(E03TransferError::CacheIdentityMismatch);
    }

    Ok(CacheDecision::ReuseVerified {
        content_ref: evidence.content_ref.clone(),
        location_ref: evidence.location_ref.clone(),
    })
}
