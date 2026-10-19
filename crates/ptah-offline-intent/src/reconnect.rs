//! E06-03 untrusted reconnect observations and non-authorizing comparison.
//!
//! Oracle transports the caller to Ptah's workspace, but is NOT E01/E02/E05
//! native authority. These fields are *observations*, not verified receipts.
//! Even an exact match must go to current external owners for verification.
use crate::{
    durable::{DurableIntentError, DurableIntentJournal},
    reconciliation::{valid_evidence_digest, ReconciliationFinding},
    QueuedIntent,
};

/// Observation of a reconnected source supplied by a separate caller.
///
/// No field is a cryptographic proof or grants native execution permission.
/// A real E01/E02/E03/E04/E05 owner must establish the current generation,
/// epoch, fence and object lineage independently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconnectObservation<'a> {
    pub intent_id: &'a str,
    pub origin_node_id: &'a str,
    pub origin_sequence: u64,
    pub workspace_id: &'a str,
    pub activity_id: &'a str,
    pub operation_id: &'a str,
    pub attempt_id: &'a str,
    pub canonical_input_digest: &'a str,
    pub created_at: &'a str,
    pub e01_session: Option<&'a str>,
    pub e02_fence: Option<&'a str>,
    pub e03_object_digest: Option<&'a str>,
    pub e03_object_generation: Option<&'a str>,
    pub e04_checkpoint_digest: Option<&'a str>,
    pub e05_host_profile_digest: Option<&'a str>,
    pub e05_admission_generation: Option<&'a str>,
    /// A previously uncertain effect must be reviewed, never replayed.
    pub uncertain_prior_effect: bool,
}

/// The only positive-shaped outcome is *pending external authority*.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconnectCheck {
    /// Observations match superficially, but are not authenticated or admitted.
    RequiresExternalOwnerReview,
    /// Negative finding eligible for one immutable local record.
    Rejected(ReconciliationFinding),
}
impl ReconnectCheck {
    #[must_use]
    pub const fn authority_granted(self) -> bool {
        false
    }
    #[must_use]
    pub const fn can_dispatch(self) -> bool {
        false
    }
}

/// Compare an exact queued envelope with a foreign reconnect observation.
///
/// This pure function may identify missing / inconsistent evidence. It
/// *cannot* verify credentials, fence freshness, host admission or A05 effect.
/// Even all fields present and equal never authorize replay.
///
/// # Panics
/// Does not panic for malformed input.
#[must_use]
pub fn check_reconnect(
    intent: &QueuedIntent,
    observed: &ReconnectObservation<'_>,
) -> ReconnectCheck {
    use ReconciliationFinding as F;
    if intent.intent_id != observed.intent_id
        || intent.origin.node_id != observed.origin_node_id
        || intent.origin.value != observed.origin_sequence
        || intent.workspace_id != observed.workspace_id
        || intent.activity_id != observed.activity_id
        || intent.operation_id != observed.operation_id
        || intent.attempt_id != observed.attempt_id
        || !intent.revalidate_required
    {
        return ReconnectCheck::Rejected(F::ConflictingEffect);
    }
    if !valid_evidence_digest(observed.canonical_input_digest)
        || observed.canonical_input_digest != intent.canonical_input_digest
    {
        return ReconnectCheck::Rejected(F::ChangedObject);
    }
    if observed.uncertain_prior_effect {
        return ReconnectCheck::Rejected(F::UnknownOutcome);
    }
    if !present(observed.e01_session) {
        return ReconnectCheck::Rejected(F::MissingE01);
    }
    if !present(observed.e02_fence) {
        return ReconnectCheck::Rejected(F::MissingE02);
    }
    if !present_digest(observed.e03_object_digest) || !present(observed.e03_object_generation) {
        return ReconnectCheck::Rejected(F::MissingE03);
    }
    if !present_digest(observed.e04_checkpoint_digest) {
        return ReconnectCheck::Rejected(F::MissingE04);
    }
    if !present_digest(observed.e05_host_profile_digest)
        || !present(observed.e05_admission_generation)
    {
        return ReconnectCheck::Rejected(F::MissingE05);
    }
    // A fresh observation alone cannot supply history absent from the
    // durable queue. Compare the observed versions against those recorded
    // *at original enqueue*, never merely the observer's current claims.
    let Some(ref saved) = intent.reconnect_dependencies else {
        return ReconnectCheck::Rejected(F::MissingE01);
    };
    if observed.created_at != saved.created_at {
        return ReconnectCheck::Rejected(F::ConflictingEffect);
    }
    if observed.e01_session != saved.e01_session.as_deref() {
        return ReconnectCheck::Rejected(F::StaleE01);
    }
    if observed.e02_fence != saved.e02_fence.as_deref() {
        return ReconnectCheck::Rejected(F::StaleFence);
    }
    if observed.e03_object_digest != saved.e03_object_digest.as_deref()
        || observed.e03_object_generation != saved.e03_object_generation.as_deref()
    {
        return ReconnectCheck::Rejected(F::ChangedObject);
    }
    if observed.e04_checkpoint_digest != saved.e04_checkpoint_digest.as_deref() {
        return ReconnectCheck::Rejected(F::ConflictingEffect);
    }
    if observed.e05_host_profile_digest != saved.e05_host_profile_digest.as_deref()
        || observed.e05_admission_generation != saved.e05_admission_generation.as_deref()
    {
        return ReconnectCheck::Rejected(F::ConflictingEffect);
    }
    ReconnectCheck::RequiresExternalOwnerReview
}

fn present(x: Option<&str>) -> bool {
    x.is_some_and(|s| {
        !s.is_empty() && s.len() <= 128 && s.trim() == s && s.bytes().all(|b| b.is_ascii_graphic())
    })
}
fn present_digest(x: Option<&str>) -> bool {
    x.is_some_and(valid_evidence_digest)
}

/// Read-only classification. Never a stored finding or admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconnectRecord {
    pub check: ReconnectCheck,
    pub authority_granted: bool,
    pub requires_external_owner_verification: bool,
}

impl DurableIntentJournal {
    /// Examine a reconnect observation without changing ANY durable state.
    ///
    /// An untrusted observer is not allowed to insert a permanent negative
    /// finding. Owners must independently verify evidence and use the
    /// separate owner-controlled record_finding API when appropriate.
    ///
    /// # Errors
    /// A missing intent, corrupted queue or a pre-existing finding fails
    /// closed. An observation cannot clear earlier reviewed evidence.
    pub fn observe_reconnect(
        &self,
        observed: &ReconnectObservation<'_>,
    ) -> Result<ReconnectRecord, DurableIntentError> {
        self.verify()?;
        let queued = self
            .history()?
            .into_iter()
            .find(|item| item.intent_id == observed.intent_id)
            .ok_or(DurableIntentError::Conflict(
                "unknown queued reconnect identity",
            ))?;
        if self
            .findings()?
            .iter()
            .any(|f| f.intent_id == queued.intent_id)
        {
            return Err(DurableIntentError::Conflict(
                "prior unresolved finding requires independent owner resolution",
            ));
        }
        Ok(ReconnectRecord {
            check: check_reconnect(&queued, observed),
            authority_granted: false,
            requires_external_owner_verification: true,
        })
    }
}
