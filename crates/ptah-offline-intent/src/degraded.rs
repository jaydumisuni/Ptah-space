//! E06 degraded-state projection. This crate cannot mint authoritative state.
use crate::durable::{DurableIntentError, DurableIntentJournal};
/// Public degraded states permitted by the offline queue owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedState {
    /// Local data is readable; no queued action and no remote authority.
    OfflineLocal,
    /// Durable local intents exist but cannot be executed until revalidated.
    QueuedNotAuthorized,
    /// Reconnect is under consideration; no E01-E05 owner has accepted effects.
    Revalidating,
    /// An inconsistency or rejected authority reference needs owner review.
    Conflict,
}
impl DegradedState {
    /// Exact stable API value for a non-authoritative degraded condition.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OfflineLocal => "offline_local",
            Self::QueuedNotAuthorized => "queued_not_authorized",
            Self::Revalidating => "revalidating",
            Self::Conflict => "conflict",
        }
    }
}
/// Read-only view; authoritative state is intentionally unavailable here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradedProjection {
    /// Current local-only UI state.
    pub state: DegradedState,
    /// Number of durably queued local envelopes.
    pub pending_count: usize,
    /// Always false; only external accepted Ptah E01-E05 owners authorize.
    pub authority_granted: bool,
    /// Always true until external authority owners make a decision.
    pub revalidate_required: bool,
}
impl DegradedProjection {
    /// Verify the entire journal and project its local state. No action runs.
    ///
    /// # Errors
    /// Propagates journal corruption or failure.
    pub fn from_queue(journal: &DurableIntentJournal) -> Result<Self, DurableIntentError> {
        journal.verify()?;
        let count = journal.history()?.len();
        Ok(Self {
            state: if count == 0 {
                DegradedState::OfflineLocal
            } else {
                DegradedState::QueuedNotAuthorized
            },
            pending_count: count,
            authority_granted: false,
            revalidate_required: true,
        })
    }
    /// Request revalidation without downgrading an unresolved conflict.
    #[must_use]
    pub fn revalidating(self) -> Self {
        Self {
            state: if self.state == DegradedState::Conflict {
                DegradedState::Conflict
            } else {
                DegradedState::Revalidating
            },
            ..self
        }
    }
    /// Surface unresolved conflict without silently skipping or replaying it.
    #[must_use]
    pub fn conflict(self) -> Self {
        Self {
            state: DegradedState::Conflict,
            ..self
        }
    }
}
