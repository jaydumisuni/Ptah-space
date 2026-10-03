#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalIntentState {
    LocalOnly,
    QueuedIntent,
    Revalidating,
    RejectedStale,
    ReadyToApply,
    Applied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSequence {
    pub node_id: String,
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedIntent {
    pub intent_id: String,
    pub workspace_id: String,
    pub activity_id: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub origin: LocalSequence,
    pub action: String,
    pub canonical_input_digest: String,
    pub revalidate_required: bool,
}

impl QueuedIntent {
    pub fn new(
        intent_id: String,
        workspace_id: String,
        activity_id: String,
        operation_id: String,
        attempt_id: String,
        origin: LocalSequence,
        action: String,
        canonical_input_digest: String,
    ) -> Self {
        Self {
            intent_id,
            workspace_id,
            activity_id,
            operation_id,
            attempt_id,
            origin,
            action,
            canonical_input_digest,
            revalidate_required: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queued_intent_is_never_authorized_by_construction() {
        let q = QueuedIntent::new(
            "i1".into(),
            "w1".into(),
            "a1".into(),
            "o1".into(),
            "t1".into(),
            LocalSequence {
                node_id: "n1".into(),
                value: 1,
            },
            "prepare".into(),
            "sha256:test".into(),
        );
        assert!(q.revalidate_required);
    }
}
