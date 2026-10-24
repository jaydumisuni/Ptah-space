use std::{collections::HashMap, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentValidationError {
    Empty(&'static str),
    ControlCharacter(&'static str),
    NonCanonicalWhitespace(&'static str),
    TooLong(&'static str),
    InvalidDigest,
    ZeroSequence,
    SequenceExhausted,
    InvalidCheckpoint,
    CheckpointNodeMismatch,
    CheckpointRollback,
    CheckpointJournalMismatch,
    ConflictingReplay,
    ReusedOriginSequence,
    OutOfOrderOriginSequence,
    MissingOriginSequence,
    UnexpectedOriginSequence,
    InvalidReplayState,
}

impl fmt::Display for IntentValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(field) => write!(f, "{field} must not be empty"),
            Self::ControlCharacter(field) => write!(f, "{field} contains a control character"),
            Self::NonCanonicalWhitespace(field) => {
                write!(f, "{field} has leading or trailing whitespace")
            }
            Self::TooLong(field) => write!(f, "{field} exceeds 128 bytes"),
            Self::InvalidDigest => write!(
                f,
                "canonical_input_digest must be sha256:<64 lowercase hex>"
            ),
            Self::ZeroSequence => write!(f, "origin sequence must be non-zero"),
            Self::SequenceExhausted => write!(f, "origin sequence exhausted"),
            Self::InvalidCheckpoint => {
                write!(f, "invalid or noncanonical local sequence checkpoint")
            }
            Self::CheckpointNodeMismatch => {
                write!(f, "recovered checkpoint belongs to another node")
            }
            Self::CheckpointRollback => {
                write!(f, "recovered checkpoint would roll back local sequence")
            }
            Self::CheckpointJournalMismatch => {
                write!(
                    f,
                    "append journal does not match recovered local checkpoint"
                )
            }
            Self::ConflictingReplay => write!(f, "intent identity replays different content"),
            Self::ReusedOriginSequence => {
                write!(f, "origin sequence is already bound to another intent")
            }
            Self::OutOfOrderOriginSequence => {
                write!(f, "journal origin sequence regressed within one node")
            }
            Self::MissingOriginSequence => {
                write!(f, "missing interior journal origin sequence")
            }
            Self::UnexpectedOriginSequence => {
                write!(
                    f,
                    "queued intent origin is not the prepared local successor"
                )
            }
            Self::InvalidReplayState => write!(f, "replay cannot waive revalidation"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalIntentState {
    LocalOnly,
    QueuedIntent,
    Revalidating,
    RejectedStale,
    ReadyToApply,
    Applied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDisposition {
    Distinct,
    Idempotent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSequence {
    pub node_id: String,
    pub value: u64,
}

fn validate_identity_field(name: &'static str, value: &str) -> Result<(), IntentValidationError> {
    if value.trim().is_empty() {
        return Err(IntentValidationError::Empty(name));
    }
    if value
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{00AD}' | '\u{034F}' | '\u{180E}' | '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{E0100}'..='\u{E01EF}' | '\u{061C}' | '\u{200E}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{206F}' | '\u{17B4}' | '\u{17B5}' | '\u{1D173}'..='\u{1D17A}' | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D185}'..='\u{1D18B}' | '\u{1D1AA}'..='\u{1D1AD}'))
    {
        return Err(IntentValidationError::ControlCharacter(name));
    }
    if value != value.trim() {
        return Err(IntentValidationError::NonCanonicalWhitespace(name));
    }
    if value.len() > 128 {
        return Err(IntentValidationError::TooLong(name));
    }
    Ok(())
}

impl LocalSequence {
    // E06-01: a deterministic successor, not a durable allocator or an authority grant.
    // E06-02 must persist and atomically advance the cursor before exposing a new intent.
    pub fn checked_next(&self) -> Result<Self, IntentValidationError> {
        validate_identity_field("origin.node_id", &self.node_id)?;
        if self.value == 0 {
            return Err(IntentValidationError::ZeroSequence);
        }
        let value = self
            .value
            .checked_add(1)
            .ok_or(IntentValidationError::SequenceExhausted)?;
        Ok(Self {
            node_id: self.node_id.clone(),
            value,
        })
    }
}

// E06-02 preparation: strict recovery codec only. This does not write, lock,
// fsync, allocate, or grant authority. A future durable allocator must commit
// the new cursor atomically before exposing an intent.
impl LocalSequence {
    // E06-02 preparation: compare recovered cursor to last trusted cursor.
    // Equality is an idempotent replay, not a new allocation or authority grant.
    pub fn validate_recovered_cursor(&self, recovered: &Self) -> Result<(), IntentValidationError> {
        self.checkpoint_bytes()?;
        recovered.checkpoint_bytes()?;
        if self.node_id != recovered.node_id {
            return Err(IntentValidationError::CheckpointNodeMismatch);
        }
        if recovered.value < self.value {
            return Err(IntentValidationError::CheckpointRollback);
        }
        Ok(())
    }

    // E06-02 preparation: untrusted bytes must be decoded and checked against
    // the trusted cursor together. This is not durable allocation or a grant.
    pub fn recover_checked_checkpoint(&self, bytes: &[u8]) -> Result<Self, IntentValidationError> {
        let recovered = Self::from_checkpoint_bytes(bytes)?;
        self.validate_recovered_cursor(&recovered)?;
        Ok(recovered)
    }

    // E06-02 preparation: produce only a tentative successor after verifying
    // untrusted recovery bytes against the trusted cursor. A durable store must
    // atomically commit this value before an intent can reference it.
    pub fn prepare_next_after_checkpoint(
        &self,
        bytes: &[u8],
    ) -> Result<Self, IntentValidationError> {
        self.recover_checked_checkpoint(bytes)?.checked_next()
    }

    pub fn checkpoint_bytes(&self) -> Result<Vec<u8>, IntentValidationError> {
        validate_identity_field("origin.node_id", &self.node_id)?;
        if self.value == 0 {
            return Err(IntentValidationError::ZeroSequence);
        }
        Ok(format!("ptah.local-sequence.v1\n{}\n{}\n", self.node_id, self.value).into_bytes())
    }

    pub fn from_checkpoint_bytes(bytes: &[u8]) -> Result<Self, IntentValidationError> {
        // Bound untrusted recovery input before UTF-8 decoding or allocating fields.
        // Header + 128-byte node ID + separators + 20-digit u64 = 173 bytes.
        if bytes.len() > 173 {
            return Err(IntentValidationError::InvalidCheckpoint);
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| IntentValidationError::InvalidCheckpoint)?;
        let mut fields = text.split('\n');
        if fields.next() != Some("ptah.local-sequence.v1") {
            return Err(IntentValidationError::InvalidCheckpoint);
        }
        let node_id = fields
            .next()
            .ok_or(IntentValidationError::InvalidCheckpoint)?;
        let raw_value = fields
            .next()
            .ok_or(IntentValidationError::InvalidCheckpoint)?;
        if fields.next() != Some("") || fields.next().is_some() {
            return Err(IntentValidationError::InvalidCheckpoint);
        }
        validate_identity_field("origin.node_id", node_id)?;
        let value: u64 = raw_value
            .parse()
            .map_err(|_| IntentValidationError::InvalidCheckpoint)?;
        if value.to_string() != raw_value {
            return Err(IntentValidationError::InvalidCheckpoint);
        }
        if value == 0 {
            return Err(IntentValidationError::ZeroSequence);
        }
        Ok(Self {
            node_id: node_id.to_owned(),
            value,
        })
    }
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
    // Public fields can be mutated after construction. Validate both envelopes
    // again before comparing identities; this is not a durable append or grant.
    fn validate_replay_envelope(&self) -> Result<(), IntentValidationError> {
        if !self.revalidate_required {
            return Err(IntentValidationError::InvalidReplayState);
        }
        Self::try_new(
            self.intent_id.clone(),
            self.workspace_id.clone(),
            self.activity_id.clone(),
            self.operation_id.clone(),
            self.attempt_id.clone(),
            self.origin.clone(),
            self.action.clone(),
            self.canonical_input_digest.clone(),
        )?;
        Ok(())
    }

    // E06-02 pre-append guard: bind the mutable intent to the exact successor
    // of a recovered checkpoint and trusted cursor. This does not persist the
    // cursor or envelope, lock the journal, or grant execution authority.
    pub fn preflight_origin_after_checkpoint(
        &self,
        trusted_cursor: &LocalSequence,
        checkpoint_bytes: &[u8],
    ) -> Result<(), IntentValidationError> {
        self.validate_replay_envelope()?;
        let expected = trusted_cursor.prepare_next_after_checkpoint(checkpoint_bytes)?;
        if self.origin.node_id != expected.node_id {
            return Err(IntentValidationError::CheckpointNodeMismatch);
        }
        if self.origin.value != expected.value {
            return Err(IntentValidationError::UnexpectedOriginSequence);
        }
        Ok(())
    }

    // E06-02 preparation: inspect the entire append history before accepting a
    // candidate. An earlier idempotent match must not conceal a later conflict.
    // This is pure preflight; the durable store must hold its append lock and
    // atomically persist the cursor and envelope before acknowledging either.
    pub fn classify_against_history<'a>(
        &self,
        history: impl IntoIterator<Item = &'a Self>,
    ) -> Result<ReplayDisposition, IntentValidationError> {
        self.validate_replay_envelope()?;
        // A candidate must not be admitted over a corrupt existing journal,
        // even when its own identity is unrelated to the conflicting records.
        // Index by both identity and origin to keep this preflight linear.
        let mut seen_ids: HashMap<&str, &Self> = HashMap::new();
        let mut seen_origins: HashMap<(&str, u64), &Self> = HashMap::new();
        let mut replayed = false;
        // Validate append order while streaming history rather than
        // materializing an unbounded second copy of the journal.
        let mut last_sequence_by_node: HashMap<&str, u64> = HashMap::new();
        for stored in history {
            stored.validate_replay_envelope()?;
            if let Some(previous) = last_sequence_by_node.get(stored.origin.node_id.as_str()) {
                if stored.origin.value < *previous {
                    return Err(IntentValidationError::OutOfOrderOriginSequence);
                }
                if stored.origin.value > *previous && stored.origin.value - *previous != 1 {
                    return Err(IntentValidationError::MissingOriginSequence);
                }
            }
            last_sequence_by_node.insert(stored.origin.node_id.as_str(), stored.origin.value);
            if let Some(prior) = seen_ids.get(stored.intent_id.as_str()) {
                prior.classify_replay(stored)?;
            }
            if let Some(prior) =
                seen_origins.get(&(stored.origin.node_id.as_str(), stored.origin.value))
            {
                prior.classify_replay(stored)?;
            }
            seen_ids.insert(&stored.intent_id, stored);
            seen_origins.insert((&stored.origin.node_id, stored.origin.value), stored);
            match stored.classify_replay(self)? {
                ReplayDisposition::Idempotent => replayed = true,
                ReplayDisposition::Distinct => {}
            }
        }
        Ok(if replayed {
            ReplayDisposition::Idempotent
        } else {
            ReplayDisposition::Distinct
        })
    }

    // E06-02 pure pre-append composition. An exact idempotent replay is not
    // a new allocation; distinct intents must be the recovered successor and
    // extend the validated journal order. The durable writer must still hold
    // its lock and atomically persist cursor plus envelope before acknowledging.
    pub fn preflight_append_after_checkpoint<'a>(
        &self,
        trusted_cursor: &LocalSequence,
        checkpoint_bytes: &[u8],
        history: impl IntoIterator<Item = &'a Self>,
    ) -> Result<ReplayDisposition, IntentValidationError> {
        self.validate_replay_envelope()?;
        let recovered = trusted_cursor.recover_checked_checkpoint(checkpoint_bytes)?;
        if self.origin.node_id != recovered.node_id {
            return Err(IntentValidationError::CheckpointNodeMismatch);
        }
        let mut last_same_node_sequence = None;
        let replay = self.classify_against_history(history.into_iter().inspect(|stored| {
            if stored.origin.node_id == self.origin.node_id {
                last_same_node_sequence = Some(stored.origin.value);
            }
        }))?;
        // The append-only journal tail must agree with the recovered cursor.
        // A missing tail is corruption too: a successor must not skip a lost
        // local intent merely because the checkpoint itself is well-formed.
        // A checkpoint cannot replace missing journal evidence, even when
        // both the trusted and recovered cursors agree on the same value.
        let journal_matches_checkpoint = last_same_node_sequence == Some(recovered.value);
        if !journal_matches_checkpoint {
            return Err(IntentValidationError::CheckpointJournalMismatch);
        }
        if replay == ReplayDisposition::Idempotent {
            return Ok(replay);
        }
        if self.origin.value != recovered.checked_next()?.value {
            return Err(IntentValidationError::UnexpectedOriginSequence);
        }
        if last_same_node_sequence.is_some_and(|last| self.origin.value < last) {
            return Err(IntentValidationError::OutOfOrderOriginSequence);
        }
        Ok(replay)
    }

    // E06-02 ordered journal recovery guard. Replay preflight and recovery
    // both reject an append journal that moves a node's sequence backwards.
    // This is pure validation; the durable reader must separately validate
    // replay conflicts and must not infer authorization from journal ordering.
    pub fn validate_append_order<'a>(
        history: impl IntoIterator<Item = &'a Self>,
    ) -> Result<(), IntentValidationError> {
        let mut last_sequence_by_node: HashMap<&str, u64> = HashMap::new();
        for stored in history {
            stored.validate_replay_envelope()?;
            if let Some(previous) = last_sequence_by_node.get(stored.origin.node_id.as_str()) {
                if stored.origin.value < *previous {
                    return Err(IntentValidationError::OutOfOrderOriginSequence);
                }
                if stored.origin.value > *previous && stored.origin.value - *previous != 1 {
                    return Err(IntentValidationError::MissingOriginSequence);
                }
            }
            last_sequence_by_node.insert(stored.origin.node_id.as_str(), stored.origin.value);
        }
        Ok(())
    }

    // E06-02 pure idempotency preflight; no storage, allocation, or authority grant.
    // The durable store must apply this under its atomic append lock.
    pub fn classify_replay(
        &self,
        candidate: &Self,
    ) -> Result<ReplayDisposition, IntentValidationError> {
        self.validate_replay_envelope()?;
        candidate.validate_replay_envelope()?;
        if self.intent_id == candidate.intent_id {
            return if self == candidate {
                Ok(ReplayDisposition::Idempotent)
            } else {
                Err(IntentValidationError::ConflictingReplay)
            };
        }
        if self.origin == candidate.origin {
            return Err(IntentValidationError::ReusedOriginSequence);
        }
        Ok(ReplayDisposition::Distinct)
    }

    // E06 keeps each canonical identity explicit at construction so authority-bound fields
    // cannot be silently omitted or inherited from ambient state.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        intent_id: String,
        workspace_id: String,
        activity_id: String,
        operation_id: String,
        attempt_id: String,
        origin: LocalSequence,
        action: String,
        canonical_input_digest: String,
    ) -> Result<Self, IntentValidationError> {
        for (name, value) in [
            ("intent_id", intent_id.as_str()),
            ("workspace_id", workspace_id.as_str()),
            ("activity_id", activity_id.as_str()),
            ("operation_id", operation_id.as_str()),
            ("attempt_id", attempt_id.as_str()),
            ("origin.node_id", origin.node_id.as_str()),
            ("action", action.as_str()),
        ] {
            validate_identity_field(name, value)?;
        }
        if origin.value == 0 {
            return Err(IntentValidationError::ZeroSequence);
        }
        let digest = canonical_input_digest
            .strip_prefix("sha256:")
            .ok_or(IntentValidationError::InvalidDigest)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(IntentValidationError::InvalidDigest);
        }
        Ok(Self {
            intent_id,
            workspace_id,
            activity_id,
            operation_id,
            attempt_id,
            origin,
            action,
            canonical_input_digest,
            revalidate_required: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> Result<QueuedIntent, IntentValidationError> {
        QueuedIntent::try_new(
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
            format!("sha256:{}", "a".repeat(64)),
        )
    }

    #[test]
    fn queued_intent_is_never_authorized_by_construction() {
        assert!(valid().unwrap().revalidate_required);
    }

    #[test]
    fn queue_identity_fails_closed_on_ambiguous_or_empty_fields() {
        let mut q = valid().unwrap();
        q.intent_id.clear();
        assert!(matches!(
            QueuedIntent::try_new(
                q.intent_id,
                q.workspace_id,
                q.activity_id,
                q.operation_id,
                q.attempt_id,
                q.origin,
                q.action,
                q.canonical_input_digest
            ),
            Err(IntentValidationError::Empty("intent_id"))
        ));
        assert!(matches!(
            QueuedIntent::try_new(
                "i1".into(),
                "w1".into(),
                "a1".into(),
                "o1".into(),
                "t1".into(),
                LocalSequence {
                    node_id: "n1".into(),
                    value: 1
                },
                "prepare\nexecute".into(),
                format!("sha256:{}", "a".repeat(64))
            ),
            Err(IntentValidationError::ControlCharacter("action"))
        ));
    }

    #[test]
    fn queue_origin_and_digest_are_canonical() {
        assert!(matches!(
            QueuedIntent::try_new(
                "i1".into(),
                "w1".into(),
                "a1".into(),
                "o1".into(),
                "t1".into(),
                LocalSequence {
                    node_id: "n1".into(),
                    value: 0
                },
                "prepare".into(),
                format!("sha256:{}", "a".repeat(64))
            ),
            Err(IntentValidationError::ZeroSequence)
        ));
        assert!(matches!(
            QueuedIntent::try_new(
                "i1".into(),
                "w1".into(),
                "a1".into(),
                "o1".into(),
                "t1".into(),
                LocalSequence {
                    node_id: "n1".into(),
                    value: 1
                },
                "prepare".into(),
                format!("sha256:{}", "A".repeat(64))
            ),
            Err(IntentValidationError::InvalidDigest)
        ));
    }
}

/// Durable per-Node queued-intent journal; no execution authority.
pub mod durable;

/// Non-authoritative offline/revalidation/conflict status projection.
pub mod degraded;

/// Immutable negative reconciliation receipts; never an authorization source.
pub mod reconciliation;
