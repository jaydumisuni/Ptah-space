use std::fmt;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSequence {
    pub node_id: String,
    pub value: u64,
}

fn validate_identity_field(name: &'static str, value: &str) -> Result<(), IntentValidationError> {
    if value.trim().is_empty() {
        return Err(IntentValidationError::Empty(name));
    }
    if value.chars().any(char::is_control) {
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
    pub fn checkpoint_bytes(&self) -> Result<Vec<u8>, IntentValidationError> {
        validate_identity_field("origin.node_id", &self.node_id)?;
        if self.value == 0 {
            return Err(IntentValidationError::ZeroSequence);
        }
        Ok(format!("ptah.local-sequence.v1\n{}\n{}\n", self.node_id, self.value).into_bytes())
    }

    pub fn from_checkpoint_bytes(bytes: &[u8]) -> Result<Self, IntentValidationError> {
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
