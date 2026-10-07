use ptah_offline_intent::{IntentValidationError, LocalSequence, QueuedIntent};

fn queued(
    action: &str,
    sequence: u64,
    digest: String,
) -> Result<QueuedIntent, IntentValidationError> {
    QueuedIntent::try_new(
        "intent-1".into(),
        "workspace-1".into(),
        "activity-1".into(),
        "operation-1".into(),
        "attempt-1".into(),
        LocalSequence {
            node_id: "node-1".into(),
            value: sequence,
        },
        action.into(),
        digest,
    )
}

#[test]
fn queued_intent_always_requires_revalidation() {
    let intent = queued("prepare", 1, format!("sha256:{}", "a".repeat(64))).unwrap();
    assert!(intent.revalidate_required);
}

#[test]
fn identity_and_action_validation_fail_closed() {
    let empty = QueuedIntent::try_new(
        String::new(),
        "workspace-1".into(),
        "activity-1".into(),
        "operation-1".into(),
        "attempt-1".into(),
        LocalSequence {
            node_id: "node-1".into(),
            value: 1,
        },
        "prepare".into(),
        format!("sha256:{}", "a".repeat(64)),
    );
    assert!(matches!(
        empty,
        Err(IntentValidationError::Empty("intent_id"))
    ));

    let spaced = QueuedIntent::try_new(
        " intent-1".into(),
        "workspace-1".into(),
        "activity-1".into(),
        "operation-1".into(),
        "attempt-1".into(),
        LocalSequence {
            node_id: "node-1".into(),
            value: 1,
        },
        "prepare".into(),
        format!("sha256:{}", "a".repeat(64)),
    );
    assert!(matches!(
        spaced,
        Err(IntentValidationError::NonCanonicalWhitespace("intent_id"))
    ));

    let control = queued("prepare\nexecute", 1, format!("sha256:{}", "a".repeat(64)));
    assert!(matches!(
        control,
        Err(IntentValidationError::ControlCharacter("action"))
    ));
}

#[test]
fn every_authority_bound_identity_length_fails_closed() {
    let oversized = "i".repeat(129);
    let cases = [
        ("intent_id", 0usize),
        ("workspace_id", 1),
        ("activity_id", 2),
        ("operation_id", 3),
        ("attempt_id", 4),
        ("origin.node_id", 5),
        ("action", 6),
    ];

    for (expected_field, field_index) in cases {
        let mut fields = [
            "intent-1".to_owned(),
            "workspace-1".to_owned(),
            "activity-1".to_owned(),
            "operation-1".to_owned(),
            "attempt-1".to_owned(),
            "node-1".to_owned(),
            "prepare".to_owned(),
        ];
        fields[field_index] = oversized.clone();

        let result = QueuedIntent::try_new(
            fields[0].clone(),
            fields[1].clone(),
            fields[2].clone(),
            fields[3].clone(),
            fields[4].clone(),
            LocalSequence {
                node_id: fields[5].clone(),
                value: 1,
            },
            fields[6].clone(),
            format!("sha256:{}", "a".repeat(64)),
        );
        assert!(matches!(
            result,
            Err(IntentValidationError::TooLong(field)) if field == expected_field
        ));
    }
}

#[test]
fn every_authority_bound_identity_rejects_control_characters() {
    let cases = [
        ("intent_id", 0usize),
        ("workspace_id", 1),
        ("activity_id", 2),
        ("operation_id", 3),
        ("attempt_id", 4),
        ("origin.node_id", 5),
        ("action", 6),
    ];
    for (expected_field, field_index) in cases {
        let mut fields = [
            "intent-1".to_owned(),
            "workspace-1".to_owned(),
            "activity-1".to_owned(),
            "operation-1".to_owned(),
            "attempt-1".to_owned(),
            "node-1".to_owned(),
            "prepare".to_owned(),
        ];
        fields[field_index].push('\n');
        let result = QueuedIntent::try_new(
            fields[0].clone(),
            fields[1].clone(),
            fields[2].clone(),
            fields[3].clone(),
            fields[4].clone(),
            LocalSequence {
                node_id: fields[5].clone(),
                value: 1,
            },
            fields[6].clone(),
            format!("sha256:{}", "a".repeat(64)),
        );
        assert!(matches!(
            result,
            Err(IntentValidationError::ControlCharacter(field)) if field == expected_field
        ));
    }
}

#[test]
fn origin_sequence_must_be_non_zero() {
    let result = queued("prepare", 0, format!("sha256:{}", "a".repeat(64)));
    assert!(matches!(result, Err(IntentValidationError::ZeroSequence)));
}

#[test]
fn canonical_digest_accepts_lowercase_and_rejects_malformed_or_uppercase() {
    assert!(queued("prepare", 1, format!("sha256:{}", "a".repeat(64))).is_ok());

    let uppercase = queued("prepare", 1, format!("sha256:{}", "A".repeat(64)));
    assert!(matches!(
        uppercase,
        Err(IntentValidationError::InvalidDigest)
    ));

    let malformed = queued("prepare", 1, "sha256:not-a-digest".into());
    assert!(matches!(
        malformed,
        Err(IntentValidationError::InvalidDigest)
    ));
}
