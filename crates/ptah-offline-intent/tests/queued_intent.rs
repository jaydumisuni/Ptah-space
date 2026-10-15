use ptah_offline_intent::{IntentValidationError, LocalSequence, QueuedIntent, ReplayDisposition};

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

#[test]
fn local_sequence_successor_is_monotonic_and_node_bound() {
    let first = LocalSequence {
        node_id: "node-1".into(),
        value: 1,
    };
    let second = first.checked_next().unwrap();
    assert_eq!(second.node_id, "node-1");
    assert_eq!(second.value, 2);
    assert_eq!(first.value, 1);
    assert_eq!(second.checked_next().unwrap().value, 3);
}

#[test]
fn local_sequence_successor_fails_closed_on_invalid_cursor_or_exhaustion() {
    for (node_id, value, expected) in [
        ("node-1", 0, IntentValidationError::ZeroSequence),
        ("node-1", u64::MAX, IntentValidationError::SequenceExhausted),
        (
            " node-1",
            1,
            IntentValidationError::NonCanonicalWhitespace("origin.node_id"),
        ),
        (
            "node\n1",
            1,
            IntentValidationError::ControlCharacter("origin.node_id"),
        ),
        ("", 1, IntentValidationError::Empty("origin.node_id")),
    ] {
        let cursor = LocalSequence {
            node_id: node_id.into(),
            value,
        };
        assert_eq!(cursor.checked_next(), Err(expected));
    }
}

#[test]
fn checkpoint_codec_roundtrips_without_granting_authority() {
    let cursor = LocalSequence {
        node_id: "node-1".into(),
        value: u64::MAX - 1,
    };
    let bytes = cursor.checkpoint_bytes().unwrap();
    assert_eq!(
        LocalSequence::from_checkpoint_bytes(&bytes),
        Ok(cursor.clone())
    );
    assert_eq!(
        LocalSequence::from_checkpoint_bytes(&bytes)
            .unwrap()
            .checked_next()
            .unwrap()
            .value,
        u64::MAX
    );
}

#[test]
fn checkpoint_recovery_rejects_oversized_untrusted_input() {
    let mut oversized = b"ptah.local-sequence.v1\n".to_vec();
    oversized.extend_from_slice(&[b'n'; 129]);
    oversized.extend_from_slice(b"\n1\n");
    assert_eq!(
        LocalSequence::from_checkpoint_bytes(&oversized),
        Err(IntentValidationError::TooLong("origin.node_id"))
    );
    oversized.extend_from_slice(&[b'n'; 20]);
    assert_eq!(
        LocalSequence::from_checkpoint_bytes(&oversized),
        Err(IntentValidationError::InvalidCheckpoint)
    );
}

#[test]
fn checkpoint_recovery_rejects_noncanonical_or_corrupt_bytes() {
    for bytes in [
        b"ptah.local-sequence.v1\nnode-1\n01\n".as_slice(),
        b"ptah.local-sequence.v1\nnode-1\n0\n",
        b"ptah.local-sequence.v1\nnode-1\n+1\n",
        b"ptah.local-sequence.v1\nnode-1\n1",
        b"ptah.local-sequence.v1\nnode-1\n1\nextra\n",
        b"ptah.local-sequence.v0\nnode-1\n1\n",
        b"ptah.local-sequence.v1\nnode-1\n18446744073709551616\n",
        b"ptah.local-sequence.v1\n node-1\n1\n",
        b"ptah.local-sequence.v1\nnode-1\n1\n\n",
        b"\xff",
    ] {
        assert!(
            LocalSequence::from_checkpoint_bytes(bytes).is_err(),
            "{bytes:?}"
        );
    }
}

#[test]
fn recovered_checkpoint_comparison_is_node_bound_and_monotonic() {
    let trusted = LocalSequence {
        node_id: "node-1".into(),
        value: 7,
    };
    let equal = trusted.clone();
    let advanced = LocalSequence {
        node_id: "node-1".into(),
        value: 9,
    };
    let rollback = LocalSequence {
        node_id: "node-1".into(),
        value: 6,
    };
    let foreign = LocalSequence {
        node_id: "node-2".into(),
        value: 9,
    };
    assert_eq!(trusted.validate_recovered_cursor(&equal), Ok(()));
    assert_eq!(trusted.validate_recovered_cursor(&advanced), Ok(()));
    assert_eq!(
        trusted.validate_recovered_cursor(&rollback),
        Err(IntentValidationError::CheckpointRollback)
    );
    assert_eq!(
        trusted.validate_recovered_cursor(&foreign),
        Err(IntentValidationError::CheckpointNodeMismatch)
    );
    let invalid = LocalSequence {
        node_id: " node-1".into(),
        value: 9,
    };
    assert_eq!(
        trusted.validate_recovered_cursor(&invalid),
        Err(IntentValidationError::NonCanonicalWhitespace(
            "origin.node_id"
        ))
    );
    let zero = LocalSequence {
        node_id: "node-1".into(),
        value: 0,
    };
    assert_eq!(
        trusted.validate_recovered_cursor(&zero),
        Err(IntentValidationError::ZeroSequence)
    );
}

#[test]
fn checked_checkpoint_recovery_rejects_foreign_or_rolled_back_bytes() {
    let trusted = LocalSequence {
        node_id: "node-1".into(),
        value: 7,
    };
    let cursor = |node_id: &str, value| LocalSequence {
        node_id: node_id.into(),
        value,
    };
    for value in [7, 8] {
        let candidate = cursor("node-1", value);
        assert_eq!(
            trusted.recover_checked_checkpoint(&candidate.checkpoint_bytes().unwrap()),
            Ok(candidate)
        );
    }
    assert_eq!(
        trusted.recover_checked_checkpoint(&cursor("node-1", 6).checkpoint_bytes().unwrap()),
        Err(IntentValidationError::CheckpointRollback)
    );
    assert_eq!(
        trusted.recover_checked_checkpoint(&cursor("node-2", 8).checkpoint_bytes().unwrap()),
        Err(IntentValidationError::CheckpointNodeMismatch)
    );
    assert_eq!(
        trusted.recover_checked_checkpoint(b"ptah.local-sequence.v1\nnode-1\n08\n"),
        Err(IntentValidationError::InvalidCheckpoint)
    );
}

#[test]
fn prepared_successor_from_checkpoint_requires_trusted_recovery() {
    let trusted = LocalSequence {
        node_id: "node-1".into(),
        value: 7,
    };
    let cursor = |node_id: &str, value| LocalSequence {
        node_id: node_id.into(),
        value,
    };
    for (recovered, expected) in [(7, 8), (9, 10)] {
        assert_eq!(
            trusted.prepare_next_after_checkpoint(
                &cursor("node-1", recovered).checkpoint_bytes().unwrap()
            ),
            Ok(cursor("node-1", expected))
        );
    }
    assert_eq!(
        trusted.prepare_next_after_checkpoint(&cursor("node-1", 6).checkpoint_bytes().unwrap()),
        Err(IntentValidationError::CheckpointRollback)
    );
    assert_eq!(
        trusted.prepare_next_after_checkpoint(&cursor("node-2", 9).checkpoint_bytes().unwrap()),
        Err(IntentValidationError::CheckpointNodeMismatch)
    );
    assert_eq!(
        trusted.prepare_next_after_checkpoint(b"ptah.local-sequence.v1\nnode-1\n09\n"),
        Err(IntentValidationError::InvalidCheckpoint)
    );
    assert_eq!(
        trusted
            .prepare_next_after_checkpoint(&cursor("node-1", u64::MAX).checkpoint_bytes().unwrap()),
        Err(IntentValidationError::SequenceExhausted)
    );
}

#[test]
fn replay_preflight_is_idempotent_but_never_grants_authority() {
    let original = queued("prepare", 7, format!("sha256:{}", "a".repeat(64))).unwrap();
    assert_eq!(
        original.classify_replay(&original),
        Ok(ReplayDisposition::Idempotent)
    );
    let mut conflicting = original.clone();
    conflicting.action = "execute".into();
    assert_eq!(
        original.classify_replay(&conflicting),
        Err(IntentValidationError::ConflictingReplay)
    );
    let mut reused = original.clone();
    reused.intent_id = "intent-2".into();
    assert_eq!(
        original.classify_replay(&reused),
        Err(IntentValidationError::ReusedOriginSequence)
    );
    reused.origin.value = 8;
    assert_eq!(
        original.classify_replay(&reused),
        Ok(ReplayDisposition::Distinct)
    );
    reused.revalidate_required = false;
    assert_eq!(
        original.classify_replay(&reused),
        Err(IntentValidationError::InvalidReplayState)
    );
}

#[test]
fn replay_preflight_revalidates_mutable_envelopes_before_identity_comparison() {
    let original = queued("prepare", 7, format!("sha256:{}", "a".repeat(64))).unwrap();
    let mut invalid_candidate = original.clone();
    invalid_candidate.workspace_id = " ".into();
    assert_eq!(
        original.classify_replay(&invalid_candidate),
        Err(IntentValidationError::Empty("workspace_id"))
    );

    invalid_candidate.workspace_id = original.workspace_id.clone();
    invalid_candidate.canonical_input_digest = format!("sha256:{}", "A".repeat(64));
    assert_eq!(
        original.classify_replay(&invalid_candidate),
        Err(IntentValidationError::InvalidDigest)
    );

    let mut invalid_stored = original.clone();
    invalid_stored.origin.value = 0;
    assert_eq!(
        invalid_stored.classify_replay(&original),
        Err(IntentValidationError::ZeroSequence)
    );
}

#[test]
fn full_history_preflight_rejects_late_conflict_after_idempotent_match() {
    let candidate = queued("prepare", 7, format!("sha256:{}", "a".repeat(64))).unwrap();
    let mut later_conflict = candidate.clone();
    later_conflict.action = "execute".into();
    assert_eq!(
        candidate.classify_against_history([&candidate, &later_conflict]),
        Err(IntentValidationError::ConflictingReplay)
    );

    let mut sequence_alias = candidate.clone();
    sequence_alias.intent_id = "intent-2".into();
    assert_eq!(
        candidate.classify_against_history([&candidate, &sequence_alias]),
        Err(IntentValidationError::ReusedOriginSequence)
    );
}

#[test]
fn full_history_preflight_preserves_distinct_and_idempotent_without_authority() {
    let candidate = queued("prepare", 7, format!("sha256:{}", "a".repeat(64))).unwrap();
    let mut other = candidate.clone();
    other.intent_id = "intent-2".into();
    other.origin.value = 8;
    assert_eq!(
        candidate.classify_against_history([&other]),
        Ok(ReplayDisposition::Distinct)
    );
    assert_eq!(
        candidate.classify_against_history([&candidate, &other]),
        Ok(ReplayDisposition::Idempotent)
    );
    assert!(candidate.revalidate_required);
}

#[test]
fn full_history_preflight_revalidates_each_stored_envelope() {
    let candidate = queued("prepare", 7, format!("sha256:{}", "a".repeat(64))).unwrap();
    let mut malformed = candidate.clone();
    malformed.intent_id = "intent-2".into();
    malformed.origin.value = 8;
    malformed.revalidate_required = false;
    assert_eq!(
        candidate.classify_against_history([&malformed]),
        Err(IntentValidationError::InvalidReplayState)
    );
}

#[test]
fn full_history_preflight_rejects_corruption_unrelated_to_candidate() {
    let candidate = queued("prepare", 7, format!("sha256:{}", "a".repeat(64))).unwrap();
    let mut first = candidate.clone();
    first.intent_id = "intent-2".into();
    first.origin.value = 8;

    let mut conflicting = first.clone();
    conflicting.action = "execute".into();
    assert_eq!(
        candidate.classify_against_history([&first, &conflicting]),
        Err(IntentValidationError::ConflictingReplay)
    );

    let mut reused_origin = first.clone();
    reused_origin.intent_id = "intent-3".into();
    assert_eq!(
        candidate.classify_against_history([&first, &reused_origin]),
        Err(IntentValidationError::ReusedOriginSequence)
    );

    // Exact duplicate journal entries are idempotent, not authority grants.
    assert_eq!(
        candidate.classify_against_history([&first, &first]),
        Ok(ReplayDisposition::Distinct)
    );
    assert!(candidate.revalidate_required);
}

#[test]
fn full_history_preflight_rejects_unrelated_corruption_after_idempotent_replay() {
    let candidate = queued("prepare", 7, format!("sha256:{}", "a".repeat(64))).unwrap();
    let mut other = candidate.clone();
    other.intent_id = "intent-2".into();
    other.origin.value = 8;
    let mut conflicting = other.clone();
    conflicting.intent_id = "intent-3".into();
    assert_eq!(
        candidate.classify_against_history([&candidate, &other, &conflicting]),
        Err(IntentValidationError::ReusedOriginSequence)
    );
}

#[test]
fn prepared_origin_preflight_requires_exact_recovered_successor() {
    let trusted = LocalSequence {
        node_id: "node-1".into(),
        value: 7,
    };
    let recovered = LocalSequence {
        node_id: "node-1".into(),
        value: 9,
    };
    let checkpoint = recovered.checkpoint_bytes().unwrap();
    let digest = format!("sha256:{}", "a".repeat(64));
    let accepted = queued("prepare", 10, digest.clone()).unwrap();
    assert_eq!(
        accepted.preflight_origin_after_checkpoint(&trusted, &checkpoint),
        Ok(())
    );

    for wrong_sequence in [8, 9, 11] {
        let candidate = queued("prepare", wrong_sequence, digest.clone()).unwrap();
        assert_eq!(
            candidate.preflight_origin_after_checkpoint(&trusted, &checkpoint),
            Err(IntentValidationError::UnexpectedOriginSequence)
        );
    }

    let mut foreign = accepted.clone();
    foreign.origin.node_id = "node-2".into();
    assert_eq!(
        foreign.preflight_origin_after_checkpoint(&trusted, &checkpoint),
        Err(IntentValidationError::CheckpointNodeMismatch)
    );

    let mut waived = accepted.clone();
    waived.revalidate_required = false;
    assert_eq!(
        waived.preflight_origin_after_checkpoint(&trusted, &checkpoint),
        Err(IntentValidationError::InvalidReplayState)
    );

    let stale = LocalSequence {
        node_id: "node-1".into(),
        value: 6,
    };
    assert_eq!(
        accepted.preflight_origin_after_checkpoint(&trusted, &stale.checkpoint_bytes().unwrap()),
        Err(IntentValidationError::CheckpointRollback)
    );
    let other = LocalSequence {
        node_id: "node-2".into(),
        value: 9,
    };
    assert_eq!(
        accepted.preflight_origin_after_checkpoint(&trusted, &other.checkpoint_bytes().unwrap()),
        Err(IntentValidationError::CheckpointNodeMismatch)
    );
}

#[test]
fn ordered_journal_rejects_reordered_origin_sequence_for_same_node() {
    let candidate = queued("prepare", 7, format!("sha256:{}", "a".repeat(64))).unwrap();
    let mut first = candidate.clone();
    first.intent_id = "intent-2".into();
    first.origin.value = 9;
    let mut older = candidate.clone();
    older.intent_id = "intent-3".into();
    older.origin.value = 8;
    assert_eq!(
        QueuedIntent::validate_append_order([&first, &older]),
        Err(IntentValidationError::OutOfOrderOriginSequence)
    );

    let mut foreign = older.clone();
    foreign.intent_id = "intent-4".into();
    foreign.origin.node_id = "node-2".into();
    assert_eq!(
        QueuedIntent::validate_append_order([&first, &foreign]),
        Ok(())
    );
}

#[test]
fn full_history_preflight_rejects_out_of_order_journal_even_when_replay_is_distinct() {
    let candidate = queued("prepare", 7, format!("sha256:{}", "a".repeat(64))).unwrap();
    let mut newer = candidate.clone();
    newer.intent_id = "intent-2".into();
    newer.origin.value = 9;
    let mut older = candidate.clone();
    older.intent_id = "intent-3".into();
    older.origin.value = 8;
    assert_eq!(
        candidate.classify_against_history([&newer, &older]),
        Err(IntentValidationError::OutOfOrderOriginSequence)
    );
    let mut other_node = older.clone();
    other_node.origin.node_id = "node-2".into();
    assert_eq!(
        candidate.classify_against_history([&newer, &other_node]),
        Ok(ReplayDisposition::Distinct)
    );
}

#[test]
fn append_preflight_requires_successor_and_preserves_idempotent_replay() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let trusted = LocalSequence {
        node_id: "node-1".into(),
        value: 7,
    };
    let recovered = LocalSequence {
        node_id: "node-1".into(),
        value: 9,
    };
    let checkpoint = recovered.checkpoint_bytes().unwrap();
    let mut earlier = queued("prepare", 8, digest.clone()).unwrap();
    earlier.intent_id = "intent-8".into();
    let mut latest = queued("prepare", 9, digest.clone()).unwrap();
    latest.intent_id = "intent-9".into();
    let next = queued("prepare", 10, digest.clone()).unwrap();
    assert_eq!(
        next.preflight_append_after_checkpoint(&trusted, &checkpoint, [&earlier, &latest]),
        Ok(ReplayDisposition::Distinct)
    );
    assert_eq!(
        earlier.preflight_append_after_checkpoint(&trusted, &checkpoint, [&earlier, &latest]),
        Ok(ReplayDisposition::Idempotent)
    );
    let stale = queued("prepare", 8, digest.clone()).unwrap();
    assert_eq!(
        stale.preflight_append_after_checkpoint(&trusted, &checkpoint, [&earlier, &latest]),
        Err(IntentValidationError::ReusedOriginSequence)
    );
    let mut skipped = next.clone();
    skipped.origin.value = 11;
    assert_eq!(
        skipped.preflight_append_after_checkpoint(&trusted, &checkpoint, [&earlier, &latest]),
        Err(IntentValidationError::UnexpectedOriginSequence)
    );
    let mut foreign = next.clone();
    foreign.origin.node_id = "node-2".into();
    assert_eq!(
        foreign.preflight_append_after_checkpoint(&trusted, &checkpoint, [&earlier, &latest]),
        Err(IntentValidationError::CheckpointNodeMismatch)
    );
    assert_eq!(
        next.preflight_append_after_checkpoint(
            &trusted,
            &earlier.origin.checkpoint_bytes().unwrap(),
            [&earlier, &latest]
        ),
        Err(IntentValidationError::CheckpointJournalMismatch)
    );
    assert_eq!(
        next.preflight_append_after_checkpoint(&trusted, &checkpoint, [&latest, &earlier]),
        Err(IntentValidationError::OutOfOrderOriginSequence)
    );
}

#[test]
fn append_preflight_rejects_journal_ahead_of_recovered_cursor_even_on_exact_replay() {
    let trusted = LocalSequence {
        node_id: "node-1".into(),
        value: 7,
    };
    let checkpoint = trusted.checkpoint_bytes().unwrap();
    let stored = queued("prepare", 8, format!("sha256:{}", "a".repeat(64))).unwrap();
    assert_eq!(
        stored.preflight_append_after_checkpoint(&trusted, &checkpoint, [&stored]),
        Err(IntentValidationError::CheckpointJournalMismatch)
    );
}

#[test]
fn append_preflight_rejects_journal_behind_recovered_cursor() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let trusted = LocalSequence {
        node_id: "node-1".into(),
        value: 7,
    };
    let recovered = LocalSequence {
        node_id: "node-1".into(),
        value: 9,
    };
    let checkpoint = recovered.checkpoint_bytes().unwrap();
    let mut stored = queued("prepare", 8, digest.clone()).unwrap();
    stored.intent_id = "intent-8".into();
    let mut successor = queued("prepare", 10, digest).unwrap();
    successor.intent_id = "intent-10".into();

    assert_eq!(
        successor.preflight_append_after_checkpoint(&trusted, &checkpoint, [&stored]),
        Err(IntentValidationError::CheckpointJournalMismatch)
    );
    assert_eq!(
        successor.preflight_append_after_checkpoint(
            &trusted,
            &checkpoint,
            std::iter::empty::<&QueuedIntent>()
        ),
        Err(IntentValidationError::CheckpointJournalMismatch)
    );
}

#[test]
fn append_preflight_rejects_missing_entire_origin_history() {
    let trusted = LocalSequence {
        node_id: "node-1".into(),
        value: 7,
    };
    let successor = queued("prepare", 8, format!("sha256:{}", "a".repeat(64))).unwrap();
    assert_eq!(
        successor.preflight_append_after_checkpoint(
            &trusted,
            &trusted.checkpoint_bytes().unwrap(),
            std::iter::empty::<&QueuedIntent>(),
        ),
        Err(IntentValidationError::CheckpointJournalMismatch)
    );
}

#[test]
fn append_preflight_rejects_invalid_first_record_without_draining_history() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let trusted = LocalSequence {
        node_id: "node-1".into(),
        value: 7,
    };
    let checkpoint = trusted.checkpoint_bytes().unwrap();
    let candidate = queued("prepare", 8, digest.clone()).unwrap();
    let mut invalid = queued("prepare", 7, digest).unwrap();
    invalid.revalidate_required = false;
    let history =
        std::iter::once(&invalid).chain(std::iter::from_fn(|| -> Option<&QueuedIntent> {
            panic!("append preflight drained history after invalid record")
        }));
    assert_eq!(
        candidate.preflight_append_after_checkpoint(&trusted, &checkpoint, history),
        Err(IntentValidationError::InvalidReplayState)
    );
}

#[test]
fn full_history_preflight_stops_at_first_invalid_record_without_draining_iterator() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let candidate = queued("prepare", 9, digest.clone()).unwrap();
    let mut invalid = queued("prepare", 8, digest).unwrap();
    invalid.revalidate_required = false;
    let history =
        std::iter::once(&invalid).chain(std::iter::from_fn(|| -> Option<&QueuedIntent> {
            panic!("preflight drained history after invalid record")
        }));
    assert_eq!(
        candidate.classify_against_history(history),
        Err(IntentValidationError::InvalidReplayState)
    );
}

#[test]
fn selected_contract_rejects_interleaved_interior_gap_even_when_tail_matches_checkpoint() {
    let mk = |key: &str, node: &str, seq: u64| {
        QueuedIntent::try_new(
            key.into(),
            "workspace-1".into(),
            "activity-1".into(),
            format!("operation-{key}"),
            format!("attempt-{key}"),
            LocalSequence {
                node_id: node.into(),
                value: seq,
            },
            "prepare".into(),
            format!("sha256:{}", "a".repeat(64)),
        )
        .unwrap()
    };
    let history = [
        mk("one", "node-1", 7),
        mk("foreign", "node-2", 3),
        mk("three", "node-1", 9),
    ];
    assert!(matches!(
        QueuedIntent::validate_append_order(history.iter()),
        Err(IntentValidationError::MissingOriginSequence)
    ));
    let candidate = mk("four", "node-1", 10);
    assert!(matches!(
        candidate.classify_against_history(history.iter()),
        Err(IntentValidationError::MissingOriginSequence)
    ));
    let trusted = LocalSequence {
        node_id: "node-1".into(),
        value: 9,
    };
    assert!(matches!(
        candidate.preflight_append_after_checkpoint(
            &trusted,
            &trusted.checkpoint_bytes().unwrap(),
            history.iter()
        ),
        Err(IntentValidationError::MissingOriginSequence)
    ));
}
