use ptah_events::{EventBus, EventClass, EventError, EventPayload, EventSpec};
use ptah_identifiers::EntityRef;

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid reference")
}

fn event_spec() -> EventSpec {
    EventSpec {
        event_type: "activity.state_changed".to_owned(),
        event_class: EventClass::Replayable,
        source_ref: reference("core.node"),
        subject_ref: reference("core.activity"),
        activity_ref: None,
        operation_ref: None,
        attempt_ref: None,
        sequence_scope_ref: reference("core.activity"),
        occurred_at: "2026-08-16T16:45:00Z".to_owned(),
        payload: EventPayload::none(),
        receipt_ref: None,
    }
}

#[test]
fn replay_preserves_monotonic_scope_sequence() {
    let bus = EventBus::default();
    let spec = event_spec();
    let scope = spec.sequence_scope_ref.entity_id;
    let first = bus.emit(spec.clone()).expect("first Event");
    let second = bus.emit(spec).expect("second Event");

    assert_eq!(first.sequence(), 0);
    assert_eq!(second.sequence(), 1);
    assert_eq!(bus.replay(scope, 1).expect("replay"), vec![second]);
}

#[test]
fn proof_notification_cannot_exist_without_receipt_reference() {
    let bus = EventBus::default();
    let mut spec = event_spec();
    spec.event_class = EventClass::ProofNotification;

    assert_eq!(bus.emit(spec), Err(EventError::MissingReceipt));
}

#[test]
fn attempt_event_requires_complete_activity_operation_hierarchy() {
    let bus = EventBus::default();
    let mut spec = event_spec();
    spec.attempt_ref = Some(reference("core.attempt"));

    assert_eq!(bus.emit(spec), Err(EventError::MissingAttemptHierarchy));
}
