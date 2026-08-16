#![forbid(unsafe_code)]
//! Typed A04 Event stream.
//!
//! Events are notifications and replay projections. They never constitute
//! execution proof by themselves; proof notifications must reference an exact
//! immutable Receipt.

use ptah_identifiers::{EntityId, EntityRef, IdentifierError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use thiserror::Error;
use tokio::sync::broadcast;

/// Frozen Event schema identifier.
pub const EVENT_SCHEMA_ID: &str = "urn:ptah:schema:activity:event:0.1.0";
/// Frozen Event schema version.
pub const EVENT_SCHEMA_VERSION: &str = "0.1.0";
/// Frozen Event entity kind.
pub const EVENT_ENTITY_KIND: &str = "event.event";

/// Delivery/retention class from the frozen Event contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventClass {
    /// Live-only notification.
    Ephemeral,
    /// Replayable operational notification.
    Replayable,
    /// Projection derived from durable ledger truth.
    LedgerDerived,
    /// Notification that points at immutable proof.
    ProofNotification,
}

/// Payload representation from the frozen Event contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadClass {
    /// Small inline JSON payload.
    InlineSmall,
    /// Durable Object reference.
    ObjectReference,
    /// Durable Artifact reference.
    ArtifactReference,
    /// Stream reference.
    StreamReference,
    /// No payload.
    None,
}

/// Optional contract metadata for an Event payload.
#[derive(Debug, Clone, PartialEq)]
pub struct EventPayload {
    /// Frozen payload representation.
    pub class: PayloadClass,
    /// Payload type entity reference, when required by the class.
    pub payload_type_ref: Option<EntityRef>,
    /// Payload schema identifier, when required by the class.
    pub schema_id: Option<String>,
    /// Payload schema version, when required by the class.
    pub schema_version: Option<String>,
    /// Small inline payload.
    pub inline: Option<Value>,
    /// Object/Artifact payload reference.
    pub payload_ref: Option<EntityRef>,
    /// Stream reference.
    pub stream_ref: Option<EntityRef>,
}

impl EventPayload {
    /// Construct an Event with no payload.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            class: PayloadClass::None,
            payload_type_ref: None,
            schema_id: None,
            schema_version: None,
            inline: None,
            payload_ref: None,
            stream_ref: None,
        }
    }

    fn validate(&self) -> Result<(), EventError> {
        match self.class {
            PayloadClass::InlineSmall => {
                if self.payload_type_ref.is_none()
                    || self.schema_id.as_deref().is_none_or(str::is_empty)
                    || self.schema_version.as_deref().is_none_or(str::is_empty)
                    || self.inline.is_none()
                    || self.payload_ref.is_some()
                    || self.stream_ref.is_some()
                {
                    return Err(EventError::InvalidPayload);
                }
            }
            PayloadClass::ObjectReference | PayloadClass::ArtifactReference => {
                if self.payload_type_ref.is_none()
                    || self.schema_id.as_deref().is_none_or(str::is_empty)
                    || self.schema_version.as_deref().is_none_or(str::is_empty)
                    || self.payload_ref.is_none()
                    || self.inline.is_some()
                    || self.stream_ref.is_some()
                {
                    return Err(EventError::InvalidPayload);
                }
            }
            PayloadClass::StreamReference => {
                if self.payload_type_ref.is_none()
                    || self.stream_ref.is_none()
                    || self.inline.is_some()
                    || self.payload_ref.is_some()
                {
                    return Err(EventError::InvalidPayload);
                }
            }
            PayloadClass::None => {
                if self.inline.is_some() || self.payload_ref.is_some() || self.stream_ref.is_some()
                {
                    return Err(EventError::InvalidPayload);
                }
            }
        }
        Ok(())
    }
}

/// Input for creating one Event.
#[derive(Debug, Clone)]
pub struct EventSpec {
    /// Namespaced Event type.
    pub event_type: String,
    /// Delivery/retention class.
    pub event_class: EventClass,
    /// Producer/source reference.
    pub source_ref: EntityRef,
    /// Subject reference.
    pub subject_ref: EntityRef,
    /// Optional parent Activity.
    pub activity_ref: Option<EntityRef>,
    /// Optional parent Operation.
    pub operation_ref: Option<EntityRef>,
    /// Optional exact Attempt.
    pub attempt_ref: Option<EntityRef>,
    /// Per-scope sequence owner.
    pub sequence_scope_ref: EntityRef,
    /// Event timestamp in contract-compatible UTC text.
    pub occurred_at: String,
    /// Payload.
    pub payload: EventPayload,
    /// Required for proof-notification Events.
    pub receipt_ref: Option<EntityRef>,
}

/// One immutable typed Event projection.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    id: EntityId,
    event_type: String,
    event_class: EventClass,
    source_ref: EntityRef,
    subject_ref: EntityRef,
    activity_ref: Option<EntityRef>,
    operation_ref: Option<EntityRef>,
    attempt_ref: Option<EntityRef>,
    sequence_scope_ref: EntityRef,
    sequence: u64,
    occurred_at: String,
    payload: EventPayload,
    receipt_ref: Option<EntityRef>,
}

impl Event {
    /// Canonical Event identity.
    #[must_use]
    pub const fn id(&self) -> EntityId {
        self.id
    }

    /// Monotonic sequence within the declared sequence scope.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Event type.
    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    /// Event class.
    #[must_use]
    pub const fn event_class(&self) -> EventClass {
        self.event_class
    }

    /// Exact Receipt reference for proof notifications.
    #[must_use]
    pub const fn receipt_ref(&self) -> Option<&EntityRef> {
        self.receipt_ref.as_ref()
    }

    /// Render the frozen canonical Event document for durable journaling.
    #[must_use]
    pub fn canonical_document(&self) -> Value {
        let mut document = json!({
            "envelope": entity_envelope(
                self.id,
                EVENT_ENTITY_KIND,
                EVENT_SCHEMA_ID,
                EVENT_SCHEMA_VERSION,
                &self.occurred_at,
                &self.source_ref,
            ),
            "event_domain": event_domain(&self.event_type),
            "event_type": self.event_type,
            "event_version": EVENT_SCHEMA_VERSION,
            "event_class": self.event_class,
            "source_ref": self.source_ref,
            "subject_ref": self.subject_ref,
            "occurred_at": self.occurred_at,
            "observed_at": self.occurred_at,
            "sequence_scope_ref": self.sequence_scope_ref,
            "sequence": self.sequence,
            "retention_class": retention_class(self.event_class),
            "payload_class": self.payload.class,
            "extensions": {},
        });
        let object = document
            .as_object_mut()
            .expect("Event document is an object");
        insert_ref(object, "activity_ref", self.activity_ref.as_ref());
        insert_ref(object, "operation_ref", self.operation_ref.as_ref());
        insert_ref(object, "attempt_ref", self.attempt_ref.as_ref());
        insert_ref(object, "receipt_ref", self.receipt_ref.as_ref());
        insert_ref(
            object,
            "payload_type_ref",
            self.payload.payload_type_ref.as_ref(),
        );
        insert_ref(object, "payload_ref", self.payload.payload_ref.as_ref());
        insert_ref(object, "stream_ref", self.payload.stream_ref.as_ref());
        if let Some(value) = &self.payload.schema_id {
            object.insert("payload_schema_id".to_owned(), json!(value));
        }
        if let Some(value) = &self.payload.schema_version {
            object.insert("payload_schema_version".to_owned(), json!(value));
        }
        if let Some(value) = &self.payload.inline {
            object.insert("inline_payload".to_owned(), value.clone());
        }
        document
    }
}

#[derive(Debug, Default)]
struct EventState {
    next_sequence: HashMap<EntityId, u64>,
    history: Vec<Event>,
}

/// In-process ordered Event bus with retained replay history.
#[derive(Clone)]
pub struct EventBus {
    state: Arc<Mutex<EventState>>,
    sender: broadcast::Sender<Event>,
}

impl EventBus {
    /// Create a bus with the requested live subscriber capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(1));
        Self {
            state: Arc::new(Mutex::new(EventState::default())),
            sender,
        }
    }

    /// Subscribe to future Events. Retained Events are available through [`Self::replay`].
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }

    /// Emit one validated Event and assign its monotonic per-scope sequence.
    ///
    /// Delivery failure to live subscribers does not invalidate the Event or turn
    /// it into execution proof.
    pub fn emit(&self, spec: EventSpec) -> Result<Event, EventError> {
        validate_spec(&spec)?;
        let mut state = self.state.lock().map_err(|_| EventError::Poisoned)?;
        let scope = spec.sequence_scope_ref.entity_id;
        let next = state.next_sequence.entry(scope).or_insert(0);
        let sequence = *next;
        *next = next.checked_add(1).ok_or(EventError::SequenceOverflow)?;
        let event = Event {
            id: EntityId::new_v7(),
            event_type: spec.event_type,
            event_class: spec.event_class,
            source_ref: spec.source_ref,
            subject_ref: spec.subject_ref,
            activity_ref: spec.activity_ref,
            operation_ref: spec.operation_ref,
            attempt_ref: spec.attempt_ref,
            sequence_scope_ref: spec.sequence_scope_ref,
            sequence,
            occurred_at: spec.occurred_at,
            payload: spec.payload,
            receipt_ref: spec.receipt_ref,
        };
        state.history.push(event.clone());
        drop(state);
        let _ = self.sender.send(event.clone());
        Ok(event)
    }

    /// Replay retained Events for one sequence scope from `from_sequence`, inclusive.
    pub fn replay(&self, scope: EntityId, from_sequence: u64) -> Result<Vec<Event>, EventError> {
        let state = self.state.lock().map_err(|_| EventError::Poisoned)?;
        Ok(state
            .history
            .iter()
            .filter(|event| {
                event.sequence_scope_ref.entity_id == scope && event.sequence >= from_sequence
            })
            .cloned()
            .collect())
    }

    /// Total retained Event count.
    pub fn len(&self) -> Result<usize, EventError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| EventError::Poisoned)?
            .history
            .len())
    }

    /// Whether no Events have been retained.
    pub fn is_empty(&self) -> Result<bool, EventError> {
        Ok(self.len()? == 0)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(256)
    }
}

/// Event construction/stream failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EventError {
    /// Event type is not namespaced.
    #[error("Event type must be a lower-case namespaced identifier")]
    InvalidEventType,
    /// Attempt hierarchy is incomplete.
    #[error("Attempt Event requires both Operation and Activity references")]
    MissingAttemptHierarchy,
    /// Operation hierarchy is incomplete.
    #[error("Operation Event requires an Activity reference")]
    MissingOperationActivity,
    /// Proof notification lacks immutable proof.
    #[error("proof-notification Event requires a Receipt reference")]
    MissingReceipt,
    /// Payload metadata is inconsistent with its class.
    #[error("Event payload does not satisfy its declared payload class")]
    InvalidPayload,
    /// Per-scope Event sequence cannot advance safely.
    #[error("Event sequence overflow")]
    SequenceOverflow,
    /// Shared Event state was poisoned.
    #[error("Event bus state is unavailable")]
    Poisoned,
    /// Canonical entity-kind construction failed.
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
}

fn validate_spec(spec: &EventSpec) -> Result<(), EventError> {
    if !valid_namespaced(&spec.event_type) {
        return Err(EventError::InvalidEventType);
    }
    if spec.attempt_ref.is_some() && (spec.operation_ref.is_none() || spec.activity_ref.is_none()) {
        return Err(EventError::MissingAttemptHierarchy);
    }
    if spec.operation_ref.is_some() && spec.activity_ref.is_none() {
        return Err(EventError::MissingOperationActivity);
    }
    if spec.event_class == EventClass::ProofNotification && spec.receipt_ref.is_none() {
        return Err(EventError::MissingReceipt);
    }
    spec.payload.validate()
}

fn valid_namespaced(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() >= 2
        && parts.iter().all(|part| {
            let mut chars = part.chars();
            chars.next().is_some_and(|first| first.is_ascii_lowercase())
                && chars.all(|ch| {
                    ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '-')
                })
        })
}

fn event_domain(event_type: &str) -> &str {
    event_type.split('.').next().unwrap_or("event")
}

fn retention_class(class: EventClass) -> &'static str {
    match class {
        EventClass::Ephemeral => "ephemeral",
        EventClass::Replayable | EventClass::LedgerDerived => "operational",
        EventClass::ProofNotification => "proof_critical",
    }
}

fn entity_envelope(
    id: EntityId,
    kind: &str,
    schema_id: &str,
    schema_version: &str,
    timestamp: &str,
    authority_ref: &EntityRef,
) -> Value {
    json!({
        "entity_id": id,
        "entity_kind": kind,
        "schema_id": schema_id,
        "schema_version": schema_version,
        "record_revision": 1,
        "created_at": timestamp,
        "updated_at": timestamp,
        "global_scope": "ptah_global",
        "authority_ref": authority_ref,
        "privacy_class": "internal",
        "audience": "organization",
        "redaction_policy": "none",
        "retention_policy": {
            "policy_id": "ptah.a04.event",
            "policy_version": "0.1.0",
            "retention_class": "operational"
        },
        "extensions": {}
    })
}

fn insert_ref(object: &mut serde_json::Map<String, Value>, key: &str, value: Option<&EntityRef>) {
    if let Some(value) = value {
        object.insert(key.to_owned(), json!(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(kind: &str) -> EntityRef {
        EntityRef::new(kind).expect("valid reference")
    }

    fn basic_spec() -> EventSpec {
        EventSpec {
            event_type: "activity.state_changed".to_owned(),
            event_class: EventClass::Replayable,
            source_ref: reference("core.node"),
            subject_ref: reference("core.activity"),
            activity_ref: None,
            operation_ref: None,
            attempt_ref: None,
            sequence_scope_ref: reference("core.activity"),
            occurred_at: "2026-08-16T16:00:00Z".to_owned(),
            payload: EventPayload::none(),
            receipt_ref: None,
        }
    }

    #[test]
    fn proof_notification_requires_receipt() {
        let bus = EventBus::default();
        let mut spec = basic_spec();
        spec.event_class = EventClass::ProofNotification;
        assert_eq!(bus.emit(spec), Err(EventError::MissingReceipt));
    }

    #[test]
    fn sequence_is_monotonic_and_replayable() {
        let bus = EventBus::default();
        let spec = basic_spec();
        let scope = spec.sequence_scope_ref.entity_id;
        let first = bus.emit(spec.clone()).expect("first Event");
        let second = bus.emit(spec).expect("second Event");
        assert_eq!(first.sequence(), 0);
        assert_eq!(second.sequence(), 1);
        assert_eq!(bus.replay(scope, 1).expect("replay"), vec![second]);
    }

    #[test]
    fn attempt_event_requires_operation_and_activity_hierarchy() {
        let bus = EventBus::default();
        let mut spec = basic_spec();
        spec.attempt_ref = Some(reference("core.attempt"));
        assert_eq!(bus.emit(spec), Err(EventError::MissingAttemptHierarchy));
    }
}
