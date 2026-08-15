#![forbid(unsafe_code)]
//! Canonical Ptah identifier primitives.
//!
//! Frozen Phase 0B contracts define canonical entity identity as lowercase `UUIDv7`
//! text. Hostnames, process IDs, boot IDs, container IDs and other endpoint facts
//! are aliases/evidence and must never replace canonical entity identity.

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;
use uuid::{Uuid, Variant, Version};

/// Canonical entity kind for a Ptah Node.
pub const NODE_ENTITY_KIND: &str = "core.node";
/// Canonical entity kind for a Ptah Event.
pub const EVENT_ENTITY_KIND: &str = "event.event";
/// Canonical entity kind for a Ptah Receipt.
pub const RECEIPT_ENTITY_KIND: &str = "proof.receipt";

/// Identifier validation failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentifierError {
    /// Text is not a canonical UUID.
    #[error("identifier is not a canonical UUID: {0}")]
    InvalidUuid(String),
    /// UUID is not version 7.
    #[error("identifier must be UUIDv7")]
    NotVersion7,
    /// UUID variant is not RFC 4122/9562 compatible.
    #[error("identifier must use the RFC 4122/9562 variant")]
    WrongVariant,
    /// Entity kind does not satisfy Ptah's namespaced entity-kind shape.
    #[error("invalid Ptah entity kind: {0}")]
    InvalidEntityKind(String),
    /// A generation/epoch counter cannot be incremented safely.
    #[error("counter overflow")]
    CounterOverflow,
}

/// One canonical `UUIDv7` Ptah entity identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntityId(Uuid);

impl EntityId {
    /// Generate a new canonical `UUIDv7` entity identifier.
    #[must_use]
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    /// Construct from a UUID after enforcing Ptah `UUIDv7` identity rules.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::NotVersion7`] when the UUID is not version 7,
    /// or [`IdentifierError::WrongVariant`] when it is not the RFC 4122/9562 variant.
    pub fn from_uuid(value: Uuid) -> Result<Self, IdentifierError> {
        if value.get_version() != Some(Version::SortRand) {
            return Err(IdentifierError::NotVersion7);
        }
        if value.get_variant() != Variant::RFC4122 {
            return Err(IdentifierError::WrongVariant);
        }
        Ok(Self(value))
    }

    /// Borrow the underlying UUID value.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Debug for EntityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}

impl FromStr for EntityId {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value != value.to_ascii_lowercase() {
            return Err(IdentifierError::InvalidUuid(value.to_owned()));
        }
        let uuid = Uuid::parse_str(value)
            .map_err(|_| IdentifierError::InvalidUuid(value.to_owned()))?;
        if uuid.hyphenated().to_string() != value {
            return Err(IdentifierError::InvalidUuid(value.to_owned()));
        }
        Self::from_uuid(uuid)
    }
}

/// Stable canonical identity of one Ptah Node.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(EntityId);

impl NodeId {
    /// Generate a new stable canonical Node identity.
    #[must_use]
    pub fn new() -> Self {
        Self(EntityId::new_v7())
    }

    /// Construct from an already validated entity identifier.
    #[must_use]
    pub const fn from_entity_id(id: EntityId) -> Self {
        Self(id)
    }

    /// Return the canonical entity identifier.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.0
    }

    /// Build a typed entity reference constrained to a Node generation/epoch.
    #[must_use]
    pub fn entity_ref(
        self,
        generation: NodeGeneration,
        connection_epoch: ConnectionEpoch,
    ) -> EntityRef {
        EntityRef {
            entity_id: self.0,
            entity_kind: NODE_ENTITY_KIND.to_owned(),
            record_revision: None,
            node_generation: Some(generation.value()),
            provider_generation: None,
            workload_generation: None,
            connection_epoch: Some(connection_epoch.value()),
        }
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("NodeId").field(&self.0).finish()
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for NodeId {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        EntityId::from_str(value).map(Self)
    }
}

/// Monotonic generation of a Node agent instance.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct NodeGeneration(u64);

impl NodeGeneration {
    /// Initial generation for the first started agent instance.
    pub const INITIAL: Self = Self(0);

    /// Construct from a contract-compatible non-negative integer.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the underlying generation number.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Advance to the next generation without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::CounterOverflow`] when the current generation
    /// is already [`u64::MAX`].
    pub fn next(self) -> Result<Self, IdentifierError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(IdentifierError::CounterOverflow)
    }
}

/// Monotonic connection epoch for a Node's current control connection.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ConnectionEpoch(u64);

impl ConnectionEpoch {
    /// Initial connection epoch.
    pub const INITIAL: Self = Self(0);

    /// Construct from a contract-compatible non-negative integer.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the underlying epoch.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Advance to the next epoch without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::CounterOverflow`] when the current epoch is
    /// already [`u64::MAX`].
    pub fn next(self) -> Result<Self, IdentifierError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(IdentifierError::CounterOverflow)
    }
}

/// Typed reference to a canonical Ptah entity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityRef {
    /// Canonical `UUIDv7` entity identifier.
    pub entity_id: EntityId,
    /// Canonical namespaced Ptah entity kind.
    pub entity_kind: String,
    /// Optional exact record revision constraint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_revision: Option<u64>,
    /// Optional exact Node generation constraint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_generation: Option<u64>,
    /// Optional exact Provider generation constraint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_generation: Option<u64>,
    /// Optional exact workload generation constraint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_generation: Option<u64>,
    /// Optional exact connection epoch constraint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_epoch: Option<u64>,
}

impl EntityRef {
    /// Create a reference to a newly allocated canonical entity.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::InvalidEntityKind`] when `entity_kind` does not
    /// satisfy the frozen Ptah namespaced entity-kind grammar.
    pub fn new(entity_kind: impl Into<String>) -> Result<Self, IdentifierError> {
        Self::from_id(EntityId::new_v7(), entity_kind)
    }

    /// Create a reference from an existing canonical entity identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::InvalidEntityKind`] when `entity_kind` does not
    /// satisfy the frozen Ptah namespaced entity-kind grammar.
    pub fn from_id(
        entity_id: EntityId,
        entity_kind: impl Into<String>,
    ) -> Result<Self, IdentifierError> {
        let entity_kind = entity_kind.into();
        validate_entity_kind(&entity_kind)?;
        Ok(Self {
            entity_id,
            entity_kind,
            record_revision: None,
            node_generation: None,
            provider_generation: None,
            workload_generation: None,
            connection_epoch: None,
        })
    }
}

fn validate_entity_kind(value: &str) -> Result<(), IdentifierError> {
    let mut parts = value.split('.');
    let Some(first) = parts.next() else {
        return Err(IdentifierError::InvalidEntityKind(value.to_owned()));
    };
    let rest: Vec<_> = parts.collect();
    if rest.is_empty() || !valid_kind_segment(first, false) {
        return Err(IdentifierError::InvalidEntityKind(value.to_owned()));
    }
    if rest.iter().any(|segment| !valid_kind_segment(segment, true)) {
        return Err(IdentifierError::InvalidEntityKind(value.to_owned()));
    }
    Ok(())
}

fn valid_kind_segment(value: &str, allow_underscore_or_dash: bool) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    characters.all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || (allow_underscore_or_dash && matches!(character, '_' | '-'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_entity_id_is_uuid_v7_and_round_trips() {
        let id = EntityId::new_v7();
        let rendered = id.to_string();
        assert_eq!(EntityId::from_str(&rendered), Ok(id));
        assert_eq!(id.as_uuid().get_version(), Some(Version::SortRand));
        assert_eq!(id.as_uuid().get_variant(), Variant::RFC4122);
    }

    #[test]
    fn node_id_rejects_non_v7_uuid() {
        let v4 = Uuid::new_v4().to_string();
        assert_eq!(NodeId::from_str(&v4), Err(IdentifierError::NotVersion7));
    }

    #[test]
    fn node_id_rejects_hostname_and_process_aliases() {
        assert!(matches!(
            NodeId::from_str("worker.example"),
            Err(IdentifierError::InvalidUuid(_))
        ));
        assert!(matches!(
            NodeId::from_str("4242"),
            Err(IdentifierError::InvalidUuid(_))
        ));
    }

    #[test]
    fn node_reference_carries_generation_and_epoch_without_changing_identity() {
        let node_id = NodeId::new();
        let reference = node_id.entity_ref(NodeGeneration::new(7), ConnectionEpoch::new(3));
        assert_eq!(reference.entity_id, node_id.entity_id());
        assert_eq!(reference.entity_kind, NODE_ENTITY_KIND);
        assert_eq!(reference.node_generation, Some(7));
        assert_eq!(reference.connection_epoch, Some(3));
    }

    #[test]
    fn generation_and_epoch_do_not_wrap() {
        assert_eq!(
            NodeGeneration::new(u64::MAX).next(),
            Err(IdentifierError::CounterOverflow)
        );
        assert_eq!(
            ConnectionEpoch::new(u64::MAX).next(),
            Err(IdentifierError::CounterOverflow)
        );
    }

    #[test]
    fn serde_uses_canonical_uuid_text() {
        let id = NodeId::new();
        let json = serde_json::to_string(&id).expect("serialize NodeId");
        assert_eq!(json, format!("\"{id}\""));
        let decoded: NodeId = serde_json::from_str(&json).expect("deserialize NodeId");
        assert_eq!(decoded, id);
    }

    #[test]
    fn entity_kind_validation_rejects_non_namespaced_or_uppercase_values() {
        assert!(EntityRef::new("node").is_err());
        assert!(EntityRef::new("Core.Node").is_err());
        assert!(EntityRef::new(EVENT_ENTITY_KIND).is_ok());
        assert!(EntityRef::new(RECEIPT_ENTITY_KIND).is_ok());
    }
}
