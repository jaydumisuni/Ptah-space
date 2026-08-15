#![forbid(unsafe_code)]
//! A02 Node identity, Generation and host-truth runtime primitives.
//!
//! This crate implements the first Node runtime semantics while deliberately
//! leaving durable ledger persistence to A03 and Activity execution to A04.
//! Canonical Node identity is independent of hostname, PID, boot ID and other
//! host observations. Runtime claims are accepted only when tied to explicit
//! evidence references.

use ptah_contracts::generated;
use ptah_identifiers::{
    ConnectionEpoch, EntityRef, IdentifierError, NodeGeneration, NodeId, EVENT_ENTITY_KIND,
    NODE_ENTITY_KIND, RECEIPT_ENTITY_KIND,
};
use serde::{Deserialize, Serialize};
use std::cmp;
use thiserror::Error;

const NODE_SCHEMA: &str = "urn:ptah:schema:runtime:node:0.1.0";
const NODE_OBSERVATION_SCHEMA: &str = "urn:ptah:schema:runtime:node-observation:0.1.0";
const NODE_CAPABILITY_SCHEMA: &str = "urn:ptah:schema:runtime:node-capability-snapshot:0.1.0";
const NODE_RESOURCE_SCHEMA: &str = "urn:ptah:schema:runtime:node-resource-snapshot:0.1.0";
const EVENT_SCHEMA: &str = "urn:ptah:schema:activity:event:0.1.0";
const RECEIPT_SCHEMA: &str = "urn:ptah:schema:activity:receipt:0.1.0";
const VIEW_SCHEMA: &str = "urn:ptah:schema:object:view:0.1.0";
const NODE_LIFECYCLE: &str = "node.lifecycle";
const NODE_LIFECYCLE_VERSION: &str = "0.1.0";
const DIAGNOSTIC_VIEW_KIND: &str = "platform_diagnostic_advisory";
const STALE_GENERATION_CODE: &str = "PTAH_STALE_NODE_GENERATION";

/// A02 runtime failures that must remain explicit and evidenceable.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum NodeAgentError {
    /// A selected frozen contract binding is missing from the generated lock.
    #[error("required frozen contract binding is missing: {0}")]
    MissingFrozenContract(&'static str),
    /// Required evidence references were omitted from a runtime claim.
    #[error("evidence references are required for {0}")]
    MissingEvidence(&'static str),
    /// A required provider revision was omitted from a capacity claim.
    #[error("provider revision evidence is required")]
    MissingProviderRevision,
    /// A resource quantity violates the frozen non-negative/finite boundary.
    #[error("invalid resource quantity: {0}")]
    InvalidResource(&'static str),
    /// A requested worker-capacity projection cannot be represented safely.
    #[error("worker capacity overflow")]
    WorkerCapacityOverflow,
    /// A diagnostic advisory lacks one of its bounded required facts.
    #[error("invalid diagnostic advisory field: {0}")]
    InvalidAdvisory(&'static str),
    /// Identifier or generation arithmetic failed.
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
}

/// Frozen Node lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeLifecycleState {
    /// Enrolled and eligible subject to independent health/capability/resource checks.
    Active,
    /// Existing work may continue but ordinary new work is withheld.
    Draining,
    /// Isolated pending investigation/remediation.
    Quarantined,
    /// Temporarily disabled without retiring identity/history.
    Suspended,
    /// Enrollment/trust authority has been revoked.
    Revoked,
    /// Historical identity retained; no future work allowed.
    Retired,
}

/// Frozen Node reachability projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeReachability {
    Unknown,
    Online,
    Offline,
    Stale,
}

/// Frozen Node health projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeHealth {
    Unknown,
    Healthy,
    Degraded,
    Unhealthy,
}

/// Frozen observation kinds for Node evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    Heartbeat,
    Reachability,
    Health,
    Boot,
    Shutdown,
    Reconciliation,
    Other,
}

/// Frozen snapshot outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotOutcome {
    Complete,
    Partial,
    Failed,
}

/// Frozen platform OS families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Linux,
    Windows,
    Macos,
    Android,
    Ios,
    Other,
}

/// Frozen platform architecture projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
    Armv7,
    Riscv64,
    Other,
}

/// Frozen resource units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceUnit {
    Count,
    Bytes,
    Millicpu,
    Cores,
    Percent,
    Watts,
    Custom,
}

/// Frozen resource pressure states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourcePressure {
    Unknown,
    Normal,
    Elevated,
    Critical,
    Unavailable,
}

/// Host endpoint facts that are evidence/aliases, never canonical Node identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostIdentityEvidence {
    pub hostname: Option<String>,
    pub process_id: u32,
    pub boot_id: Option<String>,
}

/// Platform facts carried by a capability snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformFacts {
    pub os_family: OsFamily,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub kernel_name: Option<String>,
    pub kernel_version: Option<String>,
    pub architecture: Architecture,
    pub architecture_detail: Option<String>,
}

/// Explicit state a caller/persistence owner may retain across agent restarts.
///
/// A02 defines this state but does not persist it. Durable storage belongs to A03.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRestartSeed {
    pub node_id: NodeId,
    pub generation: NodeGeneration,
    pub connection_epoch: ConnectionEpoch,
    pub record_revision: u64,
}

/// Correlation references proving that a runtime outcome can be linked to an Event and Receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationRefs {
    pub event_ref: EntityRef,
    pub receipt_ref: EntityRef,
}

impl CorrelationRefs {
    /// Allocate canonical Event and Receipt references without implementing A04 lifecycle/storage.
    pub fn new() -> Result<Self, NodeAgentError> {
        Ok(Self {
            event_ref: EntityRef::new(EVENT_ENTITY_KIND)?,
            receipt_ref: EntityRef::new(RECEIPT_ENTITY_KIND)?,
        })
    }
}

/// Evidence-bound Node observation projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeObservation {
    pub observation_ref: EntityRef,
    pub node_ref: EntityRef,
    pub node_generation: NodeGeneration,
    pub connection_epoch: ConnectionEpoch,
    pub observation_kind: ObservationKind,
    pub producer_ref: EntityRef,
    pub sequence: u64,
    pub reachability: Option<NodeReachability>,
    pub health: Option<NodeHealth>,
    pub receipt_refs: Vec<EntityRef>,
    pub host_identity_evidence: Option<HostIdentityEvidence>,
}

/// A capability snapshot tied to exact Node generation/epoch and evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCapabilitySnapshot {
    pub snapshot_ref: EntityRef,
    pub node_ref: EntityRef,
    pub node_generation: NodeGeneration,
    pub connection_epoch: ConnectionEpoch,
    pub snapshot_outcome: SnapshotOutcome,
    pub agent_revision: String,
    pub platform: PlatformFacts,
    pub capability_claim_refs: Vec<EntityRef>,
    pub capability_verification_refs: Vec<EntityRef>,
    pub provider_revision_refs: Vec<EntityRef>,
    pub observation_refs: Vec<EntityRef>,
    pub receipt_refs: Vec<EntityRef>,
    pub limitations: Vec<String>,
}

impl NodeCapabilitySnapshot {
    /// Construct a capability claim only when observation, verification and receipt evidence exists.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_ref: EntityRef,
        node_generation: NodeGeneration,
        connection_epoch: ConnectionEpoch,
        snapshot_outcome: SnapshotOutcome,
        agent_revision: impl Into<String>,
        platform: PlatformFacts,
        capability_claim_refs: Vec<EntityRef>,
        capability_verification_refs: Vec<EntityRef>,
        provider_revision_refs: Vec<EntityRef>,
        observation_refs: Vec<EntityRef>,
        receipt_refs: Vec<EntityRef>,
        limitations: Vec<String>,
    ) -> Result<Self, NodeAgentError> {
        require_non_empty(&observation_refs, "node capability observation")?;
        require_non_empty(&receipt_refs, "node capability receipt")?;
        if !capability_claim_refs.is_empty() && capability_verification_refs.is_empty() {
            return Err(NodeAgentError::MissingEvidence("capability verification"));
        }
        Ok(Self {
            snapshot_ref: EntityRef::new("core.node_capability_snapshot")?,
            node_ref,
            node_generation,
            connection_epoch,
            snapshot_outcome,
            agent_revision: agent_revision.into(),
            platform,
            capability_claim_refs,
            capability_verification_refs,
            provider_revision_refs,
            observation_refs,
            receipt_refs,
            limitations,
        })
    }
}

/// One frozen resource quantity projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceQuantity {
    pub resource_key: String,
    pub unit: ResourceUnit,
    pub observed_total: f64,
    pub administratively_allocatable: f64,
    pub reserved: f64,
    pub consumed: f64,
    pub currently_available: f64,
    pub pressure: ResourcePressure,
    pub observation_refs: Vec<EntityRef>,
}

impl ResourceQuantity {
    /// Validate the frozen non-negative finite resource boundary.
    pub fn validate(&self) -> Result<(), NodeAgentError> {
        for value in [
            self.observed_total,
            self.administratively_allocatable,
            self.reserved,
            self.consumed,
            self.currently_available,
        ] {
            if !value.is_finite() || value.is_sign_negative() {
                return Err(NodeAgentError::InvalidResource("quantity must be finite and non-negative"));
            }
        }
        require_non_empty(&self.observation_refs, "resource observation")?;
        Ok(())
    }
}

/// Evidence-bound Node resource snapshot projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeResourceSnapshot {
    pub snapshot_ref: EntityRef,
    pub node_ref: EntityRef,
    pub node_generation: NodeGeneration,
    pub connection_epoch: ConnectionEpoch,
    pub snapshot_outcome: SnapshotOutcome,
    pub resources: Vec<ResourceQuantity>,
    pub observation_refs: Vec<EntityRef>,
    pub receipt_refs: Vec<EntityRef>,
    pub limitations: Vec<String>,
}

impl NodeResourceSnapshot {
    /// Construct a resource snapshot only from explicit observation and receipt evidence.
    pub fn new(
        node_ref: EntityRef,
        node_generation: NodeGeneration,
        connection_epoch: ConnectionEpoch,
        snapshot_outcome: SnapshotOutcome,
        resources: Vec<ResourceQuantity>,
        observation_refs: Vec<EntityRef>,
        receipt_refs: Vec<EntityRef>,
        limitations: Vec<String>,
    ) -> Result<Self, NodeAgentError> {
        if resources.is_empty() {
            return Err(NodeAgentError::InvalidResource("at least one resource is required"));
        }
        for resource in &resources {
            resource.validate()?;
        }
        require_non_empty(&observation_refs, "node resource observation")?;
        require_non_empty(&receipt_refs, "node resource receipt")?;
        Ok(Self {
            snapshot_ref: EntityRef::new("core.node_resource_snapshot")?,
            node_ref,
            node_generation,
            connection_epoch,
            snapshot_outcome,
            resources,
            observation_refs,
            receipt_refs,
            limitations,
        })
    }
}

/// Mechanical worker-capacity baseline over exact Node/Provider/resource evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerCapacityBaseline {
    pub node_ref: EntityRef,
    pub resource_snapshot_ref: EntityRef,
    pub provider_revision_refs: Vec<EntityRef>,
    pub evidence_refs: Vec<EntityRef>,
    pub human_equivalent_workers: u64,
    pub configured_slots: u64,
    pub observed_available_slots: u64,
    pub usable_slots: u64,
}

impl WorkerCapacityBaseline {
    /// Build the accepted ten-for-two baseline without inventing semantic work.
    pub fn from_snapshot(
        snapshot: &NodeResourceSnapshot,
        provider_revision_refs: Vec<EntityRef>,
        evidence_refs: Vec<EntityRef>,
        human_equivalent_workers: u64,
    ) -> Result<Self, NodeAgentError> {
        if provider_revision_refs.is_empty() {
            return Err(NodeAgentError::MissingProviderRevision);
        }
        require_non_empty(&evidence_refs, "worker capacity")?;
        let resource = snapshot
            .resources
            .iter()
            .find(|item| item.resource_key == "ptah.worker_slots" && item.unit == ResourceUnit::Count)
            .ok_or(NodeAgentError::InvalidResource("ptah.worker_slots count resource missing"))?;
        let configured_slots = human_equivalent_workers
            .checked_mul(10)
            .map(|value| cmp::max(20, value))
            .ok_or(NodeAgentError::WorkerCapacityOverflow)?;
        let observed_available_slots = finite_floor_to_u64(resource.currently_available)?;
        Ok(Self {
            node_ref: snapshot.node_ref.clone(),
            resource_snapshot_ref: snapshot.snapshot_ref.clone(),
            provider_revision_refs,
            evidence_refs,
            human_equivalent_workers,
            configured_slots,
            observed_available_slots,
            usable_slots: cmp::min(configured_slots, observed_available_slots),
        })
    }
}

/// Bounded diagnostic advisory represented as an Object View over exact evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticAdvisory {
    pub view_ref: EntityRef,
    pub view_kind: String,
    pub affected_node_ref: EntityRef,
    pub evidence_refs: Vec<EntityRef>,
    pub observed_condition: String,
    pub expected_condition: String,
    pub effect: String,
    pub uncertainty: String,
    pub suggested_upgrade_class: Option<String>,
    pub required_caller_decision: String,
    pub work_state: AdvisoryWorkState,
    pub automatic_upgrade_authorized: bool,
    pub self_approved: bool,
}

/// Advisory effect on caller-submitted work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryWorkState {
    Blocked,
    Degraded,
    Unaffected,
}

impl DiagnosticAdvisory {
    /// Produce a bounded advisory. This function cannot authorize or execute an upgrade.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        affected_node_ref: EntityRef,
        evidence_refs: Vec<EntityRef>,
        observed_condition: impl Into<String>,
        expected_condition: impl Into<String>,
        effect: impl Into<String>,
        uncertainty: impl Into<String>,
        suggested_upgrade_class: Option<String>,
        required_caller_decision: impl Into<String>,
        work_state: AdvisoryWorkState,
    ) -> Result<Self, NodeAgentError> {
        require_non_empty(&evidence_refs, "diagnostic advisory")?;
        let observed_condition = non_empty(observed_condition.into(), "observed_condition")?;
        let expected_condition = non_empty(expected_condition.into(), "expected_condition")?;
        let effect = non_empty(effect.into(), "effect")?;
        let uncertainty = non_empty(uncertainty.into(), "uncertainty")?;
        let required_caller_decision =
            non_empty(required_caller_decision.into(), "required_caller_decision")?;
        Ok(Self {
            view_ref: EntityRef::new("object.view")?,
            view_kind: DIAGNOSTIC_VIEW_KIND.to_owned(),
            affected_node_ref,
            evidence_refs,
            observed_condition,
            expected_condition,
            effect,
            uncertainty,
            suggested_upgrade_class,
            required_caller_decision,
            work_state,
            automatic_upgrade_authorized: false,
            self_approved: false,
        })
    }
}

/// Result of checking a caller's generation constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationCheck {
    pub requested_generation: NodeGeneration,
    pub current_generation: NodeGeneration,
    pub accepted: bool,
    pub stable_outcome_code: Option<String>,
    pub retry_after_generation_refresh: bool,
    pub correlation: CorrelationRefs,
}

/// Current in-memory A02 Node agent state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAgent {
    node_id: NodeId,
    generation: NodeGeneration,
    connection_epoch: ConnectionEpoch,
    record_revision: u64,
    lifecycle: NodeLifecycleState,
    sequence: u64,
    current_reachability: NodeReachability,
    current_health: NodeHealth,
}

impl NodeAgent {
    /// Start the first generation of a new Node identity.
    pub fn bootstrap() -> Result<Self, NodeAgentError> {
        ensure_frozen_contracts()?;
        Ok(Self {
            node_id: NodeId::new(),
            generation: NodeGeneration::INITIAL,
            connection_epoch: ConnectionEpoch::INITIAL,
            record_revision: 1,
            lifecycle: NodeLifecycleState::Active,
            sequence: 0,
            current_reachability: NodeReachability::Unknown,
            current_health: NodeHealth::Unknown,
        })
    }

    /// Restart one already-known Node. The caller supplies the last retained seed;
    /// A03 will later own durable persistence of that seed.
    pub fn restart(seed: NodeRestartSeed) -> Result<Self, NodeAgentError> {
        ensure_frozen_contracts()?;
        Ok(Self {
            node_id: seed.node_id,
            generation: seed.generation.next()?,
            connection_epoch: seed.connection_epoch.next()?,
            record_revision: seed.record_revision.saturating_add(1),
            lifecycle: NodeLifecycleState::Active,
            sequence: 0,
            current_reachability: NodeReachability::Unknown,
            current_health: NodeHealth::Unknown,
        })
    }

    /// Stable canonical Node identity.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Current Node generation.
    #[must_use]
    pub const fn generation(&self) -> NodeGeneration {
        self.generation
    }

    /// Current control-connection epoch.
    #[must_use]
    pub const fn connection_epoch(&self) -> ConnectionEpoch {
        self.connection_epoch
    }

    /// Current Node lifecycle state.
    #[must_use]
    pub const fn lifecycle(&self) -> NodeLifecycleState {
        self.lifecycle
    }

    /// Export caller-retainable restart state without implementing A03 storage.
    #[must_use]
    pub const fn restart_seed(&self) -> NodeRestartSeed {
        NodeRestartSeed {
            node_id: self.node_id,
            generation: self.generation,
            connection_epoch: self.connection_epoch,
            record_revision: self.record_revision,
        }
    }

    /// Advance only the connection epoch while preserving Node identity/generation.
    pub fn reconnect(&mut self) -> Result<ConnectionEpoch, NodeAgentError> {
        self.connection_epoch = self.connection_epoch.next()?;
        self.record_revision = self.record_revision.saturating_add(1);
        Ok(self.connection_epoch)
    }

    /// Create an exact Node reference for the current generation/epoch.
    #[must_use]
    pub fn node_ref(&self) -> EntityRef {
        self.node_id.entity_ref(self.generation, self.connection_epoch)
    }

    /// Reject stale generation use with an Event/Receipt correlation instead of silently weakening it.
    pub fn check_generation(
        &self,
        requested_generation: NodeGeneration,
    ) -> Result<GenerationCheck, NodeAgentError> {
        let accepted = requested_generation == self.generation;
        Ok(GenerationCheck {
            requested_generation,
            current_generation: self.generation,
            accepted,
            stable_outcome_code: (!accepted).then(|| STALE_GENERATION_CODE.to_owned()),
            retry_after_generation_refresh: !accepted,
            correlation: CorrelationRefs::new()?,
        })
    }

    /// Record an evidence-bound Node observation and project current health/reachability.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        observation_kind: ObservationKind,
        producer_ref: EntityRef,
        reachability: Option<NodeReachability>,
        health: Option<NodeHealth>,
        receipt_refs: Vec<EntityRef>,
        host_identity_evidence: Option<HostIdentityEvidence>,
    ) -> Result<NodeObservation, NodeAgentError> {
        require_non_empty(&receipt_refs, "node observation")?;
        self.sequence = self.sequence.saturating_add(1);
        if let Some(value) = reachability {
            self.current_reachability = value;
        }
        if let Some(value) = health {
            self.current_health = value;
        }
        Ok(NodeObservation {
            observation_ref: EntityRef::new("core.node_observation")?,
            node_ref: self.node_ref(),
            node_generation: self.generation,
            connection_epoch: self.connection_epoch,
            observation_kind,
            producer_ref,
            sequence: self.sequence,
            reachability,
            health,
            receipt_refs,
            host_identity_evidence,
        })
    }

    /// Return a compact evidence-backed current Node state projection.
    pub fn current_projection(
        &self,
        capability_snapshot_refs: Vec<EntityRef>,
        resource_snapshot_refs: Vec<EntityRef>,
        observation_refs: Vec<EntityRef>,
    ) -> Result<NodeStateProjection, NodeAgentError> {
        require_non_empty(&observation_refs, "node state projection")?;
        Ok(NodeStateProjection {
            node_ref: self.node_ref(),
            lifecycle: self.lifecycle,
            node_generation: self.generation,
            connection_epoch: self.connection_epoch,
            current_reachability: self.current_reachability,
            current_health: self.current_health,
            capability_snapshot_refs,
            resource_snapshot_refs,
            observation_refs,
        })
    }
}

/// Compact contract-shaped Node state projection. Durable canonical record storage is deferred to A03.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStateProjection {
    pub node_ref: EntityRef,
    pub lifecycle: NodeLifecycleState,
    pub node_generation: NodeGeneration,
    pub connection_epoch: ConnectionEpoch,
    pub current_reachability: NodeReachability,
    pub current_health: NodeHealth,
    pub capability_snapshot_refs: Vec<EntityRef>,
    pub resource_snapshot_refs: Vec<EntityRef>,
    pub observation_refs: Vec<EntityRef>,
}

fn ensure_frozen_contracts() -> Result<(), NodeAgentError> {
    for schema in [
        NODE_SCHEMA,
        NODE_OBSERVATION_SCHEMA,
        NODE_CAPABILITY_SCHEMA,
        NODE_RESOURCE_SCHEMA,
        EVENT_SCHEMA,
        RECEIPT_SCHEMA,
        VIEW_SCHEMA,
    ] {
        if generated::schema_by_id(schema).is_none() {
            return Err(NodeAgentError::MissingFrozenContract(schema));
        }
    }
    if generated::state_machine(NODE_LIFECYCLE, NODE_LIFECYCLE_VERSION).is_none() {
        return Err(NodeAgentError::MissingFrozenContract(NODE_LIFECYCLE));
    }
    Ok(())
}

fn require_non_empty<T>(values: &[T], claim: &'static str) -> Result<(), NodeAgentError> {
    if values.is_empty() {
        return Err(NodeAgentError::MissingEvidence(claim));
    }
    Ok(())
}

fn non_empty(value: String, field: &'static str) -> Result<String, NodeAgentError> {
    if value.trim().is_empty() {
        return Err(NodeAgentError::InvalidAdvisory(field));
    }
    Ok(value)
}

fn finite_floor_to_u64(value: f64) -> Result<u64, NodeAgentError> {
    if !value.is_finite() || value.is_sign_negative() || value > u64::MAX as f64 {
        return Err(NodeAgentError::InvalidResource("worker slot count is invalid"));
    }
    Ok(value.floor() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence_ref(kind: &str) -> EntityRef {
        EntityRef::new(kind).expect("valid evidence ref")
    }

    fn receipt_ref() -> EntityRef {
        evidence_ref(RECEIPT_ENTITY_KIND)
    }

    fn observation_ref() -> EntityRef {
        evidence_ref("core.node_observation")
    }

    #[test]
    fn frozen_contract_bindings_exist() {
        ensure_frozen_contracts().expect("A02 frozen contracts must be bound")
    }

    #[test]
    fn restart_preserves_node_identity_and_advances_generation() {
        let first = NodeAgent::bootstrap().expect("bootstrap");
        let seed = first.restart_seed();
        let restarted = NodeAgent::restart(seed).expect("restart");
        assert_eq!(restarted.node_id(), first.node_id());
        assert_eq!(restarted.generation().value(), first.generation().value() + 1);
        assert_eq!(
            restarted.connection_epoch().value(),
            first.connection_epoch().value() + 1
        );
    }

    #[test]
    fn reconnect_changes_epoch_but_not_identity_or_generation() {
        let mut agent = NodeAgent::bootstrap().expect("bootstrap");
        let id = agent.node_id();
        let generation = agent.generation();
        let previous_epoch = agent.connection_epoch();
        let next_epoch = agent.reconnect().expect("reconnect");
        assert_eq!(agent.node_id(), id);
        assert_eq!(agent.generation(), generation);
        assert_eq!(next_epoch.value(), previous_epoch.value() + 1);
    }

    #[test]
    fn stale_generation_fails_with_event_and_receipt_evidence() {
        let agent = NodeAgent::restart(NodeAgent::bootstrap().expect("bootstrap").restart_seed())
            .expect("restart");
        let check = agent
            .check_generation(NodeGeneration::INITIAL)
            .expect("generation check");
        assert!(!check.accepted);
        assert_eq!(check.stable_outcome_code.as_deref(), Some(STALE_GENERATION_CODE));
        assert!(check.retry_after_generation_refresh);
        assert_eq!(check.correlation.event_ref.entity_kind, EVENT_ENTITY_KIND);
        assert_eq!(check.correlation.receipt_ref.entity_kind, RECEIPT_ENTITY_KIND);
    }

    #[test]
    fn current_generation_is_accepted_but_still_correlated() {
        let agent = NodeAgent::bootstrap().expect("bootstrap");
        let check = agent
            .check_generation(agent.generation())
            .expect("generation check");
        assert!(check.accepted);
        assert!(check.stable_outcome_code.is_none());
        assert_eq!(check.correlation.event_ref.entity_kind, EVENT_ENTITY_KIND);
        assert_eq!(check.correlation.receipt_ref.entity_kind, RECEIPT_ENTITY_KIND);
    }

    #[test]
    fn hostname_pid_and_boot_id_remain_observation_evidence() {
        let mut agent = NodeAgent::bootstrap().expect("bootstrap");
        let id_before = agent.node_id();
        let observation = agent
            .observe(
                ObservationKind::Boot,
                evidence_ref("core.provider_instance"),
                Some(NodeReachability::Online),
                Some(NodeHealth::Healthy),
                vec![receipt_ref()],
                Some(HostIdentityEvidence {
                    hostname: Some("test-host".to_owned()),
                    process_id: 4242,
                    boot_id: Some("boot-alias".to_owned()),
                }),
            )
            .expect("observation");
        assert_eq!(agent.node_id(), id_before);
        assert_eq!(observation.node_ref.entity_id, id_before.entity_id());
        let host = observation.host_identity_evidence.expect("host evidence");
        assert_eq!(host.hostname.as_deref(), Some("test-host"));
        assert_eq!(host.process_id, 4242);
    }

    #[test]
    fn health_projection_requires_receipt_evidence() {
        let mut agent = NodeAgent::bootstrap().expect("bootstrap");
        let result = agent.observe(
            ObservationKind::Health,
            evidence_ref("core.provider_instance"),
            None,
            Some(NodeHealth::Healthy),
            Vec::new(),
            None,
        );
        assert_eq!(result, Err(NodeAgentError::MissingEvidence("node observation")));
    }

    #[test]
    fn capability_claim_requires_verification_and_observation_evidence() {
        let agent = NodeAgent::bootstrap().expect("bootstrap");
        let claim = evidence_ref("core.capability_claim");
        let result = NodeCapabilitySnapshot::new(
            agent.node_ref(),
            agent.generation(),
            agent.connection_epoch(),
            SnapshotOutcome::Complete,
            "a02-test",
            PlatformFacts {
                os_family: OsFamily::Linux,
                os_name: Some("Test Linux".to_owned()),
                os_version: None,
                kernel_name: Some("linux".to_owned()),
                kernel_version: None,
                architecture: Architecture::X86_64,
                architecture_detail: None,
            },
            vec![claim],
            Vec::new(),
            Vec::new(),
            vec![observation_ref()],
            vec![receipt_ref()],
            Vec::new(),
        );
        assert_eq!(result, Err(NodeAgentError::MissingEvidence("capability verification")));
    }

    #[test]
    fn worker_capacity_is_bound_to_node_provider_resource_and_evidence() {
        let agent = NodeAgent::bootstrap().expect("bootstrap");
        let observation = observation_ref();
        let snapshot = NodeResourceSnapshot::new(
            agent.node_ref(),
            agent.generation(),
            agent.connection_epoch(),
            SnapshotOutcome::Complete,
            vec![ResourceQuantity {
                resource_key: "ptah.worker_slots".to_owned(),
                unit: ResourceUnit::Count,
                observed_total: 64.0,
                administratively_allocatable: 48.0,
                reserved: 8.0,
                consumed: 12.0,
                currently_available: 28.0,
                pressure: ResourcePressure::Normal,
                observation_refs: vec![observation.clone()],
            }],
            vec![observation.clone()],
            vec![receipt_ref()],
            Vec::new(),
        )
        .expect("resource snapshot");
        let capacity = WorkerCapacityBaseline::from_snapshot(
            &snapshot,
            vec![evidence_ref("core.provider_revision")],
            vec![observation],
            2,
        )
        .expect("capacity");
        assert_eq!(capacity.configured_slots, 20);
        assert_eq!(capacity.observed_available_slots, 28);
        assert_eq!(capacity.usable_slots, 20);
        assert_eq!(capacity.node_ref.entity_id, agent.node_id().entity_id());
    }

    #[test]
    fn capacity_cannot_exist_without_provider_revision_evidence() {
        let agent = NodeAgent::bootstrap().expect("bootstrap");
        let observation = observation_ref();
        let snapshot = NodeResourceSnapshot::new(
            agent.node_ref(),
            agent.generation(),
            agent.connection_epoch(),
            SnapshotOutcome::Complete,
            vec![ResourceQuantity {
                resource_key: "ptah.worker_slots".to_owned(),
                unit: ResourceUnit::Count,
                observed_total: 20.0,
                administratively_allocatable: 20.0,
                reserved: 0.0,
                consumed: 0.0,
                currently_available: 20.0,
                pressure: ResourcePressure::Normal,
                observation_refs: vec![observation.clone()],
            }],
            vec![observation.clone()],
            vec![receipt_ref()],
            Vec::new(),
        )
        .expect("resource snapshot");
        assert_eq!(
            WorkerCapacityBaseline::from_snapshot(&snapshot, Vec::new(), vec![observation], 2),
            Err(NodeAgentError::MissingProviderRevision)
        );
    }

    #[test]
    fn advisory_is_evidence_bound_and_cannot_authorize_its_own_upgrade() {
        let agent = NodeAgent::bootstrap().expect("bootstrap");
        let advisory = DiagnosticAdvisory::new(
            agent.node_ref(),
            vec![observation_ref(), receipt_ref()],
            "GPU provider unavailable",
            "caller requested gpu.execution capability",
            "requested acceleration is unavailable",
            "no compatible GPU Provider is currently evidenced",
            Some("compatible_gpu_provider".to_owned()),
            "caller must choose another Provider, degraded continuation, or an upgrade Activity",
            AdvisoryWorkState::Blocked,
        )
        .expect("advisory");
        assert_eq!(advisory.view_ref.entity_kind, "object.view");
        assert_eq!(advisory.view_kind, DIAGNOSTIC_VIEW_KIND);
        assert!(!advisory.automatic_upgrade_authorized);
        assert!(!advisory.self_approved);
    }

    #[test]
    fn advisory_without_evidence_is_rejected() {
        let agent = NodeAgent::bootstrap().expect("bootstrap");
        let result = DiagnosticAdvisory::new(
            agent.node_ref(),
            Vec::new(),
            "missing",
            "expected",
            "effect",
            "uncertain",
            None,
            "caller decides",
            AdvisoryWorkState::Degraded,
        );
        assert_eq!(result, Err(NodeAgentError::MissingEvidence("diagnostic advisory")));
    }

    #[test]
    fn state_projection_requires_observation_evidence() {
        let agent = NodeAgent::bootstrap().expect("bootstrap");
        assert_eq!(
            agent.current_projection(Vec::new(), Vec::new(), Vec::new()),
            Err(NodeAgentError::MissingEvidence("node state projection"))
        );
    }

    #[test]
    fn serialized_restart_seed_preserves_identity_without_claiming_persistence() {
        let agent = NodeAgent::bootstrap().expect("bootstrap");
        let seed = agent.restart_seed();
        let encoded = serde_json::to_string(&seed).expect("serialize restart seed");
        let decoded: NodeRestartSeed = serde_json::from_str(&encoded).expect("deserialize seed");
        let restarted = NodeAgent::restart(decoded).expect("restart");
        assert_eq!(restarted.node_id(), agent.node_id());
        assert_ne!(restarted.generation(), agent.generation());
    }
}
