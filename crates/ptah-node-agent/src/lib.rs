#![forbid(unsafe_code)]
//! A02 `Node` identity, Generation and host-truth runtime primitives.
//!
//! This crate implements the first `Node` runtime semantics while deliberately
//! leaving durable ledger persistence to A03 and Activity execution to A04.
//! Canonical `Node` identity is independent of hostname, process ID, boot ID and
//! other host observations. Runtime claims are accepted only when tied to
//! explicit evidence references.

use ptah_contracts::generated;
use ptah_identifiers::{
    ConnectionEpoch, EVENT_ENTITY_KIND, EntityRef, IdentifierError, NodeGeneration, NodeId,
    RECEIPT_ENTITY_KIND,
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
const MAX_EXACT_INTEGER_F64: f64 = 9_007_199_254_740_991.0;

/// A02 runtime failures that must remain explicit and evidenceable.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum NodeAgentError {
    /// A selected frozen contract binding is missing from the generated lock.
    #[error("required frozen contract binding is missing: {0}")]
    MissingFrozenContract(&'static str),
    /// Required evidence references were omitted from a runtime claim.
    #[error("evidence references are required for {0}")]
    MissingEvidence(&'static str),
    /// A required Provider revision was omitted from a capacity claim.
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

/// Frozen `Node` lifecycle states.
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

/// Frozen `Node` reachability projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeReachability {
    /// Reachability has not yet been established.
    Unknown,
    /// Current evidence shows the `Node` is reachable.
    Online,
    /// Current evidence shows the `Node` is unreachable.
    Offline,
    /// The latest reachability evidence has expired or become stale.
    Stale,
}

/// Frozen `Node` health projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeHealth {
    /// Health has not yet been established.
    Unknown,
    /// Current evidence satisfies the configured healthy condition.
    Healthy,
    /// Current evidence shows reduced capability without total failure.
    Degraded,
    /// Current evidence shows the `Node` is unhealthy.
    Unhealthy,
}

/// Frozen observation kinds for `Node` evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    /// Periodic liveness observation.
    Heartbeat,
    /// Reachability-state observation.
    Reachability,
    /// Health-state observation.
    Health,
    /// Host or agent boot observation.
    Boot,
    /// Host or agent shutdown observation.
    Shutdown,
    /// Reconciliation observation comparing expected and observed state.
    Reconciliation,
    /// Contract-compatible observation not covered by a narrower kind.
    Other,
}

/// Frozen snapshot outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotOutcome {
    /// All required snapshot observations completed.
    Complete,
    /// Some required observations completed and limitations are retained.
    Partial,
    /// Snapshot collection failed.
    Failed,
}

/// Frozen platform operating-system families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    /// Linux-family operating system.
    Linux,
    /// Windows-family operating system.
    Windows,
    /// macOS-family operating system.
    Macos,
    /// Android operating system.
    Android,
    /// iOS operating system.
    Ios,
    /// A platform outside the currently enumerated families.
    Other,
}

/// Frozen platform architecture projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    /// 64-bit x86 architecture.
    X86_64,
    /// 64-bit ARM architecture.
    Aarch64,
    /// 32-bit ARMv7 architecture.
    Armv7,
    /// 64-bit RISC-V architecture.
    Riscv64,
    /// An architecture outside the currently enumerated set.
    Other,
}

/// Frozen resource units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceUnit {
    /// Discrete count.
    Count,
    /// Byte quantity.
    Bytes,
    /// Thousandths of one CPU core.
    Millicpu,
    /// CPU-core quantity.
    Cores,
    /// Percentage quantity.
    Percent,
    /// Power in watts.
    Watts,
    /// Contract-defined custom unit.
    Custom,
}

/// Frozen resource pressure states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourcePressure {
    /// Pressure has not yet been established.
    Unknown,
    /// Resource pressure is within the configured normal range.
    Normal,
    /// Resource pressure is elevated but not critical.
    Elevated,
    /// Resource pressure is at a configured critical threshold.
    Critical,
    /// The resource is unavailable.
    Unavailable,
}

/// Host endpoint facts that are evidence/aliases, never canonical `Node` identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostIdentityEvidence {
    /// Observed hostname, when available.
    pub hostname: Option<String>,
    /// Observed process identifier for the producing agent instance.
    pub process_id: u32,
    /// Observed boot identifier, when the platform exposes one.
    pub boot_id: Option<String>,
}

/// Platform facts carried by a capability snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformFacts {
    /// Operating-system family.
    pub os_family: OsFamily,
    /// Human-readable operating-system name, when observed.
    pub os_name: Option<String>,
    /// Operating-system version, when observed.
    pub os_version: Option<String>,
    /// Kernel name, when observed.
    pub kernel_name: Option<String>,
    /// Kernel version, when observed.
    pub kernel_version: Option<String>,
    /// Canonical architecture class.
    pub architecture: Architecture,
    /// Additional architecture detail that does not fit the canonical class.
    pub architecture_detail: Option<String>,
}

/// Explicit state a caller or persistence owner may retain across agent restarts.
///
/// A02 defines this state but does not persist it. Durable storage belongs to A03.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRestartSeed {
    /// Stable canonical `Node` identity.
    pub node_id: NodeId,
    /// Last accepted `Node` generation.
    pub generation: NodeGeneration,
    /// Last accepted control-connection epoch.
    pub connection_epoch: ConnectionEpoch,
    /// Last accepted canonical-record revision.
    pub record_revision: u64,
}

/// Correlation references linking a runtime outcome to an `Event` and `Receipt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationRefs {
    /// Reference reserved for the correlated `Event`.
    pub event_ref: EntityRef,
    /// Reference reserved for the correlated `Receipt`.
    pub receipt_ref: EntityRef,
}

impl CorrelationRefs {
    /// Allocate canonical `Event` and `Receipt` references without implementing A04 storage.
    ///
    /// # Errors
    ///
    /// Returns [`NodeAgentError::Identifier`] if either typed reference cannot be
    /// constructed under the frozen entity-kind contract.
    pub fn new() -> Result<Self, NodeAgentError> {
        Ok(Self {
            event_ref: EntityRef::new(EVENT_ENTITY_KIND)?,
            receipt_ref: EntityRef::new(RECEIPT_ENTITY_KIND)?,
        })
    }
}

/// Evidence-bound `Node` observation projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeObservation {
    /// Canonical observation reference.
    pub observation_ref: EntityRef,
    /// Exact `Node` reference, including generation and connection epoch.
    pub node_ref: EntityRef,
    /// `Node` generation observed by this record.
    pub node_generation: NodeGeneration,
    /// Connection epoch observed by this record.
    pub connection_epoch: ConnectionEpoch,
    /// Frozen observation kind.
    pub observation_kind: ObservationKind,
    /// Producer that supplied this observation.
    pub producer_ref: EntityRef,
    /// Monotonic sequence within this agent generation.
    pub sequence: u64,
    /// Optional reachability projection supplied by this observation.
    pub reachability: Option<NodeReachability>,
    /// Optional health projection supplied by this observation.
    pub health: Option<NodeHealth>,
    /// Receipts supporting the observation.
    pub receipt_refs: Vec<EntityRef>,
    /// Optional host endpoint facts that remain evidence rather than identity.
    pub host_identity_evidence: Option<HostIdentityEvidence>,
}

/// A capability snapshot tied to exact `Node` generation/epoch and evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCapabilitySnapshot {
    /// Canonical snapshot reference.
    pub snapshot_ref: EntityRef,
    /// Exact `Node` reference.
    pub node_ref: EntityRef,
    /// `Node` generation represented by the snapshot.
    pub node_generation: NodeGeneration,
    /// Connection epoch represented by the snapshot.
    pub connection_epoch: ConnectionEpoch,
    /// Snapshot collection outcome.
    pub snapshot_outcome: SnapshotOutcome,
    /// Exact agent revision that produced the snapshot.
    pub agent_revision: String,
    /// Observed platform facts.
    pub platform: PlatformFacts,
    /// Capability claims represented by the snapshot.
    pub capability_claim_refs: Vec<EntityRef>,
    /// Verification evidence for capability claims.
    pub capability_verification_refs: Vec<EntityRef>,
    /// Exact Provider revisions supporting the snapshot.
    pub provider_revision_refs: Vec<EntityRef>,
    /// Observations supporting the snapshot.
    pub observation_refs: Vec<EntityRef>,
    /// Receipts supporting the snapshot.
    pub receipt_refs: Vec<EntityRef>,
    /// Retained limitations or uncertainty.
    pub limitations: Vec<String>,
}

impl NodeCapabilitySnapshot {
    /// Construct a capability claim only when observation, verification and receipt evidence exists.
    ///
    /// # Errors
    ///
    /// Returns [`NodeAgentError::MissingEvidence`] if required observation or
    /// receipt evidence is absent, or when claims exist without verification.
    /// Identifier construction errors are returned as [`NodeAgentError::Identifier`].
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
    /// Stable resource key.
    pub resource_key: String,
    /// Unit used by the quantity.
    pub unit: ResourceUnit,
    /// Total quantity observed on the host.
    pub observed_total: f64,
    /// Quantity administratively eligible for allocation.
    pub administratively_allocatable: f64,
    /// Quantity already reserved.
    pub reserved: f64,
    /// Quantity currently consumed.
    pub consumed: f64,
    /// Quantity currently available for new allocation.
    pub currently_available: f64,
    /// Current pressure projection.
    pub pressure: ResourcePressure,
    /// Observations supporting this resource quantity.
    pub observation_refs: Vec<EntityRef>,
}

impl ResourceQuantity {
    /// Validate the frozen non-negative finite resource boundary.
    ///
    /// # Errors
    ///
    /// Returns [`NodeAgentError::InvalidResource`] for non-finite or negative
    /// quantities and [`NodeAgentError::MissingEvidence`] when no supporting
    /// observation is present.
    pub fn validate(&self) -> Result<(), NodeAgentError> {
        for value in [
            self.observed_total,
            self.administratively_allocatable,
            self.reserved,
            self.consumed,
            self.currently_available,
        ] {
            if !value.is_finite() || value.is_sign_negative() {
                return Err(NodeAgentError::InvalidResource(
                    "quantity must be finite and non-negative",
                ));
            }
        }
        require_non_empty(&self.observation_refs, "resource observation")?;
        Ok(())
    }
}

/// Evidence-bound `Node` resource snapshot projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeResourceSnapshot {
    /// Canonical snapshot reference.
    pub snapshot_ref: EntityRef,
    /// Exact `Node` reference.
    pub node_ref: EntityRef,
    /// `Node` generation represented by the snapshot.
    pub node_generation: NodeGeneration,
    /// Connection epoch represented by the snapshot.
    pub connection_epoch: ConnectionEpoch,
    /// Snapshot collection outcome.
    pub snapshot_outcome: SnapshotOutcome,
    /// Resource quantities represented by the snapshot.
    pub resources: Vec<ResourceQuantity>,
    /// Observations supporting the snapshot.
    pub observation_refs: Vec<EntityRef>,
    /// Receipts supporting the snapshot.
    pub receipt_refs: Vec<EntityRef>,
    /// Retained limitations or uncertainty.
    pub limitations: Vec<String>,
}

impl NodeResourceSnapshot {
    /// Construct a resource snapshot only from explicit observation and receipt evidence.
    ///
    /// # Errors
    ///
    /// Returns [`NodeAgentError::InvalidResource`] when no valid resource exists,
    /// [`NodeAgentError::MissingEvidence`] when required observations or receipts
    /// are absent, and [`NodeAgentError::Identifier`] for reference failures.
    #[allow(clippy::too_many_arguments)]
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
            return Err(NodeAgentError::InvalidResource(
                "at least one resource is required",
            ));
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

/// Mechanical worker-capacity baseline over exact `Node`/Provider/resource evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerCapacityBaseline {
    /// Exact `Node` reference used by this baseline.
    pub node_ref: EntityRef,
    /// Resource snapshot supporting the capacity calculation.
    pub resource_snapshot_ref: EntityRef,
    /// Exact Provider revisions supplying worker execution.
    pub provider_revision_refs: Vec<EntityRef>,
    /// Additional evidence supporting the baseline.
    pub evidence_refs: Vec<EntityRef>,
    /// Caller-selected human-equivalent worker count.
    pub human_equivalent_workers: u64,
    /// Configured ten-for-two slot baseline.
    pub configured_slots: u64,
    /// Host-observed currently available worker slots.
    pub observed_available_slots: u64,
    /// Mechanically usable slots after applying both limits.
    pub usable_slots: u64,
}

impl WorkerCapacityBaseline {
    /// Build the accepted ten-for-two baseline without inventing semantic work.
    ///
    /// # Errors
    ///
    /// Returns [`NodeAgentError::MissingProviderRevision`] when Provider evidence
    /// is absent, [`NodeAgentError::MissingEvidence`] when capacity evidence is
    /// absent, [`NodeAgentError::InvalidResource`] when an exact worker-slot count
    /// cannot be established, or [`NodeAgentError::WorkerCapacityOverflow`] when
    /// the configured ten-for-two multiplication would overflow.
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
            .find(|item| {
                item.resource_key == "ptah.worker_slots" && item.unit == ResourceUnit::Count
            })
            .ok_or(NodeAgentError::InvalidResource(
                "ptah.worker_slots count resource missing",
            ))?;
        let configured_slots = human_equivalent_workers
            .checked_mul(10)
            .map(|value| cmp::max(20, value))
            .ok_or(NodeAgentError::WorkerCapacityOverflow)?;
        let observed_available_slots = exact_count_to_u64(resource.currently_available)?;
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
    /// Canonical Object View reference.
    pub view_ref: EntityRef,
    /// Stable view-kind discriminator.
    pub view_kind: String,
    /// Exact affected `Node` reference.
    pub affected_node_ref: EntityRef,
    /// Evidence supporting the advisory.
    pub evidence_refs: Vec<EntityRef>,
    /// Exact condition observed by Ptah.
    pub observed_condition: String,
    /// Caller-, contract-, or policy-defined expected condition.
    pub expected_condition: String,
    /// Mechanical effect on the caller-submitted work.
    pub effect: String,
    /// Known uncertainty or evidence limitation.
    pub uncertainty: String,
    /// Optional class of missing or improved capability.
    pub suggested_upgrade_class: Option<String>,
    /// Decision explicitly left to the caller or authorized application.
    pub required_caller_decision: String,
    /// Effect on the requested work.
    pub work_state: AdvisoryWorkState,
    /// Always false in A02: an advisory cannot authorize an upgrade.
    pub automatic_upgrade_authorized: bool,
    /// Always false in A02: Ptah cannot approve its own advisory.
    pub self_approved: bool,
}

/// Advisory effect on caller-submitted work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryWorkState {
    /// The requested work is mechanically blocked by the missing condition.
    Blocked,
    /// The requested work may continue with reduced capability or proof.
    Degraded,
    /// The advisory does not affect the requested work.
    Unaffected,
}

impl DiagnosticAdvisory {
    /// Produce a bounded advisory. This function cannot authorize or execute an upgrade.
    ///
    /// # Errors
    ///
    /// Returns [`NodeAgentError::MissingEvidence`] when supporting evidence is
    /// absent, [`NodeAgentError::InvalidAdvisory`] when required text is empty,
    /// or [`NodeAgentError::Identifier`] when the Object View reference cannot
    /// be constructed.
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
    /// Generation supplied by the caller.
    pub requested_generation: NodeGeneration,
    /// Current authoritative in-memory generation.
    pub current_generation: NodeGeneration,
    /// Whether the generation constraint matched.
    pub accepted: bool,
    /// Stable outcome code when the generation is stale.
    pub stable_outcome_code: Option<String>,
    /// Whether the caller should refresh generation state before retrying.
    pub retry_after_generation_refresh: bool,
    /// `Event`/Receipt correlation reserved for the outcome.
    pub correlation: CorrelationRefs,
}

/// Current in-memory A02 `Node` agent state.
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
    /// Start the first generation of a new `Node` identity.
    ///
    /// # Errors
    ///
    /// Returns [`NodeAgentError::MissingFrozenContract`] if an A02 contract
    /// binding is absent.
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

    /// Restart one already-known `Node` from caller-retained state.
    ///
    /// A03 will later own durable persistence of the seed.
    ///
    /// # Errors
    ///
    /// Returns [`NodeAgentError::MissingFrozenContract`] when required bindings
    /// are absent, or [`NodeAgentError::Identifier`] if generation, epoch, or
    /// revision advancement would overflow.
    pub fn restart(seed: NodeRestartSeed) -> Result<Self, NodeAgentError> {
        ensure_frozen_contracts()?;
        let record_revision = seed
            .record_revision
            .checked_add(1)
            .ok_or(IdentifierError::CounterOverflow)?;
        Ok(Self {
            node_id: seed.node_id,
            generation: seed.generation.next()?,
            connection_epoch: seed.connection_epoch.next()?,
            record_revision,
            lifecycle: NodeLifecycleState::Active,
            sequence: 0,
            current_reachability: NodeReachability::Unknown,
            current_health: NodeHealth::Unknown,
        })
    }

    /// Stable canonical `Node` identity.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Current `Node` generation.
    #[must_use]
    pub const fn generation(&self) -> NodeGeneration {
        self.generation
    }

    /// Current control-connection epoch.
    #[must_use]
    pub const fn connection_epoch(&self) -> ConnectionEpoch {
        self.connection_epoch
    }

    /// Current `Node` lifecycle state.
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

    /// Advance only the connection epoch while preserving `Node` identity/generation.
    ///
    /// # Errors
    ///
    /// Returns [`NodeAgentError::Identifier`] if the epoch or record revision
    /// cannot be advanced without overflow.
    pub fn reconnect(&mut self) -> Result<ConnectionEpoch, NodeAgentError> {
        let next_epoch = self.connection_epoch.next()?;
        let next_revision = self
            .record_revision
            .checked_add(1)
            .ok_or(IdentifierError::CounterOverflow)?;
        self.connection_epoch = next_epoch;
        self.record_revision = next_revision;
        Ok(self.connection_epoch)
    }

    /// Create an exact `Node` reference for the current generation/epoch.
    #[must_use]
    pub fn node_ref(&self) -> EntityRef {
        self.node_id
            .entity_ref(self.generation, self.connection_epoch)
    }

    /// Reject stale generation use with `Event`/Receipt correlation.
    ///
    /// # Errors
    ///
    /// Returns [`NodeAgentError::Identifier`] if correlation references cannot
    /// be allocated under the frozen entity-kind contract.
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

    /// Record an evidence-bound `Node` observation and project health/reachability.
    ///
    /// # Errors
    ///
    /// Returns [`NodeAgentError::MissingEvidence`] when receipt evidence is
    /// absent, [`NodeAgentError::Identifier`] when sequence advancement would
    /// overflow, or when the observation reference cannot be constructed.
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
        let next_sequence = self
            .sequence
            .checked_add(1)
            .ok_or(IdentifierError::CounterOverflow)?;
        self.sequence = next_sequence;
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

    /// Return a compact evidence-backed current `Node` state projection.
    ///
    /// # Errors
    ///
    /// Returns [`NodeAgentError::MissingEvidence`] when no observation evidence
    /// is supplied.
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

/// Compact contract-shaped `Node` state projection.
///
/// Durable canonical record storage is deferred to A03.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStateProjection {
    /// Exact current `Node` reference.
    pub node_ref: EntityRef,
    /// Current lifecycle projection.
    pub lifecycle: NodeLifecycleState,
    /// Current `Node` generation.
    pub node_generation: NodeGeneration,
    /// Current connection epoch.
    pub connection_epoch: ConnectionEpoch,
    /// Current reachability projection.
    pub current_reachability: NodeReachability,
    /// Current health projection.
    pub current_health: NodeHealth,
    /// Current capability-snapshot references supplied by the caller.
    pub capability_snapshot_refs: Vec<EntityRef>,
    /// Current resource-snapshot references supplied by the caller.
    pub resource_snapshot_refs: Vec<EntityRef>,
    /// Observations supporting the projection.
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

fn exact_count_to_u64(value: f64) -> Result<u64, NodeAgentError> {
    if !value.is_finite() || value.is_sign_negative() || value > MAX_EXACT_INTEGER_F64 {
        return Err(NodeAgentError::InvalidResource(
            "worker slot count is outside the exact integer range",
        ));
    }
    if value.fract().abs() > f64::EPSILON {
        return Err(NodeAgentError::InvalidResource(
            "worker slot count must be an integer",
        ));
    }
    format!("{value:.0}")
        .parse::<u64>()
        .map_err(|_| NodeAgentError::InvalidResource("worker slot count cannot be represented"))
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

    fn worker_snapshot(available: f64) -> NodeResourceSnapshot {
        let agent = NodeAgent::bootstrap().expect("bootstrap");
        let observation = observation_ref();
        NodeResourceSnapshot::new(
            agent.node_ref(),
            agent.generation(),
            agent.connection_epoch(),
            SnapshotOutcome::Complete,
            vec![ResourceQuantity {
                resource_key: "ptah.worker_slots".to_owned(),
                unit: ResourceUnit::Count,
                observed_total: available,
                administratively_allocatable: available,
                reserved: 0.0,
                consumed: 0.0,
                currently_available: available,
                pressure: ResourcePressure::Normal,
                observation_refs: vec![observation.clone()],
            }],
            vec![observation],
            vec![receipt_ref()],
            Vec::new(),
        )
        .expect("resource snapshot")
    }

    #[test]
    fn frozen_contract_bindings_exist() {
        ensure_frozen_contracts().expect("A02 frozen contracts must be bound");
    }

    #[test]
    fn restart_preserves_node_identity_and_advances_generation() {
        let first = NodeAgent::bootstrap().expect("bootstrap");
        let seed = first.restart_seed();
        let restarted = NodeAgent::restart(seed).expect("restart");
        assert_eq!(restarted.node_id(), first.node_id());
        assert_eq!(
            restarted.generation().value(),
            first.generation().value() + 1
        );
        assert_eq!(
            restarted.connection_epoch().value(),
            first.connection_epoch().value() + 1
        );
    }

    #[test]
    fn restart_fails_closed_on_revision_overflow() {
        let first = NodeAgent::bootstrap().expect("bootstrap");
        let mut seed = first.restart_seed();
        seed.record_revision = u64::MAX;
        assert_eq!(
            NodeAgent::restart(seed),
            Err(NodeAgentError::Identifier(IdentifierError::CounterOverflow))
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
        assert_eq!(
            check.stable_outcome_code.as_deref(),
            Some(STALE_GENERATION_CODE)
        );
        assert!(check.retry_after_generation_refresh);
        assert_eq!(check.correlation.event_ref.entity_kind, EVENT_ENTITY_KIND);
        assert_eq!(
            check.correlation.receipt_ref.entity_kind,
            RECEIPT_ENTITY_KIND
        );
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
        assert_eq!(
            check.correlation.receipt_ref.entity_kind,
            RECEIPT_ENTITY_KIND
        );
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
        assert_eq!(
            result,
            Err(NodeAgentError::MissingEvidence("node observation"))
        );
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
        assert_eq!(
            result,
            Err(NodeAgentError::MissingEvidence("capability verification"))
        );
    }

    #[test]
    fn worker_capacity_is_bound_to_node_provider_resource_and_evidence() {
        let snapshot = worker_snapshot(28.0);
        let capacity = WorkerCapacityBaseline::from_snapshot(
            &snapshot,
            vec![evidence_ref("core.provider_revision")],
            vec![observation_ref()],
            2,
        )
        .expect("capacity");
        assert_eq!(capacity.configured_slots, 20);
        assert_eq!(capacity.observed_available_slots, 28);
        assert_eq!(capacity.usable_slots, 20);
        assert_eq!(capacity.node_ref.entity_id, snapshot.node_ref.entity_id);
    }

    #[test]
    fn capacity_cannot_exist_without_provider_revision_evidence() {
        let snapshot = worker_snapshot(20.0);
        assert_eq!(
            WorkerCapacityBaseline::from_snapshot(
                &snapshot,
                Vec::new(),
                vec![observation_ref()],
                2
            ),
            Err(NodeAgentError::MissingProviderRevision)
        );
    }

    #[test]
    fn fractional_worker_slot_count_is_rejected_instead_of_rounded() {
        let snapshot = worker_snapshot(20.5);
        assert_eq!(
            WorkerCapacityBaseline::from_snapshot(
                &snapshot,
                vec![evidence_ref("core.provider_revision")],
                vec![observation_ref()],
                2
            ),
            Err(NodeAgentError::InvalidResource(
                "worker slot count must be an integer"
            ))
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
        assert_eq!(
            result,
            Err(NodeAgentError::MissingEvidence("diagnostic advisory"))
        );
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
