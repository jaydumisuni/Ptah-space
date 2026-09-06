#![forbid(unsafe_code)]
//! Mechanical E02 placement-authority primitives.
//!
//! This crate owns mechanical placement, Reservation, Lease and Fence validation.
//! Canonical Node and Attempt identity remains owned by existing Ptah authorities;
//! E02 composes those identities through [`ptah_identifiers`] primitives.

use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use ptah_node_agent::{
    NodeCapabilitySnapshot, NodeResourceSnapshot, OsFamily, ResourcePressure, ResourceUnit,
};
use ptah_node_link::SessionBinding;
use std::cmp::Ordering;
use thiserror::Error;

/// Stable machine-readable failures from E02 authority validation.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityError {
    /// Fence token zero is never valid authority.
    #[error("fence token must be positive")]
    InvalidFenceToken,
    /// A candidate Fence is not newer than the previously accepted Fence.
    #[error("fence token is stale")]
    StaleFence,
    /// A dispatch presented a Fence newer than the Fence currently accepted locally.
    #[error("fence token is not the current accepted fence")]
    FutureFence,
    /// Placement metadata was presented without a Lease.
    #[error("current lease is required")]
    MissingLease,
    /// Reservation validity ended at or before the validation instant.
    #[error("reservation is expired")]
    ExpiredReservation,
    /// Lease validity ended at or before the validation instant.
    #[error("lease is expired")]
    ExpiredLease,
    /// Attempt identity differs from the expected authority binding.
    #[error("attempt binding does not match")]
    AttemptMismatch,
    /// Stable Node identity differs from the expected authority binding.
    #[error("node binding does not match")]
    NodeMismatch,
    /// Node Generation differs from the expected authority binding.
    #[error("node generation binding does not match")]
    NodeGenerationMismatch,
    /// Connection Epoch differs from the expected authority binding.
    #[error("connection epoch binding does not match")]
    ConnectionEpochMismatch,
    /// Lease does not reference the Reservation being validated.
    #[error("lease reservation binding does not match")]
    ReservationMismatch,
}

impl AuthorityError {
    /// Return the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidFenceToken => "invalid_fence_token",
            Self::StaleFence => "stale_fence",
            Self::FutureFence => "future_fence",
            Self::MissingLease => "missing_lease",
            Self::ExpiredReservation => "expired_reservation",
            Self::ExpiredLease => "expired_lease",
            Self::AttemptMismatch => "attempt_mismatch",
            Self::NodeMismatch => "node_mismatch",
            Self::NodeGenerationMismatch => "node_generation_mismatch",
            Self::ConnectionEpochMismatch => "connection_epoch_mismatch",
            Self::ReservationMismatch => "reservation_mismatch",
        }
    }
}

/// Positive monotonically ordered E02 execution-ownership Fence token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FenceToken(u64);

impl FenceToken {
    /// Construct a positive Fence token.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidFenceToken`] when `value` is zero.
    pub const fn new(value: u64) -> Result<Self, AuthorityError> {
        if value == 0 {
            return Err(AuthorityError::InvalidFenceToken);
        }
        Ok(Self(value))
    }

    /// Return the positive integer carried by this Fence.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Require this Fence to be strictly newer than `previous`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::StaleFence`] when this Fence is equal to or
    /// older than `previous`.
    pub const fn require_newer_than(self, previous: Self) -> Result<(), AuthorityError> {
        if self.0 <= previous.0 {
            return Err(AuthorityError::StaleFence);
        }
        Ok(())
    }
}

/// Exact canonical authority binding for one Attempt on one Node session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityBinding {
    attempt_ref: EntityRef,
    node_id: NodeId,
    node_generation: NodeGeneration,
    connection_epoch: ConnectionEpoch,
}

impl AuthorityBinding {
    /// Construct an exact Attempt/Node/session authority binding.
    #[must_use]
    pub const fn new(
        attempt_ref: EntityRef,
        node_id: NodeId,
        node_generation: NodeGeneration,
        connection_epoch: ConnectionEpoch,
    ) -> Self {
        Self {
            attempt_ref,
            node_id,
            node_generation,
            connection_epoch,
        }
    }

    /// Return the canonical Attempt reference.
    #[must_use]
    pub const fn attempt_ref(&self) -> &EntityRef {
        &self.attempt_ref
    }

    /// Return the stable canonical Node identity.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Return the exact Node Generation.
    #[must_use]
    pub const fn node_generation(&self) -> NodeGeneration {
        self.node_generation
    }

    /// Return the exact E01 Connection Epoch.
    #[must_use]
    pub const fn connection_epoch(&self) -> ConnectionEpoch {
        self.connection_epoch
    }
}

/// Non-authoritative placement metadata bound to one exact Attempt/Node session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementMetadata {
    binding: AuthorityBinding,
}

impl PlacementMetadata {
    /// Construct placement metadata from an exact authority binding.
    #[must_use]
    pub const fn new(binding: AuthorityBinding) -> Self {
        Self { binding }
    }

    /// Return the placement's exact Attempt/Node/session binding.
    #[must_use]
    pub const fn binding(&self) -> &AuthorityBinding {
        &self.binding
    }
}

/// Capacity authority reserved for one exact Attempt and Node session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    reference: EntityRef,
    binding: AuthorityBinding,
    expires_at_unix_seconds: u64,
}

impl Reservation {
    /// Construct a Reservation projection for one exact authority binding.
    #[must_use]
    pub const fn new(
        reservation_ref: EntityRef,
        binding: AuthorityBinding,
        expires_at_unix_seconds: u64,
    ) -> Self {
        Self {
            reference: reservation_ref,
            binding,
            expires_at_unix_seconds,
        }
    }

    /// Return the canonical Reservation reference.
    #[must_use]
    pub const fn reservation_ref(&self) -> &EntityRef {
        &self.reference
    }

    /// Return the exact Attempt/Node/session binding.
    #[must_use]
    pub const fn binding(&self) -> &AuthorityBinding {
        &self.binding
    }

    /// Return the caller-supplied Unix-second expiry instant.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

/// Time-bounded execution authority bound to one Reservation and Fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    reference: EntityRef,
    reservation_ref: EntityRef,
    binding: AuthorityBinding,
    fence: FenceToken,
    expires_at_unix_seconds: u64,
}

impl Lease {
    /// Construct a Lease projection for one Reservation and exact authority binding.
    #[must_use]
    pub const fn new(
        lease_ref: EntityRef,
        reservation_ref: EntityRef,
        binding: AuthorityBinding,
        fence: FenceToken,
        expires_at_unix_seconds: u64,
    ) -> Self {
        Self {
            reference: lease_ref,
            reservation_ref,
            binding,
            fence,
            expires_at_unix_seconds,
        }
    }

    /// Return the canonical Lease reference.
    #[must_use]
    pub const fn lease_ref(&self) -> &EntityRef {
        &self.reference
    }

    /// Return the exact Reservation reference held by the Lease.
    #[must_use]
    pub const fn reservation_ref(&self) -> &EntityRef {
        &self.reservation_ref
    }

    /// Return the exact Attempt/Node/session binding.
    #[must_use]
    pub const fn binding(&self) -> &AuthorityBinding {
        &self.binding
    }

    /// Return the Lease's ownership Fence.
    #[must_use]
    pub const fn fence(&self) -> FenceToken {
        self.fence
    }

    /// Return the caller-supplied Unix-second expiry instant.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

/// Validated execution-changing dispatch authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchAuthority {
    binding: AuthorityBinding,
    reservation_ref: EntityRef,
    lease_ref: EntityRef,
    fence: FenceToken,
}

impl DispatchAuthority {
    /// Return the exact Attempt/Node/session binding admitted for dispatch.
    #[must_use]
    pub const fn binding(&self) -> &AuthorityBinding {
        &self.binding
    }

    /// Return the validated Reservation reference.
    #[must_use]
    pub const fn reservation_ref(&self) -> &EntityRef {
        &self.reservation_ref
    }

    /// Return the validated Lease reference.
    #[must_use]
    pub const fn lease_ref(&self) -> &EntityRef {
        &self.lease_ref
    }

    /// Return the currently accepted ownership Fence.
    #[must_use]
    pub const fn fence(&self) -> FenceToken {
        self.fence
    }
}

/// Validate placement, Reservation, Lease and Fence into dispatch authority.
///
/// Placement/capability metadata and Reservation capacity are deliberately
/// insufficient without a current Lease carrying the exact current Fence.
///
/// # Errors
///
/// Returns a typed [`AuthorityError`] for any missing, expired, stale or
/// mismatched authority component. Every failure is fail-closed and no
/// [`DispatchAuthority`] is constructed.
pub fn authorize_dispatch(
    placement: &PlacementMetadata,
    reservation: &Reservation,
    lease: Option<&Lease>,
    expected_binding: &AuthorityBinding,
    current_fence: FenceToken,
    now_unix_seconds: u64,
) -> Result<DispatchAuthority, AuthorityError> {
    validate_binding(placement.binding(), expected_binding)?;
    validate_binding(reservation.binding(), expected_binding)?;

    if reservation.expires_at_unix_seconds() <= now_unix_seconds {
        return Err(AuthorityError::ExpiredReservation);
    }

    let lease = lease.ok_or(AuthorityError::MissingLease)?;
    if lease.reservation_ref() != reservation.reservation_ref() {
        return Err(AuthorityError::ReservationMismatch);
    }
    validate_binding(lease.binding(), expected_binding)?;

    if lease.expires_at_unix_seconds() <= now_unix_seconds {
        return Err(AuthorityError::ExpiredLease);
    }

    if lease.fence() < current_fence {
        return Err(AuthorityError::StaleFence);
    }
    if lease.fence() > current_fence {
        return Err(AuthorityError::FutureFence);
    }

    Ok(DispatchAuthority {
        binding: expected_binding.clone(),
        reservation_ref: reservation.reservation_ref().clone(),
        lease_ref: lease.lease_ref().clone(),
        fence: current_fence,
    })
}

fn validate_binding(
    actual: &AuthorityBinding,
    expected: &AuthorityBinding,
) -> Result<(), AuthorityError> {
    if actual.attempt_ref() != expected.attempt_ref() {
        return Err(AuthorityError::AttemptMismatch);
    }
    if actual.node_id() != expected.node_id() {
        return Err(AuthorityError::NodeMismatch);
    }
    if actual.node_generation() != expected.node_generation() {
        return Err(AuthorityError::NodeGenerationMismatch);
    }
    if actual.connection_epoch() != expected.connection_epoch() {
        return Err(AuthorityError::ConnectionEpochMismatch);
    }
    Ok(())
}

/// Hard resource requirement used during deterministic candidate eligibility.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceRequirement {
    resource_key: String,
    unit: ResourceUnit,
    quantity: f64,
}

impl ResourceRequirement {
    /// Construct one positive finite resource requirement.
    ///
    /// # Errors
    ///
    /// Returns [`CandidateRejection::InvalidResourceRequirement`] for an empty
    /// resource key or a non-positive/non-finite quantity.
    pub fn new(
        resource_key: impl Into<String>,
        unit: ResourceUnit,
        quantity: f64,
    ) -> Result<Self, CandidateRejection> {
        let resource_key = resource_key.into();
        if resource_key.is_empty() || !quantity.is_finite() || quantity <= 0.0 {
            return Err(CandidateRejection::InvalidResourceRequirement);
        }
        Ok(Self {
            resource_key,
            unit,
            quantity,
        })
    }

    /// Return the stable resource key.
    #[must_use]
    pub fn resource_key(&self) -> &str {
        &self.resource_key
    }

    /// Return the frozen resource unit.
    #[must_use]
    pub const fn unit(&self) -> ResourceUnit {
        self.unit
    }

    /// Return the required quantity.
    #[must_use]
    pub const fn quantity(&self) -> f64 {
        self.quantity
    }
}

/// Hard placement requirements for one canonical Attempt.
#[derive(Debug, Clone, PartialEq)]
pub struct PlacementRequirement {
    attempt_ref: EntityRef,
    required_capability_refs: Vec<EntityRef>,
    required_provider_revision_refs: Vec<EntityRef>,
    resources: Vec<ResourceRequirement>,
    required_os_family: Option<OsFamily>,
}

impl PlacementRequirement {
    /// Construct deterministic hard requirements for one Attempt.
    #[must_use]
    pub fn new(
        attempt_ref: EntityRef,
        required_capability_refs: Vec<EntityRef>,
        required_provider_revision_refs: Vec<EntityRef>,
        resources: Vec<ResourceRequirement>,
        required_os_family: Option<OsFamily>,
    ) -> Self {
        Self {
            attempt_ref,
            required_capability_refs,
            required_provider_revision_refs,
            resources,
            required_os_family,
        }
    }

    /// Return the canonical Attempt reference.
    #[must_use]
    pub const fn attempt_ref(&self) -> &EntityRef {
        &self.attempt_ref
    }
}

/// Resource-pressure admission policy applied after hard capacity checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacementPolicy {
    allow_critical_pressure: bool,
    allow_unavailable_resources: bool,
}

impl PlacementPolicy {
    /// Return the strict E02 policy: critical and unavailable resources are rejected.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            allow_critical_pressure: false,
            allow_unavailable_resources: false,
        }
    }

    /// Construct an explicit pressure policy.
    #[must_use]
    pub const fn new(allow_critical_pressure: bool, allow_unavailable_resources: bool) -> Self {
        Self {
            allow_critical_pressure,
            allow_unavailable_resources,
        }
    }
}

/// Typed hard-eligibility rejection reasons. Scores are never produced for these cases.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CandidateRejection {
    /// A resource requirement itself is malformed.
    #[error("resource requirement must have a key and positive finite quantity")]
    InvalidResourceRequirement,
    /// Snapshot canonical Node identity differs from the authenticated session.
    #[error("snapshot node identity does not match current session")]
    NodeIdentityMismatch,
    /// Snapshot Node Generation differs from the authenticated session.
    #[error("snapshot node generation does not match current session")]
    NodeGenerationMismatch,
    /// Snapshot Connection Epoch differs from the authenticated session.
    #[error("snapshot connection epoch does not match current session")]
    ConnectionEpochMismatch,
    /// A required capability reference is absent.
    #[error("required capability is absent")]
    MissingCapability,
    /// A required Provider Revision reference is absent.
    #[error("required provider revision is absent")]
    MissingProviderRevision,
    /// Required platform family differs from the observed platform.
    #[error("required operating-system family does not match")]
    OperatingSystemMismatch,
    /// A required resource is absent or lacks available/allocatable capacity.
    #[error("required resource capacity is insufficient")]
    InsufficientResource,
    /// Strict policy disallows a resource currently under critical pressure.
    #[error("critical resource pressure is non-admissible")]
    CriticalResourcePressure,
    /// Strict policy disallows an unavailable resource.
    #[error("unavailable resource is non-admissible")]
    UnavailableResource,
}

impl CandidateRejection {
    /// Return a stable machine-readable rejection code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidResourceRequirement => "invalid_resource_requirement",
            Self::NodeIdentityMismatch => "node_identity_mismatch",
            Self::NodeGenerationMismatch => "node_generation_mismatch",
            Self::ConnectionEpochMismatch => "connection_epoch_mismatch",
            Self::MissingCapability => "missing_capability",
            Self::MissingProviderRevision => "missing_provider_revision",
            Self::OperatingSystemMismatch => "operating_system_mismatch",
            Self::InsufficientResource => "insufficient_resource",
            Self::CriticalResourcePressure => "critical_resource_pressure",
            Self::UnavailableResource => "unavailable_resource",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CandidateScore {
    pressure_score: u64,
    capability_surplus: usize,
    provider_surplus: usize,
}

/// An eligible Node candidate with a deterministic score and exact E01 session binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementCandidate {
    node_id: NodeId,
    node_generation: NodeGeneration,
    connection_epoch: ConnectionEpoch,
    score: CandidateScore,
}

impl PlacementCandidate {
    /// Return the stable canonical Node identity.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Return the exact Node Generation used for eligibility.
    #[must_use]
    pub const fn node_generation(&self) -> NodeGeneration {
        self.node_generation
    }

    /// Return the exact Connection Epoch used for eligibility.
    #[must_use]
    pub const fn connection_epoch(&self) -> ConnectionEpoch {
        self.connection_epoch
    }
}

/// Evaluate one current E01 session against current A02 capability/resource evidence.
///
/// Hard requirements are evaluated before score construction. A rejected Node
/// therefore has no score that could override failed eligibility.
///
/// # Errors
///
/// Returns [`CandidateRejection`] for any cross-Node/stale snapshot binding,
/// missing capability/Provider revision, platform mismatch, insufficient resource,
/// or pressure state rejected by policy.
pub fn evaluate_candidate(
    session: &SessionBinding,
    capabilities: &NodeCapabilitySnapshot,
    resources: &NodeResourceSnapshot,
    requirement: &PlacementRequirement,
    policy: PlacementPolicy,
) -> Result<PlacementCandidate, CandidateRejection> {
    validate_snapshot_binding(
        &capabilities.node_ref,
        capabilities.node_generation,
        capabilities.connection_epoch,
        session,
    )?;
    validate_snapshot_binding(
        &resources.node_ref,
        resources.node_generation,
        resources.connection_epoch,
        session,
    )?;

    if let Some(required_os_family) = requirement.required_os_family {
        if capabilities.platform.os_family != required_os_family {
            return Err(CandidateRejection::OperatingSystemMismatch);
        }
    }

    if requirement
        .required_capability_refs
        .iter()
        .any(|required| !capabilities.capability_claim_refs.contains(required))
    {
        return Err(CandidateRejection::MissingCapability);
    }

    if requirement
        .required_provider_revision_refs
        .iter()
        .any(|required| !capabilities.provider_revision_refs.contains(required))
    {
        return Err(CandidateRejection::MissingProviderRevision);
    }

    let mut pressure_score = 0_u64;
    for required in &requirement.resources {
        let Some(observed) = resources.resources.iter().find(|resource| {
            resource.resource_key == required.resource_key && resource.unit == required.unit
        }) else {
            return Err(CandidateRejection::InsufficientResource);
        };

        if observed.currently_available < required.quantity
            || observed.administratively_allocatable < required.quantity
        {
            return Err(CandidateRejection::InsufficientResource);
        }

        match observed.pressure {
            ResourcePressure::Unavailable if !policy.allow_unavailable_resources => {
                return Err(CandidateRejection::UnavailableResource);
            }
            ResourcePressure::Critical if !policy.allow_critical_pressure => {
                return Err(CandidateRejection::CriticalResourcePressure);
            }
            pressure => {
                pressure_score = pressure_score.saturating_add(resource_pressure_score(pressure));
            }
        }
    }

    let score = CandidateScore {
        pressure_score,
        capability_surplus: capabilities
            .capability_claim_refs
            .len()
            .saturating_sub(requirement.required_capability_refs.len()),
        provider_surplus: capabilities
            .provider_revision_refs
            .len()
            .saturating_sub(requirement.required_provider_revision_refs.len()),
    };

    Ok(PlacementCandidate {
        node_id: session.node_id,
        node_generation: session.node_generation,
        connection_epoch: session.connection_epoch,
        score,
    })
}

/// Select the highest deterministic eligible score with canonical Node identity
/// as the final stable tie-break.
#[must_use]
pub fn select_candidate(
    candidates: impl IntoIterator<Item = PlacementCandidate>,
) -> Option<PlacementCandidate> {
    candidates.into_iter().max_by(compare_candidates)
}

fn compare_candidates(left: &PlacementCandidate, right: &PlacementCandidate) -> Ordering {
    match left.score.cmp(&right.score) {
        Ordering::Equal => right.node_id.cmp(&left.node_id),
        ordering => ordering,
    }
}

fn validate_snapshot_binding(
    node_ref: &EntityRef,
    node_generation: NodeGeneration,
    connection_epoch: ConnectionEpoch,
    session: &SessionBinding,
) -> Result<(), CandidateRejection> {
    if node_ref.entity_id != session.node_id.entity_id() {
        return Err(CandidateRejection::NodeIdentityMismatch);
    }
    if node_generation != session.node_generation
        || node_ref.node_generation != Some(session.node_generation.value())
    {
        return Err(CandidateRejection::NodeGenerationMismatch);
    }
    if connection_epoch != session.connection_epoch
        || node_ref.connection_epoch != Some(session.connection_epoch.value())
    {
        return Err(CandidateRejection::ConnectionEpochMismatch);
    }
    Ok(())
}

const fn resource_pressure_score(pressure: ResourcePressure) -> u64 {
    match pressure {
        ResourcePressure::Normal => 4,
        ResourcePressure::Elevated => 3,
        ResourcePressure::Unknown => 2,
        ResourcePressure::Critical => 1,
        ResourcePressure::Unavailable => 0,
    }
}
