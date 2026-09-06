use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
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
