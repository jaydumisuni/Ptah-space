use crate::{AuthorityBinding, Reservation};
use ptah_identifiers::EntityRef;
use ptah_node_agent::{NodeResourceSnapshot, ResourceUnit};
use ptah_node_link::SessionBinding;
use thiserror::Error;

/// One positive finite resource quantity held by a Reservation.
#[derive(Debug, Clone, PartialEq)]
pub struct ReservedResource {
    resource_key: String,
    unit: ResourceUnit,
    quantity: f64,
}

impl ReservedResource {
    /// Construct one bounded resource hold.
    ///
    /// # Errors
    ///
    /// Returns [`ReservationError::InvalidResource`] for an empty key or a
    /// non-positive/non-finite quantity.
    pub fn new(
        resource_key: impl Into<String>,
        unit: ResourceUnit,
        quantity: f64,
    ) -> Result<Self, ReservationError> {
        let resource_key = resource_key.into();
        if resource_key.is_empty() || !quantity.is_finite() || quantity <= 0.0 {
            return Err(ReservationError::InvalidResource);
        }
        Ok(Self {
            resource_key,
            unit,
            quantity,
        })
    }

    /// Return the stable A02 resource key.
    #[must_use]
    pub fn resource_key(&self) -> &str {
        &self.resource_key
    }

    /// Return the frozen A02 resource unit.
    #[must_use]
    pub const fn unit(&self) -> ResourceUnit {
        self.unit
    }

    /// Return the held quantity.
    #[must_use]
    pub const fn quantity(&self) -> f64 {
        self.quantity
    }
}

/// Reservation lifecycle state owned by the control-side accounting registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationState {
    /// Capacity is currently held and may support Lease issuance.
    Active,
    /// Capacity was explicitly released.
    Released,
    /// Capacity expired at its fixed expiry instant.
    Expired,
    /// Capacity was administratively revoked or superseded.
    Revoked,
}

/// Stable failures from atomic Reservation accounting.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ReservationError {
    /// Registry evidence is not bound to the authenticated E01 session.
    #[error("resource snapshot does not match current authenticated session")]
    SessionMismatch,
    /// Reservation binding is not for the registry's exact current Node session.
    #[error("reservation authority binding does not match current session")]
    BindingMismatch,
    /// Reservation cites resource evidence other than the registry's accepted snapshot.
    #[error("reservation resource evidence does not match accepted snapshot")]
    EvidenceMismatch,
    /// Reservation identity already exists in this registry.
    #[error("reservation identity already exists")]
    DuplicateReservation,
    /// Requested resource quantity is malformed.
    #[error("reserved resource is invalid")]
    InvalidResource,
    /// Requested resources exceed current evidence-backed unreserved capacity.
    #[error("insufficient unreserved capacity")]
    InsufficientCapacity,
    /// Reservation expiry must be strictly later than creation/admission time.
    #[error("reservation expiry is not in the future")]
    InvalidExpiry,
    /// Reservation identity is unknown.
    #[error("reservation is unknown")]
    UnknownReservation,
    /// Reservation is no longer active.
    #[error("reservation is not active")]
    NotActive,
}

impl ReservationError {
    /// Return the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SessionMismatch => "session_mismatch",
            Self::BindingMismatch => "binding_mismatch",
            Self::EvidenceMismatch => "evidence_mismatch",
            Self::DuplicateReservation => "duplicate_reservation",
            Self::InvalidResource => "invalid_resource",
            Self::InsufficientCapacity => "insufficient_capacity",
            Self::InvalidExpiry => "invalid_expiry",
            Self::UnknownReservation => "unknown_reservation",
            Self::NotActive => "not_active",
        }
    }
}

/// Immutable Reservation authority plus control-owned lifecycle/accounting state.
#[derive(Debug, Clone, PartialEq)]
pub struct ReservationRecord {
    reservation: Reservation,
    resource_snapshot_ref: EntityRef,
    resources: Vec<ReservedResource>,
    created_at_unix_seconds: u64,
    state: ReservationState,
}

impl ReservationRecord {
    /// Return the canonical Reservation reference.
    #[must_use]
    pub fn reservation_ref(&self) -> &EntityRef {
        self.reservation.reservation_ref()
    }

    /// Return the immutable Attempt/Node/session binding.
    #[must_use]
    pub fn binding(&self) -> &AuthorityBinding {
        self.reservation.binding()
    }

    /// Return the exact resource evidence used for admission.
    #[must_use]
    pub const fn resource_snapshot_ref(&self) -> &EntityRef {
        &self.resource_snapshot_ref
    }

    /// Return the immutable reserved resource quantities.
    #[must_use]
    pub fn resources(&self) -> &[ReservedResource] {
        &self.resources
    }

    /// Return the fixed creation/admission instant.
    #[must_use]
    pub const fn created_at_unix_seconds(&self) -> u64 {
        self.created_at_unix_seconds
    }

    /// Return the fixed Reservation expiry instant.
    #[must_use]
    pub fn expires_at_unix_seconds(&self) -> u64 {
        self.reservation.expires_at_unix_seconds()
    }

    /// Return the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ReservationState {
        self.state
    }
}

#[derive(Debug, Clone, PartialEq)]
struct CapacitySlot {
    resource_key: String,
    unit: ResourceUnit,
    capacity: f64,
}

/// In-process E02 Reservation accounting authority for one exact Node session
/// and one explicitly accepted A02 resource snapshot.
///
/// The registry deliberately does not claim restart durability; Task 8 owns
/// persistence/recovery. Its mutation methods provide an atomic in-process
/// admission boundary: all requested resources are validated before insertion.
#[derive(Debug, Clone)]
pub struct ReservationRegistry {
    session: SessionBinding,
    resource_snapshot_ref: EntityRef,
    capacity: Vec<CapacitySlot>,
    reservations: Vec<ReservationRecord>,
}

impl ReservationRegistry {
    /// Construct accounting authority from one current authenticated session and
    /// its exact current A02 resource evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ReservationError::SessionMismatch`] when the snapshot is bound
    /// to another Node, Generation or Connection Epoch.
    pub fn new(
        session: &SessionBinding,
        snapshot: &NodeResourceSnapshot,
    ) -> Result<Self, ReservationError> {
        validate_snapshot_session(session, snapshot)?;
        let capacity = snapshot
            .resources
            .iter()
            .map(|resource| CapacitySlot {
                resource_key: resource.resource_key.clone(),
                unit: resource.unit,
                capacity: resource
                    .currently_available
                    .min(resource.administratively_allocatable),
            })
            .collect();
        Ok(Self {
            session: session.clone(),
            resource_snapshot_ref: snapshot.snapshot_ref.clone(),
            capacity,
            reservations: Vec::new(),
        })
    }

    /// Atomically reserve all requested quantities for one exact Attempt/Node session.
    ///
    /// # Errors
    ///
    /// Returns a typed [`ReservationError`] without inserting any state when
    /// identity/evidence/expiry/resource validation fails.
    pub fn reserve(
        &mut self,
        reservation_ref: EntityRef,
        binding: AuthorityBinding,
        resource_snapshot_ref: EntityRef,
        resources: Vec<ReservedResource>,
        created_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<Reservation, ReservationError> {
        self.expire(created_at_unix_seconds);
        if expires_at_unix_seconds <= created_at_unix_seconds {
            return Err(ReservationError::InvalidExpiry);
        }
        if binding.node_id() != self.session.node_id
            || binding.node_generation() != self.session.node_generation
            || binding.connection_epoch() != self.session.connection_epoch
        {
            return Err(ReservationError::BindingMismatch);
        }
        if resource_snapshot_ref != self.resource_snapshot_ref {
            return Err(ReservationError::EvidenceMismatch);
        }
        if self
            .reservations
            .iter()
            .any(|record| record.reservation_ref() == &reservation_ref)
        {
            return Err(ReservationError::DuplicateReservation);
        }
        if resources.is_empty() {
            return Err(ReservationError::InvalidResource);
        }
        if resources.iter().any(|resource| {
            resource.resource_key.is_empty()
                || !resource.quantity.is_finite()
                || resource.quantity <= 0.0
        }) {
            return Err(ReservationError::InvalidResource);
        }

        for resource in &resources {
            let requested_total = resources
                .iter()
                .filter(|candidate| {
                    candidate.resource_key == resource.resource_key
                        && candidate.unit == resource.unit
                })
                .map(|candidate| candidate.quantity)
                .sum::<f64>();
            let remaining = self
                .remaining(&resource.resource_key, resource.unit)
                .ok_or(ReservationError::InsufficientCapacity)?;
            if requested_total > remaining {
                return Err(ReservationError::InsufficientCapacity);
            }
        }

        let reservation = Reservation::new(reservation_ref, binding, expires_at_unix_seconds);
        self.reservations.push(ReservationRecord {
            reservation: reservation.clone(),
            resource_snapshot_ref,
            resources,
            created_at_unix_seconds,
            state: ReservationState::Active,
        });
        Ok(reservation)
    }

    /// Return remaining evidence-backed capacity after active holds.
    #[must_use]
    pub fn remaining(&self, resource_key: &str, unit: ResourceUnit) -> Option<f64> {
        let baseline = self
            .capacity
            .iter()
            .find(|slot| slot.resource_key == resource_key && slot.unit == unit)?
            .capacity;
        let held = self
            .reservations
            .iter()
            .filter(|record| record.state == ReservationState::Active)
            .flat_map(|record| &record.resources)
            .filter(|resource| resource.resource_key == resource_key && resource.unit == unit)
            .map(|resource| resource.quantity)
            .sum::<f64>();
        Some((baseline - held).max(0.0))
    }

    /// Return one Reservation record by exact canonical reference.
    #[must_use]
    pub fn reservation(&self, reservation_ref: &EntityRef) -> Option<&ReservationRecord> {
        self.reservations
            .iter()
            .find(|record| record.reservation_ref() == reservation_ref)
    }

    /// Explicitly release one active Reservation and immediately return its capacity.
    ///
    /// # Errors
    ///
    /// Returns [`ReservationError::UnknownReservation`] for an unknown identity or
    /// [`ReservationError::NotActive`] for any terminal Reservation.
    pub fn release(
        &mut self,
        reservation_ref: &EntityRef,
        effective_at_unix_seconds: u64,
    ) -> Result<(), ReservationError> {
        let record = self
            .reservations
            .iter_mut()
            .find(|record| record.reservation_ref() == reservation_ref)
            .ok_or(ReservationError::UnknownReservation)?;
        if record.state != ReservationState::Active {
            return Err(ReservationError::NotActive);
        }
        if record.expires_at_unix_seconds() <= effective_at_unix_seconds {
            record.state = ReservationState::Expired;
            return Err(ReservationError::NotActive);
        }
        record.state = ReservationState::Released;
        Ok(())
    }

    /// Expire every active Reservation whose fixed expiry is at or before `now`.
    /// Returns the number of newly expired records.
    pub fn expire(&mut self, now_unix_seconds: u64) -> usize {
        let mut expired = 0;
        for record in &mut self.reservations {
            if record.state == ReservationState::Active
                && record.expires_at_unix_seconds() <= now_unix_seconds
            {
                record.state = ReservationState::Expired;
                expired += 1;
            }
        }
        expired
    }

    /// Revoke one active Reservation without changing its immutable authority binding.
    ///
    /// # Errors
    ///
    /// Returns [`ReservationError::UnknownReservation`] or
    /// [`ReservationError::NotActive`] when revocation is not admissible.
    pub fn revoke(&mut self, reservation_ref: &EntityRef) -> Result<(), ReservationError> {
        let record = self
            .reservations
            .iter_mut()
            .find(|record| record.reservation_ref() == reservation_ref)
            .ok_or(ReservationError::UnknownReservation)?;
        if record.state != ReservationState::Active {
            return Err(ReservationError::NotActive);
        }
        record.state = ReservationState::Revoked;
        Ok(())
    }
}

fn validate_snapshot_session(
    session: &SessionBinding,
    snapshot: &NodeResourceSnapshot,
) -> Result<(), ReservationError> {
    if snapshot.node_ref.entity_id != session.node_id.entity_id()
        || snapshot.node_generation != session.node_generation
        || snapshot.connection_epoch != session.connection_epoch
        || snapshot.node_ref.node_generation != Some(session.node_generation.value())
        || snapshot.node_ref.connection_epoch != Some(session.connection_epoch.value())
    {
        return Err(ReservationError::SessionMismatch);
    }
    Ok(())
}
