use crate::{FenceToken, Lease, ReservationRecord, ReservationState};
use ptah_identifiers::EntityRef;
use thiserror::Error;

/// Lease lifecycle state owned by the control-side Fence allocator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// This Lease is the current owner for its Attempt domain.
    Active,
    /// The fixed Lease expiry instant has passed.
    Expired,
    /// Control explicitly revoked this Lease.
    Revoked,
    /// A newer Fence permanently superseded this Lease.
    Superseded,
}

/// Stable failures from E02 Lease/Fence allocation and currentness validation.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum LeaseError {
    /// Lease issuance requires an active Reservation.
    #[error("reservation is not active")]
    ReservationNotActive,
    /// Lease expiry must be after issue time and no later than Reservation expiry.
    #[error("lease expiry is outside reservation validity")]
    InvalidExpiry,
    /// Lease identity already exists.
    #[error("lease identity already exists")]
    DuplicateLease,
    /// Fence history cannot advance without integer overflow.
    #[error("fence counter overflow")]
    FenceOverflow,
    /// Lease identity is unknown to this authority owner.
    #[error("lease is unknown")]
    UnknownLease,
    /// Candidate Lease bytes do not match the recorded immutable Lease.
    #[error("lease projection does not match recorded authority")]
    LeaseMismatch,
    /// A lower Fence can never regain current ownership.
    #[error("lease fence is stale")]
    StaleFence,
    /// A Fence newer than the allocator's accepted history is not authoritative.
    #[error("lease fence is not yet accepted")]
    FutureFence,
    /// Lease validity has ended.
    #[error("lease is expired")]
    ExpiredLease,
    /// Lease was explicitly revoked.
    #[error("lease is revoked")]
    RevokedLease,
    /// Lease was superseded by a newer owner.
    #[error("lease is superseded")]
    SupersededLease,
    /// Lease is not the single current owner for its Attempt domain.
    #[error("lease is not current")]
    NotCurrent,
}

impl LeaseError {
    /// Stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ReservationNotActive => "reservation_not_active",
            Self::InvalidExpiry => "invalid_expiry",
            Self::DuplicateLease => "duplicate_lease",
            Self::FenceOverflow => "fence_overflow",
            Self::UnknownLease => "unknown_lease",
            Self::LeaseMismatch => "lease_mismatch",
            Self::StaleFence => "stale_fence",
            Self::FutureFence => "future_fence",
            Self::ExpiredLease => "expired_lease",
            Self::RevokedLease => "revoked_lease",
            Self::SupersededLease => "superseded_lease",
            Self::NotCurrent => "not_current",
        }
    }
}

/// Immutable Lease authority plus control-owned lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRecord {
    lease: Lease,
    issued_at_unix_seconds: u64,
    state: LeaseState,
}

impl LeaseRecord {
    /// Canonical Lease reference.
    #[must_use]
    pub fn lease_ref(&self) -> &EntityRef {
        self.lease.lease_ref()
    }

    /// Canonical Reservation reference bound to this Lease.
    #[must_use]
    pub fn reservation_ref(&self) -> &EntityRef {
        self.lease.reservation_ref()
    }

    /// Attempt/Node/session authority binding.
    #[must_use]
    pub fn binding(&self) -> &crate::AuthorityBinding {
        self.lease.binding()
    }

    /// Current ownership Fence carried by this immutable Lease.
    #[must_use]
    pub const fn fence(&self) -> FenceToken {
        self.lease.fence()
    }

    /// Fixed issue instant.
    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    /// Fixed expiry instant.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.lease.expires_at_unix_seconds()
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> LeaseState {
        self.state
    }

    /// Immutable Lease projection.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FenceDomain {
    attempt_ref: EntityRef,
    highest: FenceToken,
}

/// In-process E02 Lease/Fence authority for Attempt ownership domains.
///
/// Fence history is keyed by canonical Attempt reference, not Reservation ID,
/// so re-placement or transfer cannot reset ownership to a smaller token.
#[derive(Debug, Clone, Default)]
pub struct LeaseRegistry {
    domains: Vec<FenceDomain>,
    leases: Vec<LeaseRecord>,
}

impl LeaseRegistry {
    /// Construct an empty in-process Lease/Fence allocator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            domains: Vec::new(),
            leases: Vec::new(),
        }
    }

    /// Issue the next Lease/Fence for one active Reservation.
    ///
    /// A successful issuance permanently advances the Attempt's Fence and
    /// supersedes every previously active Lease in the same Attempt domain.
    ///
    /// # Errors
    ///
    /// Returns a typed [`LeaseError`] without advancing Fence history if any
    /// precondition fails.
    pub fn issue(
        &mut self,
        reservation: &ReservationRecord,
        lease_ref: EntityRef,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<Lease, LeaseError> {
        self.expire(issued_at_unix_seconds);
        if reservation.state() != ReservationState::Active {
            return Err(LeaseError::ReservationNotActive);
        }
        if expires_at_unix_seconds <= issued_at_unix_seconds
            || expires_at_unix_seconds > reservation.expires_at_unix_seconds()
        {
            return Err(LeaseError::InvalidExpiry);
        }
        if self
            .leases
            .iter()
            .any(|record| record.lease_ref() == &lease_ref)
        {
            return Err(LeaseError::DuplicateLease);
        }

        let attempt_ref = reservation.binding().attempt_ref().clone();
        let next_value = self
            .domains
            .iter()
            .find(|domain| domain.attempt_ref == attempt_ref)
            .map_or(Ok(1_u64), |domain| {
                domain
                    .highest
                    .value()
                    .checked_add(1)
                    .ok_or(LeaseError::FenceOverflow)
            })?;
        let next_fence = FenceToken::new(next_value).map_err(|_| LeaseError::FenceOverflow)?;

        for record in &mut self.leases {
            if record.state == LeaseState::Active && record.binding().attempt_ref() == &attempt_ref
            {
                record.state = LeaseState::Superseded;
            }
        }

        if let Some(domain) = self
            .domains
            .iter_mut()
            .find(|domain| domain.attempt_ref == attempt_ref)
        {
            domain.highest = next_fence;
        } else {
            self.domains.push(FenceDomain {
                attempt_ref: attempt_ref.clone(),
                highest: next_fence,
            });
        }

        let lease = Lease::new(
            lease_ref,
            reservation.reservation_ref().clone(),
            reservation.binding().clone(),
            next_fence,
            expires_at_unix_seconds,
        );
        self.leases.push(LeaseRecord {
            lease: lease.clone(),
            issued_at_unix_seconds,
            state: LeaseState::Active,
        });
        Ok(lease)
    }

    /// Validate one Lease as the exact current owner for its Attempt domain.
    ///
    /// # Errors
    ///
    /// Lower Fence replay is rejected before lifecycle inspection so a stale
    /// owner can never revive after transfer, expiry or delayed delivery.
    pub fn validate_current(&self, lease: &Lease, now_unix_seconds: u64) -> Result<(), LeaseError> {
        let attempt_ref = lease.binding().attempt_ref();
        let highest = self
            .domains
            .iter()
            .find(|domain| &domain.attempt_ref == attempt_ref)
            .ok_or(LeaseError::UnknownLease)?
            .highest;
        if lease.fence() < highest {
            return Err(LeaseError::StaleFence);
        }
        if lease.fence() > highest {
            return Err(LeaseError::FutureFence);
        }

        let record = self
            .leases
            .iter()
            .find(|record| record.lease_ref() == lease.lease_ref())
            .ok_or(LeaseError::UnknownLease)?;
        if record.lease() != lease {
            return Err(LeaseError::LeaseMismatch);
        }
        match record.state {
            LeaseState::Active => {}
            LeaseState::Expired => return Err(LeaseError::ExpiredLease),
            LeaseState::Revoked => return Err(LeaseError::RevokedLease),
            LeaseState::Superseded => return Err(LeaseError::SupersededLease),
        }
        if record.expires_at_unix_seconds() <= now_unix_seconds {
            return Err(LeaseError::ExpiredLease);
        }
        if self
            .current(attempt_ref)
            .is_none_or(|current| current.lease_ref() != lease.lease_ref())
        {
            return Err(LeaseError::NotCurrent);
        }
        Ok(())
    }

    /// Return the single active current Lease record for an Attempt domain.
    #[must_use]
    pub fn current(&self, attempt_ref: &EntityRef) -> Option<&LeaseRecord> {
        let highest = self
            .domains
            .iter()
            .find(|domain| &domain.attempt_ref == attempt_ref)?
            .highest;
        self.leases.iter().find(|record| {
            record.state == LeaseState::Active
                && record.binding().attempt_ref() == attempt_ref
                && record.fence() == highest
        })
    }

    /// Return the lifecycle state for a known Lease identity.
    #[must_use]
    pub fn state(&self, lease_ref: &EntityRef) -> Option<LeaseState> {
        self.leases
            .iter()
            .find(|record| record.lease_ref() == lease_ref)
            .map(LeaseRecord::state)
    }

    /// Return the highest Fence ever issued for an Attempt domain.
    #[must_use]
    pub fn highest_fence(&self, attempt_ref: &EntityRef) -> Option<FenceToken> {
        self.domains
            .iter()
            .find(|domain| &domain.attempt_ref == attempt_ref)
            .map(|domain| domain.highest)
    }

    /// Restore a verified durable Fence floor without minting a Lease.
    ///
    /// This hook is crate-private so client/control projections cannot supply
    /// Fence values. Durable recovery validates journal history before calling it.
    /// It only raises retained history; it can never lower or reuse a Fence.
    pub(crate) fn recover_fence_floor(&mut self, attempt_ref: EntityRef, floor: FenceToken) {
        if let Some(domain) = self
            .domains
            .iter_mut()
            .find(|domain| domain.attempt_ref == attempt_ref)
        {
            if floor > domain.highest {
                domain.highest = floor;
            }
        } else {
            self.domains.push(FenceDomain {
                attempt_ref,
                highest: floor,
            });
        }
    }

    /// Expire active Leases whose fixed expiry is at or before `now`.
    pub fn expire(&mut self, now_unix_seconds: u64) -> usize {
        let mut expired = 0;
        for record in &mut self.leases {
            if record.state == LeaseState::Active
                && record.expires_at_unix_seconds() <= now_unix_seconds
            {
                record.state = LeaseState::Expired;
                expired += 1;
            }
        }
        expired
    }

    /// Revoke one active Lease while preserving its Fence history permanently.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::UnknownLease`] or a state-specific terminal error.
    pub fn revoke(&mut self, lease_ref: &EntityRef) -> Result<(), LeaseError> {
        let record = self
            .leases
            .iter_mut()
            .find(|record| record.lease_ref() == lease_ref)
            .ok_or(LeaseError::UnknownLease)?;
        match record.state {
            LeaseState::Active => {
                record.state = LeaseState::Revoked;
                Ok(())
            }
            LeaseState::Expired => Err(LeaseError::ExpiredLease),
            LeaseState::Revoked => Err(LeaseError::RevokedLease),
            LeaseState::Superseded => Err(LeaseError::SupersededLease),
        }
    }
}
