#![forbid(unsafe_code)]
//! Mechanical E02 placement, Reservation, Lease and Fence runtime.
//!
//! Canonical Node, Attempt, capability and Provider identities remain owned by
//! their existing Ptah authorities. E02 composes those identities and adds only
//! mechanical placement and execution-ownership authority.

mod authority;
mod placement;

pub use authority::{
    AuthorityBinding, AuthorityError, DispatchAuthority, FenceToken, Lease, PlacementMetadata,
    Reservation, authorize_dispatch,
};
pub use placement::{
    CandidateRejection, PlacementCandidate, PlacementPolicy, PlacementRequirement,
    ResourceRequirement, evaluate_candidate, select_candidate,
};
