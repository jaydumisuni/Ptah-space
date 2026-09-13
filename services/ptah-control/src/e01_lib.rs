#![forbid(unsafe_code)]
//! Ptah control surface with the existing human projection plus E01/E02/E03 Node authority.

#[path = "lib.rs"]
mod legacy_control;

pub use legacy_control::*;

/// E01 secure Node-link control integration.
pub mod node_link;
/// E02 placement, Reservation, Lease and Fence authority owner.
pub mod placement;
/// E03 short-lived Node-to-Node transfer-ticket authority owner.
pub mod transfer;
