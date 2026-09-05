#![forbid(unsafe_code)]
//! Ptah control surface with the existing human projection plus E01 secure Node-link authority.

#[path = "lib.rs"]
mod legacy_control;

pub use legacy_control::*;

/// E01 secure Node-link control integration.
pub mod node_link;
