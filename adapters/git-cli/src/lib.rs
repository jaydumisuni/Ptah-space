#![forbid(unsafe_code)]
//! A09 hardened Git CLI Provider.
//!
//! This adapter owns only mechanical Git resolution/materialization. Remote URLs,
//! filesystem paths and Git object IDs are evidence/aliases, never A07 Object or
//! Revision identity. A04 remains execution-proof authority and A07 remains the
//! authority that accepts any repository projection into the Object graph.

mod provider;
mod types;
mod util;

pub use provider::{GitClock, GitProvider};
pub use types::*;
