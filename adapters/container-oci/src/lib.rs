#![forbid(unsafe_code)]
//! A10 OCI container Provider.
//!
//! This adapter owns bounded mechanical OCI execution policy and evidence. An
//! image name/tag, container ID, socket path or backend process ID remains an
//! alias/evidence fact and never becomes canonical Ptah identity. Exact image
//! digest, Provider/Node generations, A04 Attempt context, isolation grants,
//! resource bounds, output and independently observed workload completion remain
//! separate facts.

mod backend;
mod provider;
mod types;

pub use backend::{ContainerdCliBackend, OciClock};
pub use provider::OciProvider;
pub use types::*;
