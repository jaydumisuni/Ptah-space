#![forbid(unsafe_code)]
//! D04 Recipes and service registry composition.
//!
//! This crate composes frozen Ptah Recipe, execution, Provider and authority
//! primitives. It does not create a scheduler, semantic chooser, approval
//! authority, Plugin lifecycle, or network-exposure authority.

mod error;
mod operation;

pub use error::D04Error;
pub use operation::{
    OperationCatalog, OperationDescriptorRevision, OperationEffectClass, OperationResolution,
};
