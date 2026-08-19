#![forbid(unsafe_code)]
//! A08 transfer runtime: durable Request/Run/Manifest/Progress/Verification truth
//! with resumable partial byte materialization.
//!
//! A08 never promotes provider acknowledgement into Content/Object/Location
//! truth. A04 remains execution-proof authority and A07 remains object/storage
//! acceptance authority.

mod engine;
mod model;
mod records;
mod util;

pub use engine::{TransferClock, TransferEngine, UploadSink};
pub use model::*;

/// Frozen A08 transfer schema version.
pub const A08_SCHEMA_VERSION: &str = "0.1.0";
/// Frozen Transfer Request schema.
pub const TRANSFER_REQUEST_SCHEMA_ID: &str = "urn:ptah:schema:transfer:transfer-request:0.1.0";
/// Frozen Transfer Run schema.
pub const TRANSFER_RUN_SCHEMA_ID: &str = "urn:ptah:schema:transfer:transfer-run:0.1.0";
/// Frozen Transfer Manifest schema.
pub const TRANSFER_MANIFEST_SCHEMA_ID: &str = "urn:ptah:schema:transfer:transfer-manifest:0.1.0";
/// Frozen Transfer Progress Snapshot schema.
pub const TRANSFER_PROGRESS_SCHEMA_ID: &str =
    "urn:ptah:schema:transfer:transfer-progress-snapshot:0.1.0";
/// Frozen Transfer Verification schema.
pub const TRANSFER_VERIFICATION_SCHEMA_ID: &str =
    "urn:ptah:schema:transfer:transfer-verification:0.1.0";
