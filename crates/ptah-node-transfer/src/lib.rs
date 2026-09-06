#![forbid(unsafe_code)]
//! Separate E03 Node-to-Node bulk data-plane protocol.
//!
//! This crate carries E03 control metadata and bounded range payloads. It does
//! not reuse the E01 JSON control stream and does not create A07 storage truth.

mod error;
mod framing;
mod protocol;

pub use error::*;
pub use framing::*;
pub use protocol::*;
pub use ptah_transfer::TransferPeerRole;

/// Frozen E03 application protocol identifier.
pub const PROTOCOL_ID: &str = "ptah.node.transfer.v1";
/// Maximum encoded E03 JSON control frame size.
pub const MAX_CONTROL_FRAME_BYTES: usize = 65_536;
/// Maximum raw range payload size carried by one E03 frame.
pub const MAX_RANGE_BYTES: usize = 1_048_576;
