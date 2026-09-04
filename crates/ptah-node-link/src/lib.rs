#![forbid(unsafe_code)]
//! Programme E01 transport-neutral secure Node link.

/// Stable E01 application protocol identifier.
pub const PROTOCOL_ID: &str = "ptah.node.link.v1";
/// Maximum serialized E01 frame size.
pub const MAX_FRAME_BYTES: usize = 1_048_576;
