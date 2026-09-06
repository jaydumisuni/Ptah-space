use thiserror::Error;

/// Stable E03 data-plane protocol and framing failure classes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TransferDataError {
    /// Peer protocol major cannot interoperate with the local E03 major.
    #[error("E03 transfer protocol major mismatch: local={local_major}, remote={remote_major}")]
    ProtocolIncompatible {
        /// Local supported protocol major.
        local_major: u16,
        /// Remote proposed protocol major.
        remote_major: u16,
    },
    /// A peer-declared JSON control frame exceeds the frozen bound.
    #[error("E03 control frame exceeds bound: {declared_len} bytes")]
    ControlFrameTooLarge {
        /// Peer-declared encoded control byte count.
        declared_len: usize,
    },
    /// A peer-declared raw range exceeds the frozen bound.
    #[error("E03 raw range exceeds bound: {declared_len} bytes")]
    RangeTooLarge {
        /// Peer-declared raw range byte count.
        declared_len: u64,
    },
    /// Stream ended before all declared bytes were received.
    #[error("E03 framed stream ended before declared bytes were complete")]
    UnexpectedEof,
    /// Exact raw payload bytes do not match the header SHA-256.
    #[error("E03 raw range SHA-256 mismatch")]
    RangeDigestMismatch,
    /// Caller-provided raw bytes differ from the header byte count.
    #[error("E03 raw range length mismatch: declared={declared_len}, actual={actual_len}")]
    RangeLengthMismatch {
        /// Header-declared byte count.
        declared_len: u64,
        /// Actual supplied byte count.
        actual_len: usize,
    },
    /// JSON control data is not a valid E03 control message.
    #[error("invalid E03 control JSON: {0}")]
    InvalidControlJson(String),
    /// Underlying asynchronous I/O failed for a non-EOF reason.
    #[error("E03 framed I/O failed: {0}")]
    Io(String),
}
