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
}
