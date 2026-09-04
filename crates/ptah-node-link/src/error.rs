use thiserror::Error;

/// Stable mechanical failures at the E01 secure Node-link boundary.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// The peers have no compatible protocol major version.
    #[error("protocol major is incompatible: local={local_major}, remote={remote_major}")]
    ProtocolIncompatible {
        /// Local supported major.
        local_major: u16,
        /// Remote supported major.
        remote_major: u16,
    },
    /// A declared or serialized frame exceeds the E01 bound.
    #[error("frame exceeds E01 maximum: {declared} bytes")]
    FrameTooLarge {
        /// Declared or serialized frame length.
        declared: usize,
    },
    /// The frame could not be decoded as a valid E01 message.
    #[error("malformed E01 frame: {0}")]
    MalformedFrame(String),
    /// Async transport I/O failed.
    #[error("E01 transport I/O failed: {0}")]
    Io(String),
}

impl From<std::io::Error> for LinkError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}
