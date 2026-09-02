use thiserror::Error;

/// Mechanical failures emitted by the D04 composition layer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum D04Error {
    /// An operation descriptor violates the D04 structural contract.
    #[error("invalid operation descriptor: {0}")]
    InvalidOperationDescriptor(&'static str),
    /// The D04 effect metadata conflicts with the frozen A04 execution class.
    #[error("operation effect {effect} is incompatible with A04 side effect {side_effect}")]
    EffectCompatibility {
        /// D04 effect class rendered in its canonical snake-case form.
        effect: String,
        /// A04 side-effect class rendered in its canonical debug form.
        side_effect: String,
    },
    /// Canonical descriptor serialization failed before a digest could be produced.
    #[error("descriptor serialization failed: {0}")]
    DescriptorSerialization(String),
    /// The exact descriptor revision is already present in the derived catalog.
    #[error("operation descriptor already registered: {0}")]
    DescriptorDuplicate(String),
    /// No descriptor matches the exact caller-supplied lookup constraints.
    #[error("operation descriptor unavailable: {0}")]
    OperationUnavailable(String),
}
