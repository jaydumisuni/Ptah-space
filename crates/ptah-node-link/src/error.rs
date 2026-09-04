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
    /// The peers have the same major but no mutually supported minor version.
    #[error(
        "protocol minor is incompatible: local={local_minor}, remote={remote_min}..={remote_max}"
    )]
    ProtocolMinorIncompatible {
        /// Local supported minor.
        local_minor: u16,
        /// Remote minimum minor.
        remote_min: u16,
        /// Remote maximum minor.
        remote_max: u16,
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
    /// Enrollment has not reached approved authority.
    #[error("Node enrollment is not approved")]
    UnapprovedEnrollment,
    /// Enrollment authority was revoked.
    #[error("Node enrollment is revoked")]
    EnrollmentRevoked,
    /// Enrollment authority is expired.
    #[error("Node enrollment is expired")]
    EnrollmentExpired,
    /// Authenticated credential is not bound to the approved enrollment.
    #[error("authenticated credential is not bound to enrollment")]
    CredentialNotBound,
    /// Claimed canonical Node identity differs from enrollment identity.
    #[error("claimed Node identity differs from enrollment identity")]
    NodeIdentityMismatch,
    /// Hello references a different enrollment record.
    #[error("hello enrollment reference differs from approved enrollment")]
    EnrollmentReferenceMismatch,
    /// Requested Node Generation is older than the accepted current generation.
    #[error("stale Node Generation: current={current}, requested={requested}")]
    StaleNodeGeneration {
        /// Current accepted generation.
        current: u64,
        /// Requested stale generation.
        requested: u64,
    },
    /// Requested `ConnectionEpoch` is not newer within the current generation.
    #[error("stale ConnectionEpoch: current={current}, requested={requested}")]
    StaleConnectionEpoch {
        /// Current accepted epoch.
        current: u64,
        /// Requested stale/equal epoch.
        requested: u64,
    },
    /// A previously accepted session has been superseded or revoked.
    #[error("secure Node connection has been superseded")]
    SupersededConnection,
    /// Enrollment input cannot satisfy the frozen E01 boundary.
    #[error("invalid enrollment: {0}")]
    InvalidEnrollment(&'static str),
    /// Credential fingerprint text is malformed.
    #[error("invalid credential fingerprint")]
    InvalidCredentialFingerprint,
    /// TLS identity, trust-root, or certificate configuration is invalid.
    #[error("invalid E01 TLS configuration: {0}")]
    TlsConfiguration(String),
    /// TLS mutual-authentication handshake failed.
    #[error("E01 TLS handshake failed: {0}")]
    TlsHandshake(String),
    /// The authenticated TLS session did not expose an end-entity peer certificate.
    #[error("E01 TLS peer certificate is missing")]
    TlsPeerCertificateMissing,
    /// The configured TLS server name is not a valid Rustls server name.
    #[error("invalid E01 TLS server name")]
    InvalidServerName,
    /// Async transport I/O failed.
    #[error("E01 transport I/O failed: {0}")]
    Io(String),
}

impl From<std::io::Error> for LinkError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}
