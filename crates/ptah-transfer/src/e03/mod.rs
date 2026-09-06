//! E03 Node-to-Node transfer authority, route, cache and resume mechanics.

mod authority;

pub use authority::*;

use thiserror::Error;

/// Stable E03 transfer-authority and byte-domain rejection classes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum E03TransferError {
    /// Source/target byte or range geometry is invalid.
    #[error("E03 transfer geometry is invalid")]
    InvalidGeometry,
    /// Canonical content digest is not lowercase hexadecimal SHA-256.
    #[error("E03 canonical content digest is invalid")]
    InvalidCanonicalDigest,
    /// Ticket issuance/expiry bounds are invalid.
    #[error("E03 transfer ticket lifetime is invalid")]
    InvalidLifetime,
    /// Ticket contains no explicit authorized route.
    #[error("E03 transfer ticket has no authorized route")]
    NoAuthorizedRoute,
    /// The same explicit route occurs more than once.
    #[error("E03 transfer ticket contains a duplicate route")]
    DuplicateRoute,
    /// Presented stable Node identity differs from ticket authority.
    #[error("E03 transfer Node identity mismatch")]
    NodeIdentityMismatch,
    /// Presented Node Generation differs from ticket authority.
    #[error("E03 transfer Node Generation mismatch")]
    NodeGenerationMismatch,
    /// Presented ConnectionEpoch differs from ticket authority.
    #[error("E03 transfer ConnectionEpoch mismatch")]
    ConnectionEpochMismatch,
    /// Presented credential fingerprint differs from ticket authority.
    #[error("E03 transfer credential fingerprint mismatch")]
    CredentialFingerprintMismatch,
    /// Ticket is no longer live at the admission instant.
    #[error("E03 transfer ticket expired")]
    ExpiredTicket,
    /// Requested route was not frozen into the ticket.
    #[error("E03 transfer route is not authorized")]
    UnauthorizedRoute,
}
