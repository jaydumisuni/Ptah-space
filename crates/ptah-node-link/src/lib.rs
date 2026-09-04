#![forbid(unsafe_code)]
//! Programme E01 transport-neutral secure Node link.

mod enrollment;
mod error;
mod framing;
mod protocol;
mod session;
mod tls;

pub use enrollment::{ApprovedNodeEnrollment, CredentialFingerprint, EnrollmentLifecycle};
pub use error::LinkError;
pub use framing::{read_frame, write_frame};
pub use protocol::{
    CapabilityAnnouncement, Heartbeat, HelloAck, LinkAck, LinkErrorFrame, LinkMessage, NodeHello,
    ProtocolVersion, negotiate_version,
};
pub use session::{SessionBinding, SessionRegistry};
pub use tls::{
    AuthenticatedClientStream, AuthenticatedServerStream, TlsClientConfig, TlsIdentity,
    TlsServerConfig, TlsTrustRoots, accept_tls, connect_tls,
};

/// Stable E01 application protocol identifier.
pub const PROTOCOL_ID: &str = "ptah.node.link.v1";
/// Maximum serialized E01 frame size.
pub const MAX_FRAME_BYTES: usize = 1_048_576;
