use crate::{
    TransferControlMessage, TransferDataError, TransferHello, TransferHelloAck,
    TransferProtocolVersion, read_control_frame, write_control_frame,
};
use ptah_node_link::CredentialFingerprint;
use ptah_transfer::{DownloadCursor, TransferPeerRole, TransferTicket};
use std::path::Path;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

/// Source of canonical bytes addressable by exact E03 byte ranges.
pub trait ExactRangeSource {
    /// Exact canonical source byte length.
    fn len(&self) -> u64;

    /// Whether the canonical source contains no bytes.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Canonical SHA-256 for the complete source byte sequence.
    fn canonical_sha256(&self) -> &str;

    /// Read exactly one requested byte range.
    ///
    /// # Errors
    ///
    /// Returns a source-defined error when the exact range cannot be served.
    fn read_exact_range(&mut self, start: u64, len: u64) -> Result<Vec<u8>, String>;
}

/// Result of one target-side direct-transfer pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectTransferReport {
    /// Raw payload bytes received during this pass.
    pub network_bytes: u64,
    /// Exact ranges requested during this pass.
    pub requested_ranges: usize,
}

/// Direct E03 session admission failures.
#[derive(Debug, Error)]
pub enum DirectSessionError {
    /// Existing bounded E03 framing/protocol failure.
    #[error(transparent)]
    Data(#[from] TransferDataError),
    /// The authenticated TLS peer credential does not match the ticket-bound peer.
    #[error("authenticated TLS peer fingerprint does not match E03 ticket authority")]
    PeerFingerprintMismatch,
    /// The peer presented another transfer-ticket identity.
    #[error("E03 direct session ticket identity mismatch")]
    TicketMismatch,
    /// The peer claimed the wrong side of the transfer.
    #[error("E03 direct session peer role mismatch")]
    PeerRoleMismatch,
    /// The source bytes do not match the canonical geometry frozen into the ticket.
    #[error("E03 direct source does not match ticket byte identity")]
    SourceIdentityMismatch,
    /// A zero in-flight bound cannot make transfer progress.
    #[error("E03 direct session requires a non-zero in-flight range bound")]
    InvalidRangeWindow,
    /// The peer explicitly rejected the admission handshake.
    #[error("E03 direct session admission was rejected")]
    AdmissionRejected,
    /// Range exchange is intentionally deferred until its own RED contract exists.
    #[error("E03 direct range exchange is not implemented beyond admission yet")]
    RangeExchangeNotImplemented,
}

/// Source-side direct authenticated E03 session.
pub struct DirectSourceSession;

impl DirectSourceSession {
    /// Admit one target over an already-authenticated TLS 1.3 stream.
    ///
    /// This step proves only ticket identity, peer role, protocol compatibility,
    /// TLS credential binding and source byte identity. Range exchange remains a
    /// separate TDD frontier.
    ///
    /// # Errors
    ///
    /// Rejects any admission mismatch or framing failure. A non-zero range
    /// execution request is rejected until the range-exchange contract is added.
    pub async fn serve<S, R>(
        stream: &mut S,
        ticket: &TransferTicket,
        peer_fingerprint: CredentialFingerprint,
        source: &mut R,
        max_in_flight_ranges: usize,
        stop_after_ranges: Option<usize>,
    ) -> Result<(), DirectSessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        R: ExactRangeSource + ?Sized,
    {
        if max_in_flight_ranges == 0 {
            return Err(DirectSessionError::InvalidRangeWindow);
        }
        if *peer_fingerprint.as_bytes() != ticket.target().credential_fingerprint {
            return Err(DirectSessionError::PeerFingerprintMismatch);
        }
        if source.len() != ticket.expected_size()
            || source.canonical_sha256() != ticket.canonical_sha256()
        {
            return Err(DirectSessionError::SourceIdentityMismatch);
        }

        let hello = match read_control_frame(stream).await? {
            TransferControlMessage::Hello(hello) => hello,
            _ => return Err(DirectSessionError::PeerRoleMismatch),
        };
        if hello.ticket_ref != *ticket.ticket_ref() {
            return Err(DirectSessionError::TicketMismatch);
        }
        if hello.role != TransferPeerRole::Target {
            return Err(DirectSessionError::PeerRoleMismatch);
        }
        TransferProtocolVersion::CURRENT.ensure_compatible(hello.protocol)?;

        write_control_frame(
            stream,
            &TransferControlMessage::HelloAck(TransferHelloAck {
                protocol: TransferProtocolVersion::CURRENT,
                ticket_ref: ticket.ticket_ref().clone(),
                accepted: true,
            }),
        )
        .await?;

        if stop_after_ranges == Some(0) {
            return Ok(());
        }

        Err(DirectSessionError::RangeExchangeNotImplemented)
    }
}

/// Target-side direct authenticated E03 session.
pub struct DirectTargetSession;

impl DirectTargetSession {
    /// Admit the ticket-bound source and prepare a bounded missing-range pull.
    ///
    /// The current TDD slice deliberately stops after a successful admission
    /// when `stop_after_ranges` is zero. Actual range exchange is the next
    /// separately tested frontier.
    ///
    /// # Errors
    ///
    /// Rejects any admission mismatch or framing failure. A non-zero range
    /// execution request is rejected until the range-exchange contract is added.
    pub async fn pull_missing_ranges<S>(
        stream: &mut S,
        ticket: &TransferTicket,
        peer_fingerprint: CredentialFingerprint,
        _partial_path: &Path,
        _cursor: &mut DownloadCursor,
        max_in_flight_ranges: usize,
        stop_after_ranges: Option<usize>,
    ) -> Result<DirectTransferReport, DirectSessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if max_in_flight_ranges == 0 {
            return Err(DirectSessionError::InvalidRangeWindow);
        }
        if *peer_fingerprint.as_bytes() != ticket.source().credential_fingerprint {
            return Err(DirectSessionError::PeerFingerprintMismatch);
        }

        write_control_frame(
            stream,
            &TransferControlMessage::Hello(TransferHello {
                protocol: TransferProtocolVersion::CURRENT,
                ticket_ref: ticket.ticket_ref().clone(),
                role: TransferPeerRole::Target,
            }),
        )
        .await?;

        let ack = match read_control_frame(stream).await? {
            TransferControlMessage::HelloAck(ack) => ack,
            _ => return Err(DirectSessionError::AdmissionRejected),
        };
        if ack.ticket_ref != *ticket.ticket_ref() {
            return Err(DirectSessionError::TicketMismatch);
        }
        TransferProtocolVersion::CURRENT.ensure_compatible(ack.protocol)?;
        if !ack.accepted {
            return Err(DirectSessionError::AdmissionRejected);
        }

        if stop_after_ranges == Some(0) {
            return Ok(DirectTransferReport {
                network_bytes: 0,
                requested_ranges: 0,
            });
        }

        Err(DirectSessionError::RangeExchangeNotImplemented)
    }
}
