use crate::{
    MAX_RANGE_BYTES, RangeAck, RangeDataHeader, RangeRequest, TransferComplete, TransferControlMessage,
    TransferDataError, TransferHello, TransferHelloAck, TransferProtocolVersion,
    read_control_frame, read_range_payload, write_control_frame, write_range_payload,
};
use ptah_node_link::CredentialFingerprint;
use ptah_transfer::{DownloadCursor, TransferPeerRole, TransferTicket, VerifiedRange};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
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
    /// Leading verified ranges retained and reused from an earlier pass.
    pub resumed_ranges: usize,
}

/// Direct E03 session admission and bounded range-exchange failures.
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
    /// The source could not serve the exact requested range.
    #[error("E03 direct source range read failed: {0}")]
    SourceRead(String),
    /// A range control frame did not describe the exact request currently in flight.
    #[error("E03 direct range response does not match the exact request")]
    RangeMismatch,
    /// A retained partial range could not be read for resume verification.
    #[error("E03 direct retained-range read failed: {0}")]
    PartialRead(String),
    /// A verified range could not be persisted to the partial file.
    #[error("E03 direct partial-file write failed: {0}")]
    PartialWrite(String),
}

/// Source-side direct authenticated E03 session.
pub struct DirectSourceSession;

impl DirectSourceSession {
    /// Admit one target over an already-authenticated TLS 1.3 stream and serve
    /// the caller-bounded number of exact ranges sequentially on that session.
    ///
    /// # Errors
    ///
    /// Rejects any admission, authority, framing, exact-range, digest or
    /// acknowledgement mismatch.
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

        let range_limit = stop_after_ranges.unwrap_or(1);
        if range_limit == 0 {
            return Ok(());
        }

        for _ in 0..range_limit {
            let request = match read_control_frame(stream).await? {
                TransferControlMessage::RangeRequest(request) => request,
                TransferControlMessage::Complete(complete) => {
                    if complete.ticket_ref != *ticket.ticket_ref() {
                        return Err(DirectSessionError::TicketMismatch);
                    }
                    if complete.size != ticket.expected_size()
                        || complete.canonical_sha256 != ticket.canonical_sha256()
                    {
                        return Err(DirectSessionError::RangeMismatch);
                    }
                    return Ok(());
                }
                _ => return Err(DirectSessionError::RangeMismatch),
            };
            if request.ticket_ref != *ticket.ticket_ref() {
                return Err(DirectSessionError::TicketMismatch);
            }
            validate_request(&request, ticket.expected_size())?;

            let payload = source
                .read_exact_range(request.start, request.len)
                .map_err(DirectSessionError::SourceRead)?;
            let header = RangeDataHeader {
                ticket_ref: ticket.ticket_ref().clone(),
                start: request.start,
                len: request.len,
                sha256: sha256(&payload),
            };
            write_control_frame(
                stream,
                &TransferControlMessage::RangeDataHeader(header.clone()),
            )
            .await?;
            write_range_payload(stream, &header, &payload).await?;

            let ack = match read_control_frame(stream).await? {
                TransferControlMessage::RangeAck(ack) => ack,
                _ => return Err(DirectSessionError::RangeMismatch),
            };
            if ack.ticket_ref != *ticket.ticket_ref() {
                return Err(DirectSessionError::TicketMismatch);
            }
            if ack.start != header.start || ack.len != header.len || ack.sha256 != header.sha256 {
                return Err(DirectSessionError::RangeMismatch);
            }
        }

        Ok(())
    }
}

/// Target-side direct authenticated E03 session.
pub struct DirectTargetSession;

impl DirectTargetSession {
    /// Admit the ticket-bound source and pull a caller-bounded number of missing
    /// ranges sequentially on the authenticated session.
    ///
    /// Retained cursor ranges are reused only when the bytes still present in
    /// the partial file hash to the cursor-bound digest. This keeps resume
    /// selection local and fail-closed without widening the transfer protocol.
    ///
    /// # Errors
    ///
    /// Rejects any admission, authority, framing, exact-range, digest or local
    /// persistence failure.
    pub async fn pull_missing_ranges<S>(
        stream: &mut S,
        ticket: &TransferTicket,
        peer_fingerprint: CredentialFingerprint,
        partial_path: &Path,
        cursor: &mut DownloadCursor,
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

        let range_limit = stop_after_ranges.unwrap_or(1);
        if range_limit == 0 || ticket.expected_size() == 0 {
            return Ok(DirectTransferReport {
                network_bytes: 0,
                requested_ranges: 0,
                resumed_ranges: 0,
            });
        }

        let (_, resumed_ranges) =
            first_missing_range(partial_path, cursor, ticket.expected_size())?;
        let mut report = DirectTransferReport {
            network_bytes: 0,
            requested_ranges: 0,
            resumed_ranges,
        };

        for _ in 0..range_limit {
            let (next_range, _) =
                first_missing_range(partial_path, cursor, ticket.expected_size())?;
            let Some((start, len)) = next_range else {
                write_control_frame(
                    stream,
                    &TransferControlMessage::Complete(TransferComplete {
                        ticket_ref: ticket.ticket_ref().clone(),
                        size: ticket.expected_size(),
                        canonical_sha256: ticket.canonical_sha256().to_owned(),
                    }),
                )
                .await?;
                break;
            };
            let request = RangeRequest {
                ticket_ref: ticket.ticket_ref().clone(),
                start,
                len,
            };
            write_control_frame(
                stream,
                &TransferControlMessage::RangeRequest(request.clone()),
            )
            .await?;

            let header = match read_control_frame(stream).await? {
                TransferControlMessage::RangeDataHeader(header) => header,
                _ => return Err(DirectSessionError::RangeMismatch),
            };
            if header.ticket_ref != *ticket.ticket_ref() {
                return Err(DirectSessionError::TicketMismatch);
            }
            if header.start != request.start || header.len != request.len {
                return Err(DirectSessionError::RangeMismatch);
            }

            let payload = read_range_payload(stream, &header).await?;
            persist_exact_range(partial_path, header.start, &payload)?;
            let verified = VerifiedRange {
                start: header.start,
                len: header.len,
                sha256: header.sha256.clone(),
            };
            cursor.mark_verified(verified.clone());

            write_control_frame(
                stream,
                &TransferControlMessage::RangeAck(RangeAck {
                    ticket_ref: ticket.ticket_ref().clone(),
                    start: verified.start,
                    len: verified.len,
                    sha256: verified.sha256,
                }),
            )
            .await?;

            report.network_bytes = report
                .network_bytes
                .checked_add(header.len)
                .ok_or(DirectSessionError::RangeMismatch)?;
            report.requested_ranges = report
                .requested_ranges
                .checked_add(1)
                .ok_or(DirectSessionError::RangeMismatch)?;
        }

        Ok(report)
    }
}

fn first_missing_range(
    partial_path: &Path,
    cursor: &DownloadCursor,
    expected_size: u64,
) -> Result<(Option<(u64, u64)>, usize), DirectSessionError> {
    let mut retained = match File::open(partial_path) {
        Ok(file) => Some(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(DirectSessionError::PartialRead(error.to_string())),
    };
    let mut start = 0_u64;
    let mut resumed_ranges = 0_usize;

    while start < expected_size {
        let len = (expected_size - start).min(MAX_RANGE_BYTES as u64);
        let len_usize = usize::try_from(len)
            .map_err(|error| DirectSessionError::PartialRead(error.to_string()))?;
        let mut reusable = false;

        if let Some(file) = retained.as_mut() {
            file.seek(SeekFrom::Start(start))
                .map_err(|error| DirectSessionError::PartialRead(error.to_string()))?;
            let mut bytes = vec![0_u8; len_usize];
            match file.read_exact(&mut bytes) {
                Ok(()) => {
                    let candidate = VerifiedRange {
                        start,
                        len,
                        sha256: sha256(&bytes),
                    };
                    reusable = cursor.contains(&candidate);
                }
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
                Err(error) => return Err(DirectSessionError::PartialRead(error.to_string())),
            }
        }

        if !reusable {
            return Ok((Some((start, len)), resumed_ranges));
        }
        resumed_ranges = resumed_ranges
            .checked_add(1)
            .ok_or(DirectSessionError::RangeMismatch)?;
        start = start
            .checked_add(len)
            .ok_or(DirectSessionError::RangeMismatch)?;
    }

    Ok((None, resumed_ranges))
}

fn validate_request(request: &RangeRequest, expected_size: u64) -> Result<(), DirectSessionError> {
    if request.len == 0 || request.len > MAX_RANGE_BYTES as u64 {
        return Err(DirectSessionError::RangeMismatch);
    }
    let end = request
        .start
        .checked_add(request.len)
        .ok_or(DirectSessionError::RangeMismatch)?;
    if end > expected_size {
        return Err(DirectSessionError::RangeMismatch);
    }
    Ok(())
}

fn persist_exact_range(path: &Path, start: u64, payload: &[u8]) -> Result<(), DirectSessionError> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|error| DirectSessionError::PartialWrite(error.to_string()))?;
    file.seek(SeekFrom::Start(start))
        .map_err(|error| DirectSessionError::PartialWrite(error.to_string()))?;
    file.write_all(payload)
        .map_err(|error| DirectSessionError::PartialWrite(error.to_string()))?;
    file.flush()
        .map_err(|error| DirectSessionError::PartialWrite(error.to_string()))?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
