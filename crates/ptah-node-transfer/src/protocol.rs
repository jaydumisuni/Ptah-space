use ptah_identifiers::EntityRef;
use ptah_transfer::TransferPeerRole;
use serde::{Deserialize, Serialize};

/// E03 application-protocol version selected for one data-plane session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferProtocolVersion {
    /// Protocol major. Incompatible majors cannot communicate.
    pub major: u16,
    /// Backward-compatible protocol minor.
    pub minor: u16,
}

impl TransferProtocolVersion {
    /// Current E03 protocol version.
    pub const CURRENT: Self = Self { major: 1, minor: 0 };
}

/// First bounded E03 control message sent on an authenticated data-plane stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferHello {
    /// Protocol version proposed by this endpoint.
    pub protocol: TransferProtocolVersion,
    /// Exact control-issued transfer-ticket identity.
    pub ticket_ref: EntityRef,
    /// Ticket side this endpoint is serving.
    pub role: TransferPeerRole,
}

/// Acceptance of one E03 hello after ticket/session admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferHelloAck {
    /// Selected protocol version.
    pub protocol: TransferProtocolVersion,
    /// Exact admitted transfer-ticket identity.
    pub ticket_ref: EntityRef,
    /// Whether admission succeeded.
    pub accepted: bool,
}

/// Request for one exact bounded byte range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeRequest {
    /// Exact transfer-ticket identity.
    pub ticket_ref: EntityRef,
    /// Inclusive byte start offset.
    pub start: u64,
    /// Exact requested byte count.
    pub len: u64,
}

/// Metadata preceding one raw E03 range payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeDataHeader {
    /// Exact transfer-ticket identity.
    pub ticket_ref: EntityRef,
    /// Inclusive byte start offset.
    pub start: u64,
    /// Exact following raw payload byte count.
    pub len: u64,
    /// SHA-256 of the exact following raw payload bytes.
    pub sha256: String,
}

/// Receiver acknowledgement for one independently verified range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeAck {
    /// Exact transfer-ticket identity.
    pub ticket_ref: EntityRef,
    /// Inclusive byte start offset.
    pub start: u64,
    /// Exact verified byte count.
    pub len: u64,
    /// SHA-256 of the exact verified range bytes.
    pub sha256: String,
}

/// End-of-transfer byte-domain report. This is not A07 acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferComplete {
    /// Exact transfer-ticket identity.
    pub ticket_ref: EntityRef,
    /// Exact completed byte count.
    pub size: u64,
    /// SHA-256 of the complete transferred byte sequence.
    pub canonical_sha256: String,
}

/// Stable bounded peer-visible E03 error frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferErrorFrame {
    /// Ticket identity when admission reached a known ticket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_ref: Option<EntityRef>,
    /// Stable machine-readable error code.
    pub code: String,
    /// Bounded human-readable failure detail.
    pub message: String,
}

/// Versioned bounded E03 control-message vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum TransferControlMessage {
    /// Data-plane admission hello.
    Hello(TransferHello),
    /// Hello admission result.
    HelloAck(TransferHelloAck),
    /// Exact range request.
    RangeRequest(RangeRequest),
    /// Header immediately preceding raw range bytes.
    RangeDataHeader(RangeDataHeader),
    /// Verified range acknowledgement.
    RangeAck(RangeAck),
    /// Complete byte-domain report.
    Complete(TransferComplete),
    /// Explicit peer-visible error.
    Error(TransferErrorFrame),
}

impl TransferControlMessage {
    /// Stable JSON `kind` token for this message variant.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Hello(_) => "hello",
            Self::HelloAck(_) => "hello_ack",
            Self::RangeRequest(_) => "range_request",
            Self::RangeDataHeader(_) => "range_data_header",
            Self::RangeAck(_) => "range_ack",
            Self::Complete(_) => "complete",
            Self::Error(_) => "error",
        }
    }
}
