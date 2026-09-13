//! E03 bounded control and raw-range framing contract.

use ptah_identifiers::EntityRef;
use ptah_node_transfer::{
    MAX_CONTROL_FRAME_BYTES, MAX_RANGE_BYTES, RangeDataHeader, TransferControlMessage,
    TransferDataError, TransferErrorFrame, read_control_frame, read_range_payload,
    write_control_frame, write_range_payload,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncWriteExt, duplex};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid Ptah entity kind")
}

fn header(bytes: &[u8]) -> RangeDataHeader {
    RangeDataHeader {
        ticket_ref: reference("transfer.ticket"),
        start: 0,
        len: u64::try_from(bytes.len()).expect("test payload length fits u64"),
        sha256: format!("{:x}", Sha256::digest(bytes)),
    }
}

#[tokio::test]
async fn control_frame_round_trips_with_network_order_length_prefix() {
    let message = TransferControlMessage::Error(TransferErrorFrame {
        ticket_ref: Some(reference("transfer.ticket")),
        code: "test".to_owned(),
        message: "bounded".to_owned(),
    });
    let (mut writer, mut reader) = duplex(4096);

    write_control_frame(&mut writer, &message)
        .await
        .expect("write bounded control frame");
    let decoded = read_control_frame(&mut reader)
        .await
        .expect("read bounded control frame");

    assert_eq!(decoded, message);
}

#[tokio::test]
async fn oversized_control_frame_is_rejected_before_payload_allocation() {
    let (mut writer, mut reader) = duplex(16);
    let declared_len = MAX_CONTROL_FRAME_BYTES + 1;
    let prefix = u32::try_from(declared_len)
        .expect("control-frame bound fits u32")
        .to_be_bytes();
    writer
        .write_all(&prefix)
        .await
        .expect("write raw length prefix");

    assert!(matches!(
        read_control_frame(&mut reader).await,
        Err(TransferDataError::ControlFrameTooLarge { declared_len: observed })
            if observed == declared_len
    ));
}

#[tokio::test]
async fn range_larger_than_frozen_bound_is_rejected_before_read() {
    let (_writer, mut reader) = duplex(1);
    let oversized = RangeDataHeader {
        ticket_ref: reference("transfer.ticket"),
        start: 0,
        len: u64::try_from(MAX_RANGE_BYTES + 1).expect("range bound fits u64"),
        sha256: "ab".repeat(32),
    };

    assert!(matches!(
        read_range_payload(&mut reader, &oversized).await,
        Err(TransferDataError::RangeTooLarge { declared_len })
            if declared_len == oversized.len
    ));
}

#[tokio::test]
async fn short_range_payload_is_rejected_as_unexpected_eof() {
    let bytes = b"abcd";
    let expected = header(bytes);
    let (mut writer, mut reader) = duplex(16);
    writer
        .write_all(b"ab")
        .await
        .expect("write truncated payload");
    drop(writer);

    assert!(matches!(
        read_range_payload(&mut reader, &expected).await,
        Err(TransferDataError::UnexpectedEof)
    ));
}

#[tokio::test]
async fn range_payload_digest_mismatch_is_rejected() {
    let bytes = b"abcd";
    let mut expected = header(bytes);
    expected.sha256 = "00".repeat(32);
    let (mut writer, mut reader) = duplex(16);
    writer.write_all(bytes).await.expect("write payload");

    assert!(matches!(
        read_range_payload(&mut reader, &expected).await,
        Err(TransferDataError::RangeDigestMismatch)
    ));
}

#[tokio::test]
async fn exact_maximum_range_payload_round_trips() {
    let bytes = vec![0x5a; MAX_RANGE_BYTES];
    let expected = header(&bytes);
    let (mut writer, mut reader) = duplex(MAX_RANGE_BYTES + 64);

    write_range_payload(&mut writer, &expected, &bytes)
        .await
        .expect("write maximum bounded range");
    let observed = read_range_payload(&mut reader, &expected)
        .await
        .expect("read maximum bounded range");

    assert_eq!(observed, bytes);
}
