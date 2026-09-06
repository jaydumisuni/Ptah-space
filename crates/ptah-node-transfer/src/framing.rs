use crate::{
    MAX_CONTROL_FRAME_BYTES, MAX_RANGE_BYTES, RangeDataHeader, TransferControlMessage,
    TransferDataError,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Write one bounded E03 JSON control frame as a 4-byte network-order length
/// followed by the exact JSON payload.
///
/// # Errors
///
/// Rejects encoded frames above [`MAX_CONTROL_FRAME_BYTES`] and propagates
/// serialization or asynchronous I/O failures.
pub async fn write_control_frame<W>(
    writer: &mut W,
    message: &TransferControlMessage,
) -> Result<(), TransferDataError>
where
    W: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(message)
        .map_err(|error| TransferDataError::InvalidControlJson(error.to_string()))?;
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(TransferDataError::ControlFrameTooLarge {
            declared_len: payload.len(),
        });
    }
    let len = u32::try_from(payload.len()).map_err(|_| TransferDataError::ControlFrameTooLarge {
        declared_len: payload.len(),
    })?;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(map_io)?;
    writer.write_all(&payload).await.map_err(map_io)?;
    Ok(())
}

/// Read one bounded E03 JSON control frame from a 4-byte network-order length
/// prefix without allocating above the frozen bound.
///
/// # Errors
///
/// Rejects oversized declarations before payload allocation, premature EOF,
/// invalid JSON and non-EOF asynchronous I/O failures.
pub async fn read_control_frame<R>(reader: &mut R) -> Result<TransferControlMessage, TransferDataError>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; 4];
    read_exact(reader, &mut prefix).await?;
    let declared_len = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| TransferDataError::ControlFrameTooLarge {
            declared_len: usize::MAX,
        })?;
    if declared_len > MAX_CONTROL_FRAME_BYTES {
        return Err(TransferDataError::ControlFrameTooLarge { declared_len });
    }
    let mut payload = vec![0_u8; declared_len];
    read_exact(reader, &mut payload).await?;
    serde_json::from_slice(&payload)
        .map_err(|error| TransferDataError::InvalidControlJson(error.to_string()))
}

/// Write the exact raw payload named by one validated E03 range header.
///
/// # Errors
///
/// Rejects an oversized range, byte-count mismatch, digest mismatch or
/// asynchronous I/O failure.
pub async fn write_range_payload<W>(
    writer: &mut W,
    header: &RangeDataHeader,
    payload: &[u8],
) -> Result<(), TransferDataError>
where
    W: AsyncWrite + Unpin,
{
    validate_range_bound(header)?;
    let actual_len = payload.len();
    if u64::try_from(actual_len).ok() != Some(header.len) {
        return Err(TransferDataError::RangeLengthMismatch {
            declared_len: header.len,
            actual_len,
        });
    }
    if sha256(payload) != header.sha256 {
        return Err(TransferDataError::RangeDigestMismatch);
    }
    writer.write_all(payload).await.map_err(map_io)
}

/// Read exactly the raw bytes named by one E03 range header and verify their
/// SHA-256 before returning them.
///
/// # Errors
///
/// Rejects oversized declarations before allocation, premature EOF, digest
/// mismatch or non-EOF asynchronous I/O failure.
pub async fn read_range_payload<R>(
    reader: &mut R,
    header: &RangeDataHeader,
) -> Result<Vec<u8>, TransferDataError>
where
    R: AsyncRead + Unpin,
{
    validate_range_bound(header)?;
    let len = usize::try_from(header.len).map_err(|_| TransferDataError::RangeTooLarge {
        declared_len: header.len,
    })?;
    let mut payload = vec![0_u8; len];
    read_exact(reader, &mut payload).await?;
    if sha256(&payload) != header.sha256 {
        return Err(TransferDataError::RangeDigestMismatch);
    }
    Ok(payload)
}

fn validate_range_bound(header: &RangeDataHeader) -> Result<(), TransferDataError> {
    if header.len > u64::try_from(MAX_RANGE_BYTES).expect("MAX_RANGE_BYTES fits u64") {
        Err(TransferDataError::RangeTooLarge {
            declared_len: header.len,
        })
    } else {
        Ok(())
    }
}

async fn read_exact<R>(reader: &mut R, buffer: &mut [u8]) -> Result<(), TransferDataError>
where
    R: AsyncRead + Unpin,
{
    reader.read_exact(buffer).await.map(|_| ()).map_err(map_io)
}

fn map_io(error: std::io::Error) -> TransferDataError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        TransferDataError::UnexpectedEof
    } else {
        TransferDataError::Io(error.to_string())
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
