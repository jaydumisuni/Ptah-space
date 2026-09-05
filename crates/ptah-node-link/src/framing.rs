use crate::{LinkError, LinkMessage, MAX_FRAME_BYTES};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Read one length-delimited E01 message from any async byte stream.
///
/// # Errors
///
/// Returns [`LinkError::FrameTooLarge`] for an oversized declared frame,
/// [`LinkError::MalformedFrame`] for zero-length or invalid JSON frames, and
/// [`LinkError::Io`] when the underlying stream cannot provide the required bytes.
pub async fn read_frame<R>(reader: &mut R) -> Result<LinkMessage, LinkError>
where
    R: AsyncRead + Unpin,
{
    let mut length_bytes = [0_u8; 4];
    reader.read_exact(&mut length_bytes).await?;
    let declared = u32::from_be_bytes(length_bytes) as usize;
    if declared == 0 {
        return Err(LinkError::MalformedFrame(String::from("zero-length frame")));
    }
    if declared > MAX_FRAME_BYTES {
        return Err(LinkError::FrameTooLarge { declared });
    }

    let mut payload = vec![0_u8; declared];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).map_err(|error| LinkError::MalformedFrame(error.to_string()))
}

/// Serialize and write one bounded length-delimited E01 message.
///
/// # Errors
///
/// Returns [`LinkError::FrameTooLarge`] when serialized bytes exceed the E01
/// frame bound, [`LinkError::MalformedFrame`] when serialization fails, and
/// [`LinkError::Io`] when the underlying stream cannot accept the frame.
pub async fn write_frame<W>(writer: &mut W, message: &LinkMessage) -> Result<(), LinkError>
where
    W: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(message)
        .map_err(|error| LinkError::MalformedFrame(error.to_string()))?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(LinkError::FrameTooLarge {
            declared: payload.len(),
        });
    }
    let length = u32::try_from(payload.len()).map_err(|_| LinkError::FrameTooLarge {
        declared: payload.len(),
    })?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}
