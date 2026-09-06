use super::{E03TransferError, TransferTicket};
use crate::{DownloadCursor, VerifiedRange};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Re-read every ticket-compatible retained range and prove all cursor entries
/// still match their exact geometry and digest before E03 resumes.
///
/// # Errors
///
/// Returns [`E03TransferError::RetainedRangeUnavailable`] when retained bytes
/// cannot be read and [`E03TransferError::RetainedRangeDigestMismatch`] when
/// any cursor entry no longer matches exact ticket geometry and retained bytes.
pub fn validate_resume_cursor(
    ticket: &TransferTicket,
    cursor: &DownloadCursor,
    partial_path: &Path,
) -> Result<(), E03TransferError> {
    if cursor.is_empty() {
        return Ok(());
    }

    let mut file = File::open(partial_path).map_err(|_| E03TransferError::RetainedRangeUnavailable)?;
    let mut matched = 0_usize;
    let expected_size = ticket.expected_size();
    let range_size = ticket.range_size();
    let mut start = 0_u64;

    while start < expected_size {
        let len = (expected_size - start).min(range_size);
        let len_usize = usize::try_from(len).map_err(|_| E03TransferError::InvalidGeometry)?;
        let mut bytes = vec![0_u8; len_usize];
        file.seek(SeekFrom::Start(start))
            .map_err(|_| E03TransferError::RetainedRangeUnavailable)?;
        file.read_exact(&mut bytes)
            .map_err(|_| E03TransferError::RetainedRangeUnavailable)?;
        let candidate = VerifiedRange {
            start,
            len,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
        };
        if cursor.contains(&candidate) {
            matched += 1;
        }
        start = start
            .checked_add(len)
            .ok_or(E03TransferError::InvalidGeometry)?;
    }

    if matched == cursor.len() {
        Ok(())
    } else {
        Err(E03TransferError::RetainedRangeDigestMismatch)
    }
}
