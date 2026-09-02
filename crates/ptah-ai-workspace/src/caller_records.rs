//! Opaque caller-owned record containers for D02 application metadata and handoffs.

use crate::D02Error;
use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Exact caller-record container version.
pub const CALLER_RECORD_FORMAT_VERSION: &str = "ptah.caller-record.v1";
/// Visible D02 container bound; this limits transport/storage helper size, not semantic content.
pub const MAX_CALLER_RECORD_BYTES: usize = 1024 * 1024;

/// Caller-authored labels and opaque payload bytes. Ptah does not interpret label meaning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerRecord {
    /// Exact D02 caller-record container version.
    pub format_version: String,
    /// Caller/application that authored this container.
    pub author_ref: EntityRef,
    /// Caller-owned labels preserved in caller order.
    pub labels: Vec<String>,
    /// Opaque caller-authored payload bytes.
    pub payload_bytes: Vec<u8>,
}

/// Encode one caller-owned container without normalizing labels or payload bytes.
///
/// # Errors
/// Fails only on bounded structural validation or JSON encoding failure.
pub fn encode_caller_record(record: &CallerRecord) -> Result<Vec<u8>, D02Error> {
    validate_caller_record(record)?;
    let encoded = serde_json::to_vec(record)?;
    if encoded.len() > MAX_CALLER_RECORD_BYTES {
        return Err(D02Error::InvalidCallerRecord("encoded_size"));
    }
    Ok(encoded)
}

/// Decode one caller-owned container and preserve exact label order and payload bytes.
///
/// # Errors
/// Fails only on bounded structural validation or JSON decoding failure.
pub fn decode_caller_record(bytes: &[u8]) -> Result<CallerRecord, D02Error> {
    if bytes.len() > MAX_CALLER_RECORD_BYTES {
        return Err(D02Error::InvalidCallerRecord("encoded_size"));
    }
    let record: CallerRecord = serde_json::from_slice(bytes)?;
    validate_caller_record(&record)?;
    Ok(record)
}

fn validate_caller_record(record: &CallerRecord) -> Result<(), D02Error> {
    if record.format_version != CALLER_RECORD_FORMAT_VERSION {
        return Err(D02Error::InvalidCallerRecord("format_version"));
    }
    if record.labels.is_empty() {
        return Err(D02Error::InvalidCallerRecord("labels"));
    }
    let mut seen = HashSet::new();
    for label in &record.labels {
        if label.is_empty() || label != label.trim() || !seen.insert(label.as_str()) {
            return Err(D02Error::InvalidCallerRecord("labels"));
        }
    }
    Ok(())
}
