//! Thin Hunter caller adapter over exact D02 mechanical operations.

use crate::{
    CallerRecord, D02Error, RetrievalRequest, RetrievedRecord, WorkspaceReader,
    encode_caller_record,
};

/// Hunter-facing adapter. Hunter retains semantic context, source, Provider and next-action choices.
pub struct HunterAdapter<'a> {
    reader: &'a WorkspaceReader,
}

impl<'a> HunterAdapter<'a> {
    /// Bind Hunter to one existing D02 reader without gaining authority.
    #[must_use]
    pub const fn new(reader: &'a WorkspaceReader) -> Self {
        Self { reader }
    }

    /// Retrieve exactly the caller-requested canonical record through D02 authority checks.
    ///
    /// # Errors
    /// Returns the same mechanical D02 retrieval failure as [`WorkspaceReader::retrieve`].
    pub fn retrieve_exact(&self, request: &RetrievalRequest) -> Result<RetrievedRecord, D02Error> {
        self.reader.retrieve(request)
    }

    /// Encode a Hunter-authored caller record without interpreting labels or payload.
    ///
    /// # Errors
    /// Returns bounded structural/serialization failures only.
    pub fn encode_caller_record(&self, record: &CallerRecord) -> Result<Vec<u8>, D02Error> {
        encode_caller_record(record)
    }
}
