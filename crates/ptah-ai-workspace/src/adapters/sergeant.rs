//! Independent Sergeant caller adapter. Sergeant review output remains Sergeant-owned data.

use crate::{
    D02Error, MAX_CALLER_RECORD_BYTES, RetrievalRequest, RetrievedRecord, WorkspaceReader,
};
use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};

/// Caller-owned Sergeant review payload. Ptah stores it without adopting its conclusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SergeantReviewPayload {
    /// Frozen candidate reviewed by Sergeant.
    pub candidate_ref: EntityRef,
    /// Exact reviewer/Sergeant identity.
    pub reviewer_ref: EntityRef,
    /// Exact evidence references selected by Sergeant or caller policy.
    pub selected_evidence_refs: Vec<EntityRef>,
    /// Opaque Sergeant-authored result bytes.
    pub result_bytes: Vec<u8>,
}

/// Sergeant-facing adapter over exact D02 mechanical operations.
pub struct SergeantAdapter<'a> {
    reader: &'a WorkspaceReader,
}

impl<'a> SergeantAdapter<'a> {
    /// Bind Sergeant to one existing D02 reader without granting review authority to Ptah.
    #[must_use]
    pub const fn new(reader: &'a WorkspaceReader) -> Self {
        Self { reader }
    }

    /// Retrieve the exact frozen candidate requested by Sergeant.
    ///
    /// # Errors
    /// Returns the same mechanical D02 retrieval failure as [`WorkspaceReader::retrieve`].
    pub fn retrieve_candidate(
        &self,
        request: &RetrievalRequest,
    ) -> Result<RetrievedRecord, D02Error> {
        self.reader.retrieve(request)
    }

    /// Encode Sergeant's own review result without producing a Ptah verdict or promotion decision.
    ///
    /// # Errors
    /// Fails for empty review evidence/result or the visible D02 container-size limit.
    pub fn encode_review(&self, review: &SergeantReviewPayload) -> Result<Vec<u8>, D02Error> {
        if review.selected_evidence_refs.is_empty() {
            return Err(D02Error::InvalidCallerRecord(
                "sergeant.selected_evidence_refs",
            ));
        }
        if review.result_bytes.is_empty() {
            return Err(D02Error::InvalidCallerRecord("sergeant.result_bytes"));
        }
        let bytes = serde_json::to_vec(review)?;
        if bytes.len() > MAX_CALLER_RECORD_BYTES {
            return Err(D02Error::InvalidCallerRecord("sergeant.encoded_size"));
        }
        Ok(bytes)
    }
}
