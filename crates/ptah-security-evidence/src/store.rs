use std::path::Path;

use ptah_identifiers::EntityRef;
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger};
use serde_json::Value;

use crate::D07Error;

const WP12_SCHEMAS: &[(&str, &str)] = &[
    (
        "urn:ptah:schema:security:accepted-risk:0.1.0",
        "security.accepted_risk",
    ),
    ("urn:ptah:schema:security:claim:0.1.0", "security.claim"),
    (
        "urn:ptah:schema:security:disclosure-record:0.1.0",
        "security.disclosure_record",
    ),
    ("urn:ptah:schema:security:dispute:0.1.0", "security.dispute"),
    (
        "urn:ptah:schema:security:evidence-bundle:0.1.0",
        "security.evidence_bundle",
    ),
    (
        "urn:ptah:schema:security:evidence-item:0.1.0",
        "security.evidence_item",
    ),
    ("urn:ptah:schema:security:finding:0.1.0", "security.finding"),
    (
        "urn:ptah:schema:security:observation:0.1.0",
        "security.observation",
    ),
    ("urn:ptah:schema:security:patch:0.1.0", "security.patch"),
    (
        "urn:ptah:schema:security:post-fix-verification:0.1.0",
        "security.post_fix_verification",
    ),
    (
        "urn:ptah:schema:security:remediation-proposal:0.1.0",
        "security.remediation_proposal",
    ),
    (
        "urn:ptah:schema:security:remediation-run:0.1.0",
        "security.remediation_run",
    ),
    (
        "urn:ptah:schema:security:reproduction-comparison:0.1.0",
        "security.reproduction_comparison",
    ),
    (
        "urn:ptah:schema:security:reproduction-protocol:0.1.0",
        "security.reproduction_protocol",
    ),
    (
        "urn:ptah:schema:security:reproduction-request:0.1.0",
        "security.reproduction_request",
    ),
    (
        "urn:ptah:schema:security:reproduction-run:0.1.0",
        "security.reproduction_run",
    ),
    (
        "urn:ptah:schema:security:review-decision:0.1.0",
        "security.review_decision",
    ),
    (
        "urn:ptah:schema:security:validation-run:0.1.0",
        "security.validation_run",
    ),
];

/// A03-backed store bounded to the frozen WP12 security catalog.
pub struct SecurityEvidenceStore {
    ledger: Ledger,
}

impl SecurityEvidenceStore {
    /// Open or create the underlying canonical A03 ledger.
    ///
    /// # Errors
    /// Returns [`D07Error`] when the ledger cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, D07Error> {
        Ok(Self {
            ledger: Ledger::open(path).map_err(ledger_error)?,
        })
    }

    /// Persist one complete frozen WP12 canonical document.
    ///
    /// # Errors
    /// Returns [`D07Error`] when canonical validation fails or the schema/kind is outside WP12.
    pub fn record_document(&mut self, document: Value) -> Result<EntityRef, D07Error> {
        let record = CanonicalRecord::from_document(document).map_err(ledger_error)?;
        if !WP12_SCHEMAS.iter().any(|(schema, kind)| {
            record.schema_id() == *schema && record.entity_kind().as_str() == *kind
        }) {
            return Err(D07Error::UnsupportedSecuritySchema);
        }
        let entity_ref = EntityRef::from_id(record.entity_id(), record.entity_kind().as_str())
            .map_err(|_| D07Error::UnsupportedSecuritySchema)?;
        let write = self.ledger.begin_write().map_err(ledger_error)?;
        write.insert(&record).map_err(ledger_error)?;
        write.commit().map_err(ledger_error)?;
        Ok(entity_ref)
    }

    /// Read the latest canonical document for one exact security entity.
    ///
    /// # Errors
    /// Returns [`D07Error`] when the record is absent or unreadable.
    pub fn read(&self, entity_ref: &EntityRef) -> Result<Value, D07Error> {
        self.ledger
            .latest_record(entity_ref.entity_id)
            .map_err(ledger_error)?
            .map(|record| record.document().clone())
            .ok_or(D07Error::UnsupportedSecuritySchema)
    }
}

#[cfg(test)]
pub(crate) fn wp12_schema_pairs() -> &'static [(&'static str, &'static str)] {
    WP12_SCHEMAS
}

fn ledger_error(error: impl std::fmt::Display) -> D07Error {
    D07Error::Ledger(error.to_string())
}
