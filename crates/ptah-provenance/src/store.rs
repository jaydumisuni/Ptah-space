use std::path::Path;

use ptah_identifiers::EntityRef;
use ptah_ledger::{CanonicalRecord, EntityRecordRepository, Ledger};
use serde_json::Value;

use crate::D06Error;

const D06_SCHEMAS: &[(&str, &str)] = &[
    (
        "urn:ptah:schema:build:package-observation:0.1.0",
        "provenance.package_observation",
    ),
    (
        "urn:ptah:schema:build:sbom-coverage:0.1.0",
        "provenance.sbom_coverage",
    ),
    ("urn:ptah:schema:build:sbom:0.1.0", "provenance.sbom"),
    (
        "urn:ptah:schema:build:trust-policy:0.1.0",
        "provenance.trust_policy",
    ),
    (
        "urn:ptah:schema:build:transparency-evidence:0.1.0",
        "provenance.transparency_evidence",
    ),
    (
        "urn:ptah:schema:build:attestation:0.1.0",
        "provenance.attestation",
    ),
    (
        "urn:ptah:schema:build:attestation-verification:0.1.0",
        "provenance.attestation_verification",
    ),
    (
        "urn:ptah:schema:build:signature:0.1.0",
        "provenance.signature",
    ),
    (
        "urn:ptah:schema:build:signature-verification:0.1.0",
        "provenance.signature_verification",
    ),
    (
        "urn:ptah:schema:build:proof-bundle:0.1.0",
        "provenance.proof_bundle",
    ),
    (
        "urn:ptah:schema:build:verification-run:0.1.0",
        "provenance.verification_run",
    ),
    (
        "urn:ptah:schema:build:reproduction-request:0.1.0",
        "provenance.reproduction_request",
    ),
    (
        "urn:ptah:schema:build:reproduction-run:0.1.0",
        "proof.reproduction_run",
    ),
    (
        "urn:ptah:schema:build:reproduction-comparison:0.1.0",
        "proof.comparison",
    ),
    (
        "urn:ptah:schema:build:provenance-graph-revision:0.1.0",
        "provenance.graph_revision",
    ),
];

/// A03-backed canonical D06 provenance store.
pub struct ProvenanceStore {
    ledger: Ledger,
}

impl ProvenanceStore {
    /// Open or create the canonical A03 ledger.
    ///
    /// # Errors
    /// Returns [`D06Error`] when the A03 ledger cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, D06Error> {
        Ok(Self {
            ledger: Ledger::open(path).map_err(ledger_error)?,
        })
    }

    /// Persist one complete frozen D06/WP07 document through A03.
    ///
    /// # Errors
    /// Returns [`D06Error`] for any non-D06 schema/kind pair or invalid canonical document.
    pub fn record_document(&mut self, document: Value) -> Result<EntityRef, D06Error> {
        let record = CanonicalRecord::from_document(document).map_err(ledger_error)?;
        let allowed = D06_SCHEMAS.iter().any(|(schema, kind)| {
            record.schema_id() == *schema && record.entity_kind().as_str() == *kind
        });
        if !allowed {
            return Err(D06Error::InvalidCanonicalRecord);
        }
        let entity_ref = EntityRef::from_id(record.entity_id(), record.entity_kind().as_str())
            .map_err(|_| D06Error::InvalidCanonicalRecord)?;
        let write = self.ledger.begin_write().map_err(ledger_error)?;
        write.insert(&record).map_err(ledger_error)?;
        write.commit().map_err(ledger_error)?;
        Ok(entity_ref)
    }

    /// Read the latest canonical document for one exact provenance entity.
    ///
    /// # Errors
    /// Returns [`D06Error`] when the record is absent or the ledger read fails.
    pub fn read(&self, entity_ref: &EntityRef) -> Result<Value, D06Error> {
        self.ledger
            .latest_record(entity_ref.entity_id)
            .map_err(ledger_error)?
            .map(|record| record.document().clone())
            .ok_or(D06Error::InvalidCanonicalRecord)
    }
}

fn ledger_error(error: impl std::fmt::Display) -> D06Error {
    D06Error::Ledger(error.to_string())
}
