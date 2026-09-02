use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{D06Error, ExactSubject};

/// External attestation statement/envelope representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeType {
    /// Unsigned in-toto-style statement.
    UnsignedStatement,
    /// DSSE envelope.
    Dsse,
    /// in-toto statement representation.
    InTotoStatement,
    /// Registered external representation.
    OtherRegistered(String),
}

/// Whether provenance material/product evidence was declared or independently observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterialOrigin {
    /// Declared by the producer/build definition.
    Declared,
    /// Observed from runtime/readback evidence.
    Observed,
}

/// Exact material/product subject plus its evidence origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundMaterial {
    /// Exact digest-bound subject.
    pub subject: ExactSubject,
    /// Declared-vs-observed evidence origin.
    pub origin: MaterialOrigin,
}

/// Provider-neutral attestation statement projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationProjection {
    /// Exact statement subjects.
    pub subjects: Vec<ExactSubject>,
    /// Predicate type URI/name.
    pub predicate_type: String,
    /// Predicate schema/version string.
    pub predicate_version: String,
    /// Retained statement bytes as an A07 Artifact.
    pub statement_artifact_ref: EntityRef,
    /// Producer identity reference.
    pub producer_ref: EntityRef,
    /// Exact producer Facility Revision.
    pub producer_facility_revision_ref: EntityRef,
    /// Bound input/material evidence.
    pub materials: Vec<BoundMaterial>,
    /// Bound product/output evidence.
    pub products: Vec<BoundMaterial>,
    /// External statement/envelope representation.
    pub envelope_type: EnvelopeType,
}

impl AttestationProjection {
    /// Attestation creation is never verification.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        false
    }

    /// Deterministic SHA-256 over the mechanical statement projection.
    ///
    /// # Errors
    /// Returns [`D06Error::Encoding`] if the projection cannot be serialized.
    pub fn statement_digest_sha256(&self) -> Result<String, D06Error> {
        let bytes =
            serde_json::to_vec(self).map_err(|error| D06Error::Encoding(error.to_string()))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}
