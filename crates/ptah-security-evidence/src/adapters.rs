use ptah_identifiers::EntityRef;

use crate::D07Error;

/// Provider-neutral normalized observation from a replaceable private security backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAdapterObservation {
    /// Provider-local alias retained as evidence only.
    pub backend_alias: String,
    /// Exact provider revision that produced this normalized observation.
    pub provider_revision_ref: EntityRef,
    /// Exact canonical subjects observed by the backend.
    pub subject_refs: Vec<EntityRef>,
    /// Bounded normalized facts.
    pub facts: Vec<String>,
    /// Fresh evidence references produced by this backend/work run.
    pub evidence_refs: Vec<EntityRef>,
}

impl SecurityAdapterObservation {
    /// A backend alias can never be converted into canonical Finding identity.
    #[must_use]
    pub const fn backend_alias_as_finding_ref(&self) -> Option<&EntityRef> {
        None
    }

    fn validate(&self) -> Result<(), D07Error> {
        if self.backend_alias.trim().is_empty()
            || self.provider_revision_ref.entity_kind.as_str() != "runtime.provider_revision"
            || self.subject_refs.is_empty()
            || self.facts.is_empty()
            || self.evidence_refs.is_empty()
        {
            return Err(D07Error::InvalidAdapterObservation);
        }
        Ok(())
    }
}

/// Mechanical proof that backend replacement changes machinery/evidence without replacing Ptah identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendReplacementProjection {
    finding_ref: EntityRef,
    claim_ref: EntityRef,
    original: SecurityAdapterObservation,
    replacement: SecurityAdapterObservation,
}

impl BackendReplacementProjection {
    /// Build a replacement proof over two normalized backend observations.
    ///
    /// # Errors
    /// Returns [`D07Error`] unless canonical subjects stay equal while backend/provider/evidence change.
    pub fn new(
        finding_ref: EntityRef,
        claim_ref: EntityRef,
        original: SecurityAdapterObservation,
        replacement: SecurityAdapterObservation,
    ) -> Result<Self, D07Error> {
        original.validate()?;
        replacement.validate()?;
        if finding_ref.entity_kind.as_str() != "security.finding"
            || claim_ref.entity_kind.as_str() != "security.claim"
            || original.subject_refs != replacement.subject_refs
            || original.backend_alias == replacement.backend_alias
            || original.provider_revision_ref == replacement.provider_revision_ref
            || original.evidence_refs == replacement.evidence_refs
        {
            return Err(D07Error::InvalidBackendReplacement);
        }
        Ok(Self {
            finding_ref,
            claim_ref,
            original,
            replacement,
        })
    }

    /// Canonical Finding identity preserved across backend replacement.
    #[must_use]
    pub const fn finding_ref(&self) -> &EntityRef {
        &self.finding_ref
    }

    /// Canonical Claim identity preserved across backend replacement.
    #[must_use]
    pub const fn claim_ref(&self) -> &EntityRef {
        &self.claim_ref
    }

    /// Original normalized backend observation.
    #[must_use]
    pub const fn original(&self) -> &SecurityAdapterObservation {
        &self.original
    }

    /// Replacement normalized backend observation.
    #[must_use]
    pub const fn replacement(&self) -> &SecurityAdapterObservation {
        &self.replacement
    }
}
