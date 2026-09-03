use std::collections::BTreeMap;

use ptah_identifiers::EntityRef;

use crate::D07Error;

const RESTRICTED_PUBLIC_FIELD_TOKENS: &[&str] = &[
    "credential",
    "token",
    "cookie",
    "private_payload",
    "exploit_payload",
    "proprietary_source",
    "private_host",
    "topology",
    "customer_private",
];

/// Caller-authored public-safe content used to derive one Evidence Card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceCardContent {
    /// Exact bounded Claim represented by the card.
    pub claim_ref: EntityRef,
    /// Public-safe sentence the caller has explicitly allowed.
    pub allowed_claim_sentence: String,
    /// Exact public-safe evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Bounded result status.
    pub result_status: String,
    /// Bounded verification level.
    pub verification_level: String,
    /// Bounded reproduction level.
    pub reproduction_level: String,
    /// Bounded review status.
    pub review_status: String,
    /// Explicit limitations retained with the view.
    pub limitations: Vec<String>,
}

/// Derived, sanitized Evidence Card presentation with no acceptance or release authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceCardView {
    /// Exact bounded Claim represented by the card.
    pub claim_ref: EntityRef,
    /// Public-safe sentence the caller has explicitly allowed.
    pub allowed_claim_sentence: String,
    /// Exact public-safe evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Bounded result status.
    pub result_status: String,
    /// Bounded verification level.
    pub verification_level: String,
    /// Bounded reproduction level.
    pub reproduction_level: String,
    /// Bounded review status.
    pub review_status: String,
    /// Explicit limitations retained with the view.
    pub limitations: Vec<String>,
    /// Always false: an Evidence Card is never canonical authority.
    pub authoritative: bool,
    /// Always false: an Evidence Card cannot approve a release.
    pub release_approved: bool,
}

impl EvidenceCardView {
    /// Construct a sanitized derived Evidence Card.
    ///
    /// `public_fields` is inspected only as a sanitation boundary; raw restricted field
    /// families are rejected and are never retained in the returned card.
    ///
    /// # Errors
    /// Returns [`D07Error`] when the view is incomplete or a restricted public field is supplied.
    pub fn new(
        content: EvidenceCardContent,
        public_fields: &BTreeMap<String, String>,
    ) -> Result<Self, D07Error> {
        if content.claim_ref.entity_kind.as_str() != "security.claim"
            || content.allowed_claim_sentence.trim().is_empty()
            || content.evidence_refs.is_empty()
            || content.result_status.trim().is_empty()
            || content.verification_level.trim().is_empty()
            || content.reproduction_level.trim().is_empty()
            || content.review_status.trim().is_empty()
        {
            return Err(D07Error::InvalidEvidenceCard);
        }
        if public_fields.keys().any(|key| {
            let normalized = key.to_ascii_lowercase();
            RESTRICTED_PUBLIC_FIELD_TOKENS
                .iter()
                .any(|token| normalized.contains(token))
        }) {
            return Err(D07Error::RestrictedEvidenceCardField);
        }
        Ok(Self {
            claim_ref: content.claim_ref,
            allowed_claim_sentence: content.allowed_claim_sentence,
            evidence_refs: content.evidence_refs,
            result_status: content.result_status,
            verification_level: content.verification_level,
            reproduction_level: content.reproduction_level,
            review_status: content.review_status,
            limitations: content.limitations,
            authoritative: false,
            release_approved: false,
        })
    }
}
