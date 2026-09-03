use ptah_identifiers::EntityRef;

use crate::D07Error;

/// Explicit audience/redaction/privacy authority for one disclosure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosurePolicy {
    /// Audience boundary such as `public` or `workspace`.
    pub audience: String,
    /// Exact redaction policies applied to disclosed content.
    pub redaction_policy_refs: Vec<EntityRef>,
    /// Exact privacy policies authorizing the disclosure boundary.
    pub privacy_policy_refs: Vec<EntityRef>,
    /// Explicit disclosure authority.
    pub authority_ref: EntityRef,
}

impl DisclosurePolicy {
    /// Authorize disclosure only when restricted evidence is represented by explicit redacted content.
    ///
    /// # Errors
    /// Returns [`D07Error::DisclosureDenied`] when public disclosure lacks redaction/privacy authority.
    pub fn authorize(
        &self,
        restricted_evidence_refs: &[EntityRef],
        disclosed_content_refs: &[EntityRef],
    ) -> Result<(), D07Error> {
        if self.audience.trim().is_empty()
            || self.redaction_policy_refs.is_empty()
            || self.privacy_policy_refs.is_empty()
        {
            return Err(D07Error::DisclosureDenied);
        }
        if self.audience == "public"
            && !restricted_evidence_refs.is_empty()
            && (disclosed_content_refs.is_empty()
                || disclosed_content_refs
                    .iter()
                    .any(|content| restricted_evidence_refs.contains(content)))
        {
            return Err(D07Error::DisclosureDenied);
        }
        Ok(())
    }
}
