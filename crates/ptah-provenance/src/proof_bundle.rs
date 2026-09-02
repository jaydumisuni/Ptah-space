use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};

use crate::{D06Error, ExactSubject, VerificationDecision};

/// Independent proof domains retained by D06 proof bundles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofDomain {
    /// Execution/Attempt evidence.
    Execution,
    /// Exact-byte/integrity evidence.
    Integrity,
    /// Export/publication evidence.
    Export,
    /// SBOM inventory/coverage evidence.
    Sbom,
    /// Attestation evidence.
    Attestation,
    /// Signature/cryptographic verification evidence.
    Signature,
    /// Functional-test evidence.
    FunctionalTest,
    /// Independent review evidence.
    Review,
    /// Independent reproduction evidence.
    Reproduction,
    /// Release-domain evidence.
    Release,
}

/// One proof-domain record retained in a bundle manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEntry {
    /// Independent proof domain.
    pub domain: ProofDomain,
    /// Exact canonical record reference carrying evidence for this domain.
    pub record_ref: EntityRef,
    /// Mechanical outcome retained for this record.
    pub decision: VerificationDecision,
}

/// Mechanical coverage of caller-required proof domains.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BundleCoverage {
    /// Every caller-required domain has at least one retained record.
    Complete,
    /// Required proof domains with no retained record.
    Missing(Vec<ProofDomain>),
}

/// Provider-neutral proof-bundle manifest projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBundleManifest {
    /// Exact digest-bound subjects covered by this manifest.
    pub subjects: Vec<ExactSubject>,
    /// Retained manifest bytes as an A07 Artifact.
    pub manifest_artifact_ref: EntityRef,
    /// Independent proof-domain entries.
    pub entries: Vec<ProofEntry>,
    /// Principal/system identity that created the bundle manifest.
    pub creator_ref: EntityRef,
}

impl ProofBundleManifest {
    /// Construct a proof bundle without collapsing independent proof domains.
    ///
    /// # Errors
    /// Returns [`D06Error::InvalidProofBundle`] for empty subjects, invalid manifest Artifact kind,
    /// duplicate domain+record entries, or an inexact subject.
    pub fn new(
        subjects: Vec<ExactSubject>,
        manifest_artifact_ref: EntityRef,
        creator_ref: EntityRef,
        entries: Vec<ProofEntry>,
    ) -> Result<Self, D06Error> {
        if subjects.is_empty() || manifest_artifact_ref.entity_kind.as_str() != "core.artifact" {
            return Err(D06Error::InvalidProofBundle);
        }
        for subject in &subjects {
            subject.validate()?;
        }
        for (index, entry) in entries.iter().enumerate() {
            if entries[..index]
                .iter()
                .any(|prior| prior.domain == entry.domain && prior.record_ref == entry.record_ref)
            {
                return Err(D06Error::InvalidProofBundle);
            }
        }
        Ok(Self {
            subjects,
            manifest_artifact_ref,
            entries,
            creator_ref,
        })
    }

    /// Calculate mechanical coverage against caller-required domains.
    #[must_use]
    pub fn coverage(&self, required_domains: &[ProofDomain]) -> BundleCoverage {
        let missing = required_domains
            .iter()
            .copied()
            .filter(|required| !self.entries.iter().any(|entry| entry.domain == *required))
            .collect::<Vec<_>>();
        if missing.is_empty() {
            BundleCoverage::Complete
        } else {
            BundleCoverage::Missing(missing)
        }
    }

    /// Return the first retained mechanical decision for one proof domain.
    #[must_use]
    pub fn decision_for(&self, domain: ProofDomain) -> Option<VerificationDecision> {
        self.entries
            .iter()
            .find(|entry| entry.domain == domain)
            .map(|entry| entry.decision)
    }

    /// Whether one exact canonical evidence record remains retained in the bundle.
    #[must_use]
    pub fn retains_record(&self, record_ref: &EntityRef) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.record_ref == *record_ref)
    }

    /// A proof bundle never grants a universal semantic/release verdict.
    #[must_use]
    pub const fn grants_universal_acceptance(&self) -> bool {
        false
    }
}
