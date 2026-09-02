use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};

use crate::{D06Error, ExactSubject, TrustPolicyProjection};

/// Frozen WP07 signing method.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningMethod {
    /// Public keyless signing.
    PublicKeyless,
    /// Private Sigstore-compatible signing.
    PrivateSigstore,
    /// KMS or HSM backed signing.
    KmsOrHsm,
    /// Project-owned keypair signing.
    ProjectKeypair,
    /// Caller-provided PKI signing.
    CallerPki,
    /// Offline bundle signing.
    OfflineBundle,
    /// Registered external signing method.
    OtherRegistered,
}

/// Frozen WP07 verification result vocabulary used by proof-domain checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationDecision {
    /// Verification is mechanically valid.
    Valid,
    /// Verification is valid with retained limitations.
    ValidWithLimitations,
    /// Verification is mechanically invalid.
    Invalid,
    /// Required verification service/evidence was unavailable.
    Unavailable,
    /// Evidence is insufficient for a conclusion.
    Inconclusive,
    /// Verification is not applicable.
    NotApplicable,
}

/// Exact immutable signature evidence projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureProjection {
    /// Canonical Signature identity.
    pub signature_ref: EntityRef,
    /// Exact digest-bound subject.
    pub subject: ExactSubject,
    /// Retained signature bytes as an A07 Artifact.
    pub signature_artifact_ref: EntityRef,
    /// Signing mechanism.
    pub signing_method: SigningMethod,
    /// Exact signer identity or key reference.
    pub signer_identity_or_key_ref: EntityRef,
}

impl SignatureProjection {
    /// Signature creation is never signature verification.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        false
    }
}

/// One mechanical signature-verification result under an exact Trust Policy revision/version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerificationProjection {
    /// Exact Signature identity verified.
    pub signature_ref: EntityRef,
    /// Exact subject verified.
    pub subject: ExactSubject,
    /// Exact Trust Policy identity.
    pub trust_policy_ref: EntityRef,
    /// Trust Policy version retained with the result.
    pub trust_policy_version: String,
    /// Mechanical verification outcome.
    pub decision: VerificationDecision,
}

impl SignatureVerificationProjection {
    /// Cryptographic validity does not prove semantic correctness.
    #[must_use]
    pub const fn proves_correctness(&self) -> bool {
        false
    }

    /// Cryptographic validity does not grant release acceptance.
    #[must_use]
    pub const fn proves_release_acceptance(&self) -> bool {
        false
    }
}

/// Verify exact signature-to-subject binding under the supplied versioned Trust Policy.
///
/// # Errors
/// Returns [`D06Error::InvalidVerificationBinding`] when the signature subject or policy is not exact.
pub fn verify_signature_binding(
    signature: &SignatureProjection,
    observed_subject: &ExactSubject,
    policy: &TrustPolicyProjection,
) -> Result<SignatureVerificationProjection, D06Error> {
    signature.subject.validate()?;
    observed_subject.validate()?;
    if signature.subject != *observed_subject
        || policy.policy_ref.entity_kind.as_str() != "provenance.trust_policy"
        || policy.policy_version.is_empty()
        || policy.trusted_root_refs.is_empty()
    {
        return Err(D06Error::InvalidVerificationBinding);
    }
    Ok(SignatureVerificationProjection {
        signature_ref: signature.signature_ref.clone(),
        subject: observed_subject.clone(),
        trust_policy_ref: policy.policy_ref.clone(),
        trust_policy_version: policy.policy_version.clone(),
        decision: VerificationDecision::Valid,
    })
}

/// Frozen transparency evidence mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparencyMode {
    /// Public append-only log.
    PublicLog,
    /// Private append-only log.
    PrivateLog,
    /// Timestamp authority.
    TimestampAuthority,
    /// Explicit offline verification without a log.
    OfflineNoLog,
    /// Transparency not used.
    NotUsed,
    /// Registered external transparency mechanism.
    OtherRegistered,
}

/// Explicit acknowledgement authorizing identity disclosure to a public transparency service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureAcknowledgement {
    /// Principal acknowledging disclosure.
    pub principal_ref: EntityRef,
    /// Privacy/policy revision governing disclosure.
    pub policy_ref: EntityRef,
    /// Acknowledgement timestamp.
    pub acknowledged_at: String,
}

/// Provider-neutral transparency evidence projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyEvidenceProjection {
    /// Exact digest-bound subject.
    pub subject: ExactSubject,
    /// Transparency mechanism actually used.
    pub mode: TransparencyMode,
    /// Mechanical verification outcome.
    pub decision: VerificationDecision,
    /// Exact log/timestamp entry evidence refs, if any.
    pub entry_refs: Vec<EntityRef>,
    /// Identity disclosure acknowledgement, when required.
    pub disclosure_acknowledgement: Option<DisclosureAcknowledgement>,
}

impl TransparencyEvidenceProjection {
    /// Construct transparency evidence while enforcing privacy and no-log truthfulness.
    ///
    /// # Errors
    /// Returns [`D06Error::DisclosureRequired`] for public-log evidence without acknowledgement,
    /// [`D06Error::FabricatedTransparency`] for no-log modes carrying fabricated entries, or
    /// [`D06Error::InexactSubject`] for an invalid subject.
    pub fn new(
        subject: ExactSubject,
        mode: TransparencyMode,
        decision: VerificationDecision,
        entry_refs: Vec<EntityRef>,
        disclosure_acknowledgement: Option<DisclosureAcknowledgement>,
    ) -> Result<Self, D06Error> {
        subject.validate()?;
        if mode == TransparencyMode::PublicLog && disclosure_acknowledgement.is_none() {
            return Err(D06Error::DisclosureRequired);
        }
        if matches!(
            mode,
            TransparencyMode::OfflineNoLog | TransparencyMode::NotUsed
        ) && !entry_refs.is_empty()
        {
            return Err(D06Error::FabricatedTransparency);
        }
        Ok(Self {
            subject,
            mode,
            decision,
            entry_refs,
            disclosure_acknowledgement,
        })
    }
}
