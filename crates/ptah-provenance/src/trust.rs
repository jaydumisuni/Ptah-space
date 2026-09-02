use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};

/// Frozen WP07 trust mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    /// Public keyless identity/signing service.
    PublicKeyless,
    /// Private Sigstore-compatible deployment.
    PrivateSigstore,
    /// KMS or HSM backed signing.
    KmsOrHsm,
    /// Project-owned keypair.
    ProjectKeypair,
    /// Caller-provided PKI.
    CallerPki,
    /// Offline verification/signing bundle.
    OfflineBundle,
    /// Hybrid trust configuration.
    Hybrid,
    /// Registered trust mechanism outside the frozen native vocabulary.
    OtherRegistered,
}

/// Frozen WP07 transparency policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparencyPolicy {
    /// Transparency evidence is mandatory.
    Required,
    /// Transparency evidence is optional.
    Optional,
    /// Public transparency is forbidden for privacy.
    ForbiddenForPrivacy,
    /// Offline inclusion proof is required/allowed instead of live lookup.
    OfflineInclusionProof,
    /// Transparency does not apply.
    NotApplicable,
}

/// Frozen WP07 offline verification policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflinePolicy {
    /// Offline verification is allowed.
    Allowed,
    /// Offline verification is required.
    Required,
    /// Offline verification is forbidden.
    Forbidden,
    /// Offline verification is allowed only under policy conditions.
    AllowedWithConditions,
}

/// Versioned D06 trust-policy projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustPolicyProjection {
    /// Exact Trust Policy identity.
    pub policy_ref: EntityRef,
    /// Policy version retained in verification history.
    pub policy_version: String,
    /// Trust mode.
    pub trust_mode: TrustMode,
    /// Exact trusted-root references.
    pub trusted_root_refs: Vec<EntityRef>,
    /// Transparency requirement.
    pub transparency_policy: TransparencyPolicy,
    /// Offline verification policy.
    pub offline_policy: OfflinePolicy,
}
