use serde::{Deserialize, Serialize};

use crate::D06Error;

/// Exact OCI descriptor used for subject/referrer interoperability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciDescriptor {
    /// OCI media type.
    pub media_type: String,
    /// Canonical lowercase SHA-256 digest.
    pub digest: String,
    /// Descriptor size in bytes.
    pub size: u64,
}

impl OciDescriptor {
    /// Construct an exact OCI descriptor.
    ///
    /// # Errors
    /// Returns [`D06Error::InvalidOciDescriptor`] for empty media type or non-canonical digest.
    pub fn new(media_type: String, digest: String, size: u64) -> Result<Self, D06Error> {
        if media_type.trim().is_empty() || !is_canonical_sha256(&digest) {
            return Err(D06Error::InvalidOciDescriptor);
        }
        Ok(Self {
            media_type,
            digest,
            size,
        })
    }
}

/// How an OCI/ORAS referrer relationship was discovered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMethod {
    /// OCI Distribution referrers API.
    OciReferrersApi,
    /// ORAS-compatible fallback/tag discovery.
    OrasFallback,
    /// Caller-supplied exact relationship evidence.
    CallerEvidence,
}

/// Exact-digest OCI subject/referrer relationship projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciReferrerProjection {
    /// Exact subject descriptor.
    pub subject: OciDescriptor,
    /// Exact referring artifact descriptor.
    pub referrer: OciDescriptor,
    /// OCI artifact type associated with the referrer.
    pub artifact_type: String,
    /// Mutable registry/tag alias retained as evidence only.
    pub registry_alias: Option<String>,
    /// Discovery mechanism.
    pub discovery_method: DiscoveryMethod,
}

impl OciReferrerProjection {
    /// Construct one exact subject/referrer relationship.
    ///
    /// # Errors
    /// Returns [`D06Error::InvalidOciDescriptor`] when the artifact type is empty.
    pub fn new(
        subject: OciDescriptor,
        referrer: OciDescriptor,
        artifact_type: String,
        registry_alias: Option<String>,
        discovery_method: DiscoveryMethod,
    ) -> Result<Self, D06Error> {
        if artifact_type.trim().is_empty() {
            return Err(D06Error::InvalidOciDescriptor);
        }
        Ok(Self {
            subject,
            referrer,
            artifact_type,
            registry_alias,
            discovery_method,
        })
    }

    /// Registry/referrer discovery never grants Ptah trust.
    #[must_use]
    pub const fn grants_trust(&self) -> bool {
        false
    }
}

fn is_canonical_sha256(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
