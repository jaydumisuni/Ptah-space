use crate::LinkError;
use ptah_identifiers::{EntityRef, NodeId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt, str::FromStr};

/// SHA-256 fingerprint of one authenticated end-entity credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialFingerprint([u8; 32]);

impl CredentialFingerprint {
    /// Compute the credential fingerprint from exact DER bytes.
    #[must_use]
    pub fn from_der(der: &[u8]) -> Self {
        let digest = Sha256::digest(der);
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    /// Return the exact fingerprint bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for CredentialFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for CredentialFingerprint {
    type Err = LinkError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err(LinkError::InvalidCredentialFingerprint);
        }
        let mut bytes = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let text = std::str::from_utf8(chunk)
                .map_err(|_| LinkError::InvalidCredentialFingerprint)?;
            bytes[index] = u8::from_str_radix(text, 16)
                .map_err(|_| LinkError::InvalidCredentialFingerprint)?;
        }
        Ok(Self(bytes))
    }
}

/// Frozen `core.node_enrollment` lifecycle projection consumed by E01.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentLifecycle {
    /// Enrollment request exists but has no authority yet.
    Requested,
    /// Enrollment is under explicit review.
    UnderReview,
    /// Enrollment is approved for the recorded scope.
    Approved,
    /// Enrollment was rejected.
    Rejected,
    /// Previously approved enrollment was revoked.
    Revoked,
    /// Previously approved enrollment expired.
    Expired,
}

/// Mechanical approved-enrollment projection used by the E01 secure-link layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedNodeEnrollment {
    enrollment_ref: EntityRef,
    node_id: NodeId,
    lifecycle: EnrollmentLifecycle,
    approved_role_keys: Vec<String>,
    credential_fingerprints: HashSet<CredentialFingerprint>,
    expires_at_epoch_seconds: Option<u64>,
}

impl ApprovedNodeEnrollment {
    /// Construct one enrollment projection from already-reviewed canonical facts.
    ///
    /// This constructor does not approve an enrollment; it merely preserves the
    /// lifecycle supplied by the canonical caller/repository projection.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::InvalidEnrollment`] when no approved role or
    /// credential fingerprint is supplied.
    pub fn new(
        enrollment_ref: EntityRef,
        node_id: NodeId,
        lifecycle: EnrollmentLifecycle,
        approved_role_keys: Vec<String>,
        credential_fingerprints: Vec<CredentialFingerprint>,
        expires_at_epoch_seconds: Option<u64>,
    ) -> Result<Self, LinkError> {
        if approved_role_keys.is_empty() {
            return Err(LinkError::InvalidEnrollment("approved role keys are required"));
        }
        if credential_fingerprints.is_empty() {
            return Err(LinkError::InvalidEnrollment(
                "credential fingerprints are required",
            ));
        }
        Ok(Self {
            enrollment_ref,
            node_id,
            lifecycle,
            approved_role_keys,
            credential_fingerprints: credential_fingerprints.into_iter().collect(),
            expires_at_epoch_seconds,
        })
    }

    /// Exact canonical enrollment reference.
    #[must_use]
    pub const fn enrollment_ref(&self) -> &EntityRef {
        &self.enrollment_ref
    }

    /// Stable canonical Node identity bound to this enrollment.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Current enrollment lifecycle projection.
    #[must_use]
    pub const fn lifecycle(&self) -> EnrollmentLifecycle {
        self.lifecycle
    }

    /// Approved role keys retained on the enrollment.
    #[must_use]
    pub fn approved_role_keys(&self) -> &[String] {
        &self.approved_role_keys
    }

    /// Replace only the lifecycle projection after canonical state changes.
    pub fn set_lifecycle(&mut self, lifecycle: EnrollmentLifecycle) {
        self.lifecycle = lifecycle;
    }

    /// Add one explicitly approved credential during a rotation overlap window.
    pub fn add_credential(&mut self, fingerprint: CredentialFingerprint) {
        self.credential_fingerprints.insert(fingerprint);
    }

    /// Remove one credential from the active approved set.
    pub fn revoke_credential(&mut self, fingerprint: &CredentialFingerprint) -> bool {
        self.credential_fingerprints.remove(fingerprint)
    }

    /// Verify peer identity and credential against current enrollment authority.
    ///
    /// # Errors
    ///
    /// Fails closed for non-approved lifecycle, expiry, Node identity mismatch,
    /// or a credential outside the currently approved set.
    pub fn authorize_peer(
        &self,
        claimed_node_id: NodeId,
        fingerprint: CredentialFingerprint,
        now_epoch_seconds: u64,
    ) -> Result<(), LinkError> {
        match self.lifecycle {
            EnrollmentLifecycle::Approved => {}
            EnrollmentLifecycle::Revoked => return Err(LinkError::EnrollmentRevoked),
            EnrollmentLifecycle::Expired => return Err(LinkError::EnrollmentExpired),
            EnrollmentLifecycle::Requested
            | EnrollmentLifecycle::UnderReview
            | EnrollmentLifecycle::Rejected => return Err(LinkError::UnapprovedEnrollment),
        }
        if self
            .expires_at_epoch_seconds
            .is_some_and(|expires_at| now_epoch_seconds >= expires_at)
        {
            return Err(LinkError::EnrollmentExpired);
        }
        if claimed_node_id != self.node_id {
            return Err(LinkError::NodeIdentityMismatch);
        }
        if !self.credential_fingerprints.contains(&fingerprint) {
            return Err(LinkError::CredentialNotBound);
        }
        Ok(())
    }
}
