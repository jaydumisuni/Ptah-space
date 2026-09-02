use ptah_identifiers::{EntityId, EntityRef};
use ptah_workspace::WorkspaceStore;
use serde::{Deserialize, Serialize};

use crate::D05Error;

/// Distribution audience of one exact package revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistributionClass {
    /// Public distribution remains subject to trust and licence policy.
    Public,
    /// Private distribution requires exact Workspace authority.
    Private,
}

/// Mechanical licence-policy outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenceDecision {
    /// Policy allows the exact revision.
    Allowed,
    /// External governed review is still required.
    ReviewRequired,
    /// Policy denies the exact revision.
    Denied,
}

/// Exact package admission request containing references only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageAdmissionRequest {
    /// Principal requesting admission.
    pub actor_ref: EntityRef,
    /// Workspace owning the private source.
    pub source_workspace_id: EntityId,
    /// Workspace that would receive the installation.
    pub target_workspace_id: EntityId,
    /// Exact package revision.
    pub package_revision_ref: EntityRef,
    /// Distribution class.
    pub distribution: DistributionClass,
    /// Supplied governed licence outcome.
    pub licence_decision: LicenceDecision,
    /// Trust-policy references.
    pub trust_policy_refs: Vec<EntityRef>,
    /// Licence-record references.
    pub licence_record_refs: Vec<EntityRef>,
    /// Evidence references.
    pub evidence_refs: Vec<EntityRef>,
    /// Optional Secure Grant reference for private cross-Workspace admission.
    pub grant_ref: Option<EntityRef>,
}

/// Successful mechanical package admission; not installation success.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageAdmission {
    /// Exact admitted package revision.
    pub package_revision_ref: EntityRef,
    /// Target Workspace.
    pub target_workspace_id: EntityId,
    /// Retained distribution class.
    pub distribution: DistributionClass,
    /// Applied trust-policy references.
    pub trust_policy_refs: Vec<EntityRef>,
    /// Applied licence-record references.
    pub licence_record_refs: Vec<EntityRef>,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
}

/// Mechanical admission service; it does not select a package or licence outcome.
pub struct AdmissionService;

impl AdmissionService {
    /// Validate trust/licence and private Workspace authority.
    ///
    /// # Errors
    ///
    /// Returns a D05 policy/authority error when trust, licence, or Workspace access fails.
    pub fn admit(
        store: &WorkspaceStore,
        request: &PackageAdmissionRequest,
    ) -> Result<PackageAdmission, D05Error> {
        if request.package_revision_ref.entity_kind != "package.revision"
            || request.trust_policy_refs.is_empty()
            || request.licence_record_refs.is_empty()
            || request.evidence_refs.is_empty()
        {
            return Err(D05Error::TrustPolicyMissing);
        }
        match request.licence_decision {
            LicenceDecision::Denied => return Err(D05Error::LicenceDenied),
            LicenceDecision::ReviewRequired => return Err(D05Error::LicenceReviewRequired),
            LicenceDecision::Allowed => {}
        }
        if request.distribution == DistributionClass::Private {
            store
                .authorize_retrieval(
                    &request.actor_ref,
                    request.source_workspace_id,
                    request.target_workspace_id,
                    "plugin.package.install",
                    request.grant_ref.as_ref(),
                )
                .map_err(|_| D05Error::WorkspaceAccessDenied)?;
        }
        Ok(PackageAdmission {
            package_revision_ref: request.package_revision_ref.clone(),
            target_workspace_id: request.target_workspace_id,
            distribution: request.distribution,
            trust_policy_refs: request.trust_policy_refs.clone(),
            licence_record_refs: request.licence_record_refs.clone(),
            evidence_refs: request.evidence_refs.clone(),
        })
    }
}
