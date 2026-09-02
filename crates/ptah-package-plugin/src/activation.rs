use ptah_identifiers::{EntityId, EntityRef};
use ptah_workspace::WorkspaceStore;
use serde::{Deserialize, Serialize};

use crate::D05Error;

/// Exact caller-authored Plugin Activation request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationRequest {
    /// Principal/agent requesting activation.
    pub actor_ref: EntityRef,
    /// Workspace containing the governed Plugin source/private material.
    pub source_workspace_id: EntityId,
    /// Workspace receiving runtime activation.
    pub target_workspace_id: EntityId,
    /// Exact immutable Plugin Revision.
    pub plugin_revision_ref: EntityRef,
    /// Exact verified Plugin Installation.
    pub installation_ref: EntityRef,
    /// Exact target Workspace.
    pub workspace_ref: EntityRef,
    /// Explicit governing Policy references.
    pub policy_refs: Vec<EntityRef>,
    /// Exact current Secure Grant required for activation.
    pub grant_ref: Option<EntityRef>,
    /// Caller/authority that made the activation decision.
    pub decided_by_ref: EntityRef,
    /// Exact decision timestamp.
    pub decided_at: String,
}

/// Thin activation authority facade over A06.
pub struct ActivationService;

impl ActivationService {
    /// Validate exact Plugin activation identity, policy and current A06 Grant scope.
    ///
    /// # Errors
    /// Returns [`D05Error::ActivationAuthorityMissing`] when identity, policy, Grant,
    /// expiry or Workspace authority does not permit activation.
    pub fn authorize(store: &WorkspaceStore, request: &ActivationRequest) -> Result<(), D05Error> {
        if request.plugin_revision_ref.entity_kind != "plugin.revision"
            || request.installation_ref.entity_kind != "plugin.installation"
            || request.workspace_ref.entity_kind != "core.workspace"
            || request.workspace_ref.entity_id != request.target_workspace_id
            || request.policy_refs.is_empty()
            || request.grant_ref.is_none()
            || request.decided_at.trim().is_empty()
        {
            return Err(D05Error::ActivationAuthorityMissing);
        }
        store
            .authorize_retrieval(
                &request.actor_ref,
                request.source_workspace_id,
                request.target_workspace_id,
                "plugin.activate",
                request.grant_ref.as_ref(),
            )
            .map_err(|_| D05Error::ActivationAuthorityMissing)
    }
}
