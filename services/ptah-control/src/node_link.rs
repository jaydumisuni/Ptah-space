use ptah_identifiers::NodeId;
use ptah_node_agent::{NodeCapabilitySnapshot, NodeResourceSnapshot};
use ptah_node_link::{
    ApprovedNodeEnrollment, CredentialFingerprint, LinkError, NodeHello, ProtocolVersion,
    SessionBinding, SessionRegistry,
};
use std::collections::HashMap;

/// Control-plane owner of current E01 enrollment projections and secure-session fences.
#[derive(Debug)]
pub struct NodeLinkControl {
    enrollments: HashMap<NodeId, ApprovedNodeEnrollment>,
    sessions: SessionRegistry,
}

impl NodeLinkControl {
    /// Construct one control-plane secure-link registry from canonical enrollment projections.
    #[must_use]
    pub fn new(protocol: ProtocolVersion, enrollments: Vec<ApprovedNodeEnrollment>) -> Self {
        let enrollments = enrollments
            .into_iter()
            .map(|enrollment| (enrollment.node_id(), enrollment))
            .collect();
        Self {
            enrollments,
            sessions: SessionRegistry::new(protocol),
        }
    }

    /// Authenticate and fence one Node hello against its current enrollment projection.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::UnapprovedEnrollment`] when no enrollment exists for
    /// the claimed Node, or propagates the enrollment/protocol/replay failures
    /// produced by [`SessionRegistry::accept_hello`].
    pub fn accept_hello(
        &mut self,
        hello: &NodeHello,
        credential_fingerprint: CredentialFingerprint,
        now_epoch_seconds: u64,
    ) -> Result<SessionBinding, LinkError> {
        let enrollment = self
            .enrollments
            .get(&hello.node_id)
            .ok_or(LinkError::UnapprovedEnrollment)?;
        self.sessions
            .accept_hello(hello, enrollment, credential_fingerprint, now_epoch_seconds)
    }

    /// Validate one A02 capability snapshot against the exact current secure session.
    ///
    /// # Errors
    ///
    /// Returns the existing E01 currentness/identity/generation/epoch error when
    /// the snapshot is outside the accepted session.
    pub fn accept_capability(
        &self,
        binding: &SessionBinding,
        snapshot: &NodeCapabilitySnapshot,
    ) -> Result<(), LinkError> {
        self.assert_snapshot_binding(
            binding,
            snapshot.node_ref.entity_id,
            snapshot.node_generation.value(),
            snapshot.connection_epoch.value(),
        )
    }

    /// Validate one A02 resource snapshot against the exact current secure session.
    ///
    /// # Errors
    ///
    /// Returns the existing E01 currentness/identity/generation/epoch error when
    /// the snapshot is outside the accepted session.
    pub fn accept_resource(
        &self,
        binding: &SessionBinding,
        snapshot: &NodeResourceSnapshot,
    ) -> Result<(), LinkError> {
        self.assert_snapshot_binding(
            binding,
            snapshot.node_ref.entity_id,
            snapshot.node_generation.value(),
            snapshot.connection_epoch.value(),
        )
    }

    /// Return the exact current secure-session binding for one canonical Node.
    #[must_use]
    pub fn current_session(&self, node_id: NodeId) -> Option<&SessionBinding> {
        self.sessions.current(node_id)
    }

    /// Revoke one credential from an enrollment and immediately fence any session using it.
    pub fn revoke_credential(
        &mut self,
        node_id: NodeId,
        fingerprint: &CredentialFingerprint,
    ) -> bool {
        let removed = self
            .enrollments
            .get_mut(&node_id)
            .is_some_and(|enrollment| enrollment.revoke_credential(fingerprint));
        if removed {
            self.sessions.revoke_credential(fingerprint);
        }
        removed
    }

    fn assert_snapshot_binding(
        &self,
        binding: &SessionBinding,
        entity_id: ptah_identifiers::EntityId,
        node_generation: u64,
        connection_epoch: u64,
    ) -> Result<(), LinkError> {
        self.sessions.assert_current(binding)?;
        if entity_id != binding.node_id.entity_id() {
            return Err(LinkError::NodeIdentityMismatch);
        }
        if node_generation != binding.node_generation.value() {
            return Err(LinkError::StaleNodeGeneration {
                current: binding.node_generation.value(),
                requested: node_generation,
            });
        }
        if connection_epoch != binding.connection_epoch.value() {
            return Err(LinkError::StaleConnectionEpoch {
                current: binding.connection_epoch.value(),
                requested: connection_epoch,
            });
        }
        Ok(())
    }
}
