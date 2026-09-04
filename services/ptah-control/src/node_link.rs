use ptah_identifiers::NodeId;
use ptah_node_agent::NodeCapabilitySnapshot;
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
    /// This method only validates E01 authority. It deliberately does not persist,
    /// schedule, place, or transfer anything.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::SupersededConnection`] for an old session,
    /// [`LinkError::NodeIdentityMismatch`] for a different Node, and the existing
    /// stale Generation/epoch errors for a snapshot outside the accepted session.
    pub fn accept_capability(
        &self,
        binding: &SessionBinding,
        snapshot: &NodeCapabilitySnapshot,
    ) -> Result<(), LinkError> {
        self.sessions.assert_current(binding)?;

        if snapshot.node_ref.entity_id != binding.node_id.entity_id() {
            return Err(LinkError::NodeIdentityMismatch);
        }
        if snapshot.node_generation != binding.node_generation {
            return Err(LinkError::StaleNodeGeneration {
                current: binding.node_generation.value(),
                requested: snapshot.node_generation.value(),
            });
        }
        if snapshot.connection_epoch != binding.connection_epoch {
            return Err(LinkError::StaleConnectionEpoch {
                current: binding.connection_epoch.value(),
                requested: snapshot.connection_epoch.value(),
            });
        }
        Ok(())
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
}
