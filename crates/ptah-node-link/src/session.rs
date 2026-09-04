use crate::{ApprovedNodeEnrollment, CredentialFingerprint, LinkError, NodeHello, ProtocolVersion};
use ptah_identifiers::{ConnectionEpoch, EntityRef, NodeGeneration, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Exact authenticated authority attached to one active E01 secure link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBinding {
    /// Stable canonical Node identity.
    pub node_id: NodeId,
    /// Exact accepted Node Generation.
    pub node_generation: NodeGeneration,
    /// Exact accepted `ConnectionEpoch`.
    pub connection_epoch: ConnectionEpoch,
    /// Exact approved enrollment reference.
    pub enrollment_ref: EntityRef,
    /// Authenticated end-entity credential fingerprint.
    pub credential_fingerprint: CredentialFingerprint,
    /// Exact selected application-protocol version.
    pub negotiated_protocol: ProtocolVersion,
}

/// In-process current secure-link registry used only for replay/supersession fencing.
#[derive(Debug)]
pub struct SessionRegistry {
    local_protocol: ProtocolVersion,
    current: HashMap<NodeId, SessionBinding>,
}

impl SessionRegistry {
    /// Create an empty secure-link registry for one supported local protocol version.
    #[must_use]
    pub fn new(local_protocol: ProtocolVersion) -> Self {
        Self {
            local_protocol,
            current: HashMap::new(),
        }
    }

    /// Authorize and accept one authenticated Node hello.
    ///
    /// # Errors
    ///
    /// Fails closed when enrollment or credential authority is invalid, the
    /// enrollment reference differs, protocol versions are incompatible, or the
    /// requested Generation/epoch is stale relative to the current accepted link.
    pub fn accept_hello(
        &mut self,
        hello: &NodeHello,
        enrollment: &ApprovedNodeEnrollment,
        credential_fingerprint: CredentialFingerprint,
        now_epoch_seconds: u64,
    ) -> Result<SessionBinding, LinkError> {
        if &hello.enrollment_ref != enrollment.enrollment_ref() {
            return Err(LinkError::EnrollmentReferenceMismatch);
        }
        enrollment.authorize_peer(hello.node_id, credential_fingerprint, now_epoch_seconds)?;

        if hello.supported_major != self.local_protocol.major {
            return Err(LinkError::ProtocolIncompatible {
                local_major: self.local_protocol.major,
                remote_major: hello.supported_major,
            });
        }
        if self.local_protocol.minor < hello.minimum_minor
            || self.local_protocol.minor > hello.maximum_minor
        {
            return Err(LinkError::ProtocolMinorIncompatible {
                local_minor: self.local_protocol.minor,
                remote_min: hello.minimum_minor,
                remote_max: hello.maximum_minor,
            });
        }

        if let Some(active) = self.current.get(&hello.node_id) {
            let current_generation = active.node_generation.value();
            let requested_generation = hello.node_generation.value();
            if requested_generation < current_generation {
                return Err(LinkError::StaleNodeGeneration {
                    current: current_generation,
                    requested: requested_generation,
                });
            }
            if requested_generation == current_generation {
                let current_epoch = active.connection_epoch.value();
                let requested_epoch = hello.connection_epoch.value();
                if requested_epoch <= current_epoch {
                    return Err(LinkError::StaleConnectionEpoch {
                        current: current_epoch,
                        requested: requested_epoch,
                    });
                }
            }
        }

        let binding = SessionBinding {
            node_id: hello.node_id,
            node_generation: hello.node_generation,
            connection_epoch: hello.connection_epoch,
            enrollment_ref: hello.enrollment_ref.clone(),
            credential_fingerprint,
            negotiated_protocol: self.local_protocol,
        };
        self.current.insert(hello.node_id, binding.clone());
        Ok(binding)
    }

    /// Recheck that a previously accepted binding is still the current authority.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::SupersededConnection`] when another Generation,
    /// epoch or credential has replaced/revoked this binding.
    pub fn assert_current(&self, binding: &SessionBinding) -> Result<(), LinkError> {
        if self.current.get(&binding.node_id) == Some(binding) {
            Ok(())
        } else {
            Err(LinkError::SupersededConnection)
        }
    }

    /// Fence any currently active session authenticated by one revoked credential.
    pub fn revoke_credential(&mut self, fingerprint: &CredentialFingerprint) {
        self.current
            .retain(|_, binding| &binding.credential_fingerprint != fingerprint);
    }

    /// Return the current accepted session for one stable Node identity.
    #[must_use]
    pub fn current(&self, node_id: NodeId) -> Option<&SessionBinding> {
        self.current.get(&node_id)
    }
}
