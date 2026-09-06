use crate::node_link::NodeLinkControl;
use ptah_identifiers::{EntityRef, NodeId};
use ptah_node_agent::{NodeCapabilitySnapshot, NodeResourceSnapshot};
use ptah_node_link::{CredentialFingerprint, LinkError, NodeHello, SessionBinding};
use ptah_placement_runtime::{
    AuthorityBinding, AuthorityError, DispatchAuthority, Lease, LeaseError, LeaseRegistry,
    PlacementMetadata, PlacementPolicy, PlacementRequirement, Reservation, ReservationError,
    ReservationRegistry, ReservedResource, authorize_dispatch, evaluate_candidate,
    select_candidate,
};

/// Stable failures from the control-plane E02 authority owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementControlError {
    /// No current Node satisfied all hard placement requirements.
    NoEligibleNode,
    /// A canonical E02 entity reference could not be allocated.
    InvalidIdentifier,
    /// Reservation admission/accounting failed.
    Reservation(ReservationError),
    /// Lease/Fence issuance or currentness validation failed.
    Lease(LeaseError),
    /// Final dispatch-authority validation failed.
    Authority(AuthorityError),
    /// The E01 session carried by an existing grant is no longer current.
    SupersededSession,
}

impl From<ReservationError> for PlacementControlError {
    fn from(value: ReservationError) -> Self {
        Self::Reservation(value)
    }
}

impl From<LeaseError> for PlacementControlError {
    fn from(value: LeaseError) -> Self {
        Self::Lease(value)
    }
}

impl From<AuthorityError> for PlacementControlError {
    fn from(value: AuthorityError) -> Self {
        Self::Authority(value)
    }
}

/// One control-issued E02 execution authority grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementGrant {
    reservation: Reservation,
    lease: Lease,
    dispatch_authority: DispatchAuthority,
}

impl PlacementGrant {
    /// Selected canonical Node identity.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.dispatch_authority.binding().node_id()
    }

    /// Control-issued Reservation projection.
    #[must_use]
    pub const fn reservation(&self) -> &Reservation {
        &self.reservation
    }

    /// Control-issued current Lease/Fence projection.
    #[must_use]
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Fully validated dispatch authority.
    #[must_use]
    pub const fn dispatch_authority(&self) -> &DispatchAuthority {
        &self.dispatch_authority
    }
}

#[derive(Debug, Clone)]
struct NodePlacementState {
    session: SessionBinding,
    capabilities: Option<NodeCapabilitySnapshot>,
    resources: Option<NodeResourceSnapshot>,
    reservations: Option<ReservationRegistry>,
}

impl NodePlacementState {
    fn new(session: SessionBinding) -> Self {
        Self {
            session,
            capabilities: None,
            resources: None,
            reservations: None,
        }
    }
}

/// Sole control-plane owner for E02 placement, Reservation, Lease and Fence issuance.
#[derive(Debug)]
pub struct PlacementAuthorityOwner {
    node_link: NodeLinkControl,
    nodes: Vec<NodePlacementState>,
    leases: LeaseRegistry,
}

impl PlacementAuthorityOwner {
    /// Wrap the existing E01 secure-session authority with E02 placement ownership.
    #[must_use]
    pub fn new(node_link: NodeLinkControl) -> Self {
        Self {
            node_link,
            nodes: Vec::new(),
            leases: LeaseRegistry::new(),
        }
    }

    /// Accept one authenticated E01 hello and invalidate cached evidence from any
    /// superseded session for the same stable Node.
    ///
    /// # Errors
    ///
    /// Propagates E01 enrollment/protocol/replay/currentness failures.
    pub fn accept_hello(
        &mut self,
        hello: &NodeHello,
        credential_fingerprint: CredentialFingerprint,
        now_epoch_seconds: u64,
    ) -> Result<SessionBinding, LinkError> {
        let binding = self
            .node_link
            .accept_hello(hello, credential_fingerprint, now_epoch_seconds)?;
        self.nodes
            .retain(|state| state.session.node_id != binding.node_id || state.session == binding);
        if !self.nodes.iter().any(|state| state.session == binding) {
            self.nodes.push(NodePlacementState::new(binding.clone()));
        }
        Ok(binding)
    }

    /// Accept capability evidence only for the exact current E01 session.
    ///
    /// # Errors
    ///
    /// Propagates E01 supersession and snapshot-binding failures.
    pub fn accept_capability(
        &mut self,
        binding: &SessionBinding,
        snapshot: &NodeCapabilitySnapshot,
    ) -> Result<(), LinkError> {
        self.node_link.accept_capability(binding, snapshot)?;
        let state = self.state_mut(binding);
        state.capabilities = Some(snapshot.clone());
        Ok(())
    }

    /// Accept resource evidence only for the exact current E01 session.
    ///
    /// # Errors
    ///
    /// Propagates E01 supersession and snapshot-binding failures.
    pub fn accept_resource(
        &mut self,
        binding: &SessionBinding,
        snapshot: &NodeResourceSnapshot,
    ) -> Result<(), LinkError> {
        self.node_link.accept_resource(binding, snapshot)?;
        let state = self.state_mut(binding);
        state.resources = Some(snapshot.clone());
        Ok(())
    }

    /// Deterministically select one eligible current Node and mint its Reservation,
    /// Lease/Fence and dispatch authority. The API intentionally accepts no Fence
    /// input; Fence values can only originate from this owner's allocator.
    ///
    /// # Errors
    ///
    /// Returns [`PlacementControlError::NoEligibleNode`] when no current Node has
    /// complete admissible evidence, or a typed Reservation/Lease/authority error.
    pub fn place_and_issue(
        &mut self,
        requirement: &PlacementRequirement,
        policy: PlacementPolicy,
        reserved_resources: Vec<ReservedResource>,
        now_unix_seconds: u64,
        reservation_expires_at_unix_seconds: u64,
        lease_expires_at_unix_seconds: u64,
    ) -> Result<PlacementGrant, PlacementControlError> {
        let candidates = self.nodes.iter().filter_map(|state| {
            let current = self.node_link.current_session(state.session.node_id)?;
            if current != &state.session {
                return None;
            }
            let capabilities = state.capabilities.as_ref()?;
            let resources = state.resources.as_ref()?;
            evaluate_candidate(&state.session, capabilities, resources, requirement, policy).ok()
        });
        let selected = select_candidate(candidates).ok_or(PlacementControlError::NoEligibleNode)?;
        let selected_index = self
            .nodes
            .iter()
            .position(|state| {
                state.session.node_id == selected.node_id()
                    && state.session.node_generation == selected.node_generation()
                    && state.session.connection_epoch == selected.connection_epoch()
            })
            .ok_or(PlacementControlError::NoEligibleNode)?;

        let state = &mut self.nodes[selected_index];
        let resources = state
            .resources
            .as_ref()
            .ok_or(PlacementControlError::NoEligibleNode)?
            .clone();
        if state.reservations.is_none() {
            state.reservations = Some(ReservationRegistry::new(&state.session, &resources)?);
        }
        let binding = AuthorityBinding::new(
            requirement.attempt_ref().clone(),
            state.session.node_id,
            state.session.node_generation,
            state.session.connection_epoch,
        );
        let reservation_ref = EntityRef::new("resource.reservation")
            .map_err(|_| PlacementControlError::InvalidIdentifier)?;
        let reservation = state
            .reservations
            .as_mut()
            .expect("registry initialized above")
            .reserve(
                reservation_ref,
                binding.clone(),
                resources.snapshot_ref.clone(),
                reserved_resources,
                now_unix_seconds,
                reservation_expires_at_unix_seconds,
            )?;
        let reservation_record = state
            .reservations
            .as_ref()
            .and_then(|registry| registry.reservation(reservation.reservation_ref()))
            .cloned()
            .ok_or(PlacementControlError::Reservation(
                ReservationError::UnknownReservation,
            ))?;

        let lease_ref = EntityRef::new("isolation.lease")
            .map_err(|_| PlacementControlError::InvalidIdentifier)?;
        let lease = match self.leases.issue(
            &reservation_record,
            lease_ref,
            now_unix_seconds,
            lease_expires_at_unix_seconds,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                let _ = state
                    .reservations
                    .as_mut()
                    .expect("registry initialized above")
                    .revoke(reservation.reservation_ref());
                return Err(error.into());
            }
        };
        let placement = PlacementMetadata::new(binding.clone());
        let dispatch_authority = match authorize_dispatch(
            &placement,
            &reservation,
            Some(&lease),
            &binding,
            lease.fence(),
            now_unix_seconds,
        ) {
            Ok(authority) => authority,
            Err(error) => {
                let _ = self.leases.revoke(lease.lease_ref());
                let _ = state
                    .reservations
                    .as_mut()
                    .expect("registry initialized above")
                    .revoke(reservation.reservation_ref());
                return Err(error.into());
            }
        };
        Ok(PlacementGrant {
            reservation,
            lease,
            dispatch_authority,
        })
    }

    /// Revalidate an issued grant against current E01 session and current Lease/Fence.
    ///
    /// # Errors
    ///
    /// Any E01 supersession or Lease/Fence expiry/replay invalidates dispatch.
    pub fn validate_dispatch(
        &self,
        grant: &PlacementGrant,
        now_unix_seconds: u64,
    ) -> Result<(), PlacementControlError> {
        let binding = grant.dispatch_authority.binding();
        let Some(current) = self.node_link.current_session(binding.node_id()) else {
            return Err(PlacementControlError::SupersededSession);
        };
        if current.node_generation != binding.node_generation()
            || current.connection_epoch != binding.connection_epoch()
        {
            return Err(PlacementControlError::SupersededSession);
        }
        self.leases.validate_current(grant.lease(), now_unix_seconds)?;
        let placement = PlacementMetadata::new(binding.clone());
        authorize_dispatch(
            &placement,
            grant.reservation(),
            Some(grant.lease()),
            binding,
            grant.lease().fence(),
            now_unix_seconds,
        )?;
        Ok(())
    }

    fn state_mut(&mut self, binding: &SessionBinding) -> &mut NodePlacementState {
        if let Some(index) = self.nodes.iter().position(|state| state.session == *binding) {
            return &mut self.nodes[index];
        }
        self.nodes.push(NodePlacementState::new(binding.clone()));
        self.nodes
            .last_mut()
            .expect("state was inserted immediately above")
    }
}
