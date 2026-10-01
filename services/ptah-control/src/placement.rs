use crate::node_link::NodeLinkControl;
use ptah_identifiers::{EntityRef, NodeId};
use ptah_node_agent::{NodeCapabilitySnapshot, NodeResourceSnapshot, NodeStateProjection};
use ptah_node_link::{CredentialFingerprint, LinkError, NodeHello, SessionBinding};
use ptah_placement_runtime::{
    AuthorityBinding, AuthorityError, DispatchAuthority, Lease, LeaseError, LeaseRegistry,
    PlacementMetadata, PlacementPolicy, PlacementRequirement, Reservation, ReservationError,
    ReservationRegistry, ReservedResource, authorize_dispatch, evaluate_candidate,
    select_candidate,
};
use ptah_platform_admission::{
    PlatformAdmissionDecision, PlatformAdmissionProfile, PlatformAdmissionRejection,
    PlatformNodeClass, evaluate_platform_admission,
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
    /// E05-specific placement requires a current matching platform admission.
    PlatformAdmissionRequired,
    /// Exact E01/A02 evidence failed the pure E05 platform-admission policy.
    PlatformAdmission(PlatformAdmissionRejection),
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

impl From<PlatformAdmissionRejection> for PlacementControlError {
    fn from(value: PlatformAdmissionRejection) -> Self {
        Self::PlatformAdmission(value)
    }
}

/// Exact timing window used when E02 mints Reservation and Lease authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlacementAuthorityTiming {
    now: u64,
    reservation_expires_at: u64,
    lease_expires_at: u64,
}

impl PlacementAuthorityTiming {
    /// Construct one explicit authority timing window.
    #[must_use]
    pub const fn new(
        now_unix_seconds: u64,
        reservation_expires_at_unix_seconds: u64,
        lease_expires_at_unix_seconds: u64,
    ) -> Self {
        Self {
            now: now_unix_seconds,
            reservation_expires_at: reservation_expires_at_unix_seconds,
            lease_expires_at: lease_expires_at_unix_seconds,
        }
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
struct StoredPlatformAdmission {
    state: NodeStateProjection,
    profile: PlatformAdmissionProfile,
    decision: PlatformAdmissionDecision,
}

#[derive(Debug, Clone)]
struct NodePlacementState {
    session: SessionBinding,
    capabilities: Option<NodeCapabilitySnapshot>,
    resources: Option<NodeResourceSnapshot>,
    platform_admission: Option<StoredPlatformAdmission>,
    reservations: Option<ReservationRegistry>,
}

impl NodePlacementState {
    fn new(session: SessionBinding) -> Self {
        Self {
            session,
            capabilities: None,
            resources: None,
            platform_admission: None,
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
        let binding =
            self.node_link
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
    /// Propagates E01 supersession and snapshot-binding failures. A current E01
    /// binding unknown to this owner is rejected rather than creating implicit state.
    pub fn accept_capability(
        &mut self,
        binding: &SessionBinding,
        snapshot: &NodeCapabilitySnapshot,
    ) -> Result<(), LinkError> {
        self.node_link.accept_capability(binding, snapshot)?;
        let Some(state) = self.state_mut(binding) else {
            return Err(LinkError::SupersededConnection);
        };
        state.capabilities = Some(snapshot.clone());
        state.platform_admission = None;
        Ok(())
    }

    /// Accept resource evidence only for the exact current E01 session.
    ///
    /// # Errors
    ///
    /// Propagates E01 supersession and snapshot-binding failures. A current E01
    /// binding unknown to this owner is rejected rather than creating implicit state.
    pub fn accept_resource(
        &mut self,
        binding: &SessionBinding,
        snapshot: &NodeResourceSnapshot,
    ) -> Result<(), LinkError> {
        self.node_link.accept_resource(binding, snapshot)?;
        let Some(state) = self.state_mut(binding) else {
            return Err(LinkError::SupersededConnection);
        };
        state.resources = Some(snapshot.clone());
        Ok(())
    }

    /// Evaluate and retain E05 admission for one exact current E01/A02 binding.
    ///
    /// This method returns only non-authoritative admission evidence. It cannot
    /// allocate an E02 Reservation, Lease, Fence or dispatch authority.
    ///
    /// # Errors
    ///
    /// Returns a superseded-session error when the E01 binding is no longer
    /// current, a platform-admission-required error when current capability
    /// evidence is absent, or a typed E05 policy rejection.
    pub fn admit_platform_node(
        &mut self,
        binding: &SessionBinding,
        node_state: &NodeStateProjection,
        profile: &PlatformAdmissionProfile,
    ) -> Result<PlatformAdmissionDecision, PlacementControlError> {
        let Some(current) = self.node_link.current_session(binding.node_id) else {
            return Err(PlacementControlError::SupersededSession);
        };
        if current != binding {
            return Err(PlacementControlError::SupersededSession);
        }

        let Some(index) = self
            .nodes
            .iter()
            .position(|state| state.session == *binding)
        else {
            return Err(PlacementControlError::SupersededSession);
        };
        let capabilities = self.nodes[index]
            .capabilities
            .as_ref()
            .ok_or(PlacementControlError::PlatformAdmissionRequired)?;
        let decision = evaluate_platform_admission(binding, node_state, capabilities, profile)?;

        self.nodes[index].platform_admission = Some(StoredPlatformAdmission {
            state: node_state.clone(),
            profile: profile.clone(),
            decision: decision.clone(),
        });
        Ok(decision)
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
        self.place_and_issue_inner(
            None,
            requirement,
            policy,
            reserved_resources,
            PlacementAuthorityTiming::new(
                now_unix_seconds,
                reservation_expires_at_unix_seconds,
                lease_expires_at_unix_seconds,
            ),
        )
    }

    /// Select only a current E05-admitted platform Node, then delegate authority
    /// allocation to the unchanged E02 Reservation/Lease/Fence machinery.
    ///
    /// # Errors
    ///
    /// Returns a platform-admission-required error when no current exact
    /// admission exists for the requested class. Once an admitted candidate
    /// exists, ordinary E02 eligibility and authority errors remain unchanged.
    pub fn place_admitted_and_issue(
        &mut self,
        platform_class: PlatformNodeClass,
        requirement: &PlacementRequirement,
        policy: PlacementPolicy,
        reserved_resources: Vec<ReservedResource>,
        timing: PlacementAuthorityTiming,
    ) -> Result<PlacementGrant, PlacementControlError> {
        self.place_and_issue_inner(
            Some(platform_class),
            requirement,
            policy,
            reserved_resources,
            timing,
        )
    }

    fn place_and_issue_inner(
        &mut self,
        required_platform: Option<PlatformNodeClass>,
        requirement: &PlacementRequirement,
        policy: PlacementPolicy,
        reserved_resources: Vec<ReservedResource>,
        timing: PlacementAuthorityTiming,
    ) -> Result<PlacementGrant, PlacementControlError> {
        let selected_index = self.select_eligible_index(required_platform, requirement, policy)?;
        self.issue_selected(selected_index, requirement, reserved_resources, timing)
    }

    fn select_eligible_index(
        &self,
        required_platform: Option<PlatformNodeClass>,
        requirement: &PlacementRequirement,
        policy: PlacementPolicy,
    ) -> Result<usize, PlacementControlError> {
        let has_matching_admission = required_platform.is_some_and(|platform_class| {
            self.nodes.iter().any(|state| {
                self.node_link
                    .current_session(state.session.node_id)
                    .is_some_and(|current| current == &state.session)
                    && platform_admission_matches(state, platform_class)
            })
        });

        let candidates = self.nodes.iter().filter_map(|state| {
            let current = self.node_link.current_session(state.session.node_id)?;
            if current != &state.session {
                return None;
            }
            if required_platform
                .is_some_and(|platform_class| !platform_admission_matches(state, platform_class))
            {
                return None;
            }
            let capabilities = state.capabilities.as_ref()?;
            let resources = state.resources.as_ref()?;
            evaluate_candidate(&state.session, capabilities, resources, requirement, policy).ok()
        });
        let selected = select_candidate(candidates).ok_or_else(|| {
            if required_platform.is_some() && !has_matching_admission {
                PlacementControlError::PlatformAdmissionRequired
            } else {
                PlacementControlError::NoEligibleNode
            }
        })?;

        self.nodes
            .iter()
            .position(|state| {
                state.session.node_id == selected.node_id()
                    && state.session.node_generation == selected.node_generation()
                    && state.session.connection_epoch == selected.connection_epoch()
            })
            .ok_or(PlacementControlError::NoEligibleNode)
    }

    fn issue_selected(
        &mut self,
        selected_index: usize,
        requirement: &PlacementRequirement,
        reserved_resources: Vec<ReservedResource>,
        timing: PlacementAuthorityTiming,
    ) -> Result<PlacementGrant, PlacementControlError> {
        let state = &mut self.nodes[selected_index];
        let resources = state
            .resources
            .as_ref()
            .ok_or(PlacementControlError::NoEligibleNode)?
            .clone();
        if state.reservations.is_none() {
            state.reservations = Some(ReservationRegistry::new(&state.session, &resources)?);
        }
        let Some(registry) = state.reservations.as_mut() else {
            return Err(PlacementControlError::NoEligibleNode);
        };
        let binding = AuthorityBinding::new(
            requirement.attempt_ref().clone(),
            state.session.node_id,
            state.session.node_generation,
            state.session.connection_epoch,
        );
        let reservation_ref = EntityRef::new("resource.reservation")
            .map_err(|_| PlacementControlError::InvalidIdentifier)?;
        let reservation = registry.reserve(
            reservation_ref,
            binding.clone(),
            resources.snapshot_ref.clone(),
            reserved_resources,
            timing.now,
            timing.reservation_expires_at,
        )?;
        let reservation_record = registry
            .reservation(reservation.reservation_ref())
            .cloned()
            .ok_or(PlacementControlError::Reservation(
                ReservationError::UnknownReservation,
            ))?;

        let lease_ref = EntityRef::new("isolation.lease")
            .map_err(|_| PlacementControlError::InvalidIdentifier)?;
        let lease = match self.leases.issue(
            &reservation_record,
            lease_ref,
            timing.now,
            timing.lease_expires_at,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                let _ = registry.revoke(reservation.reservation_ref());
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
            timing.now,
        ) {
            Ok(authority) => authority,
            Err(error) => {
                let _ = self.leases.revoke(lease.lease_ref());
                let _ = registry.revoke(reservation.reservation_ref());
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
        self.leases
            .validate_current(grant.lease(), now_unix_seconds)?;
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

    fn state_mut(&mut self, binding: &SessionBinding) -> Option<&mut NodePlacementState> {
        self.nodes
            .iter_mut()
            .find(|state| state.session == *binding)
    }
}

fn platform_admission_matches(
    state: &NodePlacementState,
    platform_class: PlatformNodeClass,
) -> bool {
    let Some(capabilities) = state.capabilities.as_ref() else {
        return false;
    };
    let Some(stored) = state.platform_admission.as_ref() else {
        return false;
    };
    if stored.profile.platform_class() != platform_class
        || !stored
            .decision
            .matches(&state.session, capabilities, platform_class)
    {
        return false;
    }

    evaluate_platform_admission(&state.session, &stored.state, capabilities, &stored.profile)
        .is_ok_and(|decision| decision == stored.decision)
}
