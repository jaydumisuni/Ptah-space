use crate::D04Error;
use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};

/// One observed non-authoritative service-registration projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRegistration {
    /// Exact service-registration identity/evidence handle.
    pub registration_ref: EntityRef,
    /// Stable namespaced service key.
    pub service_key: String,
    /// Exact Provider Revision producing this evidence.
    pub provider_revision_ref: EntityRef,
    /// Exact live Provider Instance.
    pub provider_instance_ref: EntityRef,
    /// Exact Provider generation observed with this registration.
    pub provider_generation: u64,
    /// Provider-defined mechanical freshness token.
    pub freshness_token: String,
    /// Non-authoritative endpoint alias.
    pub endpoint_alias: String,
    /// Exact observation time.
    pub observed_at: String,
    /// Optional exact expiry time.
    pub expires_at: Option<String>,
    /// Exact mechanically advertised Capability refs.
    pub capability_refs: Vec<EntityRef>,
    /// Explicit limitations.
    pub limitations: Vec<String>,
}

impl ServiceRegistration {
    fn validate(&self) -> Result<(), D04Error> {
        if self.service_key.trim().is_empty()
            || self.provider_generation == 0
            || self.freshness_token.trim().is_empty()
            || self.endpoint_alias.trim().is_empty()
            || !strict_utc(&self.observed_at)
            || self
                .expires_at
                .as_deref()
                .is_some_and(|value| !strict_utc(value))
        {
            return Err(D04Error::InvalidServiceRegistration(
                "service fields".to_owned(),
            ));
        }
        if self
            .expires_at
            .as_deref()
            .is_some_and(|expires| expires <= self.observed_at.as_str())
        {
            return Err(D04Error::InvalidServiceRegistration(
                "service expiry".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Exact service lookup result without semantic ranking or Provider selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceResolution {
    candidates: Vec<ServiceRegistration>,
}

impl ServiceResolution {
    /// Return all exact current live candidates in registration order.
    #[must_use]
    pub fn candidates(&self) -> &[ServiceRegistration] {
        &self.candidates
    }

    /// Whether more than one exact candidate remains unresolved.
    #[must_use]
    pub fn is_ambiguous(&self) -> bool {
        self.candidates.len() > 1
    }
}

/// Derived in-memory service registry; never an exposure or execution authority.
#[derive(Debug, Default)]
pub struct ServiceRegistry {
    services: Vec<ServiceRegistration>,
}

impl ServiceRegistry {
    /// Retain one service observation only when its Provider generation is current.
    ///
    /// # Errors
    /// Returns [`D04Error`] for malformed evidence or stale Provider generation.
    pub fn register(
        &mut self,
        registration: ServiceRegistration,
        current_provider_generation: u64,
    ) -> Result<(), D04Error> {
        registration.validate()?;
        if registration.provider_generation != current_provider_generation {
            return Err(D04Error::StaleProviderGeneration {
                expected: current_provider_generation,
                observed: registration.provider_generation,
            });
        }
        self.services.push(registration);
        Ok(())
    }

    /// Resolve exact current live service candidates without ranking or fallback.
    ///
    /// # Errors
    /// Returns [`D04Error`] when no exact live candidate remains.
    pub fn resolve(
        &self,
        service_key: &str,
        provider_instance_ref: &EntityRef,
        current_provider_generation: u64,
        observed_at: &str,
    ) -> Result<ServiceResolution, D04Error> {
        if !strict_utc(observed_at) {
            return Err(D04Error::InvalidServiceRegistration(
                "resolution time".to_owned(),
            ));
        }
        let candidates = self
            .services
            .iter()
            .filter(|registration| registration.service_key == service_key)
            .filter(|registration| registration.provider_instance_ref == *provider_instance_ref)
            .filter(|registration| registration.provider_generation == current_provider_generation)
            .filter(|registration| {
                registration
                    .expires_at
                    .as_deref()
                    .is_none_or(|expires| observed_at <= expires)
            })
            .cloned()
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err(D04Error::ServiceUnavailable {
                service_key: service_key.to_owned(),
            });
        }
        Ok(ServiceResolution { candidates })
    }
}

/// Port protocol retained as mechanical observation metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortProtocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
}

/// One observed port registration. It is not network-exposure authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRegistration {
    /// Exact port-registration evidence identity.
    pub registration_ref: EntityRef,
    /// Exact service registration associated with this observation.
    pub service_registration_ref: EntityRef,
    /// Observed transport protocol.
    pub protocol: PortProtocol,
    /// Observed port number.
    pub port: u16,
    /// Non-authoritative endpoint alias.
    pub endpoint_alias: String,
    /// Exact Policy refs governing exposure.
    pub exposure_policy_refs: Vec<EntityRef>,
    /// Exact current Grant refs governing exposure.
    pub exposure_grant_refs: Vec<EntityRef>,
    /// Exact observation time.
    pub observed_at: String,
    /// Optional exact expiry time.
    pub expires_at: Option<String>,
}

impl PortRegistration {
    /// Validate structural evidence and require separately authoritative Policy+Grant refs.
    ///
    /// # Errors
    /// Returns [`D04Error`] for malformed port evidence or missing Policy/Grant refs.
    pub fn validate(&self) -> Result<(), D04Error> {
        if self.exposure_policy_refs.is_empty() || self.exposure_grant_refs.is_empty() {
            return Err(D04Error::ExposureAuthorityMissing);
        }
        if self.port == 0
            || self.endpoint_alias.trim().is_empty()
            || !strict_utc(&self.observed_at)
            || self
                .expires_at
                .as_deref()
                .is_some_and(|value| !strict_utc(value))
        {
            return Err(D04Error::InvalidServiceRegistration(
                "port fields".to_owned(),
            ));
        }
        Ok(())
    }

    /// Port observation never creates or widens network exposure authority.
    #[must_use]
    pub const fn grants_network_exposure(&self) -> bool {
        false
    }
}

/// D04-owned projection of existing container network authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerNetworkScope {
    /// No host-network exposure.
    Isolated,
    /// Host-network exposure under one exact existing Grant.
    Host {
        /// Exact current Grant authorizing this scope.
        grant_ref: EntityRef,
    },
}

/// D04-owned projection of mount access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerMountAccess {
    /// Read-only mount access.
    ReadOnly,
    /// Read/write mount access.
    ReadWrite,
}

/// D04-owned projection of one exact pre-authorized mount scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerMountScope {
    /// Host source alias from the existing authority envelope.
    pub source_alias: String,
    /// Container destination path.
    pub destination: String,
    /// Maximum admitted access.
    pub access: ContainerMountAccess,
    /// Exact current filesystem Grant.
    pub grant_ref: EntityRef,
}

/// D04-owned projection of the exact A10 network/mount authority envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerAuthorityScope {
    /// Exact admitted network scope.
    pub network: ContainerNetworkScope,
    /// Exact admitted mount scopes.
    pub mounts: Vec<ContainerMountScope>,
}

/// Verify a requested container scope does not widen the existing authority envelope.
///
/// # Errors
/// Returns [`D04Error::AuthorityWidening`] if network or mount scope exceeds the baseline.
pub fn validate_container_authority(
    baseline: &ContainerAuthorityScope,
    requested: &ContainerAuthorityScope,
) -> Result<(), D04Error> {
    let requested = crate::adapters::a10::normalize_authority(requested);
    match (&baseline.network, &requested.network) {
        (_, ContainerNetworkScope::Isolated) => {}
        (
            ContainerNetworkScope::Host { grant_ref: allowed },
            ContainerNetworkScope::Host {
                grant_ref: requested,
            },
        ) if allowed == requested => {}
        _ => {
            return Err(D04Error::AuthorityWidening {
                reason: "network".to_owned(),
            });
        }
    }
    for requested_mount in &requested.mounts {
        let allowed = baseline.mounts.iter().any(|baseline_mount| {
            baseline_mount.grant_ref == requested_mount.grant_ref
                && baseline_mount.source_alias == requested_mount.source_alias
                && baseline_mount.destination == requested_mount.destination
                && access_allows(baseline_mount.access, requested_mount.access)
        });
        if !allowed {
            return Err(D04Error::AuthorityWidening {
                reason: "mount".to_owned(),
            });
        }
    }
    Ok(())
}

const fn access_allows(allowed: ContainerMountAccess, requested: ContainerMountAccess) -> bool {
    matches!(
        (allowed, requested),
        (ContainerMountAccess::ReadWrite, _)
            | (
                ContainerMountAccess::ReadOnly,
                ContainerMountAccess::ReadOnly
            )
    )
}

fn strict_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
}
