#![forbid(unsafe_code)]
//! A05 Provider identity, revision, generation and local-instance runtime contracts.
//!
//! Backend process identifiers remain aliases/evidence and never become canonical
//! Ptah identities.

use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Frozen Provider schema identity.
pub const PROVIDER_SCHEMA_ID: &str = "urn:ptah:schema:runtime:provider:0.1.0";
/// Frozen Provider Revision schema identity.
pub const PROVIDER_REVISION_SCHEMA_ID: &str = "urn:ptah:schema:runtime:provider-revision:0.1.0";
/// Frozen Provider Instance schema identity.
pub const PROVIDER_INSTANCE_SCHEMA_ID: &str = "urn:ptah:schema:runtime:provider-instance:0.1.0";

/// Provider API validation failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// A positive generation was required.
    #[error("provider generation must be positive")]
    InvalidGeneration,
    /// A required string field was empty.
    #[error("required provider field is empty: {0}")]
    EmptyField(&'static str),
    /// The Provider kind is not suitable for this operation.
    #[error("provider kind mismatch")]
    ProviderKindMismatch,
    /// A local Provider instance omitted Node binding evidence.
    #[error("local provider instance requires node identity and generation")]
    MissingNodeBinding,
    /// A required Provider revision/capability field is absent.
    #[error("required provider evidence is missing: {0}")]
    MissingEvidence(&'static str),
    /// Generation arithmetic overflowed.
    #[error("provider generation overflow")]
    GenerationOverflow,
}

/// Frozen Provider kind vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Workspace Provider.
    Workspace,
    /// Native or delegated process Provider.
    Process,
    /// OCI runtime Provider.
    OciRuntime,
    /// Isolation runtime Provider.
    IsolationRuntime,
    /// Storage Provider.
    Storage,
    /// Transfer Provider.
    Transfer,
    /// Build Provider.
    Build,
    /// Browser Provider.
    Browser,
    /// Application Provider.
    Application,
    /// Device Provider.
    Device,
    /// Display Provider.
    Display,
    /// Semantic UI Provider.
    SemanticUi,
    /// Knowledge Provider.
    Knowledge,
    /// Data Provider.
    Data,
    /// Plugin runtime Provider.
    PluginRuntime,
    /// Scheduler Provider.
    Scheduler,
    /// Security scanner Provider.
    SecurityScanner,
    /// Reproduction Provider.
    Reproduction,
}

/// Frozen Provider reachability projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderReachability {
    /// Reachability has not been established.
    Unknown,
    /// Current evidence shows the Provider is reachable.
    Reachable,
    /// Current evidence shows the Provider is unreachable.
    Unreachable,
    /// Reachability evidence is stale.
    Stale,
}

/// Frozen Provider readiness projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderReadiness {
    /// Readiness has not been established.
    Unknown,
    /// Provider is not ready.
    NotReady,
    /// Provider is ready.
    Ready,
}

/// Frozen Provider health projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderHealth {
    /// Health has not been established.
    Unknown,
    /// Provider is healthy.
    Healthy,
    /// Provider is degraded but usable subject to limitations.
    Degraded,
    /// Provider is unhealthy.
    Unhealthy,
}

/// Positive Provider generation used to fence stale handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderGeneration(u64);

impl ProviderGeneration {
    /// Construct a positive Provider generation.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::InvalidGeneration`] when `value` is zero.
    pub fn new(value: u64) -> Result<Self, ProviderError> {
        if value == 0 {
            return Err(ProviderError::InvalidGeneration);
        }
        Ok(Self(value))
    }

    /// Return the numeric generation.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Advance to the next generation.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::GenerationOverflow`] on integer overflow.
    pub fn next(self) -> Result<Self, ProviderError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(ProviderError::GenerationOverflow)
    }
}

/// Frozen endpoint-alias vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointAliasType {
    /// Hostname alias.
    Hostname,
    /// IP address alias.
    Ip,
    /// URL alias.
    Url,
    /// Socket alias.
    Socket,
    /// Service-name alias.
    ServiceName,
    /// Operating-system process identifier alias.
    ProcessId,
    /// Container identifier alias.
    ContainerId,
    /// Virtual-machine identifier alias.
    VmId,
    /// Cloud instance identifier alias.
    CloudInstanceId,
    /// Contract-compatible alias outside the narrower vocabulary.
    Other,
}

/// Evidence/alias attached to a Provider instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointAlias {
    /// Alias class.
    pub alias_type: EndpointAliasType,
    /// Alias value. It is never a canonical Ptah identity.
    pub value: String,
    /// Scope in which the alias was observed.
    pub scope: String,
    /// Observation time.
    pub observed_at: String,
    /// Optional evidence-expiry time.
    pub valid_until: Option<String>,
}

impl EndpointAlias {
    /// Construct a process-ID alias without changing canonical identity.
    #[must_use]
    pub fn process_id(pid: u32, observed_at: impl Into<String>) -> Self {
        Self {
            alias_type: EndpointAliasType::ProcessId,
            value: pid.to_string(),
            scope: "host_process_table".to_owned(),
            observed_at: observed_at.into(),
            valid_until: None,
        }
    }
}

/// Exact Provider revision evidence consumed by A05.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRevision {
    /// Canonical Provider Revision reference.
    pub revision_ref: EntityRef,
    /// Canonical logical Provider reference.
    pub provider_ref: EntityRef,
    /// Frozen Provider kind.
    pub provider_kind: ProviderKind,
    /// Implementation/package name.
    pub implementation_name: String,
    /// Exact implementation version.
    pub implementation_version: String,
    /// Exact build or package digest.
    pub build_or_package_digest: String,
    /// Exact configuration digest.
    pub configuration_digest: String,
    /// Frozen facility/contract ranges supported by this revision.
    pub supported_facility_refs: Vec<EntityRef>,
    /// Capability evidence refs.
    pub capability_claim_refs: Vec<EntityRef>,
    /// Dependency evidence refs.
    pub dependency_refs: Vec<EntityRef>,
    /// Human-readable Node requirements.
    pub node_requirements: Vec<String>,
    /// Human-readable security requirements.
    pub security_requirements: Vec<String>,
    /// Retained known limitations.
    pub known_limitations: Vec<String>,
}

impl ProviderRevision {
    /// Validate the frozen minimum evidence needed for a process Provider revision.
    ///
    /// # Errors
    ///
    /// Returns a [`ProviderError`] when the revision is not a process Provider or
    /// mandatory package/configuration/facility evidence is absent.
    pub fn validate_process(&self) -> Result<(), ProviderError> {
        if self.provider_kind != ProviderKind::Process {
            return Err(ProviderError::ProviderKindMismatch);
        }
        require_text(&self.implementation_name, "implementation_name")?;
        require_text(&self.implementation_version, "implementation_version")?;
        require_text(&self.build_or_package_digest, "build_or_package_digest")?;
        require_text(&self.configuration_digest, "configuration_digest")?;
        if self.supported_facility_refs.is_empty() {
            return Err(ProviderError::MissingEvidence("supported_facility_refs"));
        }
        Ok(())
    }
}

/// Exact local Provider instance evidence consumed by attempts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderInstance {
    /// Canonical Provider Instance reference.
    pub instance_ref: EntityRef,
    /// Exact Provider Revision reference.
    pub provider_revision_ref: EntityRef,
    /// Exact Node reference hosting this local Provider.
    pub node_ref: EntityRef,
    /// Node generation hosting this local Provider.
    pub node_generation: u64,
    /// Current Provider generation.
    pub provider_generation: ProviderGeneration,
    /// Current connection epoch.
    pub connection_epoch: u64,
    /// Reachability projection.
    pub reachability: ProviderReachability,
    /// Readiness projection.
    pub readiness: ProviderReadiness,
    /// Health projection.
    pub health: ProviderHealth,
    /// Backend endpoint aliases/evidence.
    pub endpoint_aliases: Vec<EndpointAlias>,
    /// Canonical process/service references owned by this instance.
    pub process_or_service_refs: Vec<EntityRef>,
    /// Observations supporting the current instance state.
    pub observation_refs: Vec<EntityRef>,
    /// Start time.
    pub started_at: String,
    /// Retained current limitations.
    pub limitations: Vec<String>,
}

impl ProviderInstance {
    /// Validate local process-Provider instance evidence.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::MissingNodeBinding`] for a zero Node generation,
    /// [`ProviderError::MissingEvidence`] when no observation exists, or
    /// [`ProviderError::EmptyField`] for an empty start timestamp.
    pub fn validate_local_process(&self) -> Result<(), ProviderError> {
        if self.node_generation == 0 {
            return Err(ProviderError::MissingNodeBinding);
        }
        require_text(&self.started_at, "started_at")?;
        if self.observation_refs.is_empty() {
            return Err(ProviderError::MissingEvidence("observation_refs"));
        }
        Ok(())
    }
}

/// Immutable execution-facing Provider context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderContext {
    /// Canonical logical Provider reference.
    pub provider_ref: EntityRef,
    /// Exact Provider Revision reference.
    pub provider_revision_ref: EntityRef,
    /// Exact Provider Instance reference.
    pub provider_instance_ref: EntityRef,
    /// Exact Provider generation.
    pub provider_generation: ProviderGeneration,
    /// Exact Node reference.
    pub node_ref: EntityRef,
    /// Exact Node generation.
    pub node_generation: u64,
    /// Exact Provider control connection epoch.
    pub connection_epoch: u64,
    /// Exact implementation version.
    pub implementation_version: String,
}

impl ProviderContext {
    /// Build execution context after validating the matching revision/instance pair.
    ///
    /// # Errors
    ///
    /// Returns a [`ProviderError`] when the revision or instance is invalid or
    /// their revision reference does not match.
    pub fn from_process(
        revision: &ProviderRevision,
        instance: &ProviderInstance,
    ) -> Result<Self, ProviderError> {
        revision.validate_process()?;
        instance.validate_local_process()?;
        if instance.provider_revision_ref != revision.revision_ref {
            return Err(ProviderError::MissingEvidence(
                "instance/provider revision match",
            ));
        }
        Ok(Self {
            provider_ref: revision.provider_ref.clone(),
            provider_revision_ref: revision.revision_ref.clone(),
            provider_instance_ref: instance.instance_ref.clone(),
            provider_generation: instance.provider_generation,
            node_ref: instance.node_ref.clone(),
            node_generation: instance.node_generation,
            connection_epoch: instance.connection_epoch,
            implementation_version: revision.implementation_version.clone(),
        })
    }
}

fn require_text(value: &str, field: &'static str) -> Result<(), ProviderError> {
    if value.trim().is_empty() {
        return Err(ProviderError::EmptyField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(kind: &str) -> EntityRef {
        EntityRef::new(kind).expect("valid ref")
    }

    fn revision() -> ProviderRevision {
        ProviderRevision {
            revision_ref: reference("runtime.provider_revision"),
            provider_ref: reference("runtime.provider"),
            provider_kind: ProviderKind::Process,
            implementation_name: "native-process".to_owned(),
            implementation_version: "0.1.0".to_owned(),
            build_or_package_digest: "sha256:abcd".to_owned(),
            configuration_digest: "sha256:efgh".to_owned(),
            supported_facility_refs: vec![reference("runtime.facility")],
            capability_claim_refs: Vec::new(),
            dependency_refs: Vec::new(),
            node_requirements: Vec::new(),
            security_requirements: Vec::new(),
            known_limitations: Vec::new(),
        }
    }

    #[test]
    fn generation_is_positive_and_monotonic() {
        assert_eq!(
            ProviderGeneration::new(0),
            Err(ProviderError::InvalidGeneration)
        );
        let first = ProviderGeneration::new(1).expect("generation");
        assert_eq!(first.next().expect("next").value(), 2);
    }

    #[test]
    fn process_id_is_alias_not_provider_identity() {
        let alias = EndpointAlias::process_id(4242, "2026-08-17T00:00:00Z");
        assert_eq!(alias.alias_type, EndpointAliasType::ProcessId);
        assert_eq!(alias.value, "4242");
        assert_ne!(alias.value, revision().provider_ref.entity_id.to_string());
    }

    #[test]
    fn context_requires_exact_revision_match() {
        let revision = revision();
        let instance = ProviderInstance {
            instance_ref: reference("runtime.provider_instance"),
            provider_revision_ref: reference("runtime.provider_revision"),
            node_ref: reference("core.node"),
            node_generation: 1,
            provider_generation: ProviderGeneration::new(1).expect("generation"),
            connection_epoch: 1,
            reachability: ProviderReachability::Reachable,
            readiness: ProviderReadiness::Ready,
            health: ProviderHealth::Healthy,
            endpoint_aliases: Vec::new(),
            process_or_service_refs: Vec::new(),
            observation_refs: vec![reference("proof.evidence")],
            started_at: "2026-08-17T00:00:00Z".to_owned(),
            limitations: Vec::new(),
        };
        assert!(matches!(
            ProviderContext::from_process(&revision, &instance),
            Err(ProviderError::MissingEvidence(_))
        ));
    }
}
