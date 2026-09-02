use ptah_identifiers::EntityRef;
use ptah_recipe_registry::{PortProtocol, PortRegistration};
use serde::{Deserialize, Serialize};

use crate::D05Error;

/// Exact Plugin Instance projection; runtime PIDs/handles remain aliases only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginInstanceRecord {
    /// Canonical Plugin Instance identity.
    pub instance_ref: EntityRef,
    /// Exact immutable Plugin Revision.
    pub plugin_revision_ref: EntityRef,
    /// Exact Plugin Activation.
    pub activation_ref: EntityRef,
    /// Exact Provider Instance.
    pub provider_instance_ref: EntityRef,
    /// Exact Provider generation.
    pub provider_generation: u64,
    /// Exact Plugin Instance generation.
    pub generation: u64,
    /// Backend process/handle aliases retained as non-authoritative metadata.
    pub runtime_aliases: Vec<String>,
}

/// Expiring Plugin health observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthObservation {
    /// Provider generation observed.
    pub provider_generation: u64,
    /// Plugin Instance generation observed.
    pub instance_generation: u64,
    /// Mechanical readiness observation.
    pub readiness: bool,
    /// Mechanical health label.
    pub health: String,
    /// Observation time in caller-supplied monotonic Unix seconds.
    pub observed_at_unix: i64,
    /// Observation expiry in Unix seconds.
    pub valid_until_unix: i64,
    /// Supporting evidence refs.
    pub evidence_refs: Vec<EntityRef>,
}

/// Current capability-Grant state used only for mechanical validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrantState {
    /// Canonical Plugin Capability Grant.
    pub grant_ref: EntityRef,
    /// Grant expiry in caller-supplied Unix seconds.
    pub expires_at_unix: i64,
    /// Whether governed revocation has occurred.
    pub revoked: bool,
}

/// Exact Plugin dependency binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyBinding {
    /// Exact Plugin Instance.
    pub plugin_instance_ref: EntityRef,
    /// Stable dependency key.
    pub dependency_key: String,
    /// Exact bound canonical reference.
    pub bound_ref: EntityRef,
    /// Bound Provider generation.
    pub provider_generation: u64,
    /// Bound Plugin Instance generation.
    pub instance_generation: u64,
    /// Binding expiry in Unix seconds.
    pub valid_until_unix: i64,
    /// Supporting evidence refs.
    pub evidence_refs: Vec<EntityRef>,
}

/// Exact Plugin service registration fenced by current capability Grants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginServiceRegistration {
    /// Canonical Plugin service registration.
    pub registration_ref: EntityRef,
    /// Exact Plugin Instance.
    pub plugin_instance_ref: EntityRef,
    /// Stable service key.
    pub service_key: String,
    /// Provider generation fence.
    pub provider_generation: u64,
    /// Plugin Instance generation fence.
    pub instance_generation: u64,
    /// Exact Plugin Capability Grant refs.
    pub capability_grant_refs: Vec<EntityRef>,
    /// Registration expiry in Unix seconds.
    pub valid_until_unix: i64,
    /// Supporting evidence refs.
    pub evidence_refs: Vec<EntityRef>,
}

/// Exact Plugin port registration. It is never exposure authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginPortRegistration {
    /// Canonical Plugin port registration.
    pub registration_ref: EntityRef,
    /// Exact Plugin Instance.
    pub plugin_instance_ref: EntityRef,
    /// Exact service registration.
    pub service_registration_ref: EntityRef,
    /// Provider generation fence.
    pub provider_generation: u64,
    /// Plugin Instance generation fence.
    pub instance_generation: u64,
    /// Declared network scope metadata.
    pub network_scope: String,
    /// Transport protocol string (`tcp` or `udp`).
    pub protocol: String,
    /// Requested/bound port number.
    pub requested_port: u16,
    /// Backend endpoint alias only.
    pub bound_endpoint_alias: String,
    /// Separate exposure-policy refs.
    pub exposure_policy_refs: Vec<EntityRef>,
    /// Exact Plugin Capability Grant refs.
    pub capability_grant_refs: Vec<EntityRef>,
    /// Registration expiry in Unix seconds.
    pub valid_until_unix: i64,
    /// Exact observation timestamp for D04 structural validation.
    pub observed_at: String,
}

impl PluginPortRegistration {
    /// A bound Plugin port never creates public/network exposure authority.
    #[must_use]
    pub const fn grants_network_exposure(&self) -> bool {
        false
    }
}

/// Mechanical Plugin runtime validation facade.
pub struct PluginRuntime;

impl PluginRuntime {
    /// Validate one health observation against current Provider/Instance generation and expiry.
    ///
    /// # Errors
    /// Returns [`D05Error::StalePluginRuntime`] when health is stale, malformed or generation-mismatched.
    pub fn validate_health(
        instance: &PluginInstanceRecord,
        health: &HealthObservation,
        now_unix: i64,
    ) -> Result<(), D05Error> {
        validate_instance(instance)?;
        if health.provider_generation != instance.provider_generation
            || health.instance_generation != instance.generation
            || health.observed_at_unix > now_unix
            || health.valid_until_unix <= now_unix
            || health.valid_until_unix <= health.observed_at_unix
            || health.health.trim().is_empty()
            || health.evidence_refs.is_empty()
        {
            return Err(D05Error::StalePluginRuntime);
        }
        Ok(())
    }

    /// Validate dependency binding generation and expiry fences.
    ///
    /// # Errors
    /// Returns [`D05Error::StalePluginRuntime`] when the binding is stale or mismatched.
    pub fn validate_binding(
        instance: &PluginInstanceRecord,
        binding: &DependencyBinding,
        now_unix: i64,
    ) -> Result<(), D05Error> {
        validate_instance(instance)?;
        if binding.plugin_instance_ref != instance.instance_ref
            || binding.provider_generation != instance.provider_generation
            || binding.instance_generation != instance.generation
            || binding.valid_until_unix <= now_unix
            || binding.dependency_key.trim().is_empty()
            || binding.evidence_refs.is_empty()
        {
            return Err(D05Error::StalePluginRuntime);
        }
        Ok(())
    }

    /// Validate service registration and all referenced capability Grants.
    ///
    /// # Errors
    /// Returns a stale-runtime or invalid-Grant error on any fence/revocation/expiry mismatch.
    pub fn validate_service(
        instance: &PluginInstanceRecord,
        service: &PluginServiceRegistration,
        grants: &[CapabilityGrantState],
        now_unix: i64,
    ) -> Result<(), D05Error> {
        validate_instance(instance)?;
        if service.registration_ref.entity_kind != "plugin.service_registration"
            || service.plugin_instance_ref != instance.instance_ref
            || service.provider_generation != instance.provider_generation
            || service.instance_generation != instance.generation
            || service.valid_until_unix <= now_unix
            || service.service_key.trim().is_empty()
            || service.evidence_refs.is_empty()
        {
            return Err(D05Error::StalePluginRuntime);
        }
        validate_grants(&service.capability_grant_refs, grants, now_unix)
    }

    /// Validate Plugin port structure, generation fences and capability Grants.
    ///
    /// # Errors
    /// Returns a D05 error for stale runtime, invalid Grants, or D04 structural rejection.
    pub fn validate_port(
        instance: &PluginInstanceRecord,
        port: &PluginPortRegistration,
        grants: &[CapabilityGrantState],
        now_unix: i64,
    ) -> Result<(), D05Error> {
        validate_instance(instance)?;
        if port.registration_ref.entity_kind != "plugin.port_registration"
            || port.plugin_instance_ref != instance.instance_ref
            || port.provider_generation != instance.provider_generation
            || port.instance_generation != instance.generation
            || port.valid_until_unix <= now_unix
            || port.network_scope.trim().is_empty()
        {
            return Err(D05Error::StalePluginRuntime);
        }
        validate_grants(&port.capability_grant_refs, grants, now_unix)?;
        let protocol = match port.protocol.as_str() {
            "tcp" => PortProtocol::Tcp,
            "udp" => PortProtocol::Udp,
            _ => return Err(D05Error::InvalidPluginRegistration),
        };
        let projected = PortRegistration {
            registration_ref: port.registration_ref.clone(),
            service_registration_ref: port.service_registration_ref.clone(),
            protocol,
            port: port.requested_port,
            endpoint_alias: port.bound_endpoint_alias.clone(),
            exposure_policy_refs: port.exposure_policy_refs.clone(),
            exposure_grant_refs: port.capability_grant_refs.clone(),
            observed_at: port.observed_at.clone(),
            expires_at: None,
        };
        projected
            .validate()
            .map_err(|_| D05Error::InvalidPluginRegistration)?;
        if projected.grants_network_exposure() {
            return Err(D05Error::InvalidPluginRegistration);
        }
        Ok(())
    }
}

fn validate_instance(instance: &PluginInstanceRecord) -> Result<(), D05Error> {
    if instance.instance_ref.entity_kind != "plugin.instance"
        || instance.plugin_revision_ref.entity_kind != "plugin.revision"
        || instance.activation_ref.entity_kind != "plugin.activation"
        || instance.provider_instance_ref.entity_kind != "runtime.provider_instance"
        || instance.provider_generation == 0
        || instance.generation == 0
    {
        return Err(D05Error::StalePluginRuntime);
    }
    Ok(())
}

fn validate_grants(
    required: &[EntityRef],
    grants: &[CapabilityGrantState],
    now_unix: i64,
) -> Result<(), D05Error> {
    if required.is_empty() {
        return Err(D05Error::PluginGrantInvalid);
    }
    let all_valid = required.iter().all(|required_ref| {
        grants.iter().any(|grant| {
            grant.grant_ref == *required_ref
                && grant.grant_ref.entity_kind == "plugin.capability_grant"
                && !grant.revoked
                && grant.expires_at_unix > now_unix
        })
    });
    if all_valid {
        Ok(())
    } else {
        Err(D05Error::PluginGrantInvalid)
    }
}
