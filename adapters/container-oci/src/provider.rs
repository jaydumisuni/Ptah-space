use crate::{
    BackendLaunchPlan, BackendPinEvidence, BackendReplacementProjection, ImageDigest,
    IsolationPolicy, MountAccess, MountRequest, NetworkPolicy, OciBackend, OciExecutionContext,
    OciExecutionEvidence, OciProviderError, OciRunSpec, CONTAINERD_ARCHIVE_SHA256,
    CONTAINERD_VERSION, RUNC_BINARY_SHA256, RUNC_VERSION,
};
use ptah_identifiers::EntityRef;
use ptah_provider_api::{
    EndpointAlias, EndpointAliasType, ProviderContext, ProviderHealth, ProviderInstance,
    ProviderKind, ProviderReachability, ProviderReadiness, ProviderRevision,
};
use std::sync::Arc;

const NETWORK_GRANT_KIND: &str = "isolation.network_exposure_grant";
const FILESYSTEM_GRANT_KIND: &str = "isolation.filesystem_access_grant";

/// A10 OCI Provider over one exact, already selected mechanical backend.
pub struct OciProvider<B: OciBackend> {
    context: ProviderContext,
    policy: IsolationPolicy,
    backend: B,
    clock: Arc<dyn Fn() -> String + Send + Sync>,
}

impl<B: OciBackend> OciProvider<B> {
    /// Construct an OCI Provider from exact Provider Revision/Instance evidence.
    ///
    /// `pins` carries evidence derived from the exact pinned containerd and runc
    /// artifacts. A10 refuses to initialize when any version or digest differs
    /// from the Phase 0C backend-artifact authority.
    ///
    /// # Errors
    /// Fails closed for wrong Provider kind/version/digests, missing local Node or
    /// observation evidence, or a non-ready Provider instance.
    pub fn new(
        revision: &ProviderRevision,
        instance: &ProviderInstance,
        pins: &BackendPinEvidence,
        policy: IsolationPolicy,
        backend: B,
        clock: Arc<dyn Fn() -> String + Send + Sync>,
    ) -> Result<Self, OciProviderError> {
        validate_revision(revision, pins)?;
        validate_instance(instance)?;
        if instance.provider_revision_ref != revision.revision_ref {
            return Err(OciProviderError::Provider(
                ptah_provider_api::ProviderError::MissingEvidence(
                    "instance/provider revision match",
                ),
            ));
        }
        let context = ProviderContext {
            provider_ref: revision.provider_ref.clone(),
            provider_revision_ref: revision.revision_ref.clone(),
            provider_instance_ref: instance.instance_ref.clone(),
            provider_generation: instance.provider_generation,
            node_ref: instance.node_ref.clone(),
            node_generation: instance.node_generation,
            connection_epoch: instance.connection_epoch,
            implementation_version: revision.implementation_version.clone(),
        };
        Ok(Self {
            context,
            policy,
            backend,
            clock,
        })
    }

    /// Return the exact Provider execution context.
    #[must_use]
    pub fn context(&self) -> &ProviderContext {
        &self.context
    }

    /// Validate policy/fencing and construct a backend-neutral mechanical plan.
    ///
    /// # Errors
    /// Rejects stale A04 execution authority, unbounded resources, ambiguous image
    /// identity, or unauthorized host-network/filesystem exposure.
    pub fn plan(
        &self,
        spec: &OciRunSpec,
        execution: &OciExecutionContext,
    ) -> Result<BackendLaunchPlan, OciProviderError> {
        self.validate_execution(execution)?;
        validate_spec(spec)?;
        if execution.attempt.workload_generation != spec.workload_generation {
            return Err(OciProviderError::ExecutionContextMismatch);
        }
        let host_network = self.validate_network(&spec.network)?;
        self.validate_mounts(&spec.mounts)?;

        Ok(BackendLaunchPlan {
            image_reference: spec.image.digest_bound_reference(),
            container_alias: container_alias(
                &execution.attempt_ref,
                self.context.provider_generation.value(),
            ),
            args: spec.args.clone(),
            resources: spec.resources,
            host_network,
            mounts: spec.mounts.clone(),
            max_output_bytes: spec.max_output_bytes,
        })
    }

    /// Execute one already bounded OCI request and retain start/completion separately.
    ///
    /// A successful start acknowledgement never becomes workload success. The
    /// method returns success evidence even for a non-zero workload exit because
    /// the caller/A04 proof authority decides how that exact result affects the
    /// logical Operation.
    ///
    /// # Errors
    /// Returns policy/fencing failure before backend invocation, or mechanical
    /// backend failure while starting/waiting for exact terminal evidence.
    pub fn execute(
        &self,
        spec: &OciRunSpec,
        execution: &OciExecutionContext,
    ) -> Result<OciExecutionEvidence, OciProviderError> {
        let plan = self.plan(spec, execution)?;
        let start = self.backend.start(&plan)?;
        if start.container_alias != plan.container_alias
            || start.container_alias.trim().is_empty()
            || start.observed_at.trim().is_empty()
            || start.detail.len() > 4096
        {
            return Err(OciProviderError::InvalidBackendAck);
        }
        let completion = self.backend.wait(&start, spec.max_output_bytes)?;
        if completion.observed_at.trim().is_empty()
            || completion.stdout.len() > spec.max_output_bytes
            || completion.stderr.len() > spec.max_output_bytes
        {
            return Err(OciProviderError::InvalidBackendAck);
        }
        let backend_alias = EndpointAlias {
            alias_type: EndpointAliasType::ContainerId,
            value: start.container_alias.clone(),
            scope: "containerd_namespace".to_owned(),
            observed_at: start.observed_at.clone(),
            valid_until: None,
        };
        Ok(OciExecutionEvidence {
            workload_ref: spec.workload_ref.clone(),
            image_digest: spec.image.digest.clone(),
            image_reference_alias: spec.image.reference_alias.clone(),
            provider_context: self.context.clone(),
            activity_ref: execution.activity_ref.clone(),
            operation_ref: execution.operation_ref.clone(),
            attempt_ref: execution.attempt_ref.clone(),
            start,
            completion,
            backend_alias,
            workload_generation: spec.workload_generation,
            resources: spec.resources,
            network: spec.network.clone(),
            mounts: spec.mounts.clone(),
        })
    }

    /// Project replacement backend evidence while preserving canonical workload identity.
    ///
    /// # Errors
    /// Rejects replacement with unchanged Provider Instance+Generation authority,
    /// or a backend identifier falsely equal to the canonical workload UUID text.
    pub fn replacement_projection(
        &self,
        workload_ref: &EntityRef,
        previous_backend_alias: EndpointAlias,
        replacement_provider: ProviderContext,
        replacement_backend_alias: EndpointAlias,
    ) -> Result<BackendReplacementProjection, OciProviderError> {
        if (replacement_provider.provider_instance_ref == self.context.provider_instance_ref
            && replacement_provider.provider_generation == self.context.provider_generation)
            || replacement_backend_alias.alias_type != EndpointAliasType::ContainerId
            || previous_backend_alias.alias_type != EndpointAliasType::ContainerId
            || replacement_backend_alias.value == previous_backend_alias.value
            || replacement_backend_alias.value == workload_ref.entity_id.to_string()
            || previous_backend_alias.value == workload_ref.entity_id.to_string()
        {
            return Err(OciProviderError::InvalidReplacement);
        }
        Ok(BackendReplacementProjection {
            workload_ref: workload_ref.clone(),
            previous_provider: self.context.clone(),
            replacement_provider,
            previous_backend_alias,
            replacement_backend_alias,
            observed_at: (self.clock)(),
        })
    }

    fn validate_execution(&self, execution: &OciExecutionContext) -> Result<(), OciProviderError> {
        if execution.attempt.provider_ref != self.context.provider_ref
            || execution.attempt.producer_instance_ref != self.context.provider_instance_ref
            || execution.attempt.provider_generation != self.context.provider_generation.value()
            || execution.attempt.connection_epoch != self.context.connection_epoch
            || execution.attempt.node_ref != self.context.node_ref
            || execution.attempt.node_generation != self.context.node_generation
            || execution.attempt.workload_generation == 0
        {
            return Err(OciProviderError::ExecutionContextMismatch);
        }
        Ok(())
    }

    fn validate_network(&self, network: &NetworkPolicy) -> Result<bool, OciProviderError> {
        match network {
            NetworkPolicy::Isolated => Ok(false),
            NetworkPolicy::Host { grant_ref } => {
                let authorized = self.policy.network_grants.iter().any(|grant| {
                    grant.grant_ref == *grant_ref
                        && grant.grant_ref.entity_kind == NETWORK_GRANT_KIND
                        && grant.allow_host_network
                });
                if !authorized {
                    return Err(OciProviderError::NetworkDenied);
                }
                Ok(true)
            }
        }
    }

    fn validate_mounts(&self, mounts: &[MountRequest]) -> Result<(), OciProviderError> {
        for mount in mounts {
            if mount.source_alias.trim().is_empty()
                || !mount.source_alias.starts_with('/')
                || mount.source_alias.split('/').any(|part| part == "..")
                || mount.source_alias.contains([',', '\0', '\n', '\r'])
                || !mount.destination.starts_with('/')
                || mount.destination.contains([',', '\0', '\n', '\r'])
                || mount.destination.split('/').any(|part| part == "..")
            {
                return Err(OciProviderError::InvalidSpec("mount"));
            }
            let authorized = self.policy.filesystem_grants.iter().any(|grant| {
                grant.grant_ref == mount.grant_ref
                    && grant.grant_ref.entity_kind == FILESYSTEM_GRANT_KIND
                    && grant.source_alias == mount.source_alias
                    && grant.destination == mount.destination
                    && access_allows(grant.access, mount.access)
            });
            if !authorized {
                return Err(OciProviderError::MountDenied);
            }
        }
        Ok(())
    }
}

fn validate_revision(
    revision: &ProviderRevision,
    pins: &BackendPinEvidence,
) -> Result<(), OciProviderError> {
    if revision.provider_kind != ProviderKind::OciRuntime {
        return Err(OciProviderError::ProviderKindMismatch);
    }
    if revision.implementation_name != "containerd"
        || revision.implementation_version != CONTAINERD_VERSION
        || pins.containerd_version != CONTAINERD_VERSION
    {
        return Err(OciProviderError::BackendPinMismatch("containerd version"));
    }
    let expected_containerd = format!("sha256:{CONTAINERD_ARCHIVE_SHA256}");
    if revision.build_or_package_digest != expected_containerd
        || pins.containerd_archive_sha256 != CONTAINERD_ARCHIVE_SHA256
    {
        return Err(OciProviderError::BackendPinMismatch("containerd digest"));
    }
    if pins.runc_version != RUNC_VERSION {
        return Err(OciProviderError::BackendPinMismatch("runc version"));
    }
    if pins.runc_binary_sha256 != RUNC_BINARY_SHA256 {
        return Err(OciProviderError::BackendPinMismatch("runc digest"));
    }
    if revision.configuration_digest.trim().is_empty() {
        return Err(OciProviderError::Provider(
            ptah_provider_api::ProviderError::EmptyField("configuration_digest"),
        ));
    }
    if revision.supported_facility_refs.is_empty() {
        return Err(OciProviderError::Provider(
            ptah_provider_api::ProviderError::MissingEvidence("supported_facility_refs"),
        ));
    }
    if revision.capability_claim_refs.is_empty() {
        return Err(OciProviderError::Provider(
            ptah_provider_api::ProviderError::MissingEvidence("capability_claim_refs"),
        ));
    }
    if revision.dependency_refs.is_empty() {
        return Err(OciProviderError::Provider(
            ptah_provider_api::ProviderError::MissingEvidence("runc dependency_ref"),
        ));
    }
    Ok(())
}

fn validate_instance(instance: &ProviderInstance) -> Result<(), OciProviderError> {
    if instance.node_generation == 0 {
        return Err(OciProviderError::Provider(
            ptah_provider_api::ProviderError::MissingNodeBinding,
        ));
    }
    if instance.started_at.trim().is_empty() {
        return Err(OciProviderError::Provider(
            ptah_provider_api::ProviderError::EmptyField("started_at"),
        ));
    }
    if instance.observation_refs.is_empty() {
        return Err(OciProviderError::Provider(
            ptah_provider_api::ProviderError::MissingEvidence("observation_refs"),
        ));
    }
    if instance.reachability != ProviderReachability::Reachable
        || instance.readiness != ProviderReadiness::Ready
        || instance.health == ProviderHealth::Unhealthy
    {
        return Err(OciProviderError::ProviderNotReady);
    }
    Ok(())
}

fn access_allows(authority: MountAccess, requested: MountAccess) -> bool {
    matches!(
        (authority, requested),
        (MountAccess::ReadWrite, _) | (MountAccess::ReadOnly, MountAccess::ReadOnly)
    )
}

fn validate_spec(spec: &OciRunSpec) -> Result<(), OciProviderError> {
    if spec.image.reference_alias.trim().is_empty()
        || spec.image.reference_alias.len() > 2048
        || spec.image.reference_alias.chars().any(char::is_whitespace)
        || spec.image.reference_alias.contains(['\0', '\n', '\r'])
        || spec.image.reference_alias.contains("://")
    {
        return Err(OciProviderError::InvalidSpec("image reference_alias"));
    }
    let mut alias_parts = spec.image.reference_alias.split('@');
    let Some(base) = alias_parts.next() else {
        return Err(OciProviderError::InvalidSpec("image reference_alias"));
    };
    let suffix = alias_parts.next();
    if base.is_empty() || alias_parts.next().is_some() {
        return Err(OciProviderError::InvalidSpec("image reference_alias"));
    }
    if let Some(alias_digest) = suffix {
        let parsed = ImageDigest::parse(alias_digest.to_owned())?;
        if parsed != spec.image.digest {
            return Err(OciProviderError::InvalidSpec("image digest disagreement"));
        }
    }
    if spec.workload_generation == 0 {
        return Err(OciProviderError::InvalidSpec("workload_generation"));
    }
    ImageDigest::parse(spec.image.digest.as_str())?;
    spec.resources.validate()?;
    if spec.max_output_bytes == 0 || spec.max_output_bytes > 16 * 1024 * 1024 {
        return Err(OciProviderError::InvalidSpec("max_output_bytes"));
    }
    if spec.args.len() > 4096 || spec.mounts.len() > 128 {
        return Err(OciProviderError::InvalidSpec("collection bound"));
    }
    Ok(())
}

fn container_alias(attempt_ref: &EntityRef, provider_generation: u64) -> String {
    let compact = attempt_ref.entity_id.to_string().replace('-', "");
    format!("ptah-{}-g{provider_generation}", &compact[..20])
}
