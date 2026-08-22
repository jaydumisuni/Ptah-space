//! A10 OCI Provider acceptance and negative-proof corpus.

use container_oci::*;
use ptah_activity_runtime::AttemptContext;
use ptah_identifiers::EntityRef;
use ptah_provider_api::{
    EndpointAlias, EndpointAliasType, ProviderGeneration, ProviderHealth, ProviderInstance,
    ProviderKind, ProviderReachability, ProviderReadiness, ProviderRevision,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const IMAGE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid canonical ref")
}

fn revision() -> ProviderRevision {
    ProviderRevision {
        revision_ref: reference("runtime.provider_revision"),
        provider_ref: reference("runtime.provider"),
        provider_kind: ProviderKind::OciRuntime,
        implementation_name: "containerd".to_owned(),
        implementation_version: CONTAINERD_VERSION.to_owned(),
        build_or_package_digest: format!("sha256:{CONTAINERD_ARCHIVE_SHA256}"),
        configuration_digest: "sha256:qualified-a10-config".to_owned(),
        supported_facility_refs: vec![reference("runtime.facility")],
        capability_claim_refs: vec![reference("runtime.capability_claim")],
        dependency_refs: vec![reference("proof.evidence")],
        node_requirements: vec!["Linux OCI host".to_owned()],
        security_requirements: vec!["WP11 grants fail closed".to_owned()],
        known_limitations: vec![format!("runc {RUNC_VERSION} exact binary required")],
    }
}

fn instance(revision: &ProviderRevision, generation: u64) -> ProviderInstance {
    ProviderInstance {
        instance_ref: reference("runtime.provider_instance"),
        provider_revision_ref: revision.revision_ref.clone(),
        node_ref: reference("core.node"),
        node_generation: 7,
        provider_generation: ProviderGeneration::new(generation).expect("generation"),
        connection_epoch: 4,
        reachability: ProviderReachability::Reachable,
        readiness: ProviderReadiness::Ready,
        health: ProviderHealth::Healthy,
        endpoint_aliases: Vec::new(),
        process_or_service_refs: Vec::new(),
        observation_refs: vec![reference("proof.evidence")],
        started_at: "2026-08-21T00:00:00Z".to_owned(),
        limitations: Vec::new(),
    }
}

#[derive(Clone)]
struct MockBackend {
    starts: Arc<AtomicUsize>,
    waits: Arc<AtomicUsize>,
    completion_success: bool,
}

impl MockBackend {
    fn new(completion_success: bool) -> Self {
        Self {
            starts: Arc::new(AtomicUsize::new(0)),
            waits: Arc::new(AtomicUsize::new(0)),
            completion_success,
        }
    }
}

impl OciBackend for MockBackend {
    fn start(&self, plan: &BackendLaunchPlan) -> Result<BackendStartAck, OciProviderError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        Ok(BackendStartAck {
            container_alias: plan.container_alias.clone(),
            observed_at: "2026-08-21T00:00:01Z".to_owned(),
            detail: "accepted".to_owned(),
        })
    }

    fn wait(
        &self,
        _start: &BackendStartAck,
        _max_output_bytes: usize,
    ) -> Result<BackendCompletion, OciProviderError> {
        self.waits.fetch_add(1, Ordering::SeqCst);
        Ok(BackendCompletion {
            observed_at: "2026-08-21T00:00:02Z".to_owned(),
            exit_code: Some(if self.completion_success { 0 } else { 23 }),
            success: self.completion_success,
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
            stdout_truncated_bytes: 0,
            stderr_truncated_bytes: 0,
        })
    }
}

fn execution(provider: &OciProvider<MockBackend>) -> OciExecutionContext {
    let context = provider.context();
    OciExecutionContext {
        activity_ref: reference("core.activity"),
        operation_ref: reference("core.operation"),
        attempt_ref: reference("core.attempt"),
        attempt: AttemptContext {
            node_ref: context.node_ref.clone(),
            node_generation: context.node_generation,
            provider_ref: context.provider_ref.clone(),
            provider_generation: context.provider_generation.value(),
            workload_generation: 3,
            connection_epoch: context.connection_epoch,
            facility_ref: reference("runtime.facility"),
            producer_instance_ref: context.provider_instance_ref.clone(),
            producer_version: context.implementation_version.clone(),
        },
    }
}

fn spec(network: NetworkPolicy, mounts: Vec<MountRequest>) -> OciRunSpec {
    OciRunSpec {
        workload_ref: reference("runtime.oci_workload"),
        image: OciImage {
            reference_alias: "registry.example/team/tool:moving".to_owned(),
            digest: ImageDigest::parse(IMAGE).expect("digest"),
        },
        workload_generation: 3,
        args: vec!["/bin/true".to_owned()],
        resources: ResourceLimits {
            memory_bytes: 128 * 1024 * 1024,
            cpu_period_micros: 100_000,
            cpu_quota_micros: 50_000,
        },
        network,
        mounts,
        max_output_bytes: 64 * 1024,
    }
}

fn provider(
    backend: MockBackend,
    network_grants: Vec<NetworkGrantAuthority>,
    filesystem_grants: Vec<FilesystemGrantAuthority>,
) -> (OciProvider<MockBackend>, ProviderInstance) {
    let revision = revision();
    let instance = instance(&revision, 2);
    let provider = OciProvider::new(
        &revision,
        &instance,
        &BackendPinEvidence::locked(),
        IsolationPolicy {
            network_grants,
            filesystem_grants,
        },
        backend,
        Arc::new(|| "2026-08-21T00:00:03Z".to_owned()),
    )
    .expect("provider");
    (provider, instance)
}

#[test]
fn mutable_tag_without_exact_digest_is_rejected() {
    assert!(matches!(
        ImageDigest::parse("registry.example/team/tool:latest"),
        Err(OciProviderError::MutableImageReference)
    ));
    assert!(matches!(
        ImageDigest::parse("sha256:ABCDEF"),
        Err(OciProviderError::InvalidImageDigest)
    ));
}

#[test]
fn invalid_digest_cannot_enter_through_deserialization() {
    assert!(serde_json::from_str::<ImageDigest>("\"sha256:ABCDEF\"").is_err());
    assert!(serde_json::from_str::<ImageDigest>("\"registry.example/tool:latest\"").is_err());
    let decoded = serde_json::from_str::<ImageDigest>(&format!("\"{IMAGE}\""))
        .expect("exact digest deserializes");
    assert_eq!(decoded.as_str(), IMAGE);
}

#[test]
fn contradictory_alias_digest_is_rejected_before_backend_invocation() {
    let backend = MockBackend::new(true);
    let starts = Arc::clone(&backend.starts);
    let (provider, _instance) = provider(backend, Vec::new(), Vec::new());
    let mut request = spec(NetworkPolicy::Isolated, Vec::new());
    request.image.reference_alias = format!("registry.example/team/tool@sha256:{}", "b".repeat(64));
    assert!(matches!(
        provider.execute(&request, &execution(&provider)),
        Err(OciProviderError::InvalidSpec("image digest disagreement"))
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 0);
}

#[test]
fn exact_digest_controls_mechanical_image_reference() {
    let backend = MockBackend::new(true);
    let (provider, _instance) = provider(backend, Vec::new(), Vec::new());
    let request = spec(NetworkPolicy::Isolated, Vec::new());
    let plan = provider
        .plan(&request, &execution(&provider))
        .expect("plan");
    assert_eq!(
        plan.image_reference,
        format!("registry.example/team/tool:moving@{IMAGE}")
    );
    assert!(!plan.host_network);
    assert_eq!(plan.resources.memory_bytes, 128 * 1024 * 1024);
}

#[test]
fn backend_container_id_remains_alias_not_canonical_identity() {
    let backend = MockBackend::new(true);
    let (provider, _instance) = provider(backend, Vec::new(), Vec::new());
    let request = spec(NetworkPolicy::Isolated, Vec::new());
    let evidence = provider
        .execute(&request, &execution(&provider))
        .expect("execute");
    assert_eq!(
        evidence.backend_alias.alias_type,
        EndpointAliasType::ContainerId
    );
    assert_ne!(
        evidence.backend_alias.value,
        evidence.workload_ref.entity_id.to_string()
    );
}

#[test]
fn start_ack_does_not_equal_workload_success() {
    let backend = MockBackend::new(false);
    let starts = Arc::clone(&backend.starts);
    let waits = Arc::clone(&backend.waits);
    let (provider, _instance) = provider(backend, Vec::new(), Vec::new());
    let evidence = provider
        .execute(
            &spec(NetworkPolicy::Isolated, Vec::new()),
            &execution(&provider),
        )
        .expect("mechanically observed failure is still evidence");
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(waits.load(Ordering::SeqCst), 1);
    assert_eq!(evidence.start.detail, "accepted");
    assert!(!evidence.completion.success);
    assert_eq!(evidence.completion.exit_code, Some(23));
}

#[test]
fn stale_provider_generation_fails_before_backend_invocation() {
    let backend = MockBackend::new(true);
    let starts = Arc::clone(&backend.starts);
    let (provider, _instance) = provider(backend, Vec::new(), Vec::new());
    let mut stale = execution(&provider);
    stale.attempt.provider_generation -= 1;
    assert!(matches!(
        provider.execute(&spec(NetworkPolicy::Isolated, Vec::new()), &stale),
        Err(OciProviderError::ExecutionContextMismatch)
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 0);
}

#[test]
fn workload_generation_mismatch_fails_before_backend_invocation() {
    let backend = MockBackend::new(true);
    let starts = Arc::clone(&backend.starts);
    let (provider, _instance) = provider(backend, Vec::new(), Vec::new());
    let mut request = spec(NetworkPolicy::Isolated, Vec::new());
    request.workload_generation = 4;
    assert!(matches!(
        provider.execute(&request, &execution(&provider)),
        Err(OciProviderError::ExecutionContextMismatch)
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 0);
}

#[test]
fn unauthorized_host_network_fails_closed() {
    let backend = MockBackend::new(true);
    let starts = Arc::clone(&backend.starts);
    let (provider, _instance) = provider(backend, Vec::new(), Vec::new());
    let grant = reference("isolation.network_exposure_grant");
    let request = spec(NetworkPolicy::Host { grant_ref: grant }, Vec::new());
    assert!(matches!(
        provider.execute(&request, &execution(&provider)),
        Err(OciProviderError::NetworkDenied)
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 0);
}

#[test]
fn authorized_host_network_is_explicit_in_plan() {
    let backend = MockBackend::new(true);
    let grant = reference("isolation.network_exposure_grant");
    let (provider, _instance) = provider(
        backend,
        vec![NetworkGrantAuthority {
            grant_ref: grant.clone(),
            allow_host_network: true,
        }],
        Vec::new(),
    );
    let request = spec(NetworkPolicy::Host { grant_ref: grant }, Vec::new());
    assert!(
        provider
            .plan(&request, &execution(&provider))
            .expect("authorized plan")
            .host_network
    );
}

#[test]
fn unauthorized_mount_fails_closed_and_authorized_mount_retains_grant() {
    let backend = MockBackend::new(true);
    let starts = Arc::clone(&backend.starts);
    let grant = reference("isolation.filesystem_access_grant");
    let mount = MountRequest {
        source_alias: "/srv/input".to_owned(),
        destination: "/input".to_owned(),
        access: MountAccess::ReadOnly,
        grant_ref: grant.clone(),
    };
    let (denied, _denied_instance) = provider(backend.clone(), Vec::new(), Vec::new());
    assert!(matches!(
        denied.execute(
            &spec(NetworkPolicy::Isolated, vec![mount.clone()]),
            &execution(&denied),
        ),
        Err(OciProviderError::MountDenied)
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    let (allowed, _allowed_instance) = provider(
        backend,
        Vec::new(),
        vec![FilesystemGrantAuthority {
            grant_ref: grant.clone(),
            source_alias: "/srv/input".to_owned(),
            destination: "/input".to_owned(),
            access: MountAccess::ReadOnly,
        }],
    );
    let plan = allowed
        .plan(
            &spec(NetworkPolicy::Isolated, vec![mount]),
            &execution(&allowed),
        )
        .expect("authorized mount");
    assert_eq!(plan.mounts[0].grant_ref, grant);
}

#[test]
fn filesystem_grant_scope_and_access_cannot_be_widened() {
    let grant = reference("isolation.filesystem_access_grant");
    let authority = FilesystemGrantAuthority {
        grant_ref: grant.clone(),
        source_alias: "/srv/input".to_owned(),
        destination: "/input".to_owned(),
        access: MountAccess::ReadOnly,
    };
    let backend = MockBackend::new(true);
    let starts = Arc::clone(&backend.starts);
    let (provider, _instance) = provider(backend, Vec::new(), vec![authority]);

    let wrong_source = MountRequest {
        source_alias: "/srv/other".to_owned(),
        destination: "/input".to_owned(),
        access: MountAccess::ReadOnly,
        grant_ref: grant.clone(),
    };
    assert!(matches!(
        provider.execute(
            &spec(NetworkPolicy::Isolated, vec![wrong_source]),
            &execution(&provider),
        ),
        Err(OciProviderError::MountDenied)
    ));

    let widened_access = MountRequest {
        source_alias: "/srv/input".to_owned(),
        destination: "/input".to_owned(),
        access: MountAccess::ReadWrite,
        grant_ref: grant,
    };
    assert!(matches!(
        provider.execute(
            &spec(NetworkPolicy::Isolated, vec![widened_access]),
            &execution(&provider),
        ),
        Err(OciProviderError::MountDenied)
    ));
    assert_eq!(starts.load(Ordering::SeqCst), 0);
}

#[test]
fn replacement_preserves_workload_identity_and_changes_backend_authority() {
    let backend = MockBackend::new(true);
    let (provider, _instance) = provider(backend, Vec::new(), Vec::new());
    let workload = reference("runtime.oci_workload");
    let previous = EndpointAlias {
        alias_type: EndpointAliasType::ContainerId,
        value: "backend-old".to_owned(),
        scope: "containerd_namespace".to_owned(),
        observed_at: "2026-08-21T00:00:00Z".to_owned(),
        valid_until: None,
    };
    let replacement_alias = EndpointAlias {
        alias_type: EndpointAliasType::ContainerId,
        value: "backend-new".to_owned(),
        scope: "containerd_namespace".to_owned(),
        observed_at: "2026-08-21T00:01:00Z".to_owned(),
        valid_until: None,
    };
    let mut replacement_context = provider.context().clone();
    replacement_context.provider_generation = ProviderGeneration::new(3).expect("generation");
    replacement_context.provider_instance_ref = reference("runtime.provider_instance");
    let projection = provider
        .replacement_projection(
            &workload,
            previous,
            replacement_context.clone(),
            replacement_alias,
        )
        .expect("replacement");
    assert_eq!(projection.workload_ref, workload);
    assert_eq!(projection.replacement_provider, replacement_context);
    assert_ne!(
        projection.previous_provider.provider_generation,
        projection.replacement_provider.provider_generation
    );
}

#[test]
fn wrong_backend_pin_and_unready_instance_are_rejected() {
    let revision = revision();
    let instance = instance(&revision, 2);
    assert!(matches!(
        OciProvider::new(
            &revision,
            &instance,
            &BackendPinEvidence {
                containerd_version: CONTAINERD_VERSION.to_owned(),
                containerd_archive_sha256: "bad".to_owned(),
                runc_version: RUNC_VERSION.to_owned(),
                runc_binary_sha256: RUNC_BINARY_SHA256.to_owned(),
            },
            IsolationPolicy::default(),
            MockBackend::new(true),
            Arc::new(|| "2026-08-21T00:00:00Z".to_owned()),
        ),
        Err(OciProviderError::BackendPinMismatch(_))
    ));

    let mut unready = instance;
    unready.readiness = ProviderReadiness::NotReady;
    assert!(matches!(
        OciProvider::new(
            &revision,
            &unready,
            &BackendPinEvidence::locked(),
            IsolationPolicy::default(),
            MockBackend::new(true),
            Arc::new(|| "2026-08-21T00:00:00Z".to_owned()),
        ),
        Err(OciProviderError::ProviderNotReady)
    ));
}
