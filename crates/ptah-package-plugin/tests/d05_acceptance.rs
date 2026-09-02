#![allow(missing_docs)]
use ptah_activity_runtime::{ActivityRuntime, AttemptContext, MemoryJournal};
use ptah_identifiers::{EntityId, EntityRef};
use ptah_package_plugin::{
    ActivationRequest, ActivationService, AdmissionService, CapabilityGrantState, D05Error,
    DependencyBinding, DistributionClass, HealthObservation, InstallRequest, LicenceDecision,
    PackageAdmissionRequest, PackageCandidate, PackageCatalog, PackageConstraint,
    PackageCoordinate, PackageInstallAck, PackageInstaller, PackageStore, PackageVerificationInput,
    PluginInstanceRecord, PluginPortRegistration, PluginRevisionInput, PluginRuntime,
    PluginServiceRegistration, RegistrySource, VerificationDecision, VerificationScope,
};
use ptah_workspace::{CreateWorkspace, IssueGrant, WorkspaceStore};
use std::{fs, path::PathBuf, sync::Arc};

fn r(kind: &str) -> EntityRef {
    EntityRef::new(kind).unwrap()
}

fn exact_coordinate() -> PackageCoordinate {
    PackageCoordinate {
        ecosystem: "cargo".into(),
        namespace: "thetechguy".into(),
        package_key: "widget".into(),
        version: "1.2.3".into(),
        source_revision_ref: r("knowledge.source_revision"),
        content_object_revision_ref: r("core.object_revision"),
        content_sha256: "11".repeat(32),
    }
}

fn registry() -> RegistrySource {
    RegistrySource {
        registry_key: "public-cargo".into(),
        ecosystem: "cargo".into(),
        source_revision_ref: r("knowledge.source_revision"),
        trust_policy_refs: vec![r("core.policy")],
        observed_at_unix: 100,
        valid_until_unix: 200,
        trusted: true,
    }
}

#[test]
fn exact_package_coordinate_is_required_before_resolution() {
    let mut c = exact_coordinate();
    c.content_sha256.clear();
    assert_eq!(c.validate_exact(), Err(D05Error::InexactPackageCoordinate));
}

#[test]
fn lock_binds_exact_revision_source_and_digest() {
    let catalog = PackageCatalog::new(150);
    let coordinate = exact_coordinate();
    let candidate = PackageCandidate {
        coordinate: coordinate.clone(),
        registry: registry(),
        evidence_refs: vec![r("core.evidence")],
    };
    let resolved = catalog.resolve_exact(&candidate).unwrap();
    let lock = catalog.lock(&resolved).unwrap();
    assert_eq!(lock.entries.len(), 1);
    assert_eq!(
        lock.entries[0].package_revision_ref,
        resolved.nodes[0].package_revision_ref
    );
    assert_eq!(
        lock.entries[0].source_revision_ref,
        coordinate.source_revision_ref
    );
    assert_eq!(lock.entries[0].content_sha256, "11".repeat(32));
    assert_eq!(lock.digest_sha256.len(), 64);
}

#[test]
fn constraint_resolution_and_lock_are_distinct() {
    let catalog = PackageCatalog::new(150);
    let candidate = PackageCandidate {
        coordinate: exact_coordinate(),
        registry: registry(),
        evidence_refs: vec![],
    };
    let constraint = PackageConstraint {
        dependency_key: "widget".into(),
        expression: "^1.2".into(),
    };
    let resolved = catalog
        .resolve_with_constraint(&candidate, &constraint)
        .unwrap();
    let lock = catalog.lock(&resolved).unwrap();
    assert_ne!(constraint.expression, resolved.resolution_digest_sha256);
    assert_ne!(resolved.resolution_digest_sha256, lock.digest_sha256);
}

#[test]
fn stale_or_untrusted_registry_source_fails_closed() {
    let catalog = PackageCatalog::new(250);
    let candidate = PackageCandidate {
        coordinate: exact_coordinate(),
        registry: registry(),
        evidence_refs: vec![],
    };
    assert_eq!(
        catalog.resolve_exact(&candidate),
        Err(D05Error::RegistrySourceUnavailable)
    );
    let mut candidate = candidate;
    candidate.registry.valid_until_unix = 300;
    candidate.registry.trusted = false;
    assert_eq!(
        catalog.resolve_exact(&candidate),
        Err(D05Error::RegistrySourceUnavailable)
    );
}

fn workspace_store(label: &str) -> (PathBuf, WorkspaceStore) {
    let path =
        std::env::temp_dir().join(format!("ptah-d05-{label}-{}.sqlite3", EntityId::new_v7()));
    let _ = fs::remove_file(&path);
    let clock: Arc<dyn Fn() -> String + Send + Sync> =
        Arc::new(|| "2026-09-02T13:30:00Z".to_owned());
    let store = WorkspaceStore::open(&path, clock).unwrap();
    (path, store)
}

fn create_workspace(store: &mut WorkspaceStore, key: &str) -> EntityRef {
    store
        .create_workspace(CreateWorkspace {
            workspace_key: key.into(),
            title: key.into(),
            description: None,
            owner_ref: r("identity.principal"),
            authority_ref: r("authority.owner"),
            created_by_ref: r("identity.principal"),
            policy_refs: vec![r("policy.workspace")],
        })
        .unwrap()
        .workspace_ref
}

fn admission_request(
    source: &EntityRef,
    target: &EntityRef,
    distribution: DistributionClass,
    licence_decision: LicenceDecision,
) -> PackageAdmissionRequest {
    PackageAdmissionRequest {
        actor_ref: r("identity.principal"),
        source_workspace_id: source.entity_id,
        target_workspace_id: target.entity_id,
        package_revision_ref: r("package.revision"),
        distribution,
        licence_decision,
        trust_policy_refs: vec![r("policy.package_trust")],
        licence_record_refs: vec![r("knowledge.licence_record")],
        evidence_refs: vec![r("core.evidence")],
        grant_ref: None,
    }
}

#[test]
fn public_discovery_is_not_install_admission() {
    let candidate = PackageCandidate {
        coordinate: exact_coordinate(),
        registry: registry(),
        evidence_refs: vec![],
    };
    let value = serde_json::to_value(candidate).unwrap();
    assert!(value.get("admitted").is_none());
    assert!(value.get("installation_ref").is_none());
}

#[test]
fn private_package_requires_exact_workspace_authority() {
    let (_path, mut store) = workspace_store("private");
    let source = create_workspace(&mut store, "source");
    let target = create_workspace(&mut store, "target");
    let request = admission_request(
        &source,
        &target,
        DistributionClass::Private,
        LicenceDecision::Allowed,
    );
    assert_eq!(
        AdmissionService::admit(&store, &request),
        Err(D05Error::WorkspaceAccessDenied)
    );
    let same = admission_request(
        &target,
        &target,
        DistributionClass::Private,
        LicenceDecision::Allowed,
    );
    assert!(AdmissionService::admit(&store, &same).is_ok());
}

#[test]
fn denied_licence_blocks_admission() {
    let (_path, mut store) = workspace_store("denied");
    let ws = create_workspace(&mut store, "workspace.test");
    let request = admission_request(&ws, &ws, DistributionClass::Public, LicenceDecision::Denied);
    assert_eq!(
        AdmissionService::admit(&store, &request),
        Err(D05Error::LicenceDenied)
    );
}

#[test]
fn review_required_licence_remains_unresolved() {
    let (_path, mut store) = workspace_store("review");
    let ws = create_workspace(&mut store, "workspace.test");
    let request = admission_request(
        &ws,
        &ws,
        DistributionClass::Public,
        LicenceDecision::ReviewRequired,
    );
    assert_eq!(
        AdmissionService::admit(&store, &request),
        Err(D05Error::LicenceReviewRequired)
    );
}

#[test]
fn admission_contract_contains_references_not_raw_credentials() {
    let (_path, mut store) = workspace_store("secret-free");
    let ws = create_workspace(&mut store, "workspace.test");
    let request = admission_request(
        &ws,
        &ws,
        DistributionClass::Public,
        LicenceDecision::Allowed,
    );
    let admitted = AdmissionService::admit(&store, &request).unwrap();
    let serialized = serde_json::to_string(&admitted)
        .unwrap()
        .to_ascii_lowercase();
    for forbidden in [
        "password",
        "api_key",
        "raw_secret",
        "credential_value",
        "token_value",
    ] {
        assert!(!serialized.contains(forbidden));
    }
}

fn activity_runtime() -> ActivityRuntime {
    ActivityRuntime::new(
        8,
        Arc::new(MemoryJournal::default()),
        Arc::new(|| "2026-09-02T15:30:00Z".to_owned()),
    )
    .unwrap()
}

fn attempt_context(provider_generation: u64) -> AttemptContext {
    AttemptContext {
        node_ref: r("core.node"),
        node_generation: 3,
        provider_ref: r("runtime.provider_instance"),
        provider_generation,
        workload_generation: 11,
        connection_epoch: 5,
        facility_ref: r("runtime.facility_revision"),
        producer_instance_ref: r("runtime.provider_instance"),
        producer_version: "d05-test".to_owned(),
    }
}

fn install_request(provider_generation: u64) -> InstallRequest {
    InstallRequest {
        package_ref: r("package.package"),
        package_revision_ref: r("package.revision"),
        resolved_graph_ref: r("package.resolved_graph"),
        lock_record_ref: r("package.lock_record"),
        workspace_ref: r("core.workspace"),
        provider_instance_ref: r("runtime.provider_instance"),
        provider_generation,
        installed_object_refs: vec![r("core.object_revision")],
        activity_request_ref: r("core.activity_request"),
        caller_ref: r("identity.principal"),
        authority_ref: r("authority.owner"),
        intent_ref: r("core.intent"),
    }
}

fn install_ack() -> PackageInstallAck {
    PackageInstallAck {
        backend_alias: "fixture-pkg-manager".into(),
        accepted_at: "2026-09-02T15:30:01Z".into(),
        evidence_refs: vec![r("core.evidence")],
    }
}

fn package_store(label: &str) -> (PathBuf, PackageStore) {
    let path = std::env::temp_dir().join(format!(
        "ptah-d05-package-{label}-{}.sqlite3",
        EntityId::new_v7()
    ));
    let _ = fs::remove_file(&path);
    let store = PackageStore::open(&path).unwrap();
    (path, store)
}

#[test]
fn install_ack_is_not_package_verification() {
    let runtime = activity_runtime();
    let request = install_request(7);
    let handle =
        PackageInstaller::begin_install(&runtime, &request, attempt_context(7), &install_ack())
            .unwrap();
    assert_eq!(handle.verification_state, "unverified");
    let operation = runtime.operation(handle.operation_id).unwrap().unwrap();
    assert_ne!(format!("{:?}", operation.state()), "Succeeded");
}

#[test]
fn installed_unverified_requires_independent_integrity_and_installed_state_verification() {
    let runtime = activity_runtime();
    let request = install_request(7);
    let handle =
        PackageInstaller::begin_install(&runtime, &request, attempt_context(7), &install_ack())
            .unwrap();
    let (_path, mut store) = package_store("verified");
    store.record_installation(&handle, &request).unwrap();
    assert_eq!(
        store.installation_state(&handle.installation_ref).unwrap(),
        "installed_unverified"
    );
    let verification = PackageVerificationInput {
        scopes: vec![
            VerificationScope::Integrity,
            VerificationScope::InstalledState,
        ],
        checks: vec!["digest_match".into(), "readback_match".into()],
        decision: VerificationDecision::Verified,
        signature_verified: false,
        verified_at: "2026-09-02T15:31:00Z".into(),
        evidence_refs: vec![r("core.evidence")],
        receipt_refs: vec![r("core.receipt")],
        limitations: vec![],
    };
    let verification_ref = store.record_verification(&handle, &verification).unwrap();
    assert_eq!(
        verification_ref.entity_kind.as_str(),
        "package.verification"
    );
    assert_eq!(
        store.installation_state(&handle.installation_ref).unwrap(),
        "installed_verified"
    );
}

#[test]
fn signature_verification_does_not_claim_functionality() {
    let verification = PackageVerificationInput {
        scopes: vec![VerificationScope::Integrity],
        checks: vec!["signature_valid".into()],
        decision: VerificationDecision::Verified,
        signature_verified: true,
        verified_at: "2026-09-02T15:31:00Z".into(),
        evidence_refs: vec![r("core.evidence")],
        receipt_refs: vec![],
        limitations: vec![],
    };
    assert!(!verification.proves_functionality());
}

#[test]
fn package_install_retry_allocates_fresh_a04_attempt() {
    let runtime = activity_runtime();
    let request = install_request(7);
    let first =
        PackageInstaller::begin_install(&runtime, &request, attempt_context(7), &install_ack())
            .unwrap();
    runtime
        .fail_attempt(first.attempt_id, "backend_failure")
        .unwrap();
    let second_attempt =
        PackageInstaller::retry_install(&runtime, &first, r("core.policy"), attempt_context(7))
            .unwrap();
    assert_ne!(first.attempt_id, second_attempt);
}

#[test]
fn package_manager_replacement_preserves_package_identity_and_creates_new_installation_evidence() {
    let runtime = activity_runtime();
    let request7 = install_request(7);
    let first =
        PackageInstaller::begin_install(&runtime, &request7, attempt_context(7), &install_ack())
            .unwrap();
    let mut request8 = request7.clone();
    request8.provider_generation = 8;
    let second =
        PackageInstaller::begin_install(&runtime, &request8, attempt_context(8), &install_ack())
            .unwrap();
    assert_eq!(first.package_ref, second.package_ref);
    assert_eq!(first.package_revision_ref, second.package_revision_ref);
    assert_ne!(first.installation_ref, second.installation_ref);
    assert_ne!(first.attempt_id, second.attempt_id);
}

fn workspace_store_with_clock(label: &str, now: &'static str) -> (PathBuf, WorkspaceStore) {
    let path =
        std::env::temp_dir().join(format!("ptah-d05-{label}-{}.sqlite3", EntityId::new_v7()));
    let _ = fs::remove_file(&path);
    let clock: Arc<dyn Fn() -> String + Send + Sync> = Arc::new(move || now.to_owned());
    let store = WorkspaceStore::open(&path, clock).unwrap();
    (path, store)
}

fn plugin_revision_input() -> PluginRevisionInput {
    PluginRevisionInput {
        revision: "1.0.0".into(),
        object_revision_refs: vec![r("core.object_revision")],
        manifest_ref: r("plugin.manifest"),
        package_lock_refs: vec![r("package.lock_record")],
        created_at: "2026-09-02T15:45:00Z".into(),
    }
}

#[test]
fn plugin_revision_binds_exact_manifest_objects_and_package_locks() {
    let input = plugin_revision_input();
    assert!(input.validate_exact().is_ok());
    let mut bad = input.clone();
    bad.package_lock_refs.clear();
    assert_eq!(bad.validate_exact(), Err(D05Error::InvalidLifecycleRecord));
}

#[test]
fn plugin_installation_does_not_imply_activation() {
    let installation_ref = r("plugin.installation");
    let value = serde_json::json!({"installation_ref": installation_ref});
    assert!(value.get("activation_ref").is_none());
    assert!(value.get("active").is_none());
}

#[test]
fn activation_requires_explicit_policy_and_scoped_a06_grant() {
    let (_path, mut store) = workspace_store_with_clock("activate", "2026-09-02T16:00:00Z");
    let source = create_workspace(&mut store, "plugin.source");
    let target = create_workspace(&mut store, "plugin.target");
    let actor = r("identity.principal");
    let grant = store
        .issue_grant(IssueGrant {
            subject_ref: target.clone(),
            grantee_ref: actor.clone(),
            scopes: vec!["plugin.activate".into()],
            policy_ref: r("policy.plugin"),
            provider_generation: 7,
            fence_token: 1,
            expires_at: "2026-09-03T16:00:00Z".into(),
            authority_ref: r("authority.owner"),
        })
        .unwrap();
    let request = ActivationRequest {
        actor_ref: actor,
        source_workspace_id: source.entity_id,
        target_workspace_id: target.entity_id,
        plugin_revision_ref: r("plugin.revision"),
        installation_ref: r("plugin.installation"),
        workspace_ref: target,
        policy_refs: vec![r("policy.plugin")],
        grant_ref: Some(grant),
        decided_by_ref: r("identity.principal"),
        decided_at: "2026-09-02T16:00:01Z".into(),
    };
    assert!(ActivationService::authorize(&store, &request).is_ok());
    let mut missing_policy = request.clone();
    missing_policy.policy_refs.clear();
    assert_eq!(
        ActivationService::authorize(&store, &missing_policy),
        Err(D05Error::ActivationAuthorityMissing)
    );
}

#[test]
fn expired_a06_grant_cannot_authorize_plugin_activation() {
    let (path, mut store) = workspace_store_with_clock("activate-expired", "2026-09-02T16:00:00Z");
    let source = create_workspace(&mut store, "plugin.source");
    let target = create_workspace(&mut store, "plugin.target");
    let actor = r("identity.principal");
    let grant = store
        .issue_grant(IssueGrant {
            subject_ref: target.clone(),
            grantee_ref: actor.clone(),
            scopes: vec!["plugin.activate".into()],
            policy_ref: r("policy.plugin"),
            provider_generation: 7,
            fence_token: 1,
            expires_at: "2026-09-03T16:00:00Z".into(),
            authority_ref: r("authority.owner"),
        })
        .unwrap();
    drop(store);
    let late_clock: Arc<dyn Fn() -> String + Send + Sync> =
        Arc::new(|| "2026-09-04T16:00:00Z".to_owned());
    let reopened = WorkspaceStore::open(&path, late_clock).unwrap();
    let request = ActivationRequest {
        actor_ref: actor,
        source_workspace_id: source.entity_id,
        target_workspace_id: target.entity_id,
        plugin_revision_ref: r("plugin.revision"),
        installation_ref: r("plugin.installation"),
        workspace_ref: target,
        policy_refs: vec![r("policy.plugin")],
        grant_ref: Some(grant),
        decided_by_ref: r("identity.principal"),
        decided_at: "2026-09-04T16:00:00Z".into(),
    };
    assert_eq!(
        ActivationService::authorize(&reopened, &request),
        Err(D05Error::ActivationAuthorityMissing)
    );
}

fn plugin_instance() -> PluginInstanceRecord {
    PluginInstanceRecord {
        instance_ref: r("plugin.instance"),
        plugin_revision_ref: r("plugin.revision"),
        activation_ref: r("plugin.activation"),
        provider_instance_ref: r("runtime.provider_instance"),
        provider_generation: 7,
        generation: 11,
        runtime_aliases: vec!["pid:4242".into()],
    }
}

fn live_capability_grant() -> CapabilityGrantState {
    CapabilityGrantState {
        grant_ref: r("plugin.capability_grant"),
        expires_at_unix: 300,
        revoked: false,
    }
}

#[test]
fn process_id_or_handle_cannot_become_plugin_instance_identity() {
    let instance = plugin_instance();
    assert_eq!(
        instance.instance_ref.entity_kind.as_str(),
        "plugin.instance"
    );
    assert!(
        instance
            .runtime_aliases
            .iter()
            .any(|alias| alias.starts_with("pid:"))
    );
    assert!(!instance.instance_ref.entity_id.to_string().contains("4242"));
}

#[test]
fn stale_health_cannot_claim_ready() {
    let instance = plugin_instance();
    let health = HealthObservation {
        provider_generation: 7,
        instance_generation: 11,
        readiness: true,
        health: "healthy".into(),
        observed_at_unix: 100,
        valid_until_unix: 150,
        evidence_refs: vec![r("core.evidence")],
    };
    assert_eq!(
        PluginRuntime::validate_health(&instance, &health, 200),
        Err(D05Error::StalePluginRuntime)
    );
}

#[test]
fn dependency_binding_is_fenced_by_provider_and_instance_generation() {
    let instance = plugin_instance();
    let binding = DependencyBinding {
        plugin_instance_ref: instance.instance_ref.clone(),
        dependency_key: "database.primary".into(),
        bound_ref: r("runtime.service"),
        provider_generation: 7,
        instance_generation: 10,
        valid_until_unix: 300,
        evidence_refs: vec![r("core.evidence")],
    };
    assert_eq!(
        PluginRuntime::validate_binding(&instance, &binding, 200),
        Err(D05Error::StalePluginRuntime)
    );
}

#[test]
fn revoked_capability_grant_invalidates_service_registration() {
    let instance = plugin_instance();
    let mut grant = live_capability_grant();
    let service = PluginServiceRegistration {
        registration_ref: r("plugin.service_registration"),
        plugin_instance_ref: instance.instance_ref.clone(),
        service_key: "plugin.widget.service".into(),
        provider_generation: 7,
        instance_generation: 11,
        capability_grant_refs: vec![grant.grant_ref.clone()],
        valid_until_unix: 300,
        evidence_refs: vec![r("core.evidence")],
    };
    assert!(PluginRuntime::validate_service(&instance, &service, &[grant.clone()], 200).is_ok());
    grant.revoked = true;
    assert_eq!(
        PluginRuntime::validate_service(&instance, &service, &[grant], 200),
        Err(D05Error::PluginGrantInvalid)
    );
}

#[test]
fn bound_plugin_port_never_becomes_network_exposure_authority() {
    let instance = plugin_instance();
    let grant = live_capability_grant();
    let port = PluginPortRegistration {
        registration_ref: r("plugin.port_registration"),
        plugin_instance_ref: instance.instance_ref.clone(),
        service_registration_ref: r("plugin.service_registration"),
        provider_generation: 7,
        instance_generation: 11,
        network_scope: "workspace".into(),
        protocol: "tcp".into(),
        requested_port: 8080,
        bound_endpoint_alias: "127.0.0.1:48080".into(),
        exposure_policy_refs: vec![r("core.policy")],
        capability_grant_refs: vec![grant.grant_ref.clone()],
        valid_until_unix: 300,
        observed_at: "2026-09-02T16:00:00Z".into(),
    };
    assert!(PluginRuntime::validate_port(&instance, &port, &[grant], 200).is_ok());
    assert!(!port.grants_network_exposure());
}
