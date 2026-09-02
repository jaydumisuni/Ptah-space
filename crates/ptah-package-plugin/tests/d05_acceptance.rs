#![allow(missing_docs)]
use ptah_identifiers::{EntityId, EntityRef};
use ptah_package_plugin::{
    AdmissionService, D05Error, DistributionClass, LicenceDecision, PackageAdmissionRequest,
    PackageCandidate, PackageCatalog, PackageConstraint, PackageCoordinate, RegistrySource,
};
use ptah_workspace::{CreateWorkspace, WorkspaceStore};
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
