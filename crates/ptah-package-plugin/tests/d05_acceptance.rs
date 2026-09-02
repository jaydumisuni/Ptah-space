#![allow(missing_docs)]
use ptah_identifiers::EntityRef;
use ptah_package_plugin::{
    D05Error, PackageCandidate, PackageCatalog, PackageConstraint, PackageCoordinate,
    RegistrySource,
};

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
