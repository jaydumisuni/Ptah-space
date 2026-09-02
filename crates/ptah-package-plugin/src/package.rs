use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::D05Error;

/// Immutable exact package coordinate after discovery aliases have been resolved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageCoordinate {
    /// Package ecosystem, for example `cargo`.
    pub ecosystem: String,
    /// Registry/package namespace.
    pub namespace: String,
    /// Stable package key within the namespace.
    pub package_key: String,
    /// Exact package version.
    pub version: String,
    /// Exact source revision.
    pub source_revision_ref: EntityRef,
    /// Exact retained content Object Revision.
    pub content_object_revision_ref: EntityRef,
    /// Lowercase SHA-256 hex digest of the exact content.
    pub content_sha256: String,
}

impl PackageCoordinate {
    /// Validate that all immutable identity fields are present and digest-shaped.
    ///
    /// # Errors
    ///
    /// Returns [`D05Error::InexactPackageCoordinate`] when any identity field is missing or malformed.
    pub fn validate_exact(&self) -> Result<(), D05Error> {
        let text = [
            &self.ecosystem,
            &self.namespace,
            &self.package_key,
            &self.version,
        ];
        if text.iter().any(|v| v.trim().is_empty())
            || self.source_revision_ref.entity_kind != "knowledge.source_revision"
            || self.content_object_revision_ref.entity_kind != "core.object_revision"
            || !valid_sha256(&self.content_sha256)
        {
            return Err(D05Error::InexactPackageCoordinate);
        }
        Ok(())
    }
}

/// Exact registry-source observation used only for mechanical package resolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrySource {
    /// Caller-visible registry key/alias.
    pub registry_key: String,
    /// Package ecosystem served by the registry.
    pub ecosystem: String,
    /// Exact source revision describing this registry observation.
    pub source_revision_ref: EntityRef,
    /// Trust-policy references applied to the observation.
    pub trust_policy_refs: Vec<EntityRef>,
    /// Observation timestamp in Unix seconds.
    pub observed_at_unix: i64,
    /// Expiry timestamp in Unix seconds.
    pub valid_until_unix: i64,
    /// Mechanical trust-policy outcome; not package acceptance.
    pub trusted: bool,
}

/// One discovered package candidate; discovery is not admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageCandidate {
    /// Exact candidate coordinate.
    pub coordinate: PackageCoordinate,
    /// Registry observation that produced the candidate.
    pub registry: RegistrySource,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EntityRef>,
}

/// Caller-authored dependency constraint kept separate from resolution and lock state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageConstraint {
    /// Dependency key.
    pub dependency_key: String,
    /// Exact caller constraint expression.
    pub expression: String,
}

/// One mechanically resolved package node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPackageNode {
    /// Canonical immutable package revision identity.
    pub package_revision_ref: EntityRef,
    /// Exact package coordinate.
    pub coordinate: PackageCoordinate,
}

/// Resolved dependency graph projection; distinct from constraints and the immutable lock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedGraph {
    /// Resolved nodes.
    pub nodes: Vec<ResolvedPackageNode>,
    /// Deterministic digest of resolution inputs/output.
    pub resolution_digest_sha256: String,
}

/// Immutable package entry retained by a lock record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedPackage {
    /// Exact package revision.
    pub package_revision_ref: EntityRef,
    /// Exact source revision.
    pub source_revision_ref: EntityRef,
    /// Exact retained Object Revision.
    pub content_object_revision_ref: EntityRef,
    /// Exact content digest.
    pub content_sha256: String,
}

/// Deterministic immutable package lock projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageLock {
    /// Locked entries in deterministic caller order.
    pub entries: Vec<LockedPackage>,
    /// Deterministic digest over all locked entries.
    pub digest_sha256: String,
}

/// Backend-neutral mechanical package catalog.
#[derive(Clone, Debug)]
pub struct PackageCatalog {
    now_unix: i64,
}

impl PackageCatalog {
    /// Create a catalog view at an explicit caller-supplied observation time.
    #[must_use]
    pub const fn new(now_unix: i64) -> Self {
        Self { now_unix }
    }

    /// Resolve one already-discovered exact package candidate.
    ///
    /// # Errors
    ///
    /// Returns an error when the coordinate or registry observation is not exact/current/trusted.
    pub fn resolve_exact(&self, candidate: &PackageCandidate) -> Result<ResolvedGraph, D05Error> {
        candidate.coordinate.validate_exact()?;
        self.validate_registry(candidate)?;
        let package_revision_ref = EntityRef::new("knowledge.package_revision")
            .map_err(|_| D05Error::InexactPackageCoordinate)?;
        let node = ResolvedPackageNode {
            package_revision_ref,
            coordinate: candidate.coordinate.clone(),
        };
        let resolution_digest_sha256 = digest_json(&node);
        Ok(ResolvedGraph {
            nodes: vec![node],
            resolution_digest_sha256,
        })
    }

    /// Resolve a candidate while retaining the caller constraint as separate input.
    ///
    /// # Errors
    ///
    /// Returns an error for a constraint mismatch or any exact-resolution failure.
    pub fn resolve_with_constraint(
        &self,
        candidate: &PackageCandidate,
        constraint: &PackageConstraint,
    ) -> Result<ResolvedGraph, D05Error> {
        if constraint.dependency_key != candidate.coordinate.package_key
            || constraint.expression.trim().is_empty()
        {
            return Err(D05Error::ConstraintMismatch);
        }
        let mut graph = self.resolve_exact(candidate)?;
        graph.resolution_digest_sha256 = digest_json(&(constraint, &graph.nodes));
        Ok(graph)
    }

    /// Freeze an exact resolved graph into a deterministic lock projection.
    ///
    /// # Errors
    ///
    /// Returns [`D05Error::InexactPackageCoordinate`] when the graph has no resolved nodes.
    pub fn lock(&self, graph: &ResolvedGraph) -> Result<PackageLock, D05Error> {
        if graph.nodes.is_empty() {
            return Err(D05Error::InexactPackageCoordinate);
        }
        let entries = graph
            .nodes
            .iter()
            .map(|node| LockedPackage {
                package_revision_ref: node.package_revision_ref.clone(),
                source_revision_ref: node.coordinate.source_revision_ref.clone(),
                content_object_revision_ref: node.coordinate.content_object_revision_ref.clone(),
                content_sha256: node.coordinate.content_sha256.clone(),
            })
            .collect::<Vec<_>>();
        let digest_sha256 = digest_json(&entries);
        Ok(PackageLock {
            entries,
            digest_sha256,
        })
    }

    fn validate_registry(&self, candidate: &PackageCandidate) -> Result<(), D05Error> {
        let r = &candidate.registry;
        if !r.trusted
            || r.trust_policy_refs.is_empty()
            || r.ecosystem != candidate.coordinate.ecosystem
            || r.source_revision_ref.entity_kind != "knowledge.source_revision"
            || r.observed_at_unix > self.now_unix
            || r.valid_until_unix <= self.now_unix
        {
            return Err(D05Error::RegistrySourceUnavailable);
        }
        Ok(())
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn digest_json<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("serializable D05 value");
    format!("{:x}", Sha256::digest(bytes))
}
