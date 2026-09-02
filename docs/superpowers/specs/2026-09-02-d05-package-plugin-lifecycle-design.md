# D05 — Package and Plugin Lifecycle Design

## Authority

Roadmap authority: `ptah-roadmap-` commit `98dc8c4e8639cda80510bee0625db34b4fdf9384`.
Accepted predecessor: D04 merge `57467b3fb81ecfeb391281775dc95badcd300297`.

D05 delivers discovery, install, exact pinning, activation, health, rollback/removal, public/private controls, and licence enforcement. It reuses the frozen WP10 knowledge/package/plugin catalog and WP11 Grant authority; it does not create a new canonical entity family.

## Architecture

Add one composition crate: `crates/ptah-package-plugin`.

The crate composes:

- A03 ledger for canonical Package/Plugin WP10 records;
- A04 Activity/Operation/Attempt for every mutating install/activate/update/rollback/removal action;
- A06/WP11 Workspace and secure-Grant authority;
- A07 Object/Revision/Artifact truth for exact package/plugin bytes;
- D04 operation descriptor/Recipe/service boundaries;
- `ptah-contracts` frozen WP10 schema identities.

Package-manager, registry, marketplace, Plugin-host, MCP/workflow engines, PIDs, tags and aliases remain adapters/evidence. None becomes canonical Ptah identity or policy truth.

## Components

### 1. Package catalog and exact resolution

`PackageStore` persists stable `knowledge.package` plus immutable `package_revision`, `package_manifest`, `package_dependency_constraint`, `package_resolved_graph`, `package_lock_record`, `package_registry_source`, `package_installation`, and `package_verification` records using A03 canonical writes.

Discovery returns `PackageCandidate` records containing registry/source aliases, trust evidence, visibility and licence observations. Discovery never equals admission. `PackageCoordinate` is exact only after ecosystem, namespace, source revision/object revision, version and digest are fixed.

`PackageLock` retains exact package revision, source and digest bindings. Constraint, resolution and lock stay separate.

### 2. Distribution and licence admission

D05-owned admission projections are mechanical and non-canonical:

- `DistributionClass::{Public, Private}`;
- `LicenceDecision::{Allowed, ReviewRequired, Denied}`;
- `PackageAdmission` binding exact package revision, source/trust-policy refs, audience, licence record refs and decision evidence.

Private packages require explicit Workspace access. Public discovery does not bypass licence or trust policy. Raw credentials never enter manifests, records, logs or exports.

### 3. Package installation and verification

`PackageInstaller` accepts only an exact Package Revision + Resolved Graph + Lock Record + Workspace + Provider generation + A04 authority. Backend install acknowledgement is retained as evidence only. The installation remains unverified until independent `PackageVerification` scopes prove integrity and installed state; signature verification cannot claim functionality.

Retries always create a fresh A04 Attempt. Backend replacement preserves Package identity but creates new installation/verification evidence.

### 4. Plugin catalog and compatibility

`PluginStore` persists stable `knowledge.plugin` plus immutable Plugin Revision/Manifest/Compatibility records. Plugin Revision binds exact Object Revisions and package locks. Compatibility is exact-context, evidence-bound and expiring.

Installation never implies activation. Activation requires explicit policy refs and current scoped Grant refs.

### 5. Plugin activation, instance and health

`PluginLifecycle` separates:

`discovered → inspected → approved_for_install → installing → installed → disabled → activating → active/degraded/...`

Canonical WP10 Installation, Activation, Instance, Health Observation and Capability Grant records remain distinct. Instance identity is Ptah identity; runtime PID/handle is alias evidence only. Instance binds exact Provider and instance generations. Health expires and cannot outlive either generation. Expired/revoked Grants cannot authorize service, dependency or port bindings.

### 6. Service/port and dependency registrations

D05 reuses D04 registry semantics but canonical Plugin Service/Port/Dependency Binding records retain exact Plugin Instance, Provider generation, Instance generation, Grant refs and validity windows. Port registration is never network exposure authority.

### 7. Update, rollback and removal

`PluginUpdateDecision` is decision evidence only. Update execution requires a new A04 Operation/Attempt and new exact Plugin Revision evidence.

Rollback is a fresh Activity/Operation/Attempt and remains incomplete until post-rollback verification succeeds.

Removal is staged and separately evidenced:

1. disable activation;
2. revoke grants;
3. stop instances;
4. unregister services/ports/bindings;
5. uninstall package materialization;
6. apply explicit retention/deletion policy;
7. run cleanup verification.

Uninstall ACK alone cannot claim removal complete.

## Provider interfaces

Public D05 contracts remain backend-neutral. Private adapters may implement package discovery/install/uninstall and Plugin host start/stop/readback, but D05 exposes no raw command, PID identity, registry token, raw credential or framework-native authority.

Backend acknowledgements are never operation success. A04 proof/readback remains authoritative for execution state.

## Failure model

D05 fails closed on:

- non-exact coordinates or digest/source drift;
- lock/manifest/package revision mismatch;
- untrusted, expired or wrong registry source;
- denied/review-required licence without explicit governed decision;
- private package access without Workspace authority;
- reused Attempts;
- install ACK presented as verification;
- activation without policy + current Grants;
- stale/revoked Grants;
- stale Provider/Instance generation;
- stale health;
- update decision presented as execution;
- rollback/removal lacking independent verification;
- raw secret/credential material in contract/evidence surfaces;
- framework/backend aliases replacing Ptah identities.

Failed, partial, unsupported, stale and inconclusive states remain queryable history.

## Acceptance corpus

D05 freezes 30 milestone cases. Required cases include all WP10 package/plugin laws and golden fixtures:

1. exact package coordinate required;
2. exact lock binds revisions/sources/digests;
3. constraint ≠ resolution ≠ lock;
4. registry source trust/expiry enforced;
5. public discovery ≠ install admission;
6. private package requires Workspace authority;
7. denied licence blocks admission;
8. review-required licence remains unresolved;
9. raw credentials absent from records/evidence;
10. install ACK ≠ package verification;
11. installed-unverified → independently verified;
12. signature verification ≠ functionality;
13. package retry uses fresh Attempt;
14. package-manager replacement preserves Package identity/new evidence;
15. Plugin Revision binds exact Manifest/Objects/package locks;
16. Plugin installation ≠ activation;
17. activation requires policy + scoped Grants;
18. expired/revoked Grant blocks runtime authority;
19. PID/handle cannot become Plugin Instance identity;
20. stale health cannot claim ready;
21. dependency binding fences Provider/Instance generation;
22. service registration dies with revoked Grant;
23. bound port ≠ exposure authority;
24. update decision ≠ execution;
25. successful update creates new revision/generation evidence;
26. rollback requires fresh Attempt + post-verification;
27. removal ACK ≠ cleanup verification;
28. verified removal proves revoke/stop/unregister/uninstall/cleanup separately;
29. Plugin-host replacement preserves Plugin identity/new generation;
30. MCP/workflow/plugin-host IDs never replace Ptah Core identities.

Inherited A03/A04/A06/A07/D04/D03/WP10-related regressions and the complete locked workspace must stay green.

## Proof and shipping

D05 uses the established milestone flow: bounded implementation commits, strict fmt/Clippy with no D05 warnings or suppressions, frozen-contract and Cargo-lock audits, exact 30-case count, targeted predecessor regressions, full `cargo test --workspace --locked`, exact-head GitHub workflow, frozen SHA, PR, CI proof, merge-only-the-proven-head, and merge-parent verification.
