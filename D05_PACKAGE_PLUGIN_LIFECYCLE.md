# D05 — Package and Plugin Lifecycle

## Status

Programme D05 implementation and exact-head proof record.

Accepted predecessor: `57467b3fb81ecfeb391281775dc95badcd300297` (verified D04 merge).

D05 implements exact package discovery/resolution/locking, public/private and licence admission, canonical package installation/verification, canonical Plugin catalog/compatibility/installation/activation, fenced Plugin runtime evidence, and verified update/rollback/removal. It adds no new canonical identity family, secret store, semantic Provider chooser, automatic activation, network-exposure authority, or package/plugin-host authority.

## Authority boundaries

- A03 remains canonical persistence and frozen-schema validation authority.
- A04 remains Activity/Operation/Attempt execution and completion/proof authority.
- A06/WP11 remains Workspace and Secure Grant authority.
- A07 remains exact Object/Revision/Artifact truth.
- D04 remains service/port registration and execution-plan composition authority.
- Package managers, registries, Plugin hosts, MCP/workflow engines, PIDs, process handles and backend aliases remain adapters/evidence only.

## Delivered package

`crates/ptah-package-plugin` provides:

- exact `PackageCoordinate`, trust-bound RegistrySource, constraints, resolved graph and deterministic lock projections;
- public/private/licence admission using real A06 Workspace authority;
- A04-backed Package install/retry with ACK retained as evidence only;
- A03 canonical Package Installation and independent Package Verification;
- bounded A03 ingest for all seven frozen WP10 Package catalog schema/kind pairs;
- stable Plugin + immutable Plugin Revision + exact-context Compatibility persistence;
- separate canonical Plugin Installation and Activation records;
- bounded A03 ingest for all nine frozen Plugin runtime/lifecycle schema/kind pairs;
- A06-scoped activation policy/Grant checks including expiry;
- Plugin Instance/Provider generation fencing, expiring health and capability-Grant validation;
- dependency/service/port validation with D04 port semantics and no exposure authority;
- update decision separated from A04 execution;
- fresh A04 update/rollback/removal attempts with independent post-verification;
- staged typed Plugin removal proof and host replacement without rekeying Plugin identity.

## Canonical persistence

Package lifecycle persistence uses frozen `package.installation` and `package.verification` schemas. The Package store also exposes a bounded canonical ingest path for `package.package`, `package.revision`, `package.manifest`, `package.dependency_constraint`, `package.resolved_graph`, `package.lock_record`, and `package.registry_source`; A03 performs complete frozen-schema validation.

Plugin persistence writes `plugin.plugin`, `plugin.revision`, `plugin.compatibility`, `plugin.installation`, and `plugin.activation` directly through A03. It also exposes a bounded canonical ingest path for `plugin.instance`, `plugin.health_observation`, `plugin.capability_grant`, `plugin.dependency_binding`, `plugin.service_registration`, `plugin.port_registration`, `plugin.update_decision`, `plugin.rollback`, and `plugin.removal`. D05 does not maintain a parallel canonical database.

## Execution and verification laws

- install ACK != package verification;
- signature verification != functionality verification;
- install retries use fresh A04 Attempts;
- Plugin installation != activation;
- activation requires explicit policy + current scoped A06 Grant;
- stale/revoked Grants and stale Provider/Instance generations fail closed;
- PID/handle aliases never become Plugin Instance identity;
- stale health cannot claim readiness;
- service/dependency/port bindings are generation/Grant-fenced;
- port binding never creates network exposure authority;
- update decision != execution;
- rollback uses fresh A04 identities and requires post-verification;
- uninstall ACK != verified removal;
- removal requires disable/revoke/stop/unregister/uninstall/cleanup evidence;
- Plugin-host replacement preserves Plugin identity while advancing runtime generation.

## Acceptance evidence

The frozen D05 milestone corpus contains exactly **30 acceptance tests**, corresponding to the 30 cases in the committed D05 design specification. Fresh pre-freeze proof includes strict `clippy -D warnings -W clippy::pedantic`, D01/D02/D03/D04, A03/A04/A06/A07/A10 targeted regressions and the complete `cargo test --workspace --locked`. The inherited `ptah-control` missing-documentation warnings remain pre-existing baseline warning debt.

## Dependency / lock delta

D05 introduces no new external dependency version and no git dependency. `Cargo.lock` adds only one new workspace package stanza: `ptah-package-plugin`, whose dependencies are existing workspace crates plus already-pinned `serde`, `serde_json`, `sha2` and `thiserror 2.0.17`. No pre-existing package version/source entry moves.

## Exact-head proof requirements

The final D05 workflow proves on the frozen candidate SHA: exact D04 predecessor, linear history, approved path scope, no frozen contract/schema/migration/generated drift, reviewed single-package lock delta, Rust/Cargo 1.97.1, fmt, strict Clippy, no unsafe/TODO/FIXME/unimplemented/raw-secret/public-authority escape, exactly 30 D05 acceptance tests, targeted predecessor regressions, complete locked workspace, and a retained candidate/file SHA-256 evidence artifact.

## Explicit deferrals

D05 does not implement D06 provenance/SBOM/signing/proof bundles, D07 security evidence/reproduction, D08 platform expansion, D09 full-workspace release acceptance, Programme E distribution, or Programme F OS-ready mechanics.
