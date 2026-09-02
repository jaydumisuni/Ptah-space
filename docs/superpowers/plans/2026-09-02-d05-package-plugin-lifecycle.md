# D05 Package and Plugin Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Implement the D05 Package/Plugin lifecycle as a backend-neutral composition over frozen WP10 contracts, A03/A04/A06/A07 and D04, with exactly 30 acceptance cases and exact-head proof.

**Architecture:** Add `ptah-package-plugin`. Canonical package/plugin records live in A03 using frozen WP10 schema IDs; D05-owned projections perform admission, lifecycle fencing and backend-neutral orchestration. Backend acknowledgements never become verification or Ptah authority.

**Tech Stack:** Rust 1.97.1, existing workspace crates, serde/serde_json, sha2, thiserror. No new external dependency.

**Spec:** `docs/superpowers/specs/2026-09-02-d05-package-plugin-lifecycle-design.md`

## Global Constraints

- Accepted predecessor is D04 merge `57467b3fb81ecfeb391281775dc95badcd300297`.
- Reuse frozen WP10 schema IDs; do not modify frozen schemas, catalogs, migrations or state machines.
- No raw credentials, package-manager commands, registry tokens, PIDs or framework IDs in canonical identity.
- Mutating install/activate/update/rollback/removal paths require A04 Activity/Operation/Attempt evidence.
- Public/private and licence/trust admission remain explicit and fail closed.
- Installation, verification, activation, instance, health, grant, registration, update, rollback and removal remain separate.

---

### Task 1: Exact package resolution and lock

**Files:** Create `crates/ptah-package-plugin/Cargo.toml`, `src/lib.rs`, `src/error.rs`, `src/package.rs`; modify root `Cargo.toml` and `Cargo.lock`; create `tests/d05_acceptance.rs`.

**Interfaces:**
- `PackageCoordinate { ecosystem, namespace, package_key, version, source_revision_ref, content_object_revision_ref, content_sha256 }` with `validate_exact()`.
- `PackageConstraint`, `ResolvedPackageNode`, `ResolvedGraph`, `LockedPackage`, `PackageLock`.
- `PackageCatalog::discover(Vec<PackageCandidate>)`, `resolve_exact(...)`, `lock(...)`.

- [ ] Write cases 1–4: inexact coordinate rejects; exact lock binds revisions/source/digest; constraint/resolution/lock remain distinct; stale registry source rejects.
- [ ] Run focused test and verify missing D05 package/API RED.
- [ ] Implement package identities, deterministic SHA-256 lock digest and registry validity/trust checks.
- [ ] Run 4/4, fmt and strict Clippy.
- [ ] Commit `feat(d05): add exact package resolution`.

### Task 2: Distribution and licence admission

**Files:** Create `src/admission.rs`; extend `tests/d05_acceptance.rs`.

**Interfaces:**
- `DistributionClass::{Public, Private}`.
- `LicenceDecision::{Allowed, ReviewRequired, Denied}`.
- `PackageAdmissionRequest { actor_ref, source_workspace_id, target_workspace_id, package_revision_ref, distribution, licence_decision, trust_policy_refs, licence_record_refs, evidence_refs, grant_ref }`.
- `AdmissionService::admit(&WorkspaceStore, &PackageAdmissionRequest) -> Result<PackageAdmission, D05Error>`.

- [ ] Write cases 5–9: public discovery != admission; private requires A06 authority; denied blocks; review-required remains unresolved; serialized admission contains no raw credential fields.
- [ ] Prove RED for admission API.
- [ ] Implement exact A06 `authorize_retrieval(..., "plugin.package.install", ...)` delegation and licence/trust policy checks.
- [ ] Run 9/9, strict Clippy and raw-secret source scan.
- [ ] Commit `feat(d05): enforce package admission policy`.

### Task 3: Package installation and independent verification

**Files:** Create `src/install.rs`, `src/store.rs`; extend `src/error.rs` and tests.

**Interfaces:**
- `PackageStore::create_package`, `add_revision`, `record_installation`, `record_verification`, `latest_installation` using A03 canonical writes and frozen WP10 schemas.
- `InstallRequest { package_ref, package_revision_ref, resolved_graph_ref, lock_record_ref, workspace_ref, provider_instance_ref, provider_generation, authority_ref }`.
- `PackageInstallAck { backend_alias, accepted_at, evidence_refs }`.
- `VerificationScope::{Integrity, InstalledState, Functionality, Signature}` and `VerificationDecision`.
- `PackageInstaller::begin_install(&mut ActivityRuntime, ...) -> PackageInstallHandle`; retry always creates fresh Attempt.

- [ ] Write cases 10–14: ACK != verification; installed-unverified then verified; signature != functionality; retry fresh Attempt; backend replacement preserves Package identity/new evidence.
- [ ] Prove RED, implement A04-backed install lifecycle and canonical Installation/Verification records.
- [ ] Run 14/14 plus A03/A04 regressions and strict Clippy.
- [ ] Commit `feat(d05): add verified package installation`.

### Task 4: Plugin identity, compatibility and activation

**Files:** Create `src/plugin.rs`, `src/activation.rs`; extend store/tests.

**Interfaces:**
- `PluginStore::create_plugin`, `add_revision`, `record_compatibility`, `record_installation`, `record_activation`.
- `PluginRevisionInput` binds exact manifest/object/package-lock refs.
- `CompatibilityObservation { target_context, required_capabilities, decision, checked_at, valid_until, evidence_refs }`.
- `ActivationRequest { plugin_revision_ref, installation_ref, workspace_ref, policy_refs, grant_refs, decided_by_ref }`.

- [ ] Write cases 15–18: exact Plugin Revision binding; installation != activation; activation requires policy+Grant; expired/revoked Grant fails.
- [ ] Implement exact compatibility and activation validation using current A06/WP11 Grant evidence.
- [ ] Run 18/18 and strict Clippy.
- [ ] Commit `feat(d05): separate plugin activation authority`.

### Task 5: Instance, health and registrations

**Files:** Create `src/runtime.rs`; extend tests.

**Interfaces:**
- `PluginInstanceRecord { instance_ref, plugin_revision_ref, activation_ref, provider_instance_ref, provider_generation, generation, runtime_aliases }`.
- `HealthObservation { provider_generation, instance_generation, readiness, health, observed_at, valid_until, evidence_refs }`.
- `DependencyBinding`, `PluginServiceRegistration`, `PluginPortRegistration` with validity and Grant refs.
- `PluginRuntime::validate_health`, `validate_binding`, `validate_service`, `validate_port`.

- [ ] Write cases 19–23: PID alias cannot be identity; stale health; dependency generation fence; revoked Grant kills service; port binding != exposure.
- [ ] Implement generation/expiry/Grant fencing and D04 registry compatibility.
- [ ] Run 23/23 plus D04/A10 regressions and strict Clippy.
- [ ] Commit `feat(d05): add fenced plugin runtime state`.

### Task 6: Update, rollback and removal

**Files:** Create `src/change.rs`; extend store/tests.

**Interfaces:**
- `PluginUpdateDecision` separate from execution.
- `PluginChangeExecutor::begin_update`, `begin_rollback`, `begin_removal` each creates fresh A04 authority.
- `RemovalProof { activation_disabled, grants_revoked, instances_stopped, registrations_removed, package_uninstalled, cleanup_verified, evidence_refs }`.

- [ ] Write cases 24–29: decision != execution; successful update creates new revision/generation evidence; rollback fresh Attempt + post-verification; uninstall ACK != cleanup; verified staged removal; Plugin-host replacement preserves identity/new generation.
- [ ] Implement A04-backed change flows and verification gates.
- [ ] Run 29/29 plus A04/D04/A10 regressions and strict Clippy.
- [ ] Commit `feat(d05): add verified plugin change lifecycle`.

### Task 7: Framework boundary and final corpus

**Files:** Extend tests; create `D05_PACKAGE_PLUGIN_LIFECYCLE.md`.

**Interfaces:** no new production authority.

- [ ] Add case 30 proving MCP/workflow/plugin-host aliases cannot replace A04 Activity/A07 Object/Plugin identity.
- [ ] Assert exactly 30 D05 acceptance tests.
- [ ] Run D01/D02/D03/D04/A03/A04/A06/A07/A10/B07 targeted regressions and complete `cargo test --workspace --locked`.
- [ ] Write durable implementation record with exact limitations and acceptance map.
- [ ] Commit `test(d05): freeze package plugin lifecycle corpus`.

### Task 8: Exact-head proof and ship

**Files:** Create `.github/workflows/d05-package-plugin-lifecycle-proof.yml`.

- [ ] Lock exact D04 predecessor and reviewed D05 changed-file surface.
- [ ] Assert Cargo.lock adds only `ptah-package-plugin` and no existing dependency version moves.
- [ ] Run fmt, strict Clippy, raw-secret/framework/PID/public-authority leakage guards, exactly 30 D05 tests, targeted predecessor regressions and full locked workspace.
- [ ] Commit workflow; this commit becomes frozen candidate SHA.
- [ ] Re-run every proof locally on frozen SHA; require clean worktree.
- [ ] Push exact branch, open PR against `main`, require D05 exact-head workflow success, classify predecessor-pinned historical failures only from their logs.
- [ ] Merge with head SHA pin and verify `origin/main` parents are prior D04 main + frozen D05 candidate.
