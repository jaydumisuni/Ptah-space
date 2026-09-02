# D04 Recipes and Service Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Programme D04 as a provider-independent Recipe, operation-descriptor, precondition, schedule, service-registry and A04-dispatch composition without adding authority or a new Core identity family.

**Architecture:** Add one `ptah-recipe-registry` crate. WP07 Recipe/Revision/Proposal/Acceptance/Compiled Plan records persist through A03; D04 descriptors/plans/schedules/service registrations are deterministic projections or manifests. A04 remains Operation/Attempt authority, WP11 remains Grant/exposure authority, and A10 integration is mechanical only.

**Tech Stack:** Rust 1.97.1; edition 2024; `ptah-contracts`, `ptah-identifiers`, `ptah-ledger`, `ptah-activity-runtime`, `ptah-provider-api`, `container-oci`, `serde`, `serde_json`, `sha2`, `thiserror`.

**Spec:** `docs/superpowers/specs/2026-09-02-d04-recipes-service-registry-design.md`

## Global Constraints

- Exact predecessor: `ee07fdbe62167ed1fe4a81b47797c744a9393337`; design commit `b58ebc7` remains first D04 commit.
- Roadmap authority: `98dc8c4e8639cda80510bee0625db34b4fdf9384`.
- No external dependency additions/version movement; no git dependencies.
- No `contracts/`, `schemas/`, `migrations/`, or generated-contract changes.
- No new canonical Schedule/Service/Port/Approval/Operation/ResultHandle family.
- WP07 owns Recipe authority; A04 owns execution/retry; WP11 owns Grants/exposure.
- No D05 Plugin lifecycle, D06 trust/signing completion, or D07 security/reproduction.
- No public raw secret-value field; registration never grants network exposure.
- Every production behavior is RED -> observed failure -> minimal GREEN -> refactor.

## Files

Create `crates/ptah-recipe-registry/{Cargo.toml,src/{lib.rs,error.rs,operation.rs,recipe_store.rs,plan.rs,precondition.rs,schedule.rs,service_registry.rs,dispatcher.rs,adapters/{mod.rs,a10.rs}},tests/d04_acceptance.rs}`, `D04_RECIPES_SERVICE_REGISTRY.md`, `.github/workflows/d04-recipes-service-registry-proof.yml`. Modify only root `Cargo.toml` and `Cargo.lock` outside that surface.

---

### Task 1: Scaffold and operation descriptors

**Files:** root `Cargo.toml`; new crate manifest; `src/{lib,error,operation}.rs`; `tests/d04_acceptance.rs`.

**Produces:** `D04Error`, `OperationEffectClass`, `OperationDescriptorRevision`, `OperationCatalog`, `OperationResolution`.

- [ ] **RED:** add the package/test target first, then tests for exact seven effects, A04 compatibility, deterministic descriptor digest, and ambiguity retention. Core test shape:

```rust
assert_eq!(OperationEffectClass::ALL.len(), 7);
let mut d = descriptor("workspace.delete", 4);
d.effect = OperationEffectClass::Destructive;
d.a04_side_effect = SideEffectClass::ObservationOnly;
assert!(matches!(d.validate(), Err(D04Error::EffectCompatibility { .. })));
let mut c = OperationCatalog::default();
c.register(descriptor("source.search", 2)).unwrap();
c.register(descriptor("source.search", 3)).unwrap();
assert_eq!(c.resolve("source.search", None, None).unwrap().candidates().len(), 2);
```

Run `cargo test -p ptah-recipe-registry --test d04_acceptance --locked exposes_exact_adr0037_effect_vocabulary`; verify failure is missing production API.

- [ ] **GREEN:** implement exact enum `[Observe,Draft,Simulate,Mutate,Publish,Destructive,ExternalSideEffect]`, descriptor fields from the spec, SHA-256 digest over field-ordered serialized data, and compatibility rules: observe/simulate=>ObservationOnly; draft=>ObservationOnly|Reversible; mutate=>Reversible|IdempotentMutation|NonIdempotentMutation; publish/external=>ExternalAuthoritative|NonIdempotentMutation; destructive=>Destructive. Catalog filters only exact caller Facility/Provider constraints and never ranks candidates.

- [ ] Run `cargo test -p ptah-recipe-registry --test d04_acceptance --locked` and strict Clippy. Commit `feat(d04): add operation descriptor registry`.

---

### Task 2: Canonical WP07 Recipe store

**Files:** `src/recipe_store.rs`, exports/errors, acceptance tests.

**Produces:** `RecipeStore`, `RecipeInput`, `RecipeRevisionInput`, `RecipeStepInput`, `RecipeProposalInput`, `RecipeAcceptanceInput`, `CompiledPlanRecordInput`, `AcceptanceDecision`.

- [ ] **RED:** tests: Recipe/revision survives ledger reopen; revision number is immutable/monotonic; Proposal does not imply Acceptance; Acceptance must bind the exact Proposal+Revision; rejected/expired Acceptance blocks planning; backend replacement produces a distinct Compiled Plan without changing Recipe identity.

```rust
let created = create_recipe_revision_and_proposal(&mut store);
assert!(matches!(store.accepted_revision(created.revision_ref.entity_id), Err(D04Error::AcceptanceMissing { .. })));
```

Run the focused missing-API test and observe RED.

- [ ] **GREEN:** use exact frozen IDs:

```text
build.recipe                 urn:ptah:schema:build:build-recipe:0.1.0 / 0.1.0
build.recipe_revision        urn:ptah:schema:build:build-recipe-revision:0.1.1 / 0.1.1
build.recipe_proposal        urn:ptah:schema:build:build-recipe-proposal:0.1.0 / 0.1.0
build.recipe_acceptance      urn:ptah:schema:build:build-recipe-acceptance:0.1.0 / 0.1.0
build.compiled_plan          urn:ptah:schema:build:compiled-plan:0.1.0 / 0.1.0
```

Construct canonical nested envelopes, call `CanonicalRecord::from_document`, then `begin_write()->insert()->commit()`. Validate unique step keys, dependency existence/acyclicity, binding references, exact Proposal->Revision equality, Acceptance decision/expiry, and exact Plan->Revision+Acceptance binding. Never mutate Recipe Revision.

- [ ] Run focused tests then full crate; commit `feat(d04): persist canonical recipe authority`.

---

### Task 3: Staged execution plan and secret boundary

**Files:** `src/plan.rs`, exports/errors/tests.

**Produces:** `ExecutionStage`, `ParameterValue`, `ParameterBinding`, `CredentialBinding`, `PlannedOperation`, `ExecutionPlanManifest`, `compile_execution_plan`.

- [ ] **RED:** tests for stage monotonicity, verify separate from execute, deterministic/order-sensitive plan digest, undeclared parameter/credential/service rejection, and reference-only credentials.

```rust
assert!(matches!(plan_with_stages([ExecutionStage::Verify, ExecutionStage::Execute]).validate(), Err(D04Error::InvalidStageOrder)));
let j = serde_json::to_value(CredentialBinding{ requirement_key:"registry.auth".into(), credential_ref:reference("security.credential_reference"), provider_or_service_scope_ref:None }).unwrap().to_string();
for x in ["password","api_key","secret_value","raw_secret"] { assert!(!j.contains(x)); }
```

- [ ] **GREEN:** exact stages `Observe,Draft,Simulate,Execute,Verify`. Validate recipe dependency/stage order, descriptor digest/key, declared inputs/services/credentials, stage/effect compatibility, and exact selected Provider. `compile_execution_plan` returns ambiguity instead of selecting. Digest private field-ordered serialized representation with SHA-256.

- [ ] Run tests and `! grep -R -n -E 'pub[[:space:]]+(password|token|api_key|secret_value|raw_secret)[[:space:]]*:' crates/ptah-recipe-registry/src`; commit `feat(d04): add deterministic staged recipe plans`.

---

### Task 4: Exact preconditions

**Files:** `src/precondition.rs`, exports/errors/tests.

**Produces:** `PreconditionKind`, `ExactPrecondition`, `ObservedPrecondition`, `PreconditionConflict`, `evaluate_preconditions`.

- [ ] **RED:** one table test covers `ObjectRevisionDigest`, `CanonicalRecordRevision`, `GitBranchHead`, `DraftRevision`, `StateMachineState`, `ProviderFreshness`; another proves moved target returns expected/observed/evidence and blocks dispatch.

```rust
let conflict=evaluate_preconditions(&[expected],[observed]).expect_err("conflict");
assert_eq!(conflict.expected,"aaaaaaaa");
assert_eq!(conflict.observed.as_deref(),Some("bbbbbbbb"));
```

- [ ] **GREEN:** pair strictly by kind+target+selector; exact string/revision/generation comparison only; missing observation is conflict with `observed=None`; no fuzzy matching/refresh/reconciliation.

- [ ] Run focused tests; commit `feat(d04): enforce exact recipe preconditions`.

---

### Task 5: Schedule semantics

**Files:** `src/schedule.rs`, exports/errors/tests.

**Produces:** `ScheduleKind`, `TimingMode`, `ScheduleSpec`, `ScheduledRecipeInvocation`, `ScheduleEvaluation`, `evaluate_schedule`.

- [ ] **RED:** enforce matrix: one_off=>exact|flexible_window; recurring=>exact|flexible_window; condition_watch=>condition_dependent only. Prove scheduled invocation freezes exact Workspace, Recipe Revision/Acceptance, plan digest/ref, immutable inputs, Provider refs, Grant refs, preconditions, outputs, caller—no hidden context. Test not_due/due/condition_false/condition_true/invalidated_by_precondition.

- [ ] **GREEN:** schedules store mechanical caller data only. Recurrence remains a non-empty caller expression; evaluation consumes explicit `occurrence_due`/condition evidence rather than implementing a new global scheduler. UTC values are strict `YYYY-MM-DDTHH:MM:SSZ` lexically comparable strings; no new time dependency.

- [ ] Run focused tests; commit `feat(d04): add caller-authored schedule semantics`.

---

### Task 6: Service/port registry and A10 adapter

**Files:** `src/service_registry.rs`, `src/adapters/{mod,a10}.rs`, exports/errors/tests.

**Produces:** `ServiceRegistration`, `PortRegistration`, `ServiceRegistry`, `ServiceResolution`; private A10 adapter.

- [ ] **RED:** stale Provider generation rejected; expired service unavailable; two live services remain ambiguous; port missing Policy or Grant fails; `grants_network_exposure()==false`; A10 network/mount widening fails.

```rust
let mut p=port_registration(); p.exposure_policy_refs.clear();
assert!(matches!(p.validate(),Err(D04Error::ExposureAuthorityMissing)));
assert!(!port_registration().grants_network_exposure());
```

- [ ] **GREEN:** resolve only exact current/expiry/generation candidates. Preserve multiple candidates. Port registration requires explicit Policy+Grant refs but cannot create authority. A10 adapter may compare/project existing `NetworkPolicy`/`MountRequest`; any requested ref beyond them returns `AuthorityWidening`. No public function named `grant`, `authorize_exposure`, `open_port`, or `publish_port`.

- [ ] Run tests and static API grep; commit `feat(d04): add non-authoritative service registry`.

---

### Task 7: Thin dispatcher into A04

**Files:** `src/dispatcher.rs`, exports/errors/tests.

**Produces:** `RecipeDispatchRequest`, `RecipeDispatchMapping`, `RecipeDispatcher`.

- [ ] **RED:** conflict creates no A04 Activity/Attempt; each scheduled occurrence creates distinct Attempts; A10 start ACK cannot make A04 Operation succeeded.

- [ ] **GREEN:** sequence is exactly: validate Recipe/Acceptance/Plan binding -> evaluate preconditions -> `create_activity` -> `admit_next` -> for each ready planned operation `create_operation` -> `make_operation_ready` -> `create_attempt`. Preserve Recipe step/stage mappings. D04 never calls A04 success/proof or retry methods.

- [ ] Run D04 focused tests and `cargo test -p ptah-activity-runtime --test a04_acceptance --locked`; commit `feat(d04): dispatch accepted recipes through a04`.

---

### Task 8: Freeze 30-case corpus and implementation record

**Files:** complete `tests/d04_acceptance.rs`; create `D04_RECIPES_SERVICE_REGISTRY.md`.

- [ ] Complete exactly 30 tests covering: 1 restart persistence; 2 monotonic immutable revision; 3 Proposal != Acceptance; 4 exact acceptance binding; 5 rejected/expired acceptance; 6 backend replacement; 7 descriptor digest; 8 seven effects; 9 A04 compatibility; 10 operation ambiguity; 11 stage order; 12 plan digest; 13 undeclared inputs; 14 credential reference-only; 15 six exact preconditions; 16 moved target conflict; 17 schedule matrix; 18 exact scheduled inputs; 19 fresh scheduled Attempt; 20 stale service; 21 expired service; 22 service ambiguity; 23 port authority refs; 24 bound port not authority; 25 A10 no widening; 26 ACK not success; 27 D03 refs as exact materials; 28 B07 result not auto-accepted; 29 predecessor integration invariants; 30 no semantic chooser/approver/promoter/scheduler authority.

- [ ] Prove count:

```bash
test "$(cargo test -p ptah-recipe-registry --test d04_acceptance --locked -- --list | grep -c ': test$')" -eq 30
cargo test -p ptah-recipe-registry --locked
```

- [ ] Implementation record states predecessor, roadmap/design authority, package/dependency surface, 30 cases, non-authority boundaries, local proof commands, and D05/D06/D07 deferrals. Do not embed unknown final candidate SHA.

- [ ] Run inherited regressions:

```bash
cargo test -p ptah-activity-runtime --test a04_acceptance --locked
cargo test -p container-oci --locked
cargo test -p ptah-ai-workspace -p ptah-knowledge-search -p ptah-control -p ptah-transfer -p ptah-object-store -p ptah-workspace --locked
```

Commit `test(d04): freeze recipes service registry corpus`.

---

### Task 9: Exact-head workflow, freeze, PR, merge

**Files:** `.github/workflows/d04-recipes-service-registry-proof.yml`; implementation record only if proof-contract prose needs completion before freeze.

- [ ] Adapt D03 exact-head structure. Set `PTAH_D03_SHA=ee07fdbe62167ed1fe4a81b47797c744a9393337`. Allowed surface is only root Cargo files, D04 record, new crate, D04 spec/plan, D04 workflow. Reject contract/schema/migration/generated drift.

- [ ] Cargo-lock guard: no removed/modified pre-existing package entries; only new workspace package `ptah-recipe-registry`; no new external dependency package; no git dependencies.

- [ ] Static gates: Rust 1.97.1; fmt; strict Clippy; `#![forbid(unsafe_code)]`; no TODO/FIXME/todo!/unimplemented!/unsafe block; no public raw-secret field; no public exposure-grant/open-port API; no semantic chooser/approval/promotion/global-scheduler API.

- [ ] Runtime gates: D04 count exactly 30; D04 package; A04; A10; D01/D02/D03/Programme-B targeted regressions; full `cargo test --workspace --locked`.

- [ ] Proof artifact contains exact head/tree, D03 predecessor, linear commit count, Cargo.lock SHA-256, D04 count, workspace count, changed-file SHA-256 map. Artifact upload is required.

- [ ] Validate YAML text/static invariants locally, commit workflow as `ci(d04): prove exact recipes service registry head`. That commit becomes frozen candidate; no tracked changes afterward unless a defect creates a new candidate.

- [ ] Re-prove exact candidate locally: clean tree, predecessor ancestry, no merges, diff-check, fmt, strict Clippy, D04 count=30, targeted regressions, complete locked workspace.

- [ ] Push branch `d04-recipes-service-registry`; create PR to `main`; verify PR `headRefOid` equals local candidate. Require the D04 exact-head GitHub job itself to pass; classify predecessor-pinned milestone failures separately.

- [ ] Merge only with `gh pr merge <PR> --merge --match-head-commit <D04_SHA>`. Fetch `origin/main` and verify merge parents are exactly `<merge> ee07fdbe... <D04_SHA>`. Verify worktree clean, then recover D05 authority before D05 code.
