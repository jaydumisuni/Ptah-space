# D04 — Recipes and Service Registry Design

## 1. Status and authority

This specification defines Programme D04 — **Recipes and service registry**.

Implementation base:

`ee07fdbe62167ed1fe4a81b47797c744a9393337`

That commit is the verified D03 merge on `Ptah-space/main`.

Roadmap authority was freshly recovered at `ptah-roadmap-` commit:

`98dc8c4e8639cda80510bee0625db34b4fdf9384`

The operative D04 roadmap requires deterministic Recipes, versioned proposals/acceptance, service/exposed-port registry, reusable execution plans and parameter/secret boundaries. ADR-0037 additionally requires versioned operation descriptors, mechanical effect metadata, staged observe/draft/simulate/execute/verify Recipes, schedules and exact preconditions.

Dependencies are A04, A10, Programme B and D03. Frozen WP07 is the canonical Recipe/Build authority. Frozen WP10 supplies the future Plugin service/port identities and cross-machine authority rules. WP11 remains Grant/network/filesystem authority. D04 does not reopen WP01–WP14.

## 2. Design objective

D04 makes caller-defined reusable work mechanically representable and executable without turning Ptah into a planner, approver, semantic Provider chooser or global scheduler.

The flow is:

```text
caller/provider operation descriptors
        ↓
exact caller-authored Recipe Revision
        ↓
separate Proposal + authorized Acceptance
        ↓
backend-specific deterministic Execution Plan
        ↓
exact parameters / credential references / preconditions / schedule
        ↓
A04 Activity → Operation → Attempt execution
        ↓
Receipt / partial outputs / verification evidence
```

Service/port registration is a parallel derived registry:

```text
current Provider/Plugin observation + Grants + Policy + generation
        ↓
D04 Service Registry projection
        ↓
exact service lookup / ambiguity / expiry
```

Registration never grants network exposure and never starts a workload.

## 3. Chosen architecture

Add one new workspace crate:

`crates/ptah-recipe-registry`

The crate composes existing Ptah identities and has no new Core entity family.

Internal modules:

```text
recipe_store.rs
operation.rs
plan.rs
precondition.rs
schedule.rs
service_registry.rs
adapters/a10.rs
error.rs
```

The public crate exposes only D04-owned types plus existing canonical `EntityRef` references. A04/A10 implementation types remain private behind adapters except where an existing public enum is intentionally consumed by a D04 conversion function.

## 4. Canonical Recipe persistence

D04 uses A03 `Ledger` and the already-frozen WP07 schemas. It does not create a Recipe database or alternate identity model.

Canonical records used by `RecipeStore`:

- `build.recipe` — `urn:ptah:schema:build:build-recipe:0.1.0`;
- `build.recipe_revision` — active corrected schema `urn:ptah:schema:build:build-recipe-revision:0.1.1`;
- `build.recipe_proposal` — `urn:ptah:schema:build:build-recipe-proposal:0.1.0`;
- `build.recipe_acceptance` — `urn:ptah:schema:build:build-recipe-acceptance:0.1.0`;
- `build.compiled_plan` — `urn:ptah:schema:build:compiled-plan:0.1.0`.

`RecipeStore` owns mechanical construction/validation of those records and restart-safe retrieval.

Required invariants:

1. Recipe logical identity survives all revision/backend changes.
2. Recipe Revision is immutable and monotonically versioned.
3. Proposal and Acceptance remain separate records.
4. Proposal never implies Acceptance.
5. Acceptance binds one exact Recipe Revision and Proposal.
6. A rejected/expired/mismatched Acceptance cannot authorize plan execution.
7. Compiled Plan binds exact Recipe Revision, Acceptance and backend/compiler revisions.
8. Compiled Plan never mutates Recipe Revision.
9. Backend replacement creates another Plan while Recipe/Revision identity remains stable.
10. negative/rejected proposal and acceptance history is retained.

D04 does not implement release acceptance, signature trust or package/plugin installation. Those belong to later Programme D milestones.

## 5. Recipe Revision input model

The D04 public input mirrors the frozen WP07 contract instead of creating a new Recipe language.

`RecipeRevisionInput` includes:

- stable `recipe_ref`;
- revision number and parent revisions;
- WP07 recipe type;
- exact `content_ref` and digest refs;
- exact Workspace Revision;
- source Object Revisions;
- material bindings;
- requested targets/platform requirements;
- ordered `RecipeStepInput` values;
- Facility/Capability/toolchain/environment requirements;
- credential requirement refs;
- service requirement refs;
- output declaration refs;
- proof requirements;
- caller Policy refs;
- creator/time/limitations.

`RecipeStepInput` keeps the frozen fields:

- `step_key`;
- name;
- step type;
- dependency step keys;
- input-binding keys;
- output declaration refs;
- Facility requirement refs;
- optional credential/service requirement refs;
- network requirement;
- cache policy;
- WP07 side-effect class;
- limitations.

D04 validates step-key uniqueness, dependency existence, dependency acyclicity, input-binding existence and no duplicate requirement references before publishing canonical state.

## 6. Versioned operation descriptors

ADR-0037 operation descriptors are **derived capability metadata**, not a new canonical Operation entity. A04 `Operation` remains the logical execution identity.

`OperationDescriptorRevision` contains:

- `operation_key`;
- descriptor semantic version;
- Facility Revision ref;
- Provider Revision ref;
- optional Provider Instance ref + generation/freshness token;
- exact Capability refs;
- input/output schema refs;
- D04 `OperationEffectClass`;
- A04 execution side-effect class;
- A04 retry and idempotency classes;
- required Grant scopes;
- caller-approval requirement state;
- materialization requirement;
- supported exact precondition kinds;
- declared resource/result limits;
- expected Receipt proof/result states;
- limitations.

The accepted D04 effect vocabulary is exactly:

```text
observe
draft
simulate
mutate
publish
destructive
external_side_effect
```

Descriptor identity is deterministic over normalized descriptor bytes plus exact Facility/Provider revision context. Provider backend aliases are not descriptor identity.

### A04 compatibility

D04 does not replace A04 `SideEffectClass`, `RetryClass` or `IdempotencyClass`.

Mechanical compatibility rules:

- `observe` and `simulate` require A04 `ObservationOnly`;
- `draft` permits `ObservationOnly` or `Reversible` but cannot be destructive/external-authoritative;
- `mutate` requires `Reversible`, `IdempotentMutation` or `NonIdempotentMutation`;
- `publish` requires `ExternalAuthoritative` or `NonIdempotentMutation`;
- `destructive` requires A04 `Destructive`;
- `external_side_effect` requires `ExternalAuthoritative` or `NonIdempotentMutation`.

Retry/idempotency rules are still enforced by A04. D04 metadata cannot make an A04 non-retryable Operation retry-safe.

## 7. Operation descriptor catalog

`OperationCatalog` is a deterministic derived catalog.

It can:

- register exact descriptor revisions;
- enumerate descriptors lazily;
- resolve by exact operation key and optional Provider/Facility constraint;
- report unavailable/stale/ambiguous candidates;
- preserve conflicting descriptors rather than choosing a semantic winner.

If two valid Providers advertise the same operation and the caller did not select a Provider/Facility, lookup returns `AmbiguousOperation`; D04 does not semantically choose one.

Descriptor registration is not execution authority. Current A04/WP11 Grant/fence/generation checks still apply at dispatch.

## 8. Staged execution plan manifest

D04 introduces a D04-owned deterministic `ExecutionPlanManifest`. It is not a canonical Core family. When durable bytes are needed, callers may register the manifest through existing A07 Object/Revision machinery and use that exact Object in WP07 `build.compiled_plan.plan_object_ref`.

Stages are exactly:

```text
observe
draft
simulate
execute
verify
```

A plan may omit stages not needed for the submitted Recipe, but any declared stages must be monotonic in the order above. `verify` is always separate from the effect-producing `execute` stage.

Each `PlannedOperation` contains:

- recipe `step_key`;
- stage;
- exact operation descriptor digest/key;
- logical target refs;
- ordinary parameter bindings;
- credential-reference bindings;
- exact preconditions;
- expected outputs;
- required Grant refs/scopes;
- optional caller approval ref;
- explicit limits.

The manifest is canonically serialized and SHA-256 addressed. Reordering semantically ordered Recipe steps/stages changes the digest; map/object key ordering does not.

Plan compilation validates:

- exact accepted Recipe Revision;
- descriptor compatibility;
- stage/effect compatibility;
- all Recipe step dependencies;
- exact parameter declarations;
- exact credential/service requirements;
- precondition support;
- no undeclared Facility/Provider/Grant widening;
- no hidden input acquisition.

Compilation is mechanical. It does not choose what the caller should do or which semantically equivalent Provider is best.

## 9. Parameter and secret boundary

D04 separates ordinary parameters from credentials/secrets structurally.

`ParameterBinding` supports bounded non-secret scalar/list/object values and exact Object/Revision references.

`CredentialBinding` contains only:

- parameter/requirement key;
- opaque credential/secret reference;
- optional intended Provider/service scope reference.

No D04 Recipe, Plan, descriptor, schedule, log or export type contains a `password`, `token`, `api_key`, raw secret bytes or generic secret-value field.

D04 cannot semantically prove that arbitrary caller text is not sensitive. The mechanical contract is that sensitive values have no public raw-value slot and must enter through an opaque reference/provider delivery path.

## 10. Exact preconditions

D04 owns no new precondition entity family. Preconditions are typed values embedded in caller Recipe/Plan invocation records and may reference existing canonical evidence.

Supported General Beta kinds:

- exact Object Revision + digest;
- exact canonical entity record revision;
- exact Git branch head/commit;
- exact document/draft revision token;
- exact state-machine state;
- exact Provider generation + freshness token.

`evaluate_preconditions(expected, observed)` performs exact mechanical comparison.

A mismatch returns `PreconditionConflict` containing:

- precondition kind;
- target ref;
- expected value;
- observed value or explicit absence;
- supporting evidence refs.

The mismatch blocks dispatch before the A04 effect-producing Operation/Attempt is started. D04 never silently refreshes the expected value.

## 11. Scheduling model

D04 does not introduce a canonical `Schedule` entity. Schedule semantics are a caller-authored component of an exact Recipe invocation.

Vocabulary:

Schedule kind:

```text
one_off
recurring
condition_watch
```

Timing mode:

```text
exact
flexible_window
condition_dependent
```

Valid pairings:

- `one_off` → `exact` or `flexible_window`;
- `recurring` → `exact` or `flexible_window`;
- `condition_watch` → `condition_dependent` only.

`ScheduleSpec` stores only mechanical scheduling data such as exact UTC start, optional flexible window, caller-supplied recurrence expression, condition ref and evaluation cadence.

`ScheduledRecipeInvocation` freezes:

- Workspace ref;
- exact Recipe Revision + Acceptance;
- exact execution-plan digest/Object ref;
- immutable input Object/Revision refs;
- caller-selected Provider/Facility refs;
- exact Grant refs/scopes;
- exact preconditions;
- schedule spec;
- expected output contract refs;
- caller ref.

No transcript/context is inherited.

`evaluate_schedule` consumes an explicit current UTC time plus caller/provider condition evidence and returns only a mechanical state such as `not_due`, `due`, `expired`, `condition_false`, `condition_true` or `invalidated_by_precondition`.

A recurring/condition occurrence creates a fresh dispatch identity. It never reuses an A04 Attempt.

D04 is not Ptah's global scheduler. Later multi-Node scheduling/continuity work may dispatch these same caller-submitted records without changing their identity.

## 12. Service and exposed-port registry

`ServiceRegistry` is a **derived runtime registry**, not a new canonical Core family and not a network authority system.

`ServiceRegistration` contains:

- stable caller/provider service key;
- service kind;
- Facility/Provider/Instance refs;
- exact Provider/Instance generations;
- schema refs;
- Capability/Grant refs;
- registration time + expiry;
- health/availability observation ref where available;
- limitations.

`PortRegistration` contains:

- service key/ref;
- network scope (`loopback`, `workspace`, `node`, `private_network`, `public_gateway`);
- protocol;
- requested port;
- bound endpoint alias;
- exact exposure Policy refs;
- exact Grant refs;
- Provider/Instance generation;
- registration time + expiry.

A bound port is an alias/observation. It is never public exposure authority.

Registry lookup requires current generation and non-expired registration. Grant revocation/provider replacement makes old entries stale. Multiple matching live services without caller selection return an ambiguity result; D04 does not choose by popularity, health score or semantic relevance.

The registry can later ingest frozen WP10 `plugin.service_registration` and `plugin.port_registration` records when D05 implements Plugin lifecycle. D04 itself does not create/install/activate Plugin instances.

## 13. A10 integration

A10 OCI remains the first concrete service-capable execution Provider used for D04 integration proof.

The D04 private A10 adapter may project an OCI run/service operation descriptor from caller-selected A10 capability and current Provider evidence.

D04 may carry A10 network/mount Grant refs into an already-selected execution plan, but:

- D04 cannot widen the `NetworkPolicy` or `MountRequest`;
- D04 cannot turn a Port Registration into a WP11 network-exposure Grant;
- D04 cannot treat A10 start acknowledgement as Recipe success;
- A04 remains Activity/Operation/Attempt truth;
- A10 independently observed completion remains provider evidence until A04 Receipt/proof handling accepts it mechanically.

A10 types are hidden behind the D04 adapter and do not become D04 public identity.

## 14. D03 and Programme B integration

D04 may consume D03 source/result references as exact Recipe materials or parameters. D04 never performs D03 source ranking or authority selection.

Programme B retained-result and recovery machinery remains independent:

- large results remain stable handles/Views;
- archived/recovered inputs retain exact identity;
- a scheduled Recipe references exact caller-specified inputs;
- interruption/retry does not erase partial evidence;
- search/index state remains derived rather than Recipe source truth.

No B07 search result becomes an accepted Recipe input without caller submission or an explicit caller-authored Recipe rule.

## 15. Dispatch facade into A04

D04 exposes a thin `RecipeDispatcher` that receives an already-selected, accepted, due and precondition-clean invocation.

It mechanically:

1. validates the exact Recipe Revision/Acceptance/Plan binding;
2. validates current descriptor/provider/grant/precondition evidence;
3. creates an A04 Activity for the invocation;
4. creates one A04 Operation per ready planned step/stage;
5. preserves Recipe step dependencies;
6. creates a fresh Attempt through A04 only when the caller/provider execution context is supplied;
7. returns A04 identifiers plus D04 mapping evidence.

D04 does not automatically mark Operations succeeded. Existing A04 proof/Receipt methods remain authoritative for runtime completion.

Retry is delegated to A04 and requires the existing retry Policy/idempotency rules.

## 16. Error model

D04 public errors are D04-owned mechanical failures:

- invalid Recipe/step/plan shape;
- canonical record not found/type mismatch;
- immutable revision conflict;
- proposal/Acceptance mismatch;
- Acceptance absent/rejected/expired;
- descriptor collision/stale/ambiguous/unavailable;
- effect/A04 compatibility mismatch;
- undeclared parameter/credential/service;
- raw-secret-shaped public field prohibited by API construction;
- unsupported/failed precondition;
- precondition conflict;
- invalid schedule pairing/state;
- service/port registration expired/stale/ambiguous;
- missing Grant/Policy/exposure evidence;
- A04/A03 adapter failure;
- serialization/digest failure.

A10/B/D03 internal error types do not leak through the D04 public API.

## 17. Authority invariants

D04 may:

- persist caller-authored canonical Recipe/Revision/Proposal/Acceptance/Plan records;
- expose typed operation metadata;
- validate exact preconditions;
- evaluate caller-submitted schedules mechanically;
- preserve exact parameters/credential references;
- register/resolve current service/port observations;
- dispatch caller-submitted accepted Recipes into A04;
- retain conflicts, partial results, limits and evidence.

D04 may not:

- choose the caller's job;
- infer hidden Recipe steps or semantic scope;
- accept a proposal automatically;
- choose the semantically correct Provider when multiple candidates exist;
- manufacture caller approval;
- widen Provider/Grant/network/filesystem authority;
- turn a bound port into public exposure authority;
- store raw credentials in Recipe/Plan/schedule/registry state;
- treat start ACK as success;
- retry non-retryable work by itself;
- reconcile worker conclusions;
- accept/promote result Artifacts;
- choose schedule purpose/desired outcome;
- become Ptah's global scheduler.

## 18. Persistence and restart

Canonical WP07 records are durable in A03 and must round-trip across `RecipeStore` reopen.

Derived operation/service catalogs may be rebuilt from current Provider/Plugin observations. Their digest/version/generation lets callers detect replacement/staleness; D04 does not pretend a stale cached registry is current authority.

Caller-authored Plan/Schedule manifests can be retained as ordinary A07 Object bytes where persistence is needed. D04 does not invent a separate persistence format that overrides canonical records.

## 19. Package boundaries

Expected D04 source layout:

```text
crates/ptah-recipe-registry/
  Cargo.toml
  src/
    lib.rs
    error.rs
    recipe_store.rs
    operation.rs
    plan.rs
    precondition.rs
    schedule.rs
    service_registry.rs
    dispatcher.rs
    adapters/
      mod.rs
      a10.rs
  tests/
    d04_acceptance.rs
```

No root schema/catalog/migration file is modified.

## 20. Acceptance corpus

D04 receives one exact-head acceptance corpus covering at minimum:

1. Recipe identity/revision persists across restart;
2. Recipe Revision is immutable and monotonic;
3. Proposal does not imply Acceptance;
4. Acceptance binds exact Proposal + Recipe Revision;
5. rejected/expired Acceptance blocks execution planning;
6. backend replacement creates a distinct Compiled Plan without changing Recipe identity;
7. operation descriptor digest is deterministic and revision-bound;
8. all seven ADR-0037 effect classes are exposed exactly;
9. invalid effect/A04 side-effect combination fails closed;
10. descriptor ambiguity is retained rather than auto-selected;
11. staged plan order is monotonic and `verify` remains separate from `execute`;
12. plan digest is deterministic and changes on ordered semantic changes;
13. undeclared parameters/credentials/services fail closed;
14. credential binding contains opaque references only;
15. exact Object/entity/Git/draft/state/Provider preconditions pass when equal;
16. moved target returns expected/observed conflict evidence before dispatch;
17. schedule kind/timing pair matrix is enforced;
18. scheduled invocation retains exact caller-specified Recipe/Input/Provider/Grant/precondition set;
19. recurring/condition occurrence never reuses an A04 Attempt identity;
20. service registry rejects stale Provider generation;
21. expired service registration is unavailable;
22. ambiguous service registration is not auto-ranked;
23. port registration without exposure Policy/Grant fails closed;
24. bound port does not become network authority;
25. A10 adapter cannot widen network or mount Grants;
26. A10 start ACK does not become Recipe/A04 success;
27. D03 source/result refs can be consumed as exact materials without D03 semantic authority;
28. B07 search/index result is not automatically accepted as Recipe source truth;
29. D02/D03/D01/A04/A10/Programme-B regressions remain green;
30. full locked Ptah workspace passes.

## 21. Exact-head proof guards

The D04 workflow must prove:

- exact D03 merge predecessor `ee07fdbe62167ed1fe4a81b47797c744a9393337`;
- D04-only path surface;
- no contract/schema/migration/generated-catalog modification;
- no existing external dependency version movement;
- no git dependency;
- strict formatting and Clippy for D04;
- no TODO/FIXME/unimplemented/unsafe escape;
- no public A10/B/D03 implementation-type leakage;
- no new public semantic-choice/approval/promotion/global-scheduler method;
- no public raw-secret value field;
- no service/port API that grants exposure;
- exact D04 acceptance count;
- targeted A04/A10/B/D01/D02/D03 regressions;
- complete locked workspace;
- retained exact candidate/tree/file-hash proof.

## 22. Explicit non-goals

D04 does not implement:

- D05 Package/Plugin install/activation lifecycle;
- D06 SBOM/signing/provenance trust bundle completion;
- D07 security Finding/remediation/reproduction;
- semantic workflow generation;
- autonomous Provider selection;
- raw secret storage;
- a global distributed scheduler;
- network/firewall authority from registry metadata;
- automatic result acceptance/promotion;
- new Core identity families.

If implementation shows one of those is mechanically required to satisfy the frozen D04 contract, work stops at that proof boundary and a versioned reopening/design correction is required rather than silently expanding authority.
