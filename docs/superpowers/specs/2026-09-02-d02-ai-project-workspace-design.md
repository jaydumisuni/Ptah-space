# D02 — AI Project Workspace Substrate and Application Adapters — Design

Status: design approved in chat; implementation not started

Date: 2026-09-02

Base: `Ptah-space` `main` at `8be77210eee2b62eed753151287935bdebc369ae` (D01 merge)

Roadmap authority: `ptah-roadmap-` `IMPLEMENTATION_ROADMAP.md` D02 and ADR-0037

## 1. Objective

Implement D02 as a provider-independent composition layer over already-proven Ptah primitives.

D02 must make the accepted `ptah.workspace.ai_project.v1` profile operative and expose the D02-relevant compatibility surface of `ptah.workspace.operations.v2` without introducing a new Core entity family, changing frozen schemas, or moving intelligence/authority into Ptah.

The required product boundary is unchanged:

> Ptah is the world and machinery, not the thinker.

Hunter, Sergeant, humans and other caller applications choose context, source authority, Provider for semantic purpose, review meaning, approval, acceptance and next action. Ptah stores, retrieves, executes and mechanically enforces configured authority.

## 2. Recovered D02 deliverables

D02 must deliver:

- the `ptah.workspace.ai_project.v1` neutral runtime manifest;
- the compatible D02 subset of `ptah.workspace.operations.v2`;
- exact Workspace, Session, Activity, Object and Artifact retrieval APIs;
- caller-metadata round-trip without Ptah interpretation;
- parallel Session/thread projections;
- a reusable Artifact Library projection;
- model-independent stored state and caller-produced handoff Artifacts;
- exact caller-submitted scheduled-Activity input envelopes;
- a Hunter caller adapter;
- a Sergeant independent-review caller adapter.

D02 proof must show:

- configured Grants prevent cross-Workspace leakage;
- conflicting caller authority labels remain stored with no Ptah-selected winner;
- intelligence/Provider replacement preserves durable state and configured access;
- scheduled execution receives only exact caller-specified and mechanically granted inputs;
- private Hunter records cannot be read from a public Workspace without explicit release plus Grant;
- Sergeant output remains Sergeant-owned evidence and never becomes a Ptah verdict;
- Ptah performs no context selection, approval, review, promotion or next-action choice.

## 3. Architectural decision

Create a new composition crate:

```text
crates/ptah-ai-workspace
```

This crate is a façade over existing runtime authorities. It does not own a new canonical database and does not define a new canonical Ptah entity kind.

Primary dependencies:

```text
ptah-ai-workspace
  -> ptah-workspace            A06 Workspace / Session / Secure Grant authority
  -> ptah-ledger               A03 exact canonical record retrieval
  -> ptah-activity-runtime     A04 Activity / Attempt / execution truth
  -> ptah-object-store         A07 Object / Revision / Artifact truth
  -> ptah-checkpoint           A13 + B06 recovery / portable continuation
  -> ptah-archive-decomposition::b07
                              B07 derived source-bound search only
```

B07 coupling is isolated behind one D02 search adapter. No D02 public type exposes the archive-decomposition crate. This avoids making the entire D02 API depend semantically on the historical crate placement of B07.

### Alternatives rejected

**Extend `ptah-workspace` directly.** Rejected because A06 is already a frozen persistent Workspace/Session authority runtime. D02 is composition, not a new A06 schema or lifecycle revision.

**Implement D02 in `ptah-control`.** Rejected because D01 control/shell state is a projection. A UI/service projection cannot become the durable AI Project Workspace substrate.

**Create a context compiler inside Ptah.** Rejected by the neutral-substrate correction, the Master Plan and ADR-0037.

## 4. Frozen-contract policy

D02 MUST NOT:

- add or modify WP01–WP14 canonical schemas;
- add a new Core entity family;
- add a ledger migration merely for D02 composition;
- reinterpret caller labels such as `canonical`, `reference`, `generated_candidate`, `rejected` or `superseded`;
- infer context, relevance, trust, blockers, next actions or review conclusions;
- silently materialize an external reference;
- treat B07 index state as canonical source truth;
- treat a schedule as authority expansion;
- treat a Sergeant finding as approval/rejection;
- change configured Grants when the active intelligence Provider changes.

The existing Phase-0C candidate files remain historical non-operative design evidence. D02 implementation does **not** rewrite their `runtime_implementation_authorized` fields. Runtime authorization comes from the accepted implementation roadmap and current programme state, not by mutating historical candidate evidence.

If implementation discovers a genuinely missing mechanical primitive, work stops and opens the required versioned contract-reopening ADR rather than smuggling the primitive into D02.

## 5. Crate structure

Proposed source layout:

```text
crates/ptah-ai-workspace/
  Cargo.toml
  src/
    lib.rs
    profile.rs
    retrieval.rs
    sessions.rs
    library.rs
    caller_records.rs
    activity_inputs.rs
    search.rs
    adapters/
      mod.rs
      hunter.rs
      sergeant.rs
  tests/
    d02_acceptance.rs
```

Keep files focused. No single module should become a second control plane.

## 6. Runtime profile manifests

`profile.rs` exposes immutable runtime profile descriptors for:

```text
ptah.workspace.ai_project.v1
ptah.workspace.operations.v2
```

These descriptors are code-level composition metadata, not ledger entities.

The AI Project manifest enumerates the existing primitive families it composes and declares all semantic authority flags false.

The operations-v2 manifest exposes only D02-relevant mechanical vocabulary and invariants:

- Provider permission, Ptah Grant and caller approval are separate;
- external/indexed/mounted/materialized/generated availability states remain distinct;
- scheduled input identity is exact;
- stable result/reference identity survives interface or intelligence replacement;
- index/search output never replaces source truth;
- Views never become authority.

D04 remains responsible for the later full versioned Recipe/service-registry and operation-descriptor implementation. D02 must not pre-implement D04.

## 7. Exact retrieval API

`retrieval.rs` provides a read-only `WorkspaceReader`.

A retrieval request contains:

- actor identity;
- caller/source Workspace identity;
- target Workspace identity;
- exact entity reference;
- optional exact canonical record revision;
- required configured scope;
- optional Secure Grant reference.

Retrieval order is mechanical:

1. validate exact canonical identifiers;
2. call A06 `authorize_retrieval` for the requested Workspace boundary;
3. read the requested exact or latest canonical record through A03;
4. verify the record belongs to the requested target Workspace where the record class is Workspace-scoped;
5. return the preserved canonical document plus exact revision/provenance identity.

Supported D02 top-level retrieval classes are Workspace, Session, Activity, Object and Artifact. Other records may be returned only through an explicitly typed future extension; D02 does not expose a generic authority-bypassing ledger dump.

A missing record, wrong Workspace, stale revision or denied Grant fails closed and returns no protected document bytes.

### Record bytes versus Object bytes

Canonical record retrieval is not Object materialization.

D02 returns Object/Artifact canonical metadata and stable identities. Actual Object content remains under A07/B01 materialization/transfer mechanics. D02 never converts an Artifact reference into a local path by assumption.

## 8. Caller-owned records and metadata

Caller metadata and handoffs are stored as caller-authored bytes in ordinary A07 Objects/Revisions and, when explicitly promoted with valid A04 evidence, Artifacts.

D02 does not add semantic metadata columns to A07.

`caller_records.rs` provides bounded helper formats for application use, but preserves caller payload bytes and caller labels without ranking or normalization of meaning.

The helper may validate only mechanical concerns such as:

- maximum byte size;
- declared media type / payload version syntax;
- exact Workspace ownership;
- required A04 production evidence for Object creation or Artifact promotion.

It may not validate whether a caller label is true.

Two authorized callers can store contradictory labels. D02 must retain both records and expose both; it never emits a synthetic winner.

## 9. Parallel Session/thread projection

`sessions.rs` maps one Workspace to its durable A06 Session references and exact Session projections.

A Session may be presented to applications as a project thread, but the mapping is explicitly a View/projection:

- Session identity remains `runtime.session`;
- parallel Sessions do not imply shared semantic context;
- archived/terminal Sessions remain discoverable by exact identity when authorized;
- attaching a replacement model/Provider does not replace Workspace or Session identity;
- Provider generation/connection evidence changes independently from configured Grant truth.

D02 never labels one Session as the active, correct or relevant thread unless that label was supplied by a caller and explicitly requested.

## 10. Artifact Library projection

`library.rs` builds a reusable, non-authoritative Artifact Library View from exact Workspace scope and canonical Object relationships.

Initial v1 algorithm:

1. obtain the current A06 recovery/scope projection;
2. take its exact Workspace-scoped Object references;
3. read each exact/latest Object canonical record through A03;
4. collect the Object's retained Artifact references;
5. read exact Artifact records;
6. return deterministic entries containing Artifact identity, promoted Revision refs, lifecycle, purpose/type metadata, provenance references and availability/materialization truth when mechanically known.

The library is a projection. It cannot promote, accept, rank or delete Artifacts.

If the A06 scope projection is incomplete, the library response carries that limitation instead of claiming exhaustive Workspace truth.

## 11. Search integration

`search.rs` defines a small D02 `WorkspaceSearch` abstraction and one adapter over B07 `SearchIndex`.

D02 enforces access **before** invoking B07. B07 then searches only the exact target Workspace.

Search results retain:

- B07 index revision and digest;
- exact canonical source reference;
- exact canonical source record revision;
- exact Object Revision binding where present;
- matching copied fields and evidence source.

D02 does not reorder results into authority ranking and does not turn a top hit into accepted context. Hunter/Sergeant/human callers choose which results to use.

## 12. Exact scheduled-Activity input envelope

D02 does not implement the future D04 scheduler/Recipe registry.

`activity_inputs.rs` defines the neutral envelope that a caller or scheduler must submit when invoking D02 work:

- Workspace reference;
- Activity/request reference;
- exact input Object/Artifact Revision references;
- exact Provider/Facility references where supplied;
- exact Grant references;
- caller-supplied timing/schedule identity when the invocation originated from a schedule.

The envelope is immutable for one admitted invocation.

D02 provides an authorization/read helper that can expose only references listed in the admitted envelope and allowed by configured A06 access. A later request for a third unlisted Artifact fails with `InputNotDeclared`, even if another Workspace search could discover that Artifact.

A timer, recurrence or condition does not add context or access.

## 13. Hunter adapter

`adapters/hunter.rs` is deliberately thin.

Hunter owns:

- intent interpretation;
- context selection;
- source/trust labels;
- Provider choice;
- planning/coordination;
- approval requests;
- next-action proposals;
- handoff contents.

The D02 Hunter adapter accepts already-selected exact references/payloads and performs mechanical calls such as:

- open exact Workspace/Session state;
- retrieve exact requested records;
- execute caller-specified B07 search;
- store Hunter-authored caller records/handoffs;
- submit exact Activity input envelopes;
- retrieve retained results.

No adapter method is named or shaped as `choose_context`, `select_authority`, `approve`, `promote`, `decide_next_action` or equivalent.

Replacing Hunter's model/provider leaves durable Ptah state and Grants unchanged.

## 14. Sergeant adapter

`adapters/sergeant.rs` is a separate caller boundary, not a Hunter mode.

It accepts:

- a frozen candidate Artifact/Revision reference;
- exact review evidence references selected by Sergeant/caller policy;
- exact permitted Facilities/Providers/Grants;
- Sergeant-authored result bytes.

It may retrieve the frozen candidate, run caller-requested mechanical operations, and store Sergeant's review result as a Sergeant-attributed Artifact.

D02 does not:

- accept/reject the candidate;
- merge Sergeant findings into canonical truth;
- mark Hunter correct/incorrect;
- promote a candidate;
- choose remediation or next action.

Candidate Artifact and Sergeant review Artifact remain separate identities.

## 15. Error model

D02 errors are mechanical and fail closed. Proposed categories:

- invalid profile/request identifier;
- unsupported D02 record class;
- record not found;
- exact revision not found;
- Workspace ownership mismatch;
- configured access denied / invalid Grant;
- declared input missing;
- requested input not declared;
- canonical record malformed;
- B07 search unavailable/invalid;
- Object/Artifact materialization not available;
- A04/A07 production evidence mismatch;
- underlying ledger/workspace/object/checkpoint failure.

There are intentionally no errors such as `WrongSource`, `BadContext`, `ReviewFailed`, `NotAuthoritativeEnough` or `WrongNextAction`; those would imply semantic judgment by Ptah.

## 16. Recovery and model/provider replacement

D02 composes A06 recovery and B06 Session Vault; it does not create another checkpoint format.

Recovery proof must show:

- Workspace identity survives process restart;
- Session identities remain stable;
- caller-authored handoff bytes remain exact;
- Object/Artifact identities and provenance remain exact;
- configured Grants remain the configured Grants;
- a replacement intelligence Provider receives no additional authority merely because it is new;
- missing target capability remains an explicit B06 incompatibility rather than silent fallback.

## 17. Acceptance proof

Create `crates/ptah-ai-workspace/tests/d02_acceptance.rs` and an exact-head D02 workflow.

The runtime acceptance corpus implements the ten recovered AI Project Workspace fixtures:

1. `workspace-isolation` — deny protected cross-Workspace retrieval and return no protected bytes.
2. `caller-label-roundtrip` — exact caller labels/payload and provenance survive store/read.
3. `conflicting-labels-no-ranking` — contradictory authorized records both survive; no Ptah winner exists.
4. `model-independent-resume` — replacement Provider/model preserves Workspace/Session/handoff state.
5. `grant-survives-agent-change` — replacement caller adapter gets exactly the existing mechanical Grant set.
6. `scheduled-exact-inputs` — undeclared third Artifact is denied; no relevant replacement is inferred.
7. `private-hunter-public-workspace` — private Hunter bytes remain unavailable without explicit release plus Grant.
8. `archived-session-discoverability` — exact authorized archived Session remains retrievable without relevance ranking.
9. `failed-activity-visible` — failed Attempt and partial outputs remain discoverable and linked.
10. `sergeant-review-no-ptah-verdict` — Sergeant result is retained separately with no Ptah approval/promotion record.

Additional operations-v2 compatibility tests prove:

- both exact profile IDs are exposed;
- effect/availability/result/timing vocabularies match ADR-0037 where D02 exposes them;
- Provider permission, Ptah Grant and caller approval are not collapsed;
- B07 source-bound hits remain references, not truth promotion;
- external reference never becomes a local materialized path without evidence;
- View/library projection never mutates canonical state;
- no new canonical schema ID or ledger migration is introduced by D02.

Regression gates:

- D01 acceptance;
- A14 acceptance;
- A06/A04/A07/A13/B06/B07 targeted suites;
- full `cargo test --workspace --locked`;
- canonical `cargo fmt --all -- --check`;
- repository accepted Clippy gate;
- `git diff --check`;
- exact-head one-commit proof before merge.

## 18. CI and freeze strategy

D02 implementation is developed on one isolated branch/worktree from the D01 merge.

Before freeze:

- tests are written red-first for each new runtime behavior;
- production changes are reviewed for authority drift;
- existing historical candidate validators continue to pass unchanged.

Freeze candidate rules:

- one reviewed D02 commit over the current accepted `main` boundary unless an independently reviewed design-only commit is intentionally retained as parent;
- no unrelated refactor;
- no hidden dependency update;
- no Cargo.lock change unless a new direct dependency mechanically requires it and the exact delta is reviewed;
- exact-head local proof before push;
- exact-head CI proof after push;
- merge only after D02 proof and applicable current policy gates pass.

## 19. Scope explicitly deferred

D02 does not implement:

- D03 Knowledge/Data/Search v2 beyond consuming current B07;
- D04 Recipes/service registry/full operation-descriptor catalogue;
- D05 Plugin lifecycle;
- D06 provenance/SBOM/signing release bundle expansion;
- D07 security Finding/reproduction workflow;
- D08 wider Application platform;
- D09 full Workspace release acceptance;
- distributed Programme E placement/failover;
- a Hunter model runtime or private Hunter memory database;
- Sergeant's reasoning engine;
- autonomous approvals or canonical truth promotion.

## 20. Completion criterion

D02 is complete only when the exact frozen implementation head proves all recovered D02 fixtures and compatibility invariants while preserving every existing A–D01 regression and the neutral Ptah/Hunter/Sergeant/human authority boundary.

Passing tests demonstrate the implementation conforms to this design; they do not replace the design or authority evidence that defines it.
