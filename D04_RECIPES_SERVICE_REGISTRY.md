# D04 — Recipes and Service Registry

## Status

Programme D04 implementation and exact-head proof record.

Accepted predecessor: `ee07fdbe62167ed1fe4a81b47797c744a9393337` (verified D03 merge).

D04 implements deterministic Recipes, versioned Proposal/Acceptance/Compiled Plan handling, ADR-0037 operation descriptors/effects, exact preconditions, caller-authored schedule envelopes, a non-authoritative service/port registry and thin A04 dispatch. It adds no new Core family, migration, global scheduler, network-exposure authority, semantic chooser, approver, promoter or secret store.

## Authority and dependency boundary

- WP07 remains canonical Recipe/Revision/Proposal/Acceptance/Compiled Plan truth.
- A03 stores canonical records.
- A04 remains Activity/Operation/Attempt execution and completion/proof authority.
- A10 remains container network/mount policy and backend-completion authority.
- Programme B/B07 remains derived evidence/search only.
- D03 source/result refs may be consumed as exact materials, without source ranking or semantic authority.
- D02 caller/context/approval authority remains caller-owned.

## Delivered package

`crates/ptah-recipe-registry` owns only composition/projection mechanics:

- canonical Recipe store over existing WP07 schemas;
- versioned operation descriptor catalog with seven ADR-0037 effects;
- deterministic staged `observe -> draft -> simulate -> execute -> verify` Plan manifests;
- ordinary parameter vs opaque credential-reference separation;
- six exact precondition kinds and conflict evidence;
- `one_off`, `recurring`, `condition_watch` caller-authored schedule semantics;
- service/port observations that never create exposure authority;
- private A10 network/mount normalization and widening checks;
- thin preflight-first A04 dispatcher.

## Canonical Recipe persistence

Recipe identity is stable while immutable Recipe Revisions advance monotonically. Proposal and Acceptance are separate WP07 canonical entities. An Acceptance must bind the exact Proposal and exact Recipe Revision; rejected or expired Acceptance blocks planning. Compiled Plans bind exact accepted Recipe Revision plus backend facility/provider/compiler evidence. Replacing a backend produces a distinct Plan without rekeying the Recipe.

## Operation descriptors and Plan manifest

Descriptor revisions are digest-bound and retain Provider Revision/generation, A04 side-effect/retry/idempotency classes, required Grants, materialization requirement and limitations. Ambiguous live descriptors remain multiple candidates; D04 never selects a semantic winner.

The exact effect vocabulary is: `observe`, `draft`, `simulate`, `mutate`, `publish`, `destructive`, `external_side_effect`. Compatibility with A04 side-effect classes is validated mechanically.

Execution Plan stages are monotonic and `verify` remains distinct from `execute`. Undeclared parameters, credential requirements or services fail closed. Credential bindings contain references only; raw credential values have no public D04 field. Plan identity is deterministic SHA-256 over the ordered manifest.

## Preconditions

D04 supports six exact precondition classes: Object Revision digest, canonical record revision, Git branch head, Draft revision, state-machine state and Provider freshness. Pairing is exact by kind + target + selector. Missing or moved observations produce conflict evidence retaining expected, observed and evidence refs. No fuzzy reconciliation or silent refresh occurs.

## Schedules

Schedules are caller-authored mechanical envelopes, not a Ptah global scheduler. Valid timing pairs are:

- `one_off`: exact or flexible window;
- `recurring`: exact or flexible window plus a non-empty caller recurrence expression;
- `condition_watch`: condition-dependent plus an exact condition ref.

Evaluation consumes explicit occurrence/condition/precondition evidence. Scheduled invocations freeze Workspace, Recipe Revision, Acceptance, Compiled Plan, plan digest, inputs, Provider Revisions, Grants, preconditions, expected outputs and caller identity.

## Service / port registry and A10

Service registrations are derived observations keyed by exact Provider Instance/generation/freshness and optional expiry. Stale generations are rejected, expired candidates are unavailable, and multiple live candidates remain ambiguous.

Port registration requires explicit Policy and Grant refs but `grants_network_exposure()` is always false. D04 compares requested container network/mount scope against existing A10/WP11 authority; any widening fails before execution. Actual A10 `NetworkPolicy`/`MountRequest` types remain private. A10 start acknowledgement remains separate from terminal completion and cannot mark A04 Operation success.

## A04 dispatcher

Dispatch performs all D04 binding, descriptor, Grant and precondition validation before creating an A04 Activity. Therefore a D04 precondition conflict creates zero A04 Activities/Attempts. Each accepted scheduled occurrence creates fresh A04 Activity/Operation/Attempt identities. Root-ready Recipe steps are admitted; dependent steps remain deferred. D04 never calls A04 success/proof/retry methods.

## Acceptance evidence

The frozen D04 acceptance corpus contains exactly **30 tests**, covering:

1. restart-safe Recipe persistence; 2. monotonic immutable revisions; 3. Proposal != Acceptance; 4. exact Acceptance binding; 5. rejected/expired Acceptance; 6. backend replacement; 7. descriptor digest; 8. seven effects; 9. A04 compatibility; 10. descriptor ambiguity; 11. stage order; 12. Plan digest; 13. undeclared inputs; 14. credential reference-only; 15. six exact preconditions; 16. moved-target conflict/no A04 mutation; 17. schedule matrix; 18. exact scheduled inputs; 19. fresh scheduled Attempts; 20. stale service; 21. expired service; 22. service ambiguity; 23. port authority refs; 24. bound port not authority; 25. A10 no widening; 26. ACK not success; 27. exact D03 materials; 28. B07 result not auto-accepted; 29. predecessor integration/caller authority; 30. no semantic chooser/approver/promoter/global-scheduler public surface.

Fresh pre-freeze proof also includes strict Clippy, A04 7/7, A10 14/14, D01 13/13, D02 18/18, D03 23/23 + SQLite 4/4, B07 14/14, Programme-B/C regression suites, shared A06/A07/A08 surfaces, and complete `cargo test --workspace --locked`. The inherited `ptah-control` missing-documentation warnings remain pre-existing baseline warning debt.

## Dependency / lock delta

D04 introduces no new external dependency version and no git dependency. `Cargo.lock` adds only one new workspace package stanza: `ptah-recipe-registry`. D02/D03/B07 appear only as D04 dev/test edges used to prove integration; production D04 public types do not expose them. No pre-existing package version/source entry moves.

## Exact-head proof requirements

The final D04 workflow must prove on the frozen candidate SHA: exact D03 predecessor, linear history, approved path scope, no contract/schema/migration/generated drift, reviewed single-package lock delta, Rust/Cargo 1.97.1, fmt, strict Clippy, no unsafe/TODO/FIXME/unimplemented/raw-secret/exposure-grant/semantic-authority escape, exactly 30 D04 acceptance tests, targeted predecessor regressions, complete locked workspace, and a retained candidate/file SHA-256 evidence artifact.

## Explicit deferrals

D04 intentionally does not implement D05 plugin installation/activation lifecycle, D06 distribution/update machinery, or D07 later roadmap authority. It also does not create a background scheduler, semantic Provider chooser, automatic Recipe approval, automatic Artifact promotion, secret-value storage or network exposure authority.
