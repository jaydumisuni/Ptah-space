# D09 Full Workspace Release Acceptance Design

## Status and authority

D09 is the Programme D release-acceptance milestone. It adds no new Ptah runtime subsystem, canonical entity family, schema, migration, Provider, execution authority or product semantics.

Accepted implementation predecessor:

`ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`

Delivery authority:

- repository: `jaydumisuni/ptah-roadmap-`
- commit: `98dc8c4e8639cda80510bee0625db34b4fdf9384`
- milestone: **Full Workspace Release**

D09 must prove concurrent human/agent operation, long-running recovery, Provider replacement, Plugin rollback, provenance/security reviewability, the complete public/private/licence boundary, and the complete deep Workspace study under human, Hunter and Sergeant use without Ptah semantic-authority drift.

## Architectural decision

D09 is an acceptance-only composition layer modeled on the accepted A15 exact-head release pattern. It does not add a `ptah-d09` runtime crate or any new product mechanism.

The normal D09 implementation surface is exactly seven files:

- this design;
- `docs/superpowers/plans/2026-09-04-d09-full-workspace-release-acceptance.md`;
- `D09_FULL_WORKSPACE_RELEASE_ACCEPTANCE.md`;
- `conformance/d09/full-workspace-release-cases.v0.1.0.json`;
- `tools/check_d09_full_workspace_release.py`;
- `tools/test_check_d09_full_workspace_release.py`;
- `.github/workflows/d09-full-workspace-release-acceptance.yml`.

No Cargo, runtime, schema, migration or generated-contract content is part of the normal D09 delta.

## Release-audit proof-hygiene correction

The first D09 exact-head audit exposed eight inherited floating GitHub Action refs in completed D07/D08 proof machinery. D09 corrects that evidence machinery rather than weakening the release policy:

- `.github/workflows/d07-security-evidence-reproduction-proof.yml`: immutable checkout/upload pins plus explicit Rust 1.97.1 installation;
- `.github/workflows/d08-application-platform-expansion-proof.yml`: same correction;
- `.github/workflows/d08-tdd.yml`: retire the completed write-capable Task-4 promotion lane.

Those three paths are the only audited exception to the normal seven-file D09 surface. Final D08→D09 release delta is exactly ten paths. No product source, Cargo state, schema, migration or generated binding changes.

## Dependency/source/licence authority recovered by D09

D09 proof recovered three historical snapshots that must remain historical evidence rather than current release gates:

1. A01 scaffold checks freeze the original A01 workspace/Cargo state.
2. `tools/check_phase0c_scaffold.py` freezes an earlier 81-package external Cargo universe.
3. `dependencies/rust-direct-lock.json` retains an older nested `cargo_lock` snapshot. Its direct dependency selection and policy remain applicable, but that nested package-count/digest snapshot is not the current Cargo identity.

The actual accepted D08-identical `Cargo.lock`, mechanically reported by `tools/check_rust_dependency_lock.py`, is:

- SHA-256 `329f485f352afa35f3f6cb4df76ebf0c6e8b589a555386072f4a8750a5349987`;
- 130 resolved packages;
- 97 registry packages;
- 0 Git dependencies;
- 11 exact workspace direct dependencies.

D09 uses the accepted A15 dependency-proof pattern and strengthens it predecessor-relatively:

- byte-compare `Cargo.toml`, `Cargo.lock`, `deny.toml`, `dependencies/rust-direct-lock.json`, `dependencies/backend-artifact-lock.json`, `contracts/generated/manifest.json`, and `crates/ptah-contracts/src/generated.rs` against D08;
- run `tools/check_rust_dependency_lock.py` on the exact candidate;
- cross-check its current report against the D08 lock SHA/counts above;
- require the workspace direct-dependency set to match all 11 exact selected versions and retain their declared purposes/licence expectations;
- require canonical crates.io registry sources, 64-hex checksums and zero Git dependencies;
- require the committed `deny.toml` source, wildcard, yanked and licence allow-list policy to remain exact;
- require every external package licence expression exposed by `cargo metadata --locked` to remain inside that allow-list;
- record the older nested `cargo_lock` snapshot as historical and explicitly mark it `used_as_current_gate = false`;
- retain exact backend artifact/browser/signature identities.

This preserves historical evidence without forcing later accepted workspace state back into an earlier snapshot.

## Reused proof authorities

### Human and agent operation

- D01 remains Human Workspace shell authority.
- D02 remains AI Project Workspace composition authority.
- Hunter and Sergeant remain caller adapters; Ptah does not choose semantic context, trust, review verdict, acceptance or next action.
- A04 remains Activity/Operation/Attempt concurrency authority.

### Recovery

- A13 remains checkpoint/restart/verified-recovery authority.
- B06 remains Session Vault export/import and compatible-resume authority.
- Stable identities, result handles, partial work, exact inputs, conflicts and uncertain effects remain preserved or explicitly reconciled; stale generations/leases fail closed.

### Provider replacement and Plugin rollback

- Provider/backend IDs remain aliases/evidence, not Ptah canonical identity.
- Replacement advances generation without re-keying canonical identity.
- D05 remains Package/Plugin lifecycle authority; rollback requires fresh A04 execution identity and independent post-verification.

### Provenance and security evidence

- D06 remains provenance/SBOM/signing/proof-bundle authority.
- D07 remains authorization/Finding/Claim/Evidence/remediation/reproduction authority.
- Negative, partial, failed, inconclusive, contradictory and regressed evidence cannot be erased by D09 success.

### Application platform

- D08 remains Application/Window/Display composition authority.
- Local Linux/proven Android truth remains evidence-bound.
- Windows/macOS/iOS Simulator/live remote display remain explicit Programme E deferrals where required Node authority is absent.

### Public/private boundary

- The operative Apache-2.0 boundary tooling remains public/private source-policy authority.
- Private Hunter/customer/device/payment/restricted-adapter data cannot become public release evidence through D09.
- D09 report bundles contain approved public evidence/digests only, never raw private content.

## Deep Workspace burden

The exact candidate must retain:

- 22 mechanical capabilities;
- 20 fixtures;
- 26 original positive/adversarial cases;
- 28 gap mappings;
- no new Core entity requirement;
- no frozen-contract reopening;
- no runtime-implementation authorization from the study.

Passing that mechanical corpus never grants Ptah semantic result interpretation or acceptance authority.

## Frozen D09 release corpus

D09 freezes exactly ten categories:

1. human/agent coexistence;
2. deep Workspace authority separation;
3. concurrent Activity operation;
4. long-running recovery;
5. Provider replacement;
6. Plugin rollback;
7. provenance reviewability;
8. security reproduction history;
9. Application truth;
10. public/private release audit.

Every case declares `ptah_semantic_authority: false`. The checker fails closed on count/category drift, missing human/Hunter/Sergeant participation, authority widening, new Core requirements, frozen-contract changes or runtime-feature additions.

## Exact-head workflow

Workflow: `D09 Full Workspace Release Exact Head Acceptance`.

One exact candidate SHA must prove:

1. exact D08 predecessor `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`;
2. linear branch history and remote branch equality;
3. exact ten-path release delta;
4. no product/Cargo/schema movement and exact D08 bytes for dependency/contract authority files;
5. all external Actions immutably pinned to 40-hex commits;
6. current D08 dependency identity `329f485f…` / 130 / 97 / 0 / 11 plus licence/source/backend boundaries;
7. D09 checker regressions and exact ten-case corpus;
8. deep Workspace 22/20/26 and non-authorizing AI validator;
9. D01/D02/A04 concurrent operation;
10. A13/B06 recovery;
11. D05 rollback/replacement;
12. D06 provenance/store round-trip;
13. D07 security/store round-trip;
14. D08 exact 25+3;
15. Apache public/private boundary;
16. `cargo fmt --all -- --check` and complete `cargo test --workspace --locked`;
17. clean exact worktree;
18. explicit release limitations;
19. deterministic SHA-256 report bundle;
20. retained artifact `d09-full-workspace-release-${TARGET_SHA}`.

Green status without the retained bundle is not D09 acceptance.

## Release and merge rule

A D09 candidate may merge only after one exact SHA passes the permanent workflow, the retained artifact exists, the branch still equals that SHA, the PR base remains exact D08, repository review/rules expose no blocker, and merge uses an expected-head guard.

After merge, independently verify `main`. The merge commit must have exactly two parents in order:

1. `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`;
2. frozen proven D09 SHA.

The merge tree must equal the proven candidate tree. Only then may D09 be COMPLETE and Programme D be called **Full Workspace Release**.

## Explicit non-claims

D09 does not complete Programme E distributed Ptah or Programme F OS-ready packaging; does not grant Ptah semantic/release/remediation authority; does not erase negative evidence; does not turn hosted CI into a pinned production Node; does not make deferred D08 platforms available; and does not grant public access to private records.
