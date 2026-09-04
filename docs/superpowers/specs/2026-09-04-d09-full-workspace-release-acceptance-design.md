# D09 Full Workspace Release Acceptance Design

## Status and authority

D09 is Programme D release acceptance. It adds no Ptah runtime subsystem, Core entity, schema, migration, Provider, execution authority or product semantics.

Accepted predecessor: `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d` (independently verified D08 merge).

Roadmap authority: `jaydumisuni/ptah-roadmap-` commit `98dc8c4e8639cda80510bee0625db34b4fdf9384`.

Milestone: **Full Workspace Release**.

D09 must prove concurrent human/agent operation, long-running recovery, Provider replacement, Plugin rollback, provenance/security reviewability, complete public/private/licence boundaries, and the complete deep Workspace burden under human, Hunter and Sergeant use without Ptah semantic-authority drift.

## Acceptance-only architecture

D09 follows the accepted A15 exact-head release pattern. Normal D09 surface is seven files: this design, implementation plan, durable record, ten-case corpus, checker, checker tests and permanent workflow.

Release audit adds exactly three proof-hygiene path changes:

- pin D07 permanent proof Actions and install Rust 1.97.1 explicitly;
- pin D08 permanent proof Actions the same way;
- retire obsolete write-capable `.github/workflows/d08-tdd.yml`.

Final D08→D09 release delta is exactly ten paths. No Cargo, runtime, schema, migration or generated-contract content moves.

## Recovered dependency/source/licence authority

D09 proof recovered three historical snapshots that remain valid only in their original scope:

1. A01 scaffold checks freeze original A01 workspace/Cargo state.
2. `tools/check_phase0c_scaffold.py` freezes an earlier 81-package external Cargo universe.
3. `dependencies/rust-direct-lock.json` retains valid direct dependency selections/policy but its nested `cargo_lock` object is an older historical snapshot.

The actual D08-identical current lock, mechanically verified by `tools/check_rust_dependency_lock.py`, is:

- SHA-256 `329f485f352afa35f3f6cb4df76ebf0c6e8b589a555386072f4a8750a5349987`;
- 130 resolved packages;
- 97 registry packages;
- 0 Git dependencies;
- 11 exact workspace direct dependencies.

D09 therefore proves current dependency identity by:

1. byte-comparing `Cargo.toml`, `Cargo.lock`, `deny.toml`, `dependencies/rust-direct-lock.json`, `dependencies/backend-artifact-lock.json`, generated manifest and generated Rust bindings to D08;
2. running `tools/check_rust_dependency_lock.py` and cross-checking its report with the exact D08 identity above;
3. requiring the 11 exact direct selections, their purposes and expected licences;
4. requiring canonical crates.io sources, 64-hex checksums and zero Git dependencies;
5. requiring the committed `deny.toml` source/wildcard/yanked/licence policy;
6. evaluating external package SPDX licence expressions with boolean semantics against that allow-list: OR succeeds when any branch is allowed, AND requires all conjuncts, parentheses are preserved, and unapproved WITH exceptions fail closed;
7. retaining the older nested Cargo snapshot as historical evidence with explicit non-use as the current gate;
8. retaining exact backend artifact/browser/signature identities.

This prevents both false rejection from unselected SPDX OR alternatives (for example `Unlicense OR MIT`) and accidental licence-policy widening.

## Reused milestone authorities

- D01: Human Workspace shell.
- D02: AI Project Workspace composition; Hunter/Sergeant remain caller adapters.
- A04: Activity/Operation/Attempt concurrency.
- A13: checkpoint/restart/verified recovery.
- B06: Session Vault compatible recovery.
- D05: Package/Plugin lifecycle and independently verified rollback.
- D06: provenance/SBOM/signing/proof-bundle evidence.
- D07: authorization/Finding/Claim/Evidence/remediation/reproduction history.
- D08: Application/Window/Display truth and explicit remote-platform deferrals.
- Apache-2.0 boundary tooling: operative public/private source policy.

D09 composes these authorities; it cannot redefine them.

## Deep Workspace burden

The exact candidate must retain 22 mechanical capabilities, 20 fixtures, 26 original positive/adversarial cases and 28 gap mappings, with no new Core entity, frozen-contract reopening or runtime authorization.

Passing the mechanical corpus never grants Ptah semantic context, review, approval, result-acceptance or next-action authority.

## Frozen D09 corpus

Exactly ten release categories:

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

## Permanent exact-head workflow

One exact candidate SHA must prove:

1. exact D08 predecessor and linear history;
2. remote branch equality;
3. exact ten-path release delta;
4. no product/Cargo/schema movement and D08 byte identity for dependency/contract authority files;
5. all external GitHub Actions pinned to immutable 40-hex commits;
6. current D08 dependency identity `329f485f…` / 130 / 97 / 0 / 11, correct SPDX policy semantics, and retained backend identity;
7. D09 ten-case corpus + 15 checker regressions;
8. deep Workspace 22/20/26 and non-authorizing AI validator;
9. D01/D02/A04 concurrent operation;
10. A13/B06 recovery;
11. D05 rollback/replacement;
12. D06 provenance/store round-trip;
13. D07 security/store round-trip;
14. exact D08 25+3;
15. Apache public/private boundary;
16. formatting + complete locked workspace + clean tracked worktree;
17. explicit release limitations;
18. deterministic SHA-256 report bundle;
19. retained artifact `d09-full-workspace-release-${TARGET_SHA}`.

Green status without the retained bundle is not D09 acceptance.

## Release and merge rule

Merge only after one exact SHA passes the permanent workflow, the retained artifact exists, the branch still equals that SHA, PR base remains exact D08, changed paths remain exactly ten, repository review/rules expose no blocker, and merge uses an expected-head guard.

After merge, independently verify `main` has exactly two parents in order:

1. D08 merge `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`;
2. frozen proven D09 SHA.

Merge tree must equal the proven candidate tree. Only then may D09 be COMPLETE and Programme D be **Full Workspace Release**.

## Non-claims

D09 does not complete Programme E distributed Ptah or Programme F OS-ready packaging; does not grant Ptah semantic/release/remediation authority; does not erase negative evidence; does not turn hosted CI into a pinned production Node; does not make deferred D08 platforms available; and does not grant public access to private records.
