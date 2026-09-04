# D09 Full Workspace Release Acceptance Implementation Plan

**Goal:** Prove Programme D Full Workspace Release on one exact candidate head without adding runtime semantics or widening Ptah authority.

**Accepted predecessor:** `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`

**Roadmap authority:** `jaydumisuni/ptah-roadmap-` commit `98dc8c4e8639cda80510bee0625db34b4fdf9384`

**Toolchains:** Python 3.13, Rust/Cargo 1.97.1.

## Engineering rule

Recover repository evidence before changing a gate. Historical milestone validators remain evidence for their own frozen checkpoints; do not force a later accepted workspace back into an earlier package/member snapshot.

## Global constraints

- D09 is acceptance-only: no new Core entity, Provider, runtime crate, schema, migration, generated binding, Cargo package or external dependency.
- Normal D09 surface is seven files: design, this plan, durable record, ten-case corpus, checker, checker tests and permanent workflow.
- Reviewed proof-hygiene exception is three paths only: pin D07 proof Actions, pin D08 proof Actions, remove obsolete write-capable `d08-tdd.yml`.
- Final D08→D09 delta must therefore be exactly ten paths.
- No Cargo/product/schema/migration/generated-contract content may move.
- D09 corpus = exactly 10 cases.
- Deep Workspace = 22 capabilities / 20 fixtures / 26 original cases / 28 gap mappings.
- Human, Hunter and Sergeant use must not grant Ptah context-selection, review, approval, result-acceptance or next-action authority.
- Green status without the retained digest-bound report bundle is not acceptance.
- Merge only with an expected-head guard for the exact proven SHA.

## Recovered failed-proof evidence

Preserve these failures and do not repeat their invalid assumptions:

1. Initial D09 run found eight floating Action refs in completed D07/D08 proof machinery. Correct proof hygiene; keep the immutable-pin rule.
2. A01 scaffold checks freeze original A01 workspace/Cargo state and are historical after later accepted expansion.
3. `tools/check_phase0c_scaffold.py` freezes an earlier 81-package external Cargo universe and is historical for D09 dependency acceptance.
4. `dependencies/rust-direct-lock.json` retains valid direct selections/policy but its nested `cargo_lock` object is an older snapshot and is not the current Cargo identity.
5. Current D08-identical `Cargo.lock`, recovered by `tools/check_rust_dependency_lock.py`, is SHA `329f485f352afa35f3f6cb4df76ebf0c6e8b589a555386072f4a8750a5349987`, 130 resolved / 97 registry / 0 Git / 11 direct.
6. Licence policy must follow SPDX boolean semantics. Example: `Unlicense OR MIT` is satisfiable because MIT is allowed; an OR expression does not require every alternative identifier to be allowed. AND requires every conjunct. WITH exceptions remain fail-closed unless independently authorized by policy.

---

### Task 1 — D09 corpus/checker

- [x] Freeze exactly ten required IDs/categories.
- [x] Require human/Hunter/Sergeant participation across the corpus.
- [x] Require `ptah_semantic_authority = false` for every case.
- [x] Require no new Core/frozen-contract/runtime feature.
- [x] Add fail-closed stdlib-only checker regressions.
- [x] Require 15 checker tests and exact ten-case validation.
- [x] Provide deterministic report-file SHA-256 metadata.

### Task 2 — Full Workspace mechanical/authority burden

Permanent proof must run:

```bash
PYTHONPATH=tools python3 tools/test_check_workspace_operations_donor_v2.py -v
python3 tools/check_workspace_operations_donor_v2.py --repo-root . --output <proof>/deep-workspace-validation.json
PYTHONPATH=tools python3 tools/test_check_ai_project_workspace_candidate.py -v
python3 tools/check_ai_project_workspace_candidate.py --repo-root . --output <proof>/ai-workspace-validation.json
cargo test -p ptah-control --test d01_acceptance --locked
cargo test -p ptah-ai-workspace --test d02_acceptance --locked
cargo test -p ptah-activity-runtime --locked
cargo test -p ptah-checkpoint --test a13 --locked
cargo test -p ptah-checkpoint --test b06 --locked
cargo test -p ptah-package-plugin --test d05_acceptance --locked
cargo test -p ptah-provenance --test d06_acceptance --locked
cargo test -p ptah-provenance --test store_roundtrip --locked
cargo test -p ptah-security-evidence --test d07_acceptance --locked
cargo test -p ptah-security-evidence --test store_roundtrip --locked
cargo test -p ptah-application-runtime --test d08_acceptance --locked
cargo test -p ptah-control --test d08_application_projection --locked
cargo fmt --all -- --check
cargo test --workspace --locked
```

Require deep Workspace 22/20/26/28, AI non-operative authority fields false, D05/D06/D07 = 30 cases each, D08 = 25+3, Apache boundary `owner_accepted_operative_verified`, and clean tracked worktree.

### Task 3 — Current D08-bound dependency/licence/source identity

- [x] Byte-compare to D08: `Cargo.toml`, `Cargo.lock`, `deny.toml`, `dependencies/rust-direct-lock.json`, `dependencies/backend-artifact-lock.json`, generated manifest and generated Rust bindings.
- [x] Retain exact `Cargo.lock` and `cargo metadata --locked`.
- [x] Run and retain `tools/check_rust_dependency_lock.py` output.
- [x] Require current D08 lock SHA `329f485f352afa35f3f6cb4df76ebf0c6e8b589a555386072f4a8750a5349987` and counts 130 / 97 / 0 / 11.
- [x] Cross-check current values against `rust-dependency-lock.json`; never against the historical nested Cargo snapshot.
- [x] Require the 11 exact direct dependency names/versions, purposes and expected licences.
- [x] Require canonical crates.io sources + 64-hex checksums + zero Git dependencies.
- [x] Require `deny.toml` unknown-registry deny, unknown-Git deny, wildcard deny, yanked deny and committed licence allow-list.
- [x] Evaluate each external package SPDX expression against the committed allow-list: OR = any branch allowed; AND = all branches allowed; parentheses respected; WITH exception = fail closed unless separately authorized.
- [x] Do **not** widen the allow-list merely because an unselected OR alternative is not allowed.
- [x] Retain the old nested Cargo snapshot as historical evidence with `historical_selection_snapshot_used_as_current_gate = false`.
- [x] Retain backend evidence identity: 9 static artifacts, 599 browser files, 4 verified signatures, runtime authority false.
- [x] Require every external GitHub Action ref to be a full 40-hex pin.

If this gate fails, recover evidence first. Do not alter `Cargo.lock` or licence policy merely to satisfy a historical snapshot or an incorrect parser.

### Task 4 — Permanent exact-head bundle

The permanent workflow must prove on one exact SHA:

1. exact D08 predecessor, linear history and branch equality;
2. exact ten-path release delta;
3. no product/Cargo/schema movement and D08 byte identity for dependency/contract authority files;
4. immutable Action refs;
5. current D08 dependency/licence/source/backend identity;
6. D09 ten-case corpus + 15 checker regressions;
7. deep Workspace + AI authority separation;
8. D01/D02/A04/A13/B06;
9. D05/D06/D07;
10. exact D08 25+3;
11. Apache public/private boundary;
12. formatting + full locked workspace + clean tracked worktree;
13. explicit limitations;
14. deterministic SHA-256 report bundle;
15. retained artifact `d09-full-workspace-release-${TARGET_SHA}`.

Bundle assertions: D09=10; deep=26/22/20; D08=25+3; dependencies=130/97/0; participants exactly human/Hunter/Sergeant; Ptah semantic/decision/context/review authority all false.

### Task 5 — Freeze, prove, merge, independently verify

- [ ] Freeze exact remote D09 head; any content movement invalidates proof.
- [ ] Require every permanent workflow step green for that SHA.
- [ ] Require artifact `d09-full-workspace-release-${SHA}` for that SHA.
- [ ] Inspect bundle SHA-256, required reports, counts and authority fields.
- [ ] Open/reuse PR `D09 — Full Workspace release acceptance` against `main` with exact proven SHA/run/artifact/predecessor/non-claims.
- [ ] Verify PR head/base, exact ten changed paths and no unresolved blocker.
- [ ] Merge only with `expected_head_sha=<proven D09 SHA>` and merge-commit semantics.
- [ ] Independently verify `main` parents exactly: D08 merge first, proven D09 SHA second; merge tree equals candidate tree.
- [ ] Only then mark D09 COMPLETE and Programme D **Full Workspace Release**.

Programme E distributed Ptah and Programme F OS-ready packaging remain separate future authority.
