# D09 Full Workspace Release Acceptance Implementation Plan

**Goal:** Prove the complete Programme D Full Workspace Release on one exact candidate head without adding runtime semantics or widening Ptah authority.

**Accepted predecessor:** `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`

**Roadmap authority:** `jaydumisuni/ptah-roadmap-` commit `98dc8c4e8639cda80510bee0625db34b4fdf9384`

**Toolchains:** Python 3.13, Rust/Cargo 1.97.1.

## Engineering rule

Recover repository evidence before changing a gate. Historical milestone validators remain valid evidence for their own frozen checkpoints; do not reinterpret an earlier workspace/package snapshot as the current Full Workspace dependency baseline after later accepted milestones legitimately expanded the repository.

## Global constraints

- D09 is acceptance-only: no new Core entity, Provider, runtime crate, schema, migration, generated binding, Cargo package or external dependency.
- Normal D09 surface is exactly seven files: design, this plan, durable record, ten-case corpus, checker, checker tests and permanent workflow.
- Reviewed proof-hygiene exception is exactly three paths:
  - modify D07 permanent proof only to pin external Actions / install Rust 1.97.1 explicitly;
  - modify D08 permanent proof the same way;
  - remove obsolete write-capable `.github/workflows/d08-tdd.yml`.
- Final D08→D09 delta is therefore exactly ten paths.
- No `Cargo.toml`, `Cargo.lock`, product crate/service/adapter, schema, migration or generated-contract content may move.
- D09 corpus remains exactly 10 cases.
- Deep Workspace remains 22 capabilities / 20 fixtures / 26 original cases / 28 gap mappings.
- Human, Hunter and Sergeant use must not grant Ptah context-selection, review, approval, result-acceptance or next-action authority.
- Green status without a retained digest-bound report bundle is not D09 acceptance.
- Merge only with an expected-head guard for the exact proven SHA.

## Recovered failed-proof evidence

Preserve these failures and do not repeat their invalid assumptions:

1. Initial D09 run found eight floating Action refs in D07/D08 proof machinery. Correct the proof hygiene; keep the immutable-pin rule.
2. A01 scaffold tests/checker freeze original A01 workspace/Cargo state and are historical after later accepted workspace expansion.
3. `tools/check_phase0c_scaffold.py` freezes an earlier 81-package external Cargo universe and is historical for current D09 dependency acceptance.
4. `dependencies/rust-direct-lock.json` still contains the valid 11 direct dependency selections and policy, but its nested `cargo_lock` object is an older snapshot and must not gate current D09 totals/digest.
5. The current D08-identical lock was mechanically recovered by `tools/check_rust_dependency_lock.py` as:
   - SHA `329f485f352afa35f3f6cb4df76ebf0c6e8b589a555386072f4a8750a5349987`;
   - 130 resolved packages;
   - 97 registry packages;
   - 0 Git dependencies;
   - 11 direct workspace dependencies.

The direct selection/policy and current verifier output are both retained; the historical nested Cargo snapshot is recorded but never treated as current authority.

---

### Task 1 — Freeze D09 corpus/checker

**Files:**
- `conformance/d09/full-workspace-release-cases.v0.1.0.json`
- `tools/check_d09_full_workspace_release.py`
- `tools/test_check_d09_full_workspace_release.py`

- [x] Freeze exactly ten required IDs/categories.
- [x] Require human/Hunter/Sergeant participation across the corpus.
- [x] Require `ptah_semantic_authority = false` for every case.
- [x] Require `new_core_entity_required = false`, `frozen_contract_change_required = false`, `runtime_feature_added = false`.
- [x] Add fail-closed stdlib-only checker regressions.
- [x] Require 15 checker tests and exact ten-case validation.
- [x] Provide deterministic SHA-256 metadata for required report files.

---

### Task 2 — Prove Full Workspace mechanical/authority burden

The permanent workflow must run and retain evidence for:

#### Deep Workspace / AI authority

```bash
PYTHONPATH=tools python3 tools/test_check_workspace_operations_donor_v2.py -v
python3 tools/check_workspace_operations_donor_v2.py --repo-root . --output <proof>/deep-workspace-validation.json
PYTHONPATH=tools python3 tools/test_check_ai_project_workspace_candidate.py -v
python3 tools/check_ai_project_workspace_candidate.py --repo-root . --output <proof>/ai-workspace-validation.json
```

Require deep status `pass`, 22 capabilities, 20 fixtures, 28 gap mappings, no new Core/frozen-contract/runtime authority. Require AI status `candidate_valid_non_operative` and Ptah decision/context/review authority false.

#### Human/agent concurrency and recovery

```bash
cargo test -p ptah-control --test d01_acceptance --locked
cargo test -p ptah-ai-workspace --test d02_acceptance --locked
cargo test -p ptah-activity-runtime --locked
cargo test -p ptah-checkpoint --test a13 --locked
cargo test -p ptah-checkpoint --test b06 --locked
```

#### Plugin / provenance / security

```bash
cargo test -p ptah-package-plugin --test d05_acceptance --locked
cargo test -p ptah-provenance --test d06_acceptance --locked
cargo test -p ptah-provenance --test store_roundtrip --locked
cargo test -p ptah-security-evidence --test d07_acceptance --locked
cargo test -p ptah-security-evidence --test store_roundtrip --locked
```

Require D05/D06/D07 acceptance counts = 30 each.

#### D08 Application truth

```bash
cargo test -p ptah-application-runtime --test d08_acceptance --locked
cargo test -p ptah-control --test d08_application_projection --locked
```

Require exactly 25 runtime + 3 shell = 28.

#### Apache/public-private boundary

Run the authoritative Apache boundary unit suite + validator. Require:

- `status = owner_accepted_operative_verified`;
- `apache_2_0_accepted = true`;
- `runtime_implementation_authorized = false`.

#### Complete workspace

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
```

Require clean tracked worktree.

---

### Task 3 — Prove current D08-bound dependency/licence/source identity

This task is predecessor-relative release acceptance, not a replay of A01/Phase-0C package counts.

- [x] Byte-compare to D08:
  - `Cargo.toml`
  - `Cargo.lock`
  - `deny.toml`
  - `dependencies/rust-direct-lock.json`
  - `dependencies/backend-artifact-lock.json`
  - `contracts/generated/manifest.json`
  - `crates/ptah-contracts/src/generated.rs`
- [x] Retain exact `Cargo.lock` and `cargo metadata --locked`.
- [x] Run `tools/check_rust_dependency_lock.py` and retain its JSON report.
- [x] Require current D08-identical lock SHA `329f485f352afa35f3f6cb4df76ebf0c6e8b589a555386072f4a8750a5349987`.
- [x] Require current exact counts: 130 resolved / 97 registry / 0 Git / 11 direct.
- [x] Cross-check those values against `rust-dependency-lock.json`, not the old nested `rust-direct-lock.json.cargo_lock` snapshot.
- [x] Require workspace direct-dependency names exactly equal the 11 selected entries and every version exact `=version`.
- [x] Require direct selections retain purpose and expected licence.
- [x] Require canonical crates.io source + 64-hex checksum for every registry package.
- [x] Require `deny.toml` unknown-registry deny, unknown-Git deny, wildcard deny, yanked deny and committed licence allow-list.
- [x] Require every external package licence expression reported by `cargo metadata --locked` to be composed only of identifiers in that allow-list.
- [x] Require historical nested Cargo snapshot to exist but record `historical_selection_snapshot_used_as_current_gate = false`.
- [x] Retain backend evidence identity: 9 static artifacts, 599 browser files, 4 verified signatures, runtime authority false.
- [x] Require every external GitHub Action ref to be a full 40-hex pin.

If this gate fails, recover evidence first. Do not alter `Cargo.lock` merely to satisfy a historical snapshot.

---

### Task 4 — Permanent exact-head workflow / retained bundle

Workflow: `.github/workflows/d09-full-workspace-release-acceptance.yml`.

It must prove on one exact SHA:

1. exact D08 predecessor and linear history;
2. remote branch equality;
3. exact ten-path release delta;
4. no product/Cargo/schema movement and D08 byte identity for dependency/contract authority files;
5. immutable external Action refs;
6. current D08 dependency/licence/source/backend identity from Task 3;
7. exact D09 ten-case corpus + 15 checker regressions;
8. deep Workspace + AI authority separation;
9. D01/D02/A04/A13/B06;
10. D05/D06/D07;
11. exact D08 25+3;
12. Apache public/private boundary;
13. formatting + complete locked workspace + clean tracked worktree;
14. explicit limitations;
15. deterministic report-file SHA-256 metadata;
16. verified `report-bundle.json` + `report-bundle.sha256`;
17. retained artifact `d09-full-workspace-release-${TARGET_SHA}` for 90 days.

Bundle must retain exact candidate/predecessor/roadmap/toolchain identity, D08 byte identity, Action audit, current dependency-policy audit, current Rust dependency report, backend identity, D09/deep/AI reports, D01/D02/A04/A13/B06 evidence, D05/D06/D07 evidence/counts, D08 evidence/counts, Apache evidence, full-workspace evidence and explicit limitations.

Bundle assertions include:

- D09 cases = 10;
- deep Workspace = 26 / 22 / 20;
- D08 = 25 + 3;
- dependency counts = 130 / 97 / 0;
- participants exactly human/Hunter/Sergeant;
- Ptah semantic/decision/context/review authority all false.

Green workflow status without this bundle is not acceptance.

---

### Task 5 — Freeze, prove, merge, independently verify

- [ ] Freeze exact remote D09 head. Any content change invalidates proof.
- [ ] Require every permanent workflow step green for that exact SHA.
- [ ] Require artifact `d09-full-workspace-release-${SHA}` for that exact SHA.
- [ ] Inspect bundle and verify SHA-256, required reports, counts and authority fields.
- [ ] Open/reuse PR `D09 — Full Workspace release acceptance` against `main` with exact SHA/run/artifact/D08 predecessor/non-claims.
- [ ] Verify PR head is frozen SHA, base remains exact D08, changed paths exactly ten, and no unresolved review/repository rule blocks merge.
- [ ] Merge only with `expected_head_sha=<proven D09 SHA>` and merge-commit semantics.
- [ ] Independently verify new `main` has exactly two parents in order:
  1. `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`;
  2. frozen proven D09 SHA.
- [ ] Require merge tree equals proven D09 candidate tree.
- [ ] Only then mark D09 COMPLETE and Programme D **Full Workspace Release**.

Programme E distributed Ptah and Programme F OS-ready packaging remain separate future authority.
