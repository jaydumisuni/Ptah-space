# D09 Full Workspace Release Acceptance Implementation Plan

> **Execution rule:** recover repository evidence before changing a gate. D09 is acceptance-only; historical milestone validators are evidence for their own frozen checkpoints and must not be reinterpreted as the current Full Workspace dependency baseline when later accepted milestones legitimately changed the workspace.

**Goal:** Prove the complete Programme D Full Workspace Release on one exact candidate head without adding runtime semantics or widening Ptah authority.

**Architecture:** D09 freezes a ten-case release corpus, validates it with a stdlib-only checker, composes existing D01–D08/A04/A13/B06 acceptance authorities, audits the current D08-bound dependency/licence/source state, and retains a digest-bound exact-head release bundle.

**Accepted predecessor:** `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`

**Roadmap authority:** `jaydumisuni/ptah-roadmap-` commit `98dc8c4e8639cda80510bee0625db34b4fdf9384`

**Toolchains:** Python 3.13, Rust/Cargo 1.97.1.

## Global constraints

- No new Core entity, Provider, runtime crate, schema, migration, generated binding, Cargo package or external dependency.
- Normal D09 surface is exactly seven acceptance/proof files:
  - `docs/superpowers/specs/2026-09-04-d09-full-workspace-release-acceptance-design.md`
  - this plan
  - `D09_FULL_WORKSPACE_RELEASE_ACCEPTANCE.md`
  - `conformance/d09/full-workspace-release-cases.v0.1.0.json`
  - `tools/check_d09_full_workspace_release.py`
  - `tools/test_check_d09_full_workspace_release.py`
  - `.github/workflows/d09-full-workspace-release-acceptance.yml`
- The reviewed release audit adds exactly three proof-hygiene path changes:
  - modify `.github/workflows/d07-security-evidence-reproduction-proof.yml` only to restore immutable Action pins / explicit Rust 1.97.1 installation;
  - modify `.github/workflows/d08-application-platform-expansion-proof.yml` for the same proof-hygiene correction;
  - remove obsolete write-capable `.github/workflows/d08-tdd.yml`.
- Therefore final D08→D09 delta is exactly ten paths.
- No `Cargo.toml`, `Cargo.lock`, product crate/service/adapter, schema, migration or generated-contract content may move.
- Frozen D09 corpus contains exactly 10 cases.
- Deep Workspace profile remains 22 mechanical capabilities / 20 fixtures / 26 original cases / 28 gap mappings.
- Human, Hunter and Sergeant use must not grant Ptah context-selection, review, approval, result-acceptance or next-action authority.
- Negative, partial, failed, inconclusive, contradictory and regressed evidence remains visible.
- Green status without the retained digest-bound report bundle is not D09 acceptance.
- Merge only with an expected-head guard for the exact proven candidate SHA.

## Recovered release-audit history

The D09 proof process has already produced useful failed evidence. Preserve it; do not repeat the same invalid assumptions.

1. Initial exact-head audit found eight floating external Action refs in completed D07/D08 workflows. Correct the proof machinery; do not weaken the immutable-pin rule.
2. A later proof invoked `tools/test_check_a01_scaffold.py` / `tools/check_a01_scaffold.py` and failed because those tools freeze the original A01 workspace/Cargo state. Repository history already identifies those assumptions as historical after later workspace expansion.
3. The next proof invoked `tools/check_phase0c_scaffold.py` and failed on its frozen 81-package external Cargo universe. The accepted D08 predecessor now carries the later committed dependency identity: 11 exact direct workspace dependencies, 116 resolved packages, 97 registry packages, zero Git dependencies.
4. The accepted A15 exact-head workflow establishes the current dependency-proof precedent: capture `Cargo.lock`, run `cargo metadata --locked`, run `tools/check_rust_dependency_lock.py`, and bind retained backend identities. D09 strengthens this by byte-comparing the dependency/contract authority files to D08 and mechanically checking the present licence/source policy.

Historical A01 and Phase-0C package-universe validators remain valid historical evidence. They are not the current D09 dependency baseline.

---

### Task 1 — Freeze D09 release corpus and checker

**Files:**
- `conformance/d09/full-workspace-release-cases.v0.1.0.json`
- `tools/check_d09_full_workspace_release.py`
- `tools/test_check_d09_full_workspace_release.py`

- [x] Freeze exactly ten case IDs/categories covering human/agent coexistence, deep Workspace authority separation, A04 concurrency, A13/B06 recovery, Provider replacement, D05 rollback, D06 provenance, D07 security history, D08 Application truth, and public/private release audit.
- [x] Require participants across the corpus to be exactly human/Hunter/Sergeant.
- [x] Require `ptah_semantic_authority: false`, `new_core_entity_required: false`, `frozen_contract_change_required: false`, and `runtime_feature_added: false`.
- [x] Add fail-closed regression coverage and deterministic report-file SHA-256 metadata.
- [x] Require checker regression count to remain 15 and corpus count to remain 10.

---

### Task 2 — Re-prove cross-milestone Full Workspace burden

The permanent workflow must prove on one candidate:

#### Deep Workspace and AI authority

```bash
PYTHONPATH=tools python3 tools/test_check_workspace_operations_donor_v2.py -v
python3 tools/check_workspace_operations_donor_v2.py --repo-root . --output <proof>/deep-workspace-validation.json
PYTHONPATH=tools python3 tools/test_check_ai_project_workspace_candidate.py -v
python3 tools/check_ai_project_workspace_candidate.py --repo-root . --output <proof>/ai-workspace-validation.json
```

Require:

- deep Workspace status `pass`;
- 22 capabilities / 20 fixtures / 28 gap mappings;
- no new Core entity / no frozen-contract change / no runtime authorization;
- AI status `candidate_valid_non_operative`;
- Ptah decision/context/review authority all false.

#### Human/agent concurrency and recovery

```bash
cargo test -p ptah-control --test d01_acceptance --locked
cargo test -p ptah-ai-workspace --test d02_acceptance --locked
cargo test -p ptah-activity-runtime --locked
cargo test -p ptah-checkpoint --test a13 --locked
cargo test -p ptah-checkpoint --test b06 --locked
```

#### Plugin/provenance/security

```bash
cargo test -p ptah-package-plugin --test d05_acceptance --locked
cargo test -p ptah-provenance --test d06_acceptance --locked
cargo test -p ptah-provenance --test store_roundtrip --locked
cargo test -p ptah-security-evidence --test d07_acceptance --locked
cargo test -p ptah-security-evidence --test store_roundtrip --locked
```

Require D05/D06/D07 acceptance counts to remain exactly 30 each.

#### Application truth

```bash
cargo test -p ptah-application-runtime --test d08_acceptance --locked
cargo test -p ptah-control --test d08_application_projection --locked
```

Require exactly 25 runtime + 3 shell = 28 cases.

#### Public/private boundary

Run the current Apache-2.0 boundary unit suite and validator. Require:

- `status = owner_accepted_operative_verified`;
- `apache_2_0_accepted = true`;
- `runtime_implementation_authorized = false`.

#### Complete workspace

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
```

Require clean tracked worktree afterward.

---

### Task 3 — Current D08-bound dependency/licence/source proof

This is predecessor-relative release acceptance, not a Phase-0C package-count replay.

- [x] Prove these candidate files are byte-identical to D08:
  - `Cargo.toml`
  - `Cargo.lock`
  - `deny.toml`
  - `dependencies/rust-direct-lock.json`
  - `dependencies/backend-artifact-lock.json`
  - `contracts/generated/manifest.json`
  - `crates/ptah-contracts/src/generated.rs`
- [x] Retain exact `Cargo.lock` bytes and `cargo metadata --locked` output.
- [x] Run `tools/check_rust_dependency_lock.py` on the candidate.
- [x] Require committed/current Cargo identity to match:
  - resolved packages = 116;
  - registry packages = 97;
  - Git dependencies = 0;
  - current `Cargo.lock` SHA-256 equals the committed dependency selection.
- [x] Require the exact workspace direct-dependency set to equal the 11 committed selections and exact `=version` constraints.
- [x] Require canonical crates.io source and 64-hex checksum for every registry package.
- [x] Require `deny.toml` to retain unknown-registry deny, unknown-Git deny, wildcard deny, yanked deny and the committed licence allow-list.
- [x] Require every external package licence expression reported by `cargo metadata --locked` to use only identifiers in the committed allow-list.
- [x] Retain backend lock identity and exact Phase-0C backend evidence counts: 9 static artifacts, 599 browser files, 4 verified signatures, runtime authorization false.
- [x] Audit every external GitHub Action reference for a full 40-hex immutable pin.

Any mismatch is a failed D09 candidate. Do not edit `Cargo.lock` to make this gate pass; recover the owning milestone/authority first.

---

### Task 4 — Permanent exact-head workflow and retained bundle

**Workflow:** `.github/workflows/d09-full-workspace-release-acceptance.yml`

The workflow must:

1. checkout exact candidate SHA;
2. pin Python 3.13 and Rust/Cargo 1.97.1;
3. prove `origin/main` equals D08 merge `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`;
4. prove linear branch history and remote branch equality;
5. prove exact ten-path D08→D09 release delta;
6. prove no product/Cargo/schema movement and D08 byte identity for dependency/contract authority files;
7. prove immutable external Action refs;
8. prove current dependency/licence/source/backend identity;
9. prove D09 ten-case corpus and checker regressions;
10. prove deep Workspace + AI authority separation;
11. prove D01/D02/A04/A13/B06;
12. prove D05/D06/D07;
13. prove exact D08 25+3;
14. prove Apache public/private boundary;
15. prove formatting + full locked workspace + clean tracked worktree;
16. write explicit release limitations;
17. bind every required report into deterministic SHA-256 metadata;
18. write and verify `report-bundle.json` + `report-bundle.sha256`;
19. upload `d09-full-workspace-release-${TARGET_SHA}` with 90-day retention.

The report bundle must retain at least:

- exact D09 candidate and D08 predecessor identities;
- roadmap authority;
- host/toolchain identity;
- D08 byte-identity proof;
- immutable Action audit;
- Cargo metadata/current dependency-policy audit/Rust dependency-lock report;
- retained backend identity;
- D09/deep Workspace/AI reports;
- D01/D02/A04/A13/B06 test evidence;
- D05/D06/D07 counts and test evidence;
- D08 25+3 lists and test evidence;
- Apache boundary evidence;
- formatting/full-workspace evidence;
- explicit limitations and release instructions.

Green workflow status without this retained bundle is not acceptance.

---

### Task 5 — Freeze, prove, merge, independently verify

- [ ] **Freeze:** record exact remote D09 branch head. Any content movement invalidates proof.
- [ ] **Prove:** require every step of the permanent D09 workflow successful for that exact SHA.
- [ ] **Artifact:** require retained artifact `d09-full-workspace-release-${SHA}` for that same SHA.
- [ ] **Inspect bundle:** verify bundle status, exact head, SHA-256, required report presence, D09=10, deep Workspace=26/22/20, D08=25+3, dependency Git count=0, participants human/Hunter/Sergeant, Ptah semantic authority=false.
- [ ] **PR:** open/reuse PR `D09 — Full Workspace release acceptance` against `main`; state exact proven SHA/run/artifact/predecessor/non-claims.
- [ ] **Review:** verify PR head equals proven SHA, base equals exact D08 merge, changed paths are exactly the reviewed ten paths, and no unresolved review/repository rule blocks merge.
- [ ] **Merge:** use merge commit with `expected_head_sha=<proven D09 SHA>`. Any head movement aborts promotion.
- [ ] **Independent main verification:** require merge parents exactly:
  1. `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`;
  2. frozen proven D09 candidate SHA.
- [ ] Require merge tree equals proven D09 candidate tree.
- [ ] Only then mark D09 COMPLETE and Programme D at **Full Workspace Release**.

Programme E distributed Ptah and Programme F OS-ready packaging remain separate future authority.
