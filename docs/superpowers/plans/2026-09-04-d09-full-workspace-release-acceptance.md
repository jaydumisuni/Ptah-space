# D09 Full Workspace Release Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the complete Programme D Full Workspace Release on one exact candidate head without adding runtime semantics or widening Ptah authority.

**Architecture:** D09 is an acceptance-only layer. It freezes a ten-case release corpus, validates that corpus with a stdlib-only checker, composes existing D01–D08/A04/A13/B06 acceptance surfaces in one permanent exact-head workflow, and retains a digest-bound release evidence bundle. Product crates, Cargo locks, schemas, migrations and generated bindings stay byte-identical to the accepted D08 predecessor unless proof reveals a real defect.

**Tech Stack:** Python 3.13 stdlib, GitHub Actions, Rust/Cargo 1.97.1, existing Ptah Rust acceptance targets and existing Phase-0C/A15 Python validators.

**Spec:** `docs/superpowers/specs/2026-09-04-d09-full-workspace-release-acceptance-design.md`

## Global Constraints

- Accepted predecessor is exact D08 merge `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`.
- Roadmap authority is `jaydumisuni/ptah-roadmap-` commit `98dc8c4e8639cda80510bee0625db34b4fdf9384`.
- D09 is acceptance-only: no new Core entity, Provider, runtime crate, schema, migration, generated binding, Cargo package or external dependency.
- Normal D09 delta is limited to the design, this plan, durable record, ten-case corpus, checker, checker tests and exact-head workflow.
- The frozen D09 release corpus contains exactly 10 cases.
- The accepted deep Workspace validator must retain 22 mechanical capabilities, 20 fixtures and 26 original cases.
- Human, Hunter and Sergeant use must not give Ptah context-selection, review, approval, acceptance or next-action authority.
- Negative, partial, failed, inconclusive, contradictory and regressed evidence remains visible.
- Green status without a retained digest-bound report bundle is not D09 acceptance.
- Merge only with an expected-head guard for the exact proven candidate SHA.

---

### Task 1: Freeze the D09 Release Corpus and Checker Contract

**Files:**
- Create: `conformance/d09/full-workspace-release-cases.v0.1.0.json`
- Create: `tools/test_check_d09_full_workspace_release.py`
- Create: `tools/check_d09_full_workspace_release.py`

**Interfaces:**
- Consumes: accepted D09 design and existing A15 checker/report-bundle conventions.
- Produces: `load_and_validate_corpus(path: Path) -> dict`, `require_report_files(root: Path, names: list[str]) -> list[dict]`, and CLI `python3 tools/check_d09_full_workspace_release.py --repo-root . --output <path>`.

- [ ] **Step 1: Write the frozen ten-case JSON corpus.**

Use schema:

```json
{
  "schema_version": "0.1.0",
  "record_type": "ptah.d09.full_workspace_release_corpus",
  "accepted_predecessor": "ca6b3526ce9b58ffce11f8582be8fbf860dfa53d",
  "roadmap_authority": "98dc8c4e8639cda80510bee0625db34b4fdf9384",
  "new_core_entity_required": false,
  "frozen_contract_change_required": false,
  "runtime_feature_added": false,
  "cases": [
    {
      "id": "d09-01-human-agent-coexistence",
      "category": "human_agent_coexistence",
      "participants": ["human", "hunter", "sergeant"],
      "ptah_semantic_authority": false,
      "required_evidence": ["d01_acceptance", "d02_acceptance"]
    },
    {
      "id": "d09-02-deep-workspace-authority-separation",
      "category": "deep_workspace_authority_separation",
      "participants": ["human", "hunter", "sergeant"],
      "ptah_semantic_authority": false,
      "required_evidence": ["deep_workspace_26", "ai_workspace_validator"]
    },
    {
      "id": "d09-03-concurrent-activity-operation",
      "category": "concurrent_activity_operation",
      "participants": ["human", "hunter"],
      "ptah_semantic_authority": false,
      "required_evidence": ["a04_activity_runtime"]
    },
    {
      "id": "d09-04-long-running-recovery",
      "category": "long_running_recovery",
      "participants": ["human", "hunter"],
      "ptah_semantic_authority": false,
      "required_evidence": ["a13_recovery", "b06_session_vault"]
    },
    {
      "id": "d09-05-provider-replacement",
      "category": "provider_replacement",
      "participants": ["human"],
      "ptah_semantic_authority": false,
      "required_evidence": ["d05_provider_generation", "d06_backend_replacement", "d07_backend_replacement"]
    },
    {
      "id": "d09-06-plugin-rollback",
      "category": "plugin_rollback",
      "participants": ["human"],
      "ptah_semantic_authority": false,
      "required_evidence": ["d05_plugin_rollback"]
    },
    {
      "id": "d09-07-provenance-reviewability",
      "category": "provenance_reviewability",
      "participants": ["human", "sergeant"],
      "ptah_semantic_authority": false,
      "required_evidence": ["d06_acceptance", "d06_store_roundtrip"]
    },
    {
      "id": "d09-08-security-reproduction-history",
      "category": "security_reproduction_history",
      "participants": ["human", "sergeant"],
      "ptah_semantic_authority": false,
      "required_evidence": ["d07_acceptance", "d07_store_roundtrip"]
    },
    {
      "id": "d09-09-application-truth",
      "category": "application_truth",
      "participants": ["human", "hunter"],
      "ptah_semantic_authority": false,
      "required_evidence": ["d08_runtime_25", "d08_shell_3"]
    },
    {
      "id": "d09-10-public-private-release-audit",
      "category": "public_private_release_audit",
      "participants": ["human", "hunter", "sergeant"],
      "ptah_semantic_authority": false,
      "required_evidence": ["apache_boundary", "d02_private_workspace_denial"]
    }
  ]
}
```

- [ ] **Step 2: Write checker unit tests before implementation.**

`tools/test_check_d09_full_workspace_release.py` must cover at least:

```python
class D09CheckerTests(unittest.TestCase):
    def test_repository_corpus_is_valid(self): ...
    def test_rejects_wrong_case_count(self): ...
    def test_rejects_duplicate_case_id(self): ...
    def test_rejects_missing_required_category(self): ...
    def test_rejects_missing_human_hunter_or_sergeant_participant(self): ...
    def test_rejects_ptah_semantic_authority(self): ...
    def test_rejects_new_core_entity_requirement(self): ...
    def test_rejects_frozen_contract_change(self): ...
    def test_rejects_runtime_feature_addition(self): ...
    def test_require_report_files_rejects_missing_file(self): ...
    def test_require_report_files_rejects_empty_file(self): ...
    def test_require_report_files_returns_deterministic_sha256(self): ...
```

The tests import only `tools/check_d09_full_workspace_release.py` and Python stdlib modules.

- [ ] **Step 3: Run RED.**

Run:

```bash
PYTHONPATH=tools python3 -m unittest -v tools/test_check_d09_full_workspace_release.py
```

Expected: failure because the checker module or required functions are absent.

- [ ] **Step 4: Implement the minimal checker.**

Required constants:

```python
EXPECTED_SCHEMA_VERSION = "0.1.0"
EXPECTED_RECORD_TYPE = "ptah.d09.full_workspace_release_corpus"
EXPECTED_PREDECESSOR = "ca6b3526ce9b58ffce11f8582be8fbf860dfa53d"
EXPECTED_ROADMAP_AUTHORITY = "98dc8c4e8639cda80510bee0625db34b4fdf9384"
EXPECTED_CATEGORIES = {
    "human_agent_coexistence",
    "deep_workspace_authority_separation",
    "concurrent_activity_operation",
    "long_running_recovery",
    "provider_replacement",
    "plugin_rollback",
    "provenance_reviewability",
    "security_reproduction_history",
    "application_truth",
    "public_private_release_audit",
}
EXPECTED_PARTICIPANTS = {"human", "hunter", "sergeant"}
```

`load_and_validate_corpus` must raise `ValueError` on any contract violation and return the parsed dictionary on success.

`require_report_files` must reject missing, non-file or zero-byte paths and return sorted records shaped exactly as:

```python
{
    "path": name,
    "size": path.stat().st_size,
    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
}
```

CLI output must be JSON with:

```json
{
  "schema_version": "0.1.0",
  "record_type": "ptah.d09.full_workspace_release_validation",
  "status": "pass",
  "case_count": 10,
  "participants": ["human", "hunter", "sergeant"],
  "ptah_semantic_authority": false,
  "new_core_entity_required": false,
  "frozen_contract_change_required": false,
  "runtime_feature_added": false
}
```

- [ ] **Step 5: Run GREEN and direct validator.**

Run:

```bash
PYTHONPATH=tools python3 -m unittest -v tools/test_check_d09_full_workspace_release.py
python3 tools/check_d09_full_workspace_release.py --repo-root . --output /tmp/d09-validation.json
```

Expected: all checker tests pass; validation reports `status: pass` and `case_count: 10`.

- [ ] **Step 6: Commit Task 1.**

Commit:

`test(d09): freeze full workspace release corpus`

---

### Task 2: Re-prove the Cross-Milestone Full Workspace Burden

**Files:**
- Modify only if a genuine proof defect is found: existing product source/tests owned by the failing predecessor milestone.
- No normal D09 source file change is expected in this task.

**Interfaces:**
- Consumes: existing D01/D02/A04/A13/B06/D05/D06/D07/D08 acceptance targets and accepted Phase-0C validators.
- Produces: fresh command evidence for the permanent D09 workflow design.

- [ ] **Step 1: Prove deep Workspace and AI authority validators.**

Run:

```bash
PYTHONPATH=tools python3 tools/test_check_workspace_operations_donor_v2.py -v
python3 tools/check_workspace_operations_donor_v2.py --repo-root . --output /tmp/d09-deep-workspace.json
PYTHONPATH=tools python3 tools/test_check_ai_project_workspace_candidate.py -v
python3 tools/check_ai_project_workspace_candidate.py --repo-root . --output /tmp/d09-ai-workspace.json
```

Require deep Workspace report fields:

```text
status = pass
mechanical_capability_count = 22
fixture_count = 20
gap_mapping_count = 28
new_core_entity_required = false
frozen_contract_change_required = false
runtime_implementation_authorized = false
```

Require AI report fields:

```text
status = candidate_valid_non_operative
ptah_decision_authority = false
ptah_context_selection_authority = false
ptah_review_authority = false
runtime_implementation_authorized = false
```

- [ ] **Step 2: Prove human/agent and concurrency/recovery acceptance.**

Run:

```bash
cargo test -p ptah-control --test d01_acceptance --locked
cargo test -p ptah-ai-workspace --test d02_acceptance --locked
cargo test -p ptah-activity-runtime --locked
cargo test -p ptah-checkpoint --test a13 --locked
cargo test -p ptah-checkpoint --test b06 --locked
```

Every command must exit 0.

- [ ] **Step 3: Prove Plugin/provenance/security/Application acceptance.**

Run:

```bash
cargo test -p ptah-package-plugin --test d05_acceptance --locked
cargo test -p ptah-provenance --test d06_acceptance --locked
cargo test -p ptah-provenance --test store_roundtrip --locked
cargo test -p ptah-security-evidence --test d07_acceptance --locked
cargo test -p ptah-security-evidence --test store_roundtrip --locked
cargo test -p ptah-application-runtime --test d08_acceptance --locked
cargo test -p ptah-control --test d08_application_projection --locked
```

Before accepting the D08 result, count tests:

```bash
runtime_count="$(cargo test -p ptah-application-runtime --test d08_acceptance --locked -- --list 2>/dev/null | grep -c ': test$')"
shell_count="$(cargo test -p ptah-control --test d08_application_projection --locked -- --list 2>/dev/null | grep -c ': test$')"
test "$runtime_count" -eq 25
test "$shell_count" -eq 3
test "$((runtime_count + shell_count))" -eq 28
```

- [ ] **Step 4: Prove public/private and licence boundary.**

Use the exact invocation recovered from the current Apache boundary tool/workflow. Run its unit tests and validator against repository root; require accepted/public boundary state and no runtime authorization claim.

- [ ] **Step 5: Prove formatting and complete locked workspace.**

Run:

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
```

Require clean Git status afterward.

- [ ] **Step 6: If a genuine defect appears, repair only the owning milestone and restart D09 Review.**

Any product-source correction invalidates the current D09 candidate. Add a focused regression to the owning package, perform its required RED/GREEN proof, rerun the affected predecessor proof, then rerun all D09 Task 2 commands. Do not weaken a D09 acceptance expectation to make a failing predecessor pass.

---

### Task 3: Create the Durable D09 Release Record and Permanent Exact-Head Workflow

**Files:**
- Create: `D09_FULL_WORKSPACE_RELEASE_ACCEPTANCE.md`
- Create: `.github/workflows/d09-full-workspace-release-acceptance.yml`

**Interfaces:**
- Consumes: Task 1 checker/corpus and Task 2 proven commands.
- Produces: permanent exact-head release proof and retained artifact `d09-full-workspace-release-${TARGET_SHA}`.

- [ ] **Step 1: Create durable release record.**

The record must state:

- exact D08 predecessor `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`;
- roadmap authority `98dc8c4e8639cda80510bee0625db34b4fdf9384`;
- acceptance-only architecture;
- exact ten D09 cases;
- deep Workspace 22/20/26 burden under human/Hunter/Sergeant;
- concurrency and recovery boundaries;
- Provider replacement and Plugin rollback boundaries;
- provenance/security negative-history retention;
- D08 deferred-platform honesty;
- public/private and licence boundary;
- exact-head bundle/merge rule;
- explicit Programme E/F deferrals and hosted-CI limitation.

The record must not assert that D09 is complete before merge verification.

- [ ] **Step 2: Create exact-head workflow with immutable checkout/setup pins.**

Use the accepted A15 immutable action pins for checkout and Python setup. Recover the current immutable upload-artifact pin before committing the workflow.

Workflow environment:

```yaml
env:
  D08_BASE: ca6b3526ce9b58ffce11f8582be8fbf860dfa53d
  TARGET_SHA: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}
```

Triggers:

```yaml
on:
  push:
    branches: [d09-full-workspace-release-acceptance]
    paths:
      - D09_FULL_WORKSPACE_RELEASE_ACCEPTANCE.md
      - conformance/d09/**
      - tools/check_d09_full_workspace_release.py
      - tools/test_check_d09_full_workspace_release.py
      - docs/superpowers/specs/2026-09-04-d09-full-workspace-release-acceptance-design.md
      - docs/superpowers/plans/2026-09-04-d09-full-workspace-release-acceptance.md
      - .github/workflows/d09-full-workspace-release-acceptance.yml
  pull_request:
    branches: [main]
    paths: [same D09 surface]
  workflow_dispatch:
```

- [ ] **Step 3: Implement exact predecessor/scope proof.**

The workflow must prove:

```bash
test "$(git rev-parse HEAD)" = "$TARGET_SHA"
git fetch origin main d09-full-workspace-release-acceptance
test "$(git rev-parse origin/main)" = "$D08_BASE"
test "$(git merge-base "$D08_BASE" HEAD)" = "$D08_BASE"
test -z "$(git rev-list --min-parents=2 "$D08_BASE"..HEAD)"
test "$(git rev-parse origin/d09-full-workspace-release-acceptance)" = "$TARGET_SHA"
```

A Python scope audit must reject every D08→D09 changed path outside the seven D09 acceptance files and explicitly reject changes to:

```text
Cargo.toml
Cargo.lock
crates/**
services/**
adapters/**
schemas/**
migrations/**
```

- [ ] **Step 4: Add checker/deep-workspace/AI proof steps.**

Run the exact Task 1 and Task 2 Python commands, retain logs/reports under `$RUNNER_TEMP/d09-proof`, and assert the exact frozen count/authority fields.

- [ ] **Step 5: Add Rust release proof steps.**

Run the exact Task 2 Rust commands, exact D08 counts, formatting, and full locked workspace. Capture command output files for the bundle. Require clean `git status --porcelain` after all proof commands.

- [ ] **Step 6: Add public/private audit step.**

Use the recovered exact Apache boundary unit-test/validator commands and retain its JSON report. Require accepted boundary state and `runtime_implementation_authorized = false` if that field is present in the authoritative report.

- [ ] **Step 7: Build immutable report bundle.**

The workflow must call `require_report_files` from the D09 checker for every required report. Bundle shape:

```json
{
  "schema_version": "0.1.0",
  "record_type": "ptah.d09.full_workspace_release_exact_head_bundle",
  "status": "pass",
  "implementation_commit": "<TARGET_SHA>",
  "d08_predecessor": "ca6b3526ce9b58ffce11f8582be8fbf860dfa53d",
  "d09_case_count": 10,
  "deep_workspace_case_count": 26,
  "deep_workspace_capability_count": 22,
  "deep_workspace_fixture_count": 20,
  "d08_runtime_cases": 25,
  "d08_shell_cases": 3,
  "participants": ["human", "hunter", "sergeant"],
  "ptah_semantic_authority": false,
  "files": []
}
```

Serialize with sorted keys, write `report-bundle.json`, compute `report-bundle.sha256`, and verify with `sha256sum -c`.

- [ ] **Step 8: Upload retained exact-head artifact.**

Artifact name:

`d09-full-workspace-release-${TARGET_SHA}`

Retain the full D09 proof directory, not only the bundle manifest.

- [ ] **Step 9: Review workflow and durable record; commit.**

Run `git diff --check` and inspect every changed D09 path. Commit:

`proof(d09): add full workspace release acceptance`

---

### Task 4: Freeze, Prove, Merge and Independently Verify the Full Workspace Release

**Files:**
- No new files expected.

**Interfaces:**
- Consumes: exact D09 candidate from Task 3.
- Produces: verified D09 merge on `main` or a precise failed-proof boundary.

- [ ] **Step 1: Freeze candidate SHA.**

Record exact remote branch head. No content movement after this point without invalidating proof.

- [ ] **Step 2: Run permanent D09 workflow for the exact frozen SHA.**

Require every workflow step successful and retained artifact `d09-full-workspace-release-${TARGET_SHA}` present and unexpired.

- [ ] **Step 3: Inspect retained bundle evidence.**

Require:

- exact candidate SHA matches artifact head;
- bundle status is `pass`;
- report-bundle SHA-256 verifies;
- all required reports are present and non-empty;
- D09 count = 10;
- deep Workspace = 26 cases / 22 capabilities / 20 fixtures;
- D08 = 25 + 3 = 28;
- participants exactly include human/Hunter/Sergeant;
- Ptah semantic authority remains false.

- [ ] **Step 4: Open PR against exact D08 `main`.**

PR title:

`D09 — Full Workspace release acceptance`

PR body must state exact frozen SHA, permanent workflow run ID, retained artifact name, exact D08 predecessor, ten-case release burden, and explicit non-claims.

- [ ] **Step 5: Verify PR head/base/mergeability and repository rules.**

Require head equals frozen proven SHA and base SHA equals `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`. Review changed paths and any unresolved review/check requirements.

- [ ] **Step 6: Merge with expected-head guard.**

Merge only with `expected_head_sha=<frozen proven D09 SHA>`. Any head movement aborts merge and returns to Review → Freeze → Prove.

- [ ] **Step 7: Independently verify `main`.**

Require new `main` to be a merge commit whose parents are exactly:

1. `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`;
2. frozen proven D09 candidate SHA.

Require the merge tree to equal the proven D09 candidate tree.

- [ ] **Step 8: Mark D09 COMPLETE only after independent merge verification.**

At that point Programme D reaches the roadmap milestone **Full Workspace Release**. Programme E remains separate future authority; D09 completion does not imply distributed Ptah or OS-ready completion.
