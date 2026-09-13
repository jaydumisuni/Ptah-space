# E04 Compatible Workspace Movement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the narrow E04 orchestration layer that moves one verified B06 Session Vault between exact E02-authorized Nodes through E03/A08, restores it through B06/A13, and reports success only after independent Recovery Verification returns `Recovered`.

**Architecture:** Add a stateless `ptah-workspace-movement` crate. It stores no canonical identity or hidden durable authority; each transition consumes exact evidence from E02, E03/A08, B06/A13, A04 and A07 and returns typed phase/evidence. Every authority-changing step revalidates the owning subsystem immediately before use.

**Tech Stack:** Rust workspace; existing Ptah crates `ptah-checkpoint`, `ptah-placement-runtime`, `ptah-node-transfer`, `ptah-transfer`, `ptah-contracts`.

**Spec:** `docs/superpowers/specs/2026-09-13-e04-compatible-workspace-movement-design.md`

## Global Constraints

- Accepted predecessor is E03 merge `d25679c7f039d7328fe1a785af91e82bd403b44e`.
- E04 owns orchestration only; it creates no second checkpoint, transfer, placement, Session, recovery, Object, Lease/Fence or Node identity truth system.
- Transport ACK, archive existence/import, compatibility evaluation, or restore invocation alone never means movement success.
- Only `RecoveryOutcome::Recovered` plus current owner evidence may yield E04 `Recovered`.
- E05 platform admission and E06 discovery/offline reconciliation remain out of scope.
- Source deletion or automatic source retirement is not introduced.
- Every implementation slice follows bounded RED -> GREEN and exact-head proof discipline.

---

### Task 1: Source Preparation Boundary

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/ptah-workspace-movement/Cargo.toml`
- Create: `crates/ptah-workspace-movement/src/lib.rs`
- Create: `crates/ptah-workspace-movement/tests/source_preparation.rs`

**Interfaces:**
- Consumes: `ptah_checkpoint::SessionVaultArchive`.
- Produces: `WorkspaceMovePhase`, `WorkspaceMoveEvidence`, `PreparedWorkspaceMove`, `WorkspaceMover::prepare_source`.

- [ ] Write the failing contract: a valid B06 archive retains exact archive/checkpoint evidence and initially yields `AwaitingPlacement`, never `Recovered`.
- [ ] Run `cargo test -p ptah-workspace-movement --test source_preparation`; require failure because the E04 API does not exist.
- [ ] Implement only the typed coordinator surface and source preparation transition.
- [ ] Run the focused test and `cargo clippy -p ptah-workspace-movement --all-targets -- -D warnings`.
- [ ] Commit `feat(e04): add source preparation boundary`.

### Task 2: Exact E02 Target Authority Admission

**Files:**
- Modify: `crates/ptah-workspace-movement/src/lib.rs`
- Create: `crates/ptah-workspace-movement/tests/placement_authority.rs`

**Interfaces:**
- Consumes: current E02 `PlacementMetadata`, `Reservation`, `Lease`, `FenceToken` and dispatch authority.
- Produces: `WorkspaceMover::admit_target` with exact retained target/Lease/Fence evidence.

- [ ] RED: missing Lease, expired/revoked/superseded Lease, stale/future Fence, binding mismatch, exact-current success.
- [ ] Verify authority-specific RED.
- [ ] Compose existing E02 authorization; duplicate no Lease/Fence rules.
- [ ] Run focused E04 and inherited E02 tests plus strict Clippy.
- [ ] Commit `feat(e04): require exact target dispatch authority`.

### Task 3: E03/A08 Exact Vault Transfer Composition

**Files:**
- Modify: `crates/ptah-workspace-movement/src/lib.rs`
- Create: `crates/ptah-workspace-movement/tests/transfer_composition.rs`

- [ ] RED: exact digest success, transport ACK without read-back, corrupt destination, direct transfer, explicit relay, verified-range resume.
- [ ] Verify RED.
- [ ] Compose existing E03/A08 evidence without copying transfer/cursor logic.
- [ ] Run E04 transfer plus E03 direct/relay/resume regressions.
- [ ] Commit `feat(e04): compose verified vault transfer`.

### Task 4: Target Import and Independent Re-verification

**Files:**
- Modify: `crates/ptah-workspace-movement/src/lib.rs`
- Create: `crates/ptah-workspace-movement/tests/target_reverification.rs`

- [ ] RED: import alone cannot authorize restore, tamper fails closed, target re-verification is mandatory.
- [ ] Verify RED.
- [ ] Orchestrate only `import_session_vault` and `reverify_checkpoint` owner calls.
- [ ] Run focused and inherited B06/A13 tests.
- [ ] Commit `feat(e04): require target vault reverification`.

### Task 5: Compatibility and Restore Fence Recheck

**Files:**
- Modify: `crates/ptah-workspace-movement/src/lib.rs`
- Create: `crates/ptah-workspace-movement/tests/restore_admission.rs`

- [ ] RED: missing B06/A13 capability, target/Provider generation mismatch, expired compatibility, foreign Workspace Revision, retained conflicts, stale Fence, expired/revoked Lease.
- [ ] Verify RED.
- [ ] Recheck B06/A13 compatibility and E02 current authority immediately before restore.
- [ ] Run focused, B06/A13, E02 and strict Clippy regressions.
- [ ] Commit `feat(e04): gate restore on current compatibility and fence`.

### Task 6: Recovery Verification Is the Only Success Boundary

**Files:**
- Modify: `crates/ptah-workspace-movement/src/lib.rs`
- Create: `crates/ptah-workspace-movement/tests/recovery_outcome.rs`

- [ ] RED `Partial`, `Inconclusive`, `Failed`, `Recovered` outcomes.
- [ ] Verify RED.
- [ ] Implement `Recovered` only for exact `RecoveryOutcome::Recovered`, preserving all owner evidence.
- [ ] Run focused and A13 regressions.
- [ ] Commit `feat(e04): bind success to recovery verification`.

### Task 7: Retry, Restart and Concurrency Isolation

**Files:**
- Modify: `crates/ptah-workspace-movement/src/lib.rs`
- Create: `crates/ptah-workspace-movement/tests/recovery_isolation.rs`

- [ ] RED coordinator restart reconstruction, failed Attempt non-reuse, fresh Attempt retry retaining prior failure, generation-change invalidation and concurrent movement isolation.
- [ ] Verify RED.
- [ ] Implement stateless reconstruction helpers only where owner evidence proves state.
- [ ] Run focused and full E04 tests.
- [ ] Commit `feat(e04): prove restart and movement isolation`.

### Task 8: Frozen E04 Conformance Corpus

**Files:**
- Create: `conformance/e04-cases.json`
- Create: `tools/check-e04-conformance.py`
- Create: `tools/test_check_e04_conformance.py`

- [ ] RED checker regressions for wrong case count, duplicate IDs, failed cases and scope claims.
- [ ] Verify RED.
- [ ] Implement deterministic checker and exact 32-case corpus from the design obligations.
- [ ] Run checker plus all E04/inherited regressions.
- [ ] Commit `test(e04): freeze workspace movement conformance`.

### Task 9: Permanent Exact-Head E04 Proof

**Files:**
- Create: `.github/workflows/e04-proof.yml`
- Create: `E04_COMPATIBLE_WORKSPACE_MOVEMENT.md`

- [ ] Add exact-head guard and SHA-bound proof artifact metadata.
- [ ] Run local YAML/static checks.
- [ ] Push unchanged candidate and require exact-head workflow success.
- [ ] Record the retained artifact digest without claiming merge success.
- [ ] Re-prove any metadata-only head advance.

### Task 10: Freeze, Release PR and Guarded Merge

- [ ] Review the full E04 delta against the frozen design/nonclaims.
- [ ] Freeze one exact candidate and require exact-head push proof plus retained artifact.
- [ ] Open the release PR from that unchanged head and require PR-context proof on the same SHA.
- [ ] Merge only with expected-head guard after all required proof is green.
- [ ] Verify merge parent 1 equals accepted E03 merge, parent 2 equals proven E04 candidate, and merge tree equals candidate tree before marking E04 complete and advancing to the next roadmap authority.
