# E04 Compatible Workspace Movement — Design

**Status:** Proposed implementation baseline under Programme E continuous execution

**Accepted predecessor:** E03 merge `d25679c7f039d7328fe1a785af91e82bd403b44e`

**Roadmap authority:** Ptah Implementation Roadmap 1.1.0 / Programme E04 — Compatible Workspace movement.

## 1. Purpose

E04 composes already-proven Ptah authorities so one compatible Workspace can move from a source Node to a target Node without inventing a second checkpoint, transfer, placement, Session, or recovery truth system.

The roadmap requires four outcomes: capability comparison, checkpoint-bundle movement, target restore, and Recovery Verification. E04 therefore owns orchestration only. E02 remains authoritative for current target placement/Lease/Fence, E03 for exact inter-Node byte movement, B06/A13 for portable Session Vault/checkpoint integrity and restore, A04 for Activity/Attempt execution identity, A07 for canonical Object/Revision/Artifact/Location truth, and A08 for transfer run/progress/verification truth.

## 2. Core invariant

A Workspace move is successful only when all of the following are true for one exact movement Attempt:

1. the source B06 Session Vault export came from a currently independently verified A13 checkpoint;
2. the target Node was selected from current E02/E01 capability and resource evidence and owns current dispatch authority for the restore Attempt;
3. the exact Session Vault bytes were moved under E03/A08 authority and their destination digest equals the source digest;
4. the imported Vault independently re-earned checkpoint verification on the target;
5. target compatibility was evaluated against exact current target Node/Provider generations and required capability references;
6. restore executed only through B06/A13 with a fresh Attempt and current E02 Fence;
7. independent A13 Recovery Verification returns `RecoveryOutcome::Recovered`; and
8. all retained conflicts, limitations, partials, detached attachments and fenced stale authorities remain visible.

Transport success, archive existence, compatibility evaluation, restore invocation, or process ACK alone can never claim Workspace movement success.

## 3. Existing authority reused unchanged

### 3.1 E02 placement authority

E04 consumes E02 current Node eligibility, Reservation, Lease and Fence authority for the target restore Attempt. E04 does not create a scheduler, alternate placement identity, or implicit placement derived from network reachability. A stale/superseded E01 session, expired/revoked Lease, stale Fence, Provider generation mismatch, or incompatible capability snapshot blocks restore admission.

### 3.2 E03 transfer authority

E04 carries Session Vault bytes through the accepted E03 data plane. E04 does not copy bulk bytes through the E01 control stream and does not add route discovery. Direct/relay route authorization, range verification, resume and exact destination digest remain E03/A08 concerns.

### 3.3 B06/A13 recovery authority

B06 remains the portable archive boundary. `export_session_vault` requires current independent A13 checkpoint verification. `import_session_vault` validates archive digest and checkpoint-state binding and intentionally drops restore authorization. The target must call `reverify_checkpoint`, `evaluate_compatibility`, `restore_on_target`, and `verify_recovery` in that order. E04 never mutates a compatibility report to manufacture success and never bypasses A13 Attempt fencing.

### 3.4 A04/A07/A08 truth

The movement operation is represented by existing A04 Activity/Attempt identity. Session Vault bytes become transportable only through existing A07/A08 materialization/transfer boundaries; E04 introduces no new canonical Object family and no second transfer run/cursor model.

## 4. E04 orchestration boundary

Introduce a narrow `ptah-workspace-movement` crate. It owns only typed orchestration state and fail-closed sequencing between existing owners. It has no database schema and no durable canonical identity family.

The public surface is intentionally small:

- `WorkspaceMoveRequest` — source Workspace/checkpoint references, source and target Node/session bindings, A04 Activity/Attempt reference, A08 transfer references, and explicit route/target constraints.
- `WorkspaceMovePhase` — `Preparing`, `AwaitingPlacement`, `Transferring`, `Reverifying`, `CompatibilityChecked`, `Restoring`, `VerifyingRecovery`, `Recovered`, or `Failed`.
- `WorkspaceMoveEvidence` — exact references to B06 archive digest, E02 placement/Fence, E03/A08 transport evidence, target re-verification, compatibility decision, restore run and Recovery Verification.
- `WorkspaceMoveError` — stable mechanical failure classes preserving the first authority boundary that rejected progress.
- `WorkspaceMover` — stateless coordinator methods that require caller-supplied current owner objects/records and return typed next-state/evidence.

The crate must not persist hidden mutable authority. Durable truth stays with the existing A03/A04/A07/A08/E02/B06 owners.

## 5. Required sequence

### 5.1 Source preparation

E04 receives an exact independently verified A13 checkpoint and exports one B06 Session Vault. The archive digest is retained. The archive is materialized through the existing A07/A08 object/transfer path so E03 can move exact bytes without becoming canonical Workspace truth.

### 5.2 Target selection and authority

The Vault manifest's required capability references plus restore requirements are compared against current target evidence. E02 may select or validate the target, but movement may proceed only with current Reservation/Lease/Fence authority bound to the same target Node/session and A04 restore Attempt.

A network-reachable Node that lacks current E02 authority is not a valid E04 target.

### 5.3 Exact movement

E03 transfers the exact Vault materialization. Resume may reuse only E03/A08 verified range state. A route change does not alter Workspace/checkpoint identity. Completion requires destination read-back/digest evidence; E03 transport ACK alone is insufficient.

### 5.4 Target import and re-verification

The target imports the Vault through B06. Import success is not restore authorization. The target independently re-verifies every retained A13 component using target-side evidence. Any archive tamper, missing component bytes, digest mismatch, or evidence acquisition failure blocks the move.

### 5.5 Compatibility and restore

B06/A13 evaluates the exact target. Missing mandatory capability, stale/foreign Workspace revision, missing Provider target, stale Provider generation, retained conflict that makes restoration unsafe, or expired compatibility decision blocks restore. Immediately before restore, E04 rechecks the E02 Fence/Lease and exact target session so compatibility cannot outlive execution authority.

### 5.6 Recovery verification

After restore, A13 independently evaluates required postconditions. Only `RecoveryOutcome::Recovered` can advance E04 to `Recovered`. `Failed`, `Partial`, and `Inconclusive` remain non-success terminal evidence. Source state is not deleted automatically; source retirement or cleanup requires separate explicit authority after recovery is proven.

## 6. Failure and recovery semantics

E04 is restartable because each underlying owner already retains its own truth. After coordinator restart, the caller reconstructs progress from A04 Attempt state plus referenced E02/E03/A08/B06/A13 evidence. No in-memory E04 phase can override those records.

Rules:

- failure before verified E03 destination bytes leaves no restore authorization;
- failure after transfer but before target re-verification resumes at target re-verification, not retransmission when A08/E03 still proves exact destination bytes;
- a target reconnect or generation change invalidates old E02/E03 authority and requires fresh current authority;
- an expired compatibility decision requires re-evaluation;
- a failed restore Attempt cannot be reused; retry uses a fresh A04/A13 Attempt while retaining prior failure evidence;
- recovered source checkpoint/Vault evidence remains immutable history.

## 7. Concurrency and isolation

Concurrent moves are isolated by exact Workspace, checkpoint bundle, A04 Attempt, A08 Run, E03 ticket and E02 Fence references. No cache, cursor, relay ticket, compatibility report, restore Attempt or Recovery Verification may be shared across movement Attempts unless its owning subsystem explicitly permits that reuse and the exact references match.

Two movements involving the same Workspace Revision may coexist as evidence, but only independently authorized Attempts can restore. E04 does not implement distributed multi-writer Workspace synchronization.

## 8. Security and privacy

E04 introduces no new credentials or PKI. E01/E03 TLS identity and configured trust remain authoritative. Raw private keys, bearer credentials, browser secrets and machine-specific secret paths must not enter E04 records or retained public proof. Session Vault privacy behavior remains B06-owned.

Public conformance fixtures use synthetic Nodes, Workspaces, digests and evidence references only.

## 9. Explicit nonclaims

E04 does **not** implement or authorize:

- live collaborative multi-writer editing or CRDT/OT synchronization;
- automatic peer/relay discovery, route selection, offline queues or local-first reconciliation (E06);
- platform-specific Node admission policy (E05);
- a second checkpoint/archive format, restore engine or recovery verifier;
- a second scheduler, Lease/Fence model or Node identity family;
- a second transfer cursor/run model;
- source deletion, failover election or automatic source retirement after recovery;
- semantic success from transport ACK, archive import, compatibility evaluation or restore invocation alone.

## 10. Initial conformance obligations

The frozen E04 corpus must eventually prove at least these classes on one exact release candidate:

1. verified B06 source Vault can be prepared for movement;
2. unverified source checkpoint cannot enter E04;
3. exact Vault digest is preserved across E03 transfer;
4. E01 control frames never carry Vault bulk bytes;
5. direct transfer works;
6. explicit relay transfer works;
7. interrupted transfer resumes only verified missing ranges;
8. corrupted destination bytes block import/restore;
9. target import loses prior restore authorization;
10. target checkpoint re-verification is mandatory;
11. exact compatible target restores;
12. missing B06 capability blocks restore;
13. missing A13 component capability blocks restore;
14. stale target Node Generation blocks progress;
15. stale ConnectionEpoch blocks progress;
16. expired/revoked E02 Lease blocks restore;
17. stale Fence blocks restore;
18. Provider generation mismatch blocks restore;
19. expired compatibility decision blocks restore;
20. foreign Workspace Revision/generation blocks restore;
21. retained conflicts remain visible;
22. failed restore Attempt cannot be reused;
23. retry uses fresh Attempt while retaining prior failure;
24. `RecoveryOutcome::Partial` is not success;
25. `RecoveryOutcome::Inconclusive` is not success;
26. `RecoveryOutcome::Failed` is not success;
27. `RecoveryOutcome::Recovered` plus current owner evidence is success;
28. coordinator restart reconstructs state from owner evidence without hidden authority;
29. concurrent movement Attempts do not alias state;
30. source is not automatically deleted after recovery;
31. E05/E06 scope is not introduced;
32. inherited E02, E03, B06/A13, A04, A07, A08 and full-workspace regressions remain green.

## 11. Release discipline

E04 follows the established Programme E discipline:

1. branch from the exact accepted E03 merge;
2. develop by bounded RED -> GREEN slices;
3. review the full E04 delta against this design and roadmap authority;
4. freeze one exact candidate SHA;
5. run a permanent exact-head E04 proof workflow and retain a SHA-bound proof artifact;
6. open the release PR only from that proven head;
7. require the same permanent workflow to succeed in PR context on the unchanged head;
8. merge only with exact-head guard; and
9. independently verify merge parent 1, parent 2 and tree identity before marking E04 COMPLETE.

A green run for another SHA is not E04 release evidence.
