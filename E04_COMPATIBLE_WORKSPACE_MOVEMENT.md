# E04 Compatible Workspace Movement — Durable Proof Record

## Frozen authority

E04 is implemented strictly above the accepted E03 merge:

`d25679c7f039d7328fe1a785af91e82bd403b44e`

The frozen design and implementation plan are:

- `docs/superpowers/specs/2026-09-13-e04-compatible-workspace-movement-design.md`
- `docs/superpowers/plans/2026-09-13-e04-compatible-workspace-movement.md`

The final implementation-and-conformance head before adding the permanent proof record/workflow is:

`ae9dabe3c20f5aa1e66440ea94b5fbedc97742f6`

The exact commit containing this record and `.github/workflows/e04-proof.yml` must be independently proven before release. E04 changes no frozen schema or migration surface.

## Authority composition

E04 is a stateless orchestration layer. It does not replace the authorities it composes:

- E02 owns target eligibility, Reservation, Lease, Fence and exact Node session authority.
- E03/A08 own exact Vault byte movement, route authority, transfer runs, resume and destination verification.
- B06/A13 own Session Vault import/export, checkpoint integrity, compatibility, restore Attempt fencing and Recovery Verification.
- A04 owns Activity/Attempt execution identity.
- A07 owns canonical Object/Revision/Artifact/Location truth.

The A13 restore Attempt is derived from the exact E02/A04 Attempt binding. E04 cannot accept a caller-supplied alternate restore Attempt string.

## Success boundary

Workspace movement success requires the exact owner sequence and ends only when independent A13 Recovery Verification reports `RecoveryOutcome::Recovered`.

`Partial`, `Inconclusive`, and `Failed` remain E04 non-success. Transport acknowledgement, destination existence, Vault import, compatibility evaluation, and restore invocation are never sufficient.

Source state is not automatically deleted or retired.

## Retry, restart and concurrency

Coordinator restart reconstructs only non-authoritative evidence projections from exact linked owner records. It creates no hidden E04 durable authority.

A retry requires a prior non-success movement and a distinct fresh A04 Attempt while retaining prior failure evidence. Concurrent movement Attempts remain isolated by exact Workspace/checkpoint, Attempt, target session, E02 Fence, E03 ticket and A08 run/verification references.

## Frozen conformance corpus

`conformance/e04-cases.json` freezes exactly 32 design-order obligations. `tools/check-e04-conformance.py` rejects count, identity/order, result, evidence, class or scope drift. The corpus explicitly preserves these nonclaims as false:

- E05 platform admission;
- E06 automatic discovery, relay selection, offline queueing or reconciliation;
- a new checkpoint format;
- a new transfer model;
- a new placement authority;
- automatic source deletion;
- multi-writer synchronization;
- frozen contract changes.

## Proof state

Before adding the permanent proof workflow, Task 8 established:

- E04 Rust tests: 33/33 PASS;
- B06/A13 tests: 25/25 PASS;
- E02 placement-runtime tests: 42/42 PASS;
- E02/E03/E04 Python checker regressions: 21/21 PASS;
- full locked Rust workspace: PASS;
- Patrol project-boundary check: ALLOW;
- exact 32-case corpus evidence paths: 0 missing.

These results are development evidence, not a substitute for the permanent exact-head GitHub Actions proof.

Retained exact-head proof for candidate `0a4cc4f037a71b774e780714e415f994fd371a7d`:

- GitHub Actions run: `35832825170`;
- retained artifact ID: `10737777519`;
- retained artifact name: `e04-compatible-workspace-movement-0a4cc4f037a71b774e780714e415f994fd371a7d`;
- GitHub artifact digest: `sha256:095db7082df17c43551da4db23329335a4228e1804b290f0d1eb6b1400d98e49`;
- retained proof manifest exact tree: `20c001462b79631af08a367970f1f46fff260408`;
- retained proof manifest evidence-index SHA-256: `701a2f860eb252730ec51e3bb9e95434ddf94bde604c321e90dc7be2a8e841f1`;
- all 23 downloaded retained checksum entries were independently re-hashed with zero mismatches.

This is exact-head proof evidence only. It does not claim that E04 has been merged.

## Shipping gate

This record does **not** assert that E04 is merged or complete.

The release candidate may advance only after:

1. the exact branch SHA passes `E04 Compatible Workspace Movement Exact Head Proof` from a fresh checkout;
2. the retained artifact `e04-compatible-workspace-movement-${TARGET_SHA}` exists for that exact SHA;
3. the artifact is SHA-bound to the same candidate and its retained digest is recorded without claiming merge success;
4. any metadata-only head advance is re-proven by the same permanent workflow;
5. PR-context proof succeeds on the unchanged exact head;
6. merge uses an expected-head guard; and
7. the resulting merge has parent 1 equal to the accepted E03 merge, parent 2 equal to the proven E04 candidate, and a tree identical to that candidate.

Any candidate movement after Freeze invalidates prior exact-head proof for release purposes.
