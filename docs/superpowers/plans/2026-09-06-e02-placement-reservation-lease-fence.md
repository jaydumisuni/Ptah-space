# E02 Placement, Reservation, Lease and Fence Runtime — Implementation Plan

**Date:** 2026-09-06
**Design:** `docs/superpowers/specs/2026-09-06-e02-placement-reservation-lease-fence-design.md`
**Accepted predecessor:** E01 release `18c1bb26bf074fd8146c2dd8e47838d658af8561`

## Goal

Implement policy-aware multi-Node placement and current execution ownership without duplicating A02, A04, A05 or E01 truth.

The implementation order deliberately establishes authority invariants before transport and orchestration. Each task is TDD-first: write a narrow failing test, confirm the intended failure, implement the minimum behavior, then refactor while retaining the proof.

## Non-negotiable invariants

- Capability/offer/placement selection never authorize execution.
- Reservation allocates capacity but does not authorize execution.
- A current Lease plus current Fence are required for execution-changing dispatch.
- Every authority is bound to one A04 Attempt and one exact E01 Node session (`NodeId`, `NodeGeneration`, `ConnectionEpoch`).
- Fence tokens advance monotonically and stale tokens never revive.
- E01 `SessionBinding` currentness is a prerequisite for E02 dispatch.
- Node-side authority validation happens before Provider invocation.
- Existing A02 snapshot, A04 Attempt, A05 Provider and E01 secure-link models remain canonical.

---

## Task 1 — Introduce placement-authority domain primitives

**Files**

- Modify: `Cargo.toml`
- Create: `crates/ptah-placement-runtime/Cargo.toml`
- Create: `crates/ptah-placement-runtime/src/lib.rs`
- Create: `crates/ptah-placement-runtime/tests/e02_authority.rs`

**RED**

Add tests defining the first mechanical authority boundary:

1. `FenceToken` must be positive and monotonic.
2. `Reservation` is bound to an exact Attempt and exact Node generation/epoch.
3. `Lease` is bound to the Reservation/Attempt/Node authority and carries a Fence.
4. capability/placement metadata without a Lease cannot produce `DispatchAuthority`.
5. a valid unexpired Reservation + Lease produces `DispatchAuthority` only when all bindings match.
6. stale Fence, expired Lease, wrong Attempt, wrong Node generation and wrong connection epoch fail closed with typed errors.

Run the narrow test target and retain the expected RED reason before implementation.

**GREEN**

Implement only the domain types and validation necessary for those tests. Use `ptah-identifiers` primitives and `EntityRef`; do not add alternate Node/Attempt identity types.

**REFACTOR**

Centralize repeated binding checks and keep errors stable/machine-readable.

---

## Task 2 — Deterministic eligibility and policy scoring

**Files**

- Modify: `crates/ptah-placement-runtime/Cargo.toml`
- Modify: `crates/ptah-placement-runtime/src/lib.rs`
- Create: `crates/ptah-placement-runtime/tests/e02_placement.rs`

**RED**

Define candidate evaluation over existing `NodeCapabilitySnapshot` and `NodeResourceSnapshot`:

- reject mismatched Node identity/generation/epoch between session and snapshots;
- reject missing required capability refs;
- reject missing required Provider Revision refs;
- reject insufficient requested resources;
- reject unavailable/critical resources when policy says they are non-admissible;
- score eligible Nodes deterministically;
- use canonical Node identity as the final stable tie-break.

**GREEN**

Implement hard eligibility separately from score. Never allow score to override a failed requirement.

---

## Task 3 — Advisory Node offers

**Files**

- Modify: `crates/ptah-placement-runtime/src/lib.rs`
- Modify: `crates/ptah-node-link/src/protocol.rs`
- Create/modify tests under `crates/ptah-placement-runtime/tests/` and `crates/ptah-node-link/tests/`

**RED**

Prove that:

- an offer is bound to exact Node generation/epoch and current evidence refs;
- expired offers are ineligible;
- an offer cannot be converted directly to dispatch authority;
- malformed or cross-Node offers fail closed.

**GREEN**

Add bounded offer wire projection to the existing versioned E01 protocol. No second transport stack.

---

## Task 4 — Reservation accounting and conflict rejection

**Files**

- Modify: `crates/ptah-placement-runtime/src/lib.rs`
- Create: `crates/ptah-placement-runtime/tests/e02_reservations.rs`

**RED**

Prove:

- atomic capacity accounting across two competing Attempts;
- no double allocation beyond allocatable capacity;
- release returns capacity;
- expiry returns capacity;
- a Reservation cannot move to another Node/Attempt/session by mutation;
- stale resource evidence cannot silently expand capacity.

**GREEN**

Implement a deterministic Reservation registry/state machine with explicit active/released/expired/revoked states.

Persistence is introduced in Task 8; until then this registry is explicitly in-process and must not be represented as restart-safe.

---

## Task 5 — Lease/Fence allocator and validator

**Files**

- Modify: `crates/ptah-placement-runtime/src/lib.rs`
- Create: `crates/ptah-placement-runtime/tests/e02_leases.rs`

**RED**

Prove:

- only an active Reservation can receive a Lease;
- Fence increases monotonically per ownership domain;
- renewal/transfer never decreases or reuses Fence;
- expired/revoked Lease rejects new dispatch;
- a higher Fence permanently rejects lower Fence replay;
- competing placement attempts result in exactly one current owner.

**GREEN**

Implement the minimal Lease/Fence registry and validation surface.

---

## Task 6 — Control-plane E02 authority owner

**Files**

- Modify: `services/ptah-control/Cargo.toml`
- Modify: `services/ptah-control/src/lib.rs`
- Modify: `services/ptah-control/src/node_link.rs`
- Add: `services/ptah-control/src/placement.rs`
- Add: `services/ptah-control/tests/e02_placement.rs`

**RED**

Prove `ptah-control`:

- evaluates only the current E01 session for each Node;
- accepts capability/resource evidence only when bound to that session;
- creates Reservation/Lease/Fence only after successful deterministic placement;
- invalidates dispatch eligibility when E01 session authority is superseded;
- cannot mint a Fence from client-provided projection state.

**GREEN**

Make `ptah-control` the sole authority owner while delegating mechanical placement/lease logic to `ptah-placement-runtime`.

---

## Task 7 — E01 wire dispatch and Node-side authority guard

**Files**

- Modify: `crates/ptah-node-link/src/protocol.rs`
- Modify: `services/ptah-control/src/node_link.rs`
- Modify: `services/ptah-node/src/lib.rs`
- Modify: `crates/ptah-node-agent/src/lib.rs` only if a reusable guard belongs there; otherwise keep the guard in the placement runtime/service boundary.
- Add focused protocol/Node tests.

**RED**

Prove:

- authority envelope serializes over existing authenticated link;
- capability-only dispatch is impossible;
- Reservation-only dispatch is impossible;
- wrong Attempt/Node generation/epoch/Lease/Fence rejects before Provider invocation;
- superseded E01 session rejects;
- delayed stale dispatch remains rejected after newer Fence;
- Provider invocation observation remains zero for rejected authority.

**GREEN**

Add bounded E02 messages to `LinkMessage` and Node dispatch guard. Keep protocol versioning explicit and backwards-fail-closed.

---

## Task 8 — Durable authority recovery

**Files**

- Modify: `crates/ptah-placement-runtime/Cargo.toml`
- Add durable journal/store module(s) under `crates/ptah-placement-runtime/src/`
- Add restart tests.

**RED**

Prove:

- control restart does not forget an active higher Fence and issue a lower/reused Fence;
- expired authority remains expired after recovery;
- ambiguous/corrupt recovery state fails closed;
- recovered Reservation accounting prevents duplicate capacity allocation;
- Node reconnect with newer Generation/Epoch leaves old authority stale.

**GREEN**

Use existing Ptah durable primitives (A03 ledger/journal pattern) rather than an ad-hoc database format. Reconstruct current authority deterministically from canonical records.

---

## Task 9 — Provider dispatch integration

**Files**

- Modify only the minimal Provider/runtime boundary selected by the acceptance case.
- Add `crates/ptah-placement-runtime/tests/e02_provider_dispatch.rs` or service-level integration equivalent.

**RED**

Prove a real existing Provider path is invoked only after E02 authority validation, and that stale authority cannot reach it.

**GREEN**

Connect one existing Provider execution path without broad Provider redesign. The E02 layer must pass through A05 Provider identity/generation checks rather than replacing them.

---

## Task 10 — D08 remote-placement integration

**Files**

- Modify: `crates/ptah-application-runtime/src/compatibility.rs` and/or the narrow owning integration surface selected by evidence.
- Extend D08/E02 integration tests.

**RED**

Prove:

- a real compatible current Node can satisfy the Programme E placement-authority blocker;
- lack of a compatible real Node remains `RequiresRemoteNode`/typed unavailable;
- no synthetic Windows/macOS/iOS agent/session is created;
- E03/E04/E05/E06 concerns remain outside E02.

**GREEN**

Bridge only the actual authority now supplied by E02.

---

## Task 11 — Two-Node adversarial conformance corpus

**Files**

- Create: `conformance/e02/placement-authority-cases.v0.1.0.json`
- Create: `tools/check_e02_placement_authority.py`
- Create: `tools/test_check_e02_placement_authority.py`
- Add Rust integration acceptance target(s).

Freeze the design's minimum 28 proof cases with stable IDs. Include at least two concurrently connected authenticated Nodes and adversarial stale/replay cases.

The checker must fail for missing, duplicate, unexpected or falsely passing cases.

---

## Task 12 — Exact-head CI, milestone record and release freeze

**Files**

- Create: `.github/workflows/e02-placement-reservation-lease-fence.yml`
- Create: `.github/workflows/e02-tdd.yml` if a development workflow is useful before final gate.
- Create: `E02_PLACEMENT_RESERVATION_LEASE_FENCE.md`

Final gate must include:

- formatting;
- workspace compile/check appropriate to repository policy;
- focused and workspace tests;
- Clippy with warnings policy;
- dependency/license/security gates already required by the repo;
- E02 conformance checker;
- exact-head SHA capture;
- retained proof artifact containing the exact candidate SHA and required evidence.

Then:

1. review the full branch diff against the approved E02 design;
2. correct any findings;
3. freeze one candidate SHA;
4. prove that exact SHA;
5. merge through the repository's guarded release process;
6. verify post-merge parents and merged tree equal the proven candidate tree.

## Execution rule

Do not skip ahead by implementing transport or Provider integration before the local authority model is mechanically correct. Conversely, local unit tests alone cannot complete E02: the release must prove the authority on the real E01 authenticated Node boundary and a real existing Provider path.
