# E02 Placement, Reservation, Lease and Fence Runtime — Design

**Date:** 2026-09-06  
**Status:** Approved / implementation baseline  
**Accepted predecessor:** E01 release `18c1bb26bf074fd8146c2dd8e47838d658af8561`

## 1. Purpose

E02 implements the Programme E placement-authority boundary described by the roadmap:

> Policy-aware placement, resource reservation, dispatch eligibility, expiry and stale-owner fencing.

E02 answers one question mechanically:

> May this exact Attempt execute on this exact Node, under this exact current authority, now?

It does not replace A02 Node/capability/resource truth, A04 Activity/Operation/Attempt truth, A05 Provider truth, or E01 secure Node-session identity. It composes them.

## 2. Architectural rule

E02 uses the strongest combination of the considered scheduler models:

**Centralized authority, distributed decision inputs, decentralized execution.**

- `ptah-control` is the sole issuer of Reservation, Lease and Fence authority.
- Nodes publish evidence-bound capability/resource state and may publish advisory availability/offers.
- Offers, capability matches and placement scores are decision inputs only; none authorize execution.
- After a valid Reservation and current Lease/Fence are issued, execution dispatch proceeds directly over the authenticated E01 Node link.
- The Node validates authority before invoking an existing Provider.

## 3. Existing authorities retained

### 3.1 A02 Node truth

E02 consumes the existing `NodeCapabilitySnapshot` and `NodeResourceSnapshot` models. Both are already bound to exact Node generation and connection epoch and carry evidence references.

E02 does not create alternate capability or resource snapshot models.

### 3.2 A04 execution truth

A04 remains authoritative for:

`Activity -> Operation -> Attempt`

Every E02 placement is bound to one existing physical Attempt identity. E02 does not create a second job/task/execution identity family.

The existing `AttemptContext` already carries Node generation, Provider generation, workload generation and connection epoch. E02 uses those fields as execution-context consistency checks; it does not silently rewrite them.

### 3.3 A05 Provider truth

Provider identity, Provider Revision, Provider Instance, Provider Generation and Provider execution remain owned by A05 and the concrete Provider adapters/runtimes.

E02 authorizes *where and under what current ownership* an Attempt may be dispatched. It does not replace Provider admission or execution semantics.

### 3.4 E01 secure Node-session truth

E01 remains authoritative for:

- `NodeId`;
- `NodeGeneration`;
- `ConnectionEpoch`;
- approved enrollment and credential identity;
- exact current authenticated `SessionBinding`;
- capability announcements over the authenticated link;
- stale Generation/epoch/session rejection.

E02 never accepts a placement authority for a session that E01 no longer considers current.

## 4. Authority progression

The canonical progression is:

`requirements -> candidates -> score/offer -> placement -> Reservation -> Lease + Fence -> Dispatch`

Meanings are deliberately distinct:

- **Capability** — the Node could execute the requirement according to current evidence.
- **Availability/offer** — the Node reports that it can currently accept some amount of work/resource. Advisory only.
- **Placement** — control selects the preferred Node based on policy and current evidence. Selection alone grants no execution authority.
- **Reservation** — control allocates bounded capacity on the selected Node for one Attempt.
- **Lease** — time-bounded current execution authority for the Reservation.
- **Fence** — monotonic ownership token. A larger accepted fence permanently supersedes every smaller fence for the same placement authority domain.
- **Dispatch** — execution-changing request admitted only after all authority checks pass.

No stage may infer the authority of a later stage.

## 5. E02 domain model

### 5.1 PlacementRequirement

A placement request is bound to one A04 Attempt and declares the minimum evidence/policy needed to consider a Node. The initial implementation supports deterministic requirements over:

- required capability references;
- required Provider Revision references;
- resource quantities keyed by stable resource key/unit;
- optional OS/platform family affinity;
- priority;
- locality/policy scoring inputs when supplied.

Requirements are immutable for a specific placement decision. A materially changed requirement creates a new placement decision rather than mutating evidence retrospectively.

### 5.2 NodeOffer

A Node offer is an advisory, short-lived projection over exact current evidence:

- Node identity;
- Node generation;
- connection epoch;
- capability snapshot reference;
- resource snapshot reference;
- offered resources/slots;
- optional load/locality scoring facts;
- `valid_until`;
- unique offer identity/nonce.

An offer cannot authorize execution and cannot mint Reservation/Lease/Fence authority.

### 5.3 PlacementDecision

Control evaluates only Nodes whose E01 session and A02 evidence are current and whose capability/resource evidence satisfies the requirement. Policy scoring is deterministic for identical inputs, including an explicit stable tie-break.

The first E02 scoring surface may include:

- hard capability compatibility;
- Provider availability/revision compatibility;
- allocatable/available resources;
- current pressure;
- locality/affinity;
- operator policy/priority;
- existing reservation pressure;
- health/reachability evidence where available.

Hard eligibility is evaluated before score. A high score can never override a failed hard requirement.

### 5.4 Reservation

A Reservation binds allocated capacity to one Attempt and one exact Node session authority:

- Reservation identity;
- Attempt reference;
- selected `NodeId`;
- exact `NodeGeneration`;
- exact `ConnectionEpoch`;
- capability/resource evidence references used to admit it;
- reserved resources;
- creation time;
- expiry time;
- lifecycle state.

At minimum the lifecycle distinguishes active, consumed/released, expired and revoked/superseded authority.

A Reservation prevents double allocation of the same bounded capacity but does not by itself authorize execution.

### 5.5 Lease

A Lease binds live execution authority to one active Reservation:

- Lease identity;
- Reservation identity;
- Attempt reference;
- exact Node identity/generation/connection epoch;
- issuance time;
- expiry time;
- current Fence token;
- lifecycle state.

Only an unexpired, non-revoked Lease whose Reservation remains current can authorize execution-changing dispatch.

### 5.6 Fence

Fence tokens are positive monotonically increasing integers within a stable placement ownership domain.

Once fence `N+1` becomes current, fence `N` can never become authoritative again, including after delayed delivery, reconnect, control restart or Node restart.

Control is the sole allocator of new workload-placement Fence values.

## 6. Node-side dispatch authority

Every execution-changing dispatch is bound to an authority envelope containing enough information to validate:

- Attempt identity;
- Reservation identity;
- Lease identity;
- Fence token;
- Node identity;
- Node generation;
- connection epoch;
- Provider identity/revision/generation where required by the Provider path;
- lease expiry/currentness.

The Node fails closed before Provider invocation when any binding is missing, expired, revoked, mismatched or stale.

Mandatory rejection classes include:

- wrong Node identity;
- stale/future-unaccepted Node Generation;
- stale/future-unaccepted ConnectionEpoch;
- unknown/expired/released/revoked Reservation;
- Reservation bound to another Attempt;
- unknown/expired/revoked Lease;
- Lease bound to another Reservation/Attempt;
- stale Fence;
- authority from a superseded E01 session;
- capability match without Reservation;
- Reservation without current Lease/Fence.

## 7. Availability under control-plane interruption

A Node may continue an already-authorized operation while its current Lease remains valid, subject to Provider semantics.

Loss of contact with control does not manufacture a new Lease or extend an old one.

After Lease expiry:

- no new execution-changing dispatch is accepted under that Lease;
- no stale Fence may be revived;
- reconciliation requires fresh control authority.

This permits bounded local resilience without weakening ownership fencing.

## 8. Disconnect, restart and orphan semantics

A placement becomes non-dispatchable when its E01 authority is superseded or its Lease expires/revokes.

If a Node reconnects with a newer Generation or ConnectionEpoch, old placement authority remains stale. Re-placement/recovery must issue fresh authority and, where the same ownership domain is reused, a higher Fence.

Control restart must recover durable Reservation/Lease/Fence state before issuing conflicting authority. Until current authority is proven, dispatch fails closed.

The initial E02 implementation must make restart/recovery behavior explicit rather than assuming process memory is canonical persistence.

## 9. D08 integration boundary

D08 intentionally leaves remote Windows/macOS/iOS execution as `RequiresRemoteNode` until Programme E supplies real Node placement/reservation/lease/fence authority.

E02 may satisfy the placement/dispatch-authority portion only when a real authenticated Node and compatible Provider/capability evidence exist.

E02 does not invent:

- Windows/macOS/iOS Node agents;
- remote display/streaming transports;
- platform-specific admission that belongs to E05;
- Node-to-Node Object transfer that belongs to E03;
- Workspace movement/collaboration transport that belongs to E04;
- discovery/relay/intermittent reconciliation that belongs to E06.

If no real compatible Node/Provider exists, D08 remains truthfully unavailable/`RequiresRemoteNode`.

## 10. Wire integration

E02 extends the existing E01 authenticated application protocol rather than creating a second network stack.

The exact message vocabulary is implementation-owned but must represent, at minimum:

- Node resource/availability evidence or offer publication;
- reservation hold/admission acknowledgement;
- lease/fence-bound dispatch;
- dispatch acknowledgement/rejection;
- cancel/revoke/status/result paths needed by the accepted Provider operation;
- bounded machine-readable failure codes.

Wire messages must remain versioned, bounded and authenticated by the existing E01 secure transport.

## 11. Determinism and scheduling policy

Given identical canonical inputs and policy, placement produces the same winner. Tie-breaking must use a stable canonical value, never hash-map iteration order, wall-clock accident or hostname.

Admission and scoring remain separate:

1. validate current E01 authority;
2. validate snapshot identity/generation/epoch;
3. apply hard capability/Provider/resource/policy requirements;
4. compute deterministic score among eligible candidates;
5. reserve capacity atomically;
6. issue Lease/Fence;
7. dispatch.

## 12. Proof boundary

E02 is not complete until durable evidence proves at least:

1. two concurrently connected capable Nodes;
2. deterministic winner for equal repeated inputs;
3. deterministic stable tie-break;
4. capability mismatch rejection;
5. Provider-revision mismatch rejection;
6. resource insufficiency rejection;
7. critical/unavailable resource-pressure rejection where policy requires it;
8. Reservation conflict/double-allocation rejection;
9. Reservation expiry;
10. capability match alone cannot dispatch;
11. Reservation alone cannot dispatch;
12. valid Reservation + current Lease/Fence dispatches;
13. Lease expiry blocks new dispatch;
14. stale Fence rejection;
15. wrong Attempt binding rejection;
16. stale Node Generation rejection;
17. stale ConnectionEpoch rejection;
18. superseded E01 session rejection;
19. disconnect before dispatch fails closed;
20. disconnect/temporary control loss during valid Lease follows bounded continuation semantics;
21. Node restart invalidates stale authority;
22. control restart recovers/fails closed without duplicate authority;
23. re-placement issues newer authority;
24. delayed/replayed old dispatch remains rejected;
25. no capable Node returns a typed unavailable result;
26. exactly one current owner after competing placement attempts;
27. Provider invocation cannot occur before Node-side authority validation;
28. release acceptance uses real E01 session and Provider boundaries, not a mock that bypasses authority.

The proof corpus must be machine-checkable and exact-head gated, following the E01 release discipline.

## 13. Implementation decomposition

E02 should be introduced in narrow layers:

1. authority-domain primitives and invariants;
2. deterministic eligibility/scoring over existing A02 snapshots;
3. Reservation accounting and expiry;
4. Lease/Fence issuance and validation;
5. E01 wire extensions;
6. Node-side dispatch guard before Provider execution;
7. control-plane orchestration and durable recovery;
8. D08 integration where real remote Node/Provider capability exists;
9. two-Node/adversarial conformance corpus and exact-head proof workflow.

A dedicated placement-runtime crate is appropriate only for the mechanical placement/authority logic; `ptah-control` remains the authority owner and the existing runtimes remain owners of their canonical records.

## 14. Frozen invariants

- Capability is never authority.
- An offer is never authority.
- Placement selection is never authority.
- Reservation is capacity authority, not execution authority.
- Lease + current Fence are required for execution-changing dispatch.
- E01 current-session authority is a prerequisite, not a substitute for E02 authority.
- Older Fence values never regain authority.
- Node/Provider generations and connection epochs are never inferred from aliases.
- Existing A02/A04/A05/E01 canonical models are reused, not duplicated.
- Failure to prove current ownership fails closed.
