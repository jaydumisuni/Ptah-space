# E06 — Intermittent and local-first operation

Status: design candidate
Accepted predecessor: `e11c744c4e9900c460e3c4a3fda9fe385f6e1dc9`

## Purpose

E06 makes an already-authorized Ptah Workspace useful across intermittent connectivity without creating new authority while disconnected. It adds durable local intent, deterministic reconciliation, and explicit degraded-state evidence.

## Preserved authority boundaries

- E01 remains the authority for authenticated current Node sessions and stale-session fencing.
- E02 remains the authority for Reservation, Lease, Fence, placement and DispatchAuthority.
- E03 remains the authority for explicitly authorized Node-to-Node Object/Artifact transfer.
- E04 remains the authority for compatible Workspace movement orchestration.
- E05 remains the authority for platform-specific Node admission evidence.
- A/B/C/D package authority is unchanged.

E06 MUST NOT infer discovery, execution, transfer, placement, promotion, or synchronization authority from cached state.

## State model

A local operation is one of `local_only`, `queued_intent`, `revalidating`, `rejected_stale`, `ready_to_apply`, or `applied`. Queueing never means approval.

## Durable queue envelope

Every queued intent must bind Workspace/Activity/Operation/Attempt identity, originating Node and local sequence, requested action and canonical input digest, referenced Object/Artifact generations, referenced E01/E02 authority when applicable, E05 admission generation when applicable, creation/ordering evidence, and `revalidate_required`. It must contain no credential or secret material. The envelope is append-only; mutation creates a new intent identity.

## Reconciliation rules

On reconnect Ptah must authenticate a current E01 session, obtain current owner-package state, compare queued references with current generations, reject stale authority rather than silently rebasing it, detect duplicate intent identities idempotently, preserve conflicts as evidence, route accepted work through the existing owner package, and retain rejected/applied receipts.

No last-write-wins rule may overwrite an authority conflict.

## Degraded operation

Permitted offline work is limited to actions requiring no remote or expired authority: local reads, local edits, local computation, preparation of immutable inputs, and creation of queued intents. Authority-bearing effects fail closed until revalidation.

The UI/API must distinguish `offline_local`, `queued_not_authorized`, `revalidating`, `conflict`, and `online_authoritative`.

## Implementation slices

- E06-01: queue-envelope types and deterministic local sequence.
- E06-02: durable append/read/idempotency store.
- E06-03: reconnect revalidation against E01/E02/E03/E04/E05 owners.
- E06-04: conflict and stale-authority receipts.
- E06-05: degraded-state API/evidence surface.
- E06-06: conformance corpus for duplicate replay, stale session/fence, changed object generation, partial reconnect, and crash/restart.
- E06-07: exact-head proof and release freeze.

## Acceptance boundary

E06 is complete only when deterministic conformance proves useful offline work while all authority-bearing effects fail closed until current owner authority is re-established. Crash/restart preserves queue identity and ordering; duplicate replay is idempotent; stale authority is never silently refreshed or widened.

This design grants no runtime authority by itself.
