# B01 — Transfer and storage expansion

Status: candidate; promotion is valid only for an exact implementation head proven by the B01 workflow.

## Authority

- Accepted A15 / Online Ptah Alpha merge base: `6f096697fb65fe023e7cdf31abf9a7996486326f`.
- B01 roadmap dependency: A15.
- Existing A08 transfer truth remains authoritative for durable Request/Run/Manifest/Progress/Verification semantics.
- Existing A07 object/storage truth remains authoritative for Content/Object/Revision/Location identity, CAS materialization and storage verification.
- Existing A13 recovery truth remains authoritative for Workspace checkpoint/recovery claims.

B01 extends transfer/storage mechanics. It does not reopen A07, A08 or A13 authority boundaries.

## Delivered surface

B01 adds the following to `ptah-transfer`:

1. resumable upload from an exact provider-accepted offset, with source size/digest fencing, streamed-prefix verification and fail-closed cursor/provider disagreement;
2. segmented download with digest-bound verified-range cursor, crash-durable range admission, multi-source fallback and retained source failures;
3. deterministic transfer priority/queue policy with local-capacity reservation while local work is pending;
4. one bounded export adapter contract usable by Node-to-Node, object-store and Drive-style providers;
5. local-first export orchestration where optional remote failure remains explicit and does not erase completed primary work;
6. SHA-256 content deduplication policy that reuses storage keys without collapsing logical reference count;
7. conservative retention planning that never automatically prunes pinned or unverified state;
8. explicit Sync Relationship, Cursor, Conflict, non-conflict reconciliation and caller-selected Resolution state;
9. independent Backup Policy, Snapshot, Verification, Prune and Restore state;
10. restore results that explicitly cannot claim Workspace recovery.

## Acceptance proofs

The exact-head B01 workflow must prove:

- a large interrupted upload resumes from the exact provider offset and produces identical final bytes;
- a stale/mismatched upload cursor is rejected before additional provider bytes are written;
- a segmented large download can stop, retain exact verified ranges, resume, and complete with whole-file SHA-256 equality;
- one failed source range falls back to another source while the failed attempt remains visible;
- priority scheduling reserves configured local capacity while local work is pending;
- Node, object-store and Drive adapters share one bounded export contract;
- optional Drive/remote failure does not block or rewrite the primary local/object-store result;
- equal bytes deduplicate to one content-addressed key while retaining distinct logical reference count;
- retention policy prunes only older verified, unpinned generations;
- two-sided sync divergence produces an explicit conflict and Ptah does not infer the winner;
- one-sided sync advance remains pending rather than becoming an automatic merge;
- backup restore is blocked until independent snapshot verification succeeds;
- restored bytes expose `workspace_recovery_claim = false`;
- backup prune state remains independent from sync state;
- all inherited A08 transfer tests still pass;
- the complete inherited Rust workspace still passes at the exact B01 head.

## Non-claims

- Provider acknowledgement is not Content/Object/Location truth.
- Export adapter success is bounded adapter evidence, not universal external-effect truth.
- A sync relationship is not a backup snapshot.
- A backup snapshot is not a Workspace checkpoint.
- Restored backup bytes are not proof that a Workspace, Session, Activity, Provider generation or external effect recovered.
- B01 does not choose conflict winners or silently merge divergent revisions.
- B01 does not make optional remote adapters mandatory for local work.

## Promotion rule

Promote only the exact PR head for which the B01 exact-head workflow succeeds and retains its proof manifest. If the head moves after proof, the proof is obsolete and must be rerun.
