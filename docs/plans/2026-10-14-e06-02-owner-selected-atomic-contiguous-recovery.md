# E06-02 — Owner-selected sequence and verified-recovery contract

**Selected:** 2026-10-14 (owner direction)
**Status:** DESIGN SELECTED; independent review and E06 implementation qualification pending
**Scope:** E06-02 append journal and reconnect recovery; never E01–E05 authority promotion.

## Decision

Adopt **atomic per-origin Node commit + contiguous durable sequence +
independently verified exceptional recovery**. This supersedes the
unresolved choice in the 2026-10-13 preparatory gap review, without
retroactively altering its evidence or authorizing release.

1. **Atomic visibility.** Allocate the next unsigned 64-bit local sequence
   and durably append its canonical intent envelope in **one transaction**.
   A counter advance without its record, or an exposed record without its
   committed counter, is prohibited. Do not hand an uncommitted sequence
   to an external operation. A process crash before commit exposes neither;
   after commit recovery must find both. Use storage-specific verified
   durability guarantees, not assumptions about a successful return.
2. **Independent cursors.** Maintain contiguous ordering per canonical
   originating Node, not one global fleet counter. Interleaved records
   from other Nodes cannot hide or satisfy a gap. Preserve origin identity
   across reconnect; E01 Node Generation and Connection Epoch govern
   current authority separately, not silent sequence resets.
3. **Validation.** Adjacent distinct committed sequences for the same
   Node must be exactly successor (+1, overflow checked). Exact same
   origin/sequence/intent/digest is idempotent; conflicting reuse and
   regressions fail. An interior gap remains corrupt even when the tail
   matches a checkpoint. A checkpoint alone cannot prove missing entries.
4. **Default on mismatch.** Stop dependent authoritative replay, mark
   the affected origin stream degraded and `needs_reconciliation`,
   preserve the original bytes and diagnostics, and allow unrelated
   streams/local non-authority work to continue.
5. **Exceptional repair.** First recover the **original immutable record**
   using independently authenticated backups, receipts, or equivalent
   trusted evidence. A no-effect gap marker/tombstone is permissible
   only under a separately specified, approved, auditably append-only
   correction protocol showing that the missing sequence was only a
   reservation and **was never committed or externally executed**.
   Such evidence cannot be inferred from elapsed time, a newer cursor,
   a lease change, or one Node's unsupported assertion. The current E06
   contract defines **no automatic tombstone acceptance**.
6. **Unknown effect.** Any ambiguous external A05/transfer/device
   operation stays unresolved, even under a newer fence; never
   recreate missing authoritative history, silently skip, or retry the
   same Attempt. Owner disposition and independent outcome proof are
   required before downstream work proceeds.
7. **Reconnection.** Locally valid queued intents remain
   `queued_not_authorized` until current E01/E02/E03/E04/E05 owners
   revalidate the exact referenced generations, leases and grants.
   Contiguity is an integrity check, not an authority grant.
8. **Bounds.** Reject zero sequence and successor overflow at u64::MAX;
   prevent multiple writers, torn journal/cursor commits, stale backups,
   untrusted file aliases and rollback under a verified storage protocol.

## Accepted design expectations

The original non-authorizing corpus
`e06-02-sequence-gap-cases.json` (SHA-256
`bb9449ef4bc3c9c4cf4f5982b34963639a502d78b49658dd5a3710c2597f5d91`)
remains unchanged. The **`contiguous_contract`** expected outcome is
the selected default for all existing cases; `explicit_gap_contract`
is retained as an alternate historical design, not a runtime rule.

Before E06-02 implementation qualifies, add hostile cases for:
atomic commit before/after process death, interior gap hidden by an
interleaved Node, missing record with checkpoint at the tail, competing
writers, journal/Cursor rollback, malformed or forged gap evidence,
duplicate-or-conflicting replay precedence, u64 boundary, and
reconnect-currentness checks. Prove independent stream containment.

## Why this option

The 2026-10-14 bounded mathematical and TTG-Simulation comparison
ranked the atomic/verified candidate highest among five synthetic
policies: TTG-Simulation structural score **99.0132/100**, versus
**98.8512/100** for non-atomic verified recovery; all 12 structural
hostile cases passed, and the atomic candidate won 7 tested weight
variations. The Monte Carlo model estimated ~98.70% versus ~98.48%
productive time in its *assumed* workload. These are **candidate
modeling results, not production measurements or mathematical proof
of a global optimum**. The difference is small; measured write
latency, fsync overhead and physical crash recovery can reverse the
performance ranking. Benchmark KRATOS/ATHENA at actual workloads
before treating throughput as established.

## Approval and authority

This records the **owner's choice of the E06-02 design**. It does not
change the accepted E05 release, authorize an E06 runtime deployment,
satisfy E06-01–07 qualification, mint any E02 authority, or accept
E07. The current Ptah roadmap records runtime authorization through
E05 while E06 remains in design/recovery. Independent scoped review
must validate this contract and its tests before implementation is
promoted.

**Next:** freeze this design in E06's scoped review; implement
the atomic store and selected gap validator only under the applicable
E06 engineering authority; independently verify exact-head conformance,
storage failure injection and measured overhead. No Supervisor cutover.
