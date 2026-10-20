# E06-02 atomic queue implementation candidate — KRATOS proof

**Date:** 2026-10-14
**Status:** ENGINEERING CANDIDATE, not accepted E06-02, E06 release, or E07.
**Owner-selected contract:** `2026-10-14-e06-02-owner-selected-atomic-contiguous-recovery.md`

## Implementation
- `crates/ptah-offline-intent/src/durable.rs`: SQLite local-intent store using `WAL`, `synchronous=FULL` and immediate write transactions.
- `enqueue(IntentDraft)` allocates a per-Node origin sequence **inside** the same transaction committing a fully validated `QueuedIntent` envelope and cursor. Sequence is returned only after a successful commit.
- Exact immutable replay is idempotent. New or conflicting reused identities, skipped origin sequences, forged cursor/tail, missing journal evidence and malformed envelopes fail closed. Queued state always carries `revalidate_required=true`.
- The existing E06-01/E06-02 pure-history validators now reject interior gaps between adjacent distinct same-Node sequences, including interleaved Node histories and a forged matching checkpoint tail.
- Recovery scans the complete per-Node journal and compares each cursor with its last record. Each append validates the immediate cursor/tail under its exclusive SQLite transaction, avoiding an O(n²) history rescan.
- Entire unsigned 64-bit sequence domain uses canonical 20-digit zero-padded TEXT encoding; terminal sequence overflow rejects further appends.
- On Unix, database opening requires restrictive filesystem permissions and disallows symlink/hardlink-alias access. Production must additionally qualify an owner-controlled private state directory, rollback protection and independently anchored receipts.

## Tests and negative evidence
`cargo test -p ptah-offline-intent --locked --offline` and `cargo clippy -p ptah-offline-intent --all-targets --locked --offline -- -D warnings` PASS on KRATOS.

Durable tests cover:
- interleaved independent Nodes, exact replay and conflict;
- atomic `enqueue` allocation through two concurrent SQLite connections;
- SQL trigger failure between intent insert and cursor update, preserving full rollback;
- process-close/reopen and full journal read-back;
- removed interior record even when checkpoint cursor still matches the last record;
- mismatched cursor, skipped successor and duplicate origin;
- private 0600 file creation, symlink/hardlink aliases and world-readable rejection;
- canonical `u64` encoding and successor boundary.

## Performance baseline (not production service SLA)
An explicitly opt-in KRATOS physical storage test committed 1,000 local-intent entries through `enqueue` in **77.497 ms**, approximately **12,903.8 operations/second**; full restart validation of those entries took **9.338 ms**. Debug build; one machine, one local filesystem, a single workload and no fsync fault/physical power-loss instrumentation. Do not extrapolate universally or claim cross-host performance.

## Remaining E06 requirements
E06-03 through E06-07 require authenticated E01–E05 owner revalidation, immutable conflict/stale receipts, degraded-state API, crash/reboot and power-loss qualification, independent exact-head review and release acceptance. This queue cannot itself execute or authorize a task. Gap tombstones have **no automatic acceptance path**.

**E07, production enrollment and Supervisor transfer remain NOT AUTHORIZED by this proof.**
