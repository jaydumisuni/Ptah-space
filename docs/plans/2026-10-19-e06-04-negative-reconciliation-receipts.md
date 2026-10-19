# E06-04 — Immutable negative reconciliation receipt candidate

Date: 2026-10-19. Status: QUALIFIED ENGINEERING CANDIDATE, not E06/E07 release acceptance.

## Authority

Ptah is the shared mechanical workspace. Oracle remains machine transport.
The E06 local intent queue and negative receipt table do not replace E01
authenticated session, E02 dispatch authority, E03 transfer, E04 Workspace
movement, E05 platform admission, or independent owner decisions.
Native E07 service enrollment is optional for Oracle-backed workspace use,
not a workspace-entry prerequisite.

## Additive delivery

The SQLite WAL/FULL journal adds a reconciliation_findings table bound by
(node, sequence) to existing queued_intents. It accepts only a closed
vocabulary of negative or unknown observations: missing or stale E01/E02/
E03/E04/E05, stale Fence, changed Object, conflicting effect, interrupted
reconnect, and unknown outcome. There is no approved, ready, dispatched,
or applied receipt variant.

record_finding validates existing journal, exact intent identity, and a
canonical sha256 evidence address. An identical replay is idempotent; a changed
digest or verdict is a conflict, never an overwrite. verify_findings validates
the records at journal reopen, including their canonical sequence, parent,
reason and digest. The degraded status now surfaces unresolved findings as
conflict while retaining authority_granted=false and revalidate_required=true.

The digest is only a reference to an external observation. This package does
not cryptographically authenticate the observation source or authorize effects.
Retain sensitive raw evidence with its owner; never store keys or customer
records inside a reconciliation finding.

## KRATOS qualification

- Full offline ptah-offline-intent Rust suite: PASS, including six new
  receipt/integrity/reopen/replay tests; one prior opt-in benchmark ignored.
- Strict all-target Clippy with warnings denied: PASS.
- Workspace rustfmt check: PASS.
- Git diff whitespace check: PASS.
- Isolated worktree; no production services, credentials, routes or device
  state changed.
- Reused existing E06 Cargo target artifacts to avoid duplicate cache bloat.

## Explicit remaining E06 closure

E06-03 needs actual E01-E05 owner-verified current session and generation
revalidation, without silent rebasing. E06-06 still needs multi-step reconnect,
power-loss, adversarial and sustained recovery conformance. E06-07 requires
independently reviewed exact-head proofs and guarded release.
E07 native execution and two-host admission remain a separate optional track.
