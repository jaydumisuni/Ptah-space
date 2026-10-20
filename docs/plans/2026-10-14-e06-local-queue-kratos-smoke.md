# E06 local-first executable — KRATOS physical smoke

**Date:** 2026-10-14
**Status:** E06 offline preparation capability proven; NO runtime execution authority.

The `ptah-local-queue` executable is part of the Ptah E06 crate. It provides
only `status` and `enqueue` operations against a private local SQLite
journal; it has no shell, A05, process, network, transfer, permission or
promotion endpoint. It never accepts arbitrary authority as input.

KRATOS execution from the Ptah source tree:

- Initially `status` returned `offline_local`, count 0,
  `authority_granted=false`.
- First `enqueue` committed sequence **1**, `Distinct`,
  `queued_not_authorized`.
- Repeated identical `enqueue` returned `Idempotent`, unchanged sequence 1.
- Second distinct intent committed sequence **2**.
- Independent `status` process recovered count 2 and
  `queued_not_authorized`.
- All receipts reported `revalidate_required=true` and
  `authority_granted=false`.
- State was isolated under
  `.tmp/e06-qualification/queue.sqlite`, which Patrol allowed; no live
  Supervisor queue or deployment service was modified.

The E06 crate also passes offline tests and strict all-target Clippy.
This is a concrete local-first working component but **not** E06-03 live
E01–E05 revalidation, E06-04 independent conflict receipt qualification,
E06-07 release, E07 dual-host acceptance, or Supervisor transfer.

`ptah-node` remains a separate Node service and currently requires
deployment-specific E01 secure-link configuration. The local queue
executable is not a substitute for a production Ptah Node agent.
