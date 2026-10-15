# E07 SIGKILL Node Journal Evidence — Development Candidate

**Scope:** Real Linux process death; not a host reboot or live production enrollment.

The physical KRATOS `supervisor_gateway_boundary` suite now has an independent
process-kill qualification: `e07_sigkill_after_durable_node_stage_requires_reconciliation`.
The parent launches a separate test executable with a bounded, uniquely isolated
SQLite WAL journal. The child acquires Ptah's Node E02 fixture
Reservation/Lease/Fence, commits one exact A04 Attempt to the durable Node
journal, writes a completion-of-stage marker, and stays alive.
The parent then sends SIGKILL **only** to this owned test child.

A separate journal opener recovers the persisted in-flight Attempt as
`needs_reconciliation`. The original request digest and Attempt identity
are retained; exit and stdout evidence remain unset. Attempt restaging is
reported as `AlreadyRegistered` and the unresolved inventory is preserved.
No external effect is automatically replayed.

KRATOS observed one successful SIGKILL qualification and strict Clippy
`-D warnings` passing on 14 October 2026. CI repeats the child-process
kill and the full active Node gateway suite without test certificates being
treated as production credentials.

## Closure boundary

This qualifies **process-death recovery only**, under fixture E02 authority.
It does not prove a physical hard power loss, survive a whole machine's
unflushed write cache, prove actual independently signed external side
effects, or enroll two production Nodes. Do not mark E07 or G4 complete.
Physical hard-reboot acceptance requires a scheduled safe test window,
a running independent effect witness, validated two-node production
enrollment, and signed owner go/no-go.

Related Ptah #110, #114, #116, gateway PR #112, E07 PR #113.
No Ptah production services, host reboots, firewall settings or Supervisor
routes are changed by this test.


## Post-effect / pre-receipt physical process kill — 2026-10-15

An additional independent KRATOS process-death test covers the case that
the original pre-effect stage test could not: the Node **actually launched**
a bounded `/usr/bin/python3` process through Ptah A05 and observed that
it wrote a unique external-effect file. Before the Node completed its durable
A05 receipt, the test parent killed only its explicitly owned Node child.
On restart the Node journal retained the matching E02-fenced Attempt in
`needs_reconciliation`, with no invented exit/stdout digest; replay via
`spawn_once` was denied, despite the separately observed external file.

Evidence on KRATOS: 1/1 targeted post-effect SIGKILL PASS, active gateway
suite 16/16 PASS (two external specialist tests intentionally opt-in).
The same exact test is added to the hosted E07 SIGKILL workflow.

This is **not** a trusted production witness: the marker is an independently
read fixture file, not an approved signer or verified two-machine effect
receipt. Hard power loss, durable cross-host signed witness operation,
Node enrollment, and supervised production dispatch are still NO-GO.
