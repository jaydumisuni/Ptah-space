# Shared Ptah Control client — Python

This Ptah-owned adapter exposes one existing Ptah Workspace Control interface to Supervisor, Hunter, Formula, COG, TTG-Simulation and other clients. It is not a separate execution service and does not choose policy or approve work.

Currently supported native routes: GET /api/state; GET /api/shell-v2; POST /api/control.

Both state projections must have the exact same canonical authority stamp. Every protected submission carries the current authority stamp. A 202 response means **authorized for dispatch, not executed**. Execution/completion requires genuine Node-side E02/A05 receipts and independent recovery evidence.

Limits: loopback-only HTTP, no redirects, bounded response/request, no arbitrary command execution, no minted grants/leases/fences, no credentials created, and no automatic Supervisor cutover. Missing service or mismatched authority fails closed. Approval-dependent actions require a caller-provided approval reference.

Usage: import PtahControlClient from ptah_control_client; instantiate with an existing loopback ptah-control endpoint; observe() returns matching state/shell projections; submit_control() submits an already caller-selected operation and returns its request ID with explicit non-completion status.

Run tests inside this directory using: python3 -m unittest -v test_ptah_control_client.py

Six local HTTP-fixture tests exercised the Python adapter on 16 Oct 2026. They do not prove that a production Ptah Control/Node service was running or a tool was physically dispatched. The E07 admission, real execution, retained receipt and restart test remain separate.

## Shared workspace for multiple independent tools

`ptah_shared_workspace.py` provides bounded caller handles that reuse the
**same canonical Ptah Workspace/Session/Node authority**, rather than adding
a parallel scheduler per tool:

```python
from ptah_control_client import PtahControlClient
from ptah_shared_workspace import SharedWorkspace

workspace = SharedWorkspace(PtahControlClient("http://127.0.0.1:7800"))
cookpit = workspace.for_tool("cookpit", "ptah")
supervisor = workspace.for_tool("supervisor", "ptah")
formula = workspace.for_tool("formula", "ptah")
simulation = workspace.for_tool("ttg-simulation", "ptah")

receipt = supervisor.checkpoint({"milestone": "qualified-candidate"})
readback = supervisor.readback(receipt)  # still not execution
```

Additional callers (Hunter, COG, Sergeant, TechGuy applications) can create
their own handles without editing Ptah's core. Each checkpoint stores a bounded
descriptive caller/project tag and an immutable Control request identity.
Control echoes the tag on readback; the handle checks the exact workspace and
tag after restart. Caller tags are **informational**, not authenticated roles,
approvals, or grants. Independent tools own task planning, ownership,
approvals, and result interpretation. Ptah alone owns common workspaces,
resources, transport, and durable execution receipts once E02/A05 is admitted.

A canonical workspace-change guard rejects a submission if its Workspace
changes between initial observation and the pre-submit authority read. The
shared client exposes no local subprocess, scheduler, E02 lease minting, or
synthetic completion. `run_tool()` deliberately refuses until an admitted
Control→Node→provider route supplies durable verified results.

**16 October physical KRATOS evidence:** with the genuine Rust Control binary,
five callers (Cookpit, Supervisor, Formula, TTG-Simulation, Hunter) made five
separate checkpoints through one Control listener. After Control restarted
using its durable submission log, all five IDs and caller tags were read back
unchanged. Exactly five records persisted and all accurately reported
`not_executed_by_this_control_service`. This qualifies multi-caller
submission/readback, **not** actual tool execution or an E07 production
shared-workspace cutover.

Run tests:
`python3 -m unittest -v test_ptah_control_client.py test_ptah_shared_workspace.py`.
