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


## Independently witnessed A05 result readback

The optional Control flag \`--verified-dispatch-journal /secure/ptah/control-dispatch.sqlite\`
enables read-only lookup of evidence **already verified and durably recorded**
through Ptah's E07 \`ControlDispatchJournal::record_verified_effect\`.
No journal is created or opened for writing by this HTTP projection.
When absent, the Control response remains
\`not_executed_by_this_control_service\`.

For each persisted \`AuthorizedSubmission\`, Control computes
\`sha256:\` + SHA-256 of the canonical serialized submission and matches
that exact digest against the dispatch journal. A matching immutable
\`control_verified_effects\` row with the same Attempt and Dispatch permits
the response state \`independent_a05_effect_verified\` and returns:
\`witness_id\`, \`evidence_digest\`, \`exit_code\`, \`stdout_digest\`,
and \`completion_accepted=false\`. No second record for the same
submission is accepted; ambiguity results in HTTP 503.

**Boundary:** This is a read projection of previously verified evidence,
not a new witness signature verification, not a dispatch service,
not a success or approval decision, and not a way for clients to mint
receipts. The writer must be the existing pinned, independently qualified
Control verification process. Store the journal as a private regular file
inside a deployment-controlled state directory. On Unix, readback rejects
symlinked, hardlinked or group/world-accessible journal files.
Direct modification of the underlying database by a privileged actor
remains outside this HTTP readback's cryptographic validation.

A genuine cross-tool Ptah submission must carry its canonical submission
digest all the way into E02 \`stage_issued\`. The A05 result must be
observed by the actual Node and an independent signed witness must
pass \`record_verified_effect\` before this projection becomes populated.
Do not seed the evidence tables from a client or untrusted tool.

Focused KRATOS proof: 12/12 Rust Control tests, 19/19 Python tests,
strict Clippy, and actual five-caller Control submit/restart/readback PASS.
These tests do not represent an automatically running production E02/A05
dispatcher. ATHENA's Oracle execution works, but no admitted Ptah Node
executable/service was found in the checked Windows locations.

## Local Ptah workspace access through Oracle (no native Node prerequisite)

`ptah_local_workspace.py` exposes the existing on-disk Ptah repository and
workspace areas to independently selected callers. It **does not** open,
authenticate or replace an Oracle connection. ChatGPT/Hunter first access
their machine using Oracle, then inspect the Ptah path that already exists
on that machine.

On KRATOS:

```bash
python3 clients/python/ptah_local_workspace.py \
  --root /home/kratos/projects/Ptah-space --caller hunter
python3 clients/python/ptah_local_workspace.py \
  --root /home/kratos/projects/Ptah-space --caller chatgpt
```

A partially populated Ptah directory (including an ATHENA workspace without a
Git checkout) is still discoverable: `git_checkout_present=false` and
`missing_optional_areas` report exactly what is absent. No missing
directory is created or claimed to exist.

Both resolve the same canonical `.workspace/workspaces`, `worktrees`,
`evidence`, `proof-history` and `recovery` areas. The caller label is
provenance only. Files and tools are used via the caller's existing Oracle
machine session and ordinary host filesystem/Git capabilities.

For an existing local Hunter Python process, with its own host access:

```python
from ptah_local_workspace import LocalPtahWorkspace
view = LocalPtahWorkspace(
    "/home/kratos/projects/Ptah-space"
).caller_view("hunter")
```

Add this clients/python directory to that process's trusted Python import
path when integrating the runtime; importing the module does not mutate
Hunter state or attach it to a running process. A Windows/ATHENA caller must
supply and verify its **actual** Ptah root, not reuse the KRATOS path.

The separate `PtahControlClient` / `SharedWorkspace` API is an
**optional** authority-stamped checkpoint/readback facility. Absence of a
loopback Control listener must not prevent normal Ptah workspace access;
nor does a successful local directory discovery grant permission to issue
E02/A05 work, change Supervisor routing, or accept a result.

KRATOS evidence 17 October 2026: local caller discovery succeeded for
`hunter` and `chatgpt`, and Python tests were 23/23 PASS. Oracle reported
ATHENA **offline** during this check, so cross-host live continuity and
adoption by the running Hunter process are not claimed.
