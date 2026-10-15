# Shared Ptah Control client — Python

This Ptah-owned adapter exposes one existing Ptah Workspace Control interface to Supervisor, Hunter, Formula, COG, TTG-Simulation and other clients. It is not a separate execution service and does not choose policy or approve work.

Currently supported native routes: GET /api/state; GET /api/shell-v2; POST /api/control.

Both state projections must have the exact same canonical authority stamp. Every protected submission carries the current authority stamp. A 202 response means **authorized for dispatch, not executed**. Execution/completion requires genuine Node-side E02/A05 receipts and independent recovery evidence.

Limits: loopback-only HTTP, no redirects, bounded response/request, no arbitrary command execution, no minted grants/leases/fences, no credentials created, and no automatic Supervisor cutover. Missing service or mismatched authority fails closed. Approval-dependent actions require a caller-provided approval reference.

Usage: import PtahControlClient from ptah_control_client; instantiate with an existing loopback ptah-control endpoint; observe() returns matching state/shell projections; submit_control() submits an already caller-selected operation and returns its request ID with explicit non-completion status.

Run tests inside this directory using: python3 -m unittest -v test_ptah_control_client.py

Six local HTTP-fixture tests exercised the Python adapter on 16 Oct 2026. They do not prove that a production Ptah Control/Node service was running or a tool was physically dispatched. The E07 admission, real execution, retained receipt and restart test remain separate.
