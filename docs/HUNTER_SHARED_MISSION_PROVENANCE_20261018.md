# Ptah E07 shared mission provenance — qualification

Purpose: retain one Hunter mission and canonical AgentOps operation reference across
the existing E07 A14 shared-Control checkpoint/readback interface. No new broker,
transport, scheduler, specialist authority, or persistent resident service.

The existing Ptah E07 `SharedWorkspace.for_mission` creates a caller-specific handle
bound to one canonical Ptah Workspace/Session/Node authority stamp and informational
`hunter:mission:*` / `agentops:operation:*` references. Both values are bounded and
validated together. A handle refuses another tool's receipt and a changed operation.

On KRATOS, real native Ptah Control ran on a temporary localhost listener using its
existing A14 qualification snapshot. Five independent caller handles (Hunter,
Cookpit, Supervisor, Formula, TTG-Simulation) submitted five checkpoints through
one Control process. After process termination and restart, the same five durable
Control submissions were read back with identical caller, mission and AgentOps
provenance; all reported `not_executed_by_this_control_service`.

CRITICAL LIMIT: The operation reference in this qualification is a **descriptive
fixture string**, not proof the referenced AgentOps operation exists. This Control
fixture does not enroll the production TTG owner, issue E02 Reservation/Lease/Fence,
dispatch A05, accept a specialist result, or perform Eco second-use. Real missions
must independently bind authenticated owner, real AgentOps operations, existing
Ptah D02 workspace and owning E02/A05 approvals before dispatch.

Tests: `python3 -m unittest discover -s clients/python -p test_ptah_shared_workspace.py`;
`python3 -m unittest discover -s clients/python -p test_ptah_control_client.py`;
`python3 clients/python/qualify_live_ptah_control.py --binary <qualified-ptah-control>
`--fixture services/ptah-control/tests/fixtures/a14_snapshot.json
`--shared-clients --mission-bound`.

These tests keep `run_tool()` fail-closed and refuse unapproved
`accept_worker_result`, cross-mission readback, wrong-operation identity,
invalid mission refs, and missing authority. Existing unbound clients stay unchanged.
