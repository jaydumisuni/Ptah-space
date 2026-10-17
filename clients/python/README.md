# Ptah workspace access — Oracle transport boundary

Ptah is the neutral workspace and execution/evidence machinery, **not**
the host-to-host transport, autonomous planner, approver, or project owner.
Oracle is the existing transport to KRATOS, ATHENA, Nodie and other
Oracle-connected machines. Every caller (ChatGPT, Hunter, Cookpit,
Supervisor, Formula, TTG-Simulation) keeps its own approval and decision
authority.

## Standalone read-only locator

`ptah_local_workspace.py` discovers existing Ptah workspace directories
on a machine **after Oracle or the caller's authorized host transport has
provided access**. It creates no workspace, service, Node enrollment,
network listener, credentials, execution authority or approval.

KRATOS example:

```bash
python3 clients/python/ptah_local_workspace.py \
  --root /home/kratos/projects/Ptah-space --caller hunter
```

For ATHENA, use the same Python module with the **actual Windows Ptah
workspace root** under an Oracle Windows session. The caller must verify
the real local path. A partial `.workspace` without Git or a Ptah E07
Node service is a valid **partial** workspace; absent areas are
reported as `missing_optional_areas`, never synthesized.

An ordinary workspace directory lookup requires **neither Ptah E01
enrollment nor Ptah Control**. A protected execution, A05 effect, or
cross-host data transfer still requires the *separate applicable*
capability, credentials and independent grant. Discovery is not
execution, and a Control 202 response is not an execution receipt.

## Security and test boundary

The locator rejects symlinked roots and areas, invalid caller labels,
and missing canonical workspace state. Caller labels are provenance only,
never roles. No path is created and no subprocess is launched by the
imported module. Directory names and paths are read-only local data:
do not expose them directly to an untrusted remote user without the
caller's own authorization and redaction.

Run focused unit tests:

```bash
cd clients/python
python3 -m unittest -v test_ptah_local_workspace.py test_ptah_windows_workspace.py
```

This work isolates the workspace/transport correction from **draft
E07 execution work** in Ptah PR #126. E07 physical Node qualification,
E02 dispatch, independent witness acceptance, Supervisor cutover and
the Hunter bridge's own review are **not** claimed or approved by this
change. Oracle is reused for host access; Ptah is the workspace.
