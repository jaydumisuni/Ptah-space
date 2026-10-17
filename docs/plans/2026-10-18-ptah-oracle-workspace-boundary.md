# Oracle → Ptah shared workspace boundary closure

**Scope:** Corrected workspace discovery and transport ownership.
**Date:** 2026-10-18
**Disposition:** Scoped implementation and tests; separate E07 release.

## Locked separation

- Oracle authenticates/transports machine operations to connected host
  nodes such as KRATOS and ATHENA. Ptah does not duplicate Oracle.
- Ptah exposes existing local Workspace, Session, Artifact, checkpoint
  and recovery *mechanics* consumed by independent tools.
- Hunter, Supervisor, Formula, COG, TTG-Simulation and project owners
  select work and retain their own planning, approval and acceptance.
  Sergeant/review controls remain independently authoritative.
- Local workspace inspection does not require Ptah's optional
  Control HTTP endpoint, a Git checkout, or a resident E07 Node.
- A client can report a partial workspace truthfully without mutating
  its filesystem or claiming capabilities it does not have.
- Protected execution remains separately governed. Neither Oracle
  connectivity nor Ptah directory discovery grants A05 execution.

## Scope of this closure

The portable read-only locator and focused tests are extracted from
the broader E07 shared-workspace branch as a standalone correction.
No E07-native transport, remote listener, Node enrollment, Control
dispatch, Supervisor scheduling or production key is introduced.

A successful test of a partial Windows Ptah root is a Windows
compatibility proof, **not** evidence of all Ptah workspace areas
or running Hunter on ATHENA. Verify host-specific actual directories
and operator permissions separately.

E07 PR #126 and Hunter PR #226 have their own engineering
qualification and independent-review requirements. This correction
must not mark either larger project COMPLETE.
