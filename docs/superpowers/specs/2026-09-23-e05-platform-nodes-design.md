# E05 Platform Nodes — Design

Status: implementation design frozen for branch `e05-platform-nodes`

Accepted predecessor: E04 merge `77bbd876aaefd78fed2c0583b2b124eee428eb5f`

Roadmap authority: `jaydumisuni/ptah-roadmap-` commit `98dc8c4e8639cda80510bee0625db34b4fdf9384`, `IMPLEMENTATION_ROADMAP.md` E05 section.

## 1. Roadmap scope

E05 admits Platform Nodes in proof-need order:

1. always-on Linux mini PC;
2. workstation/GPU Node;
3. Windows Node;
4. macOS Node;
5. Android/Device Nodes.

E06 intermittent/local-first queues, discovery, sync and reconciliation remain out of scope.

## 2. Existing authority owners

E05 adds no Core entity family and does not replace existing owners.

- E01 owns authenticated Node identity, Node Generation, Connection Epoch, enrollment and current secure-session authority.
- A02 owns Node observations, health, reachability, PlatformFacts, NodeCapabilitySnapshot, NodeResourceSnapshot and platform diagnostic advisory Views.
- E02 owns placement eligibility, Reservation, Lease, Fence and DispatchAuthority.
- D08 owns Application platform compatibility and remote Application execution disposition.
- C10 owns Android Device/Application Session authority.
- ADR-0036 owns the diagnostic-advisory boundary: Ptah may report missing/degraded platform capability but may not approve or perform its own upgrade.

## 3. E05 authority

E05 owns only one new mechanical fact:

> whether exact current E01/A02 evidence satisfies one explicit platform-admission profile.

An E05 admission decision is evidence, not execution authority. It cannot create a Reservation, Lease, Fence, Provider, Application Session, Display Session, Device Session, transfer, checkpoint or upgrade Activity.

## 4. Admission classes

E05 uses an implementation-level `PlatformNodeClass`; this is not a Core identity.

- `AlwaysOnLinux` requires Linux PlatformFacts plus explicit verified capability evidence supplied by policy for the always-on role.
- `WorkstationGpu` requires Linux PlatformFacts plus explicit verified GPU/workstation capability evidence supplied by policy.
- `Windows` requires Windows PlatformFacts.
- `Macos` requires macOS PlatformFacts.
- `AndroidDevice` requires Android PlatformFacts plus explicit Device/agent capability evidence supplied by policy.

The class never infers capability from a hostname, product name, GPU vendor string or filesystem path.

## 5. PlatformAdmissionProfile

A profile contains:

- platform class;
- explicit required capability references;
- explicit required Provider Revision references;
- optional allowed architecture set;
- whether degraded health is admissible.

The class supplies the expected OS family. Semantic capabilities such as always-on role, GPU execution, graphical display, remote application execution or Device control must be represented by verified capability references, not by string heuristics.

## 6. Admission input binding

Evaluation consumes:

- exact current E01 `SessionBinding`;
- A02 `NodeStateProjection`;
- A02 `NodeCapabilitySnapshot`;
- explicit `PlatformAdmissionProfile`.

All Node identity, Node Generation and Connection Epoch values must match exactly across session, state and capability evidence.

The state projection must reference the exact capability snapshot being admitted.

## 7. Fail-closed conditions

Admission is blocked when any of the following holds:

- Node identity mismatch;
- Node Generation mismatch;
- Connection Epoch mismatch;
- capability snapshot not referenced by current Node state;
- Node lifecycle is not `Active`;
- reachability is not `Online`;
- health is `Unknown` or `Unhealthy`;
- health is `Degraded` unless the explicit profile allows it;
- capability snapshot outcome is not `Complete`;
- OS family mismatch;
- architecture outside the explicit allowed set;
- required capability reference missing;
- required Provider Revision reference missing;
- capability claims exist without their existing A02 verification boundary.

A failure never falls back to hostname, ambient OS detection or network reachability.

## 8. Diagnostic advisory

A blocked admission may be projected into the existing A02 `DiagnosticAdvisory`.

The advisory must:

- retain exact Node/evidence references;
- separate observed condition from expected condition;
- identify the mechanical work effect;
- state uncertainty;
- leave the caller decision explicit;
- keep `automatic_upgrade_authorized=false`;
- keep `self_approved=false`.

The advisory cannot make an admission pass.

## 9. E02 composition

Existing E02 `place_and_issue` remains unchanged for generic placement compatibility and regression stability.

E05 adds an E05-specific control path:

1. control accepts current E01/A02 evidence as before;
2. control evaluates and stores an E05 admission for the exact session/snapshot;
3. E05-specific placement filters candidates to the required admitted class;
4. unchanged E02 candidate evaluation then rechecks capability/resource requirements;
5. unchanged E02 owner mints Reservation, Lease/Fence and DispatchAuthority.

A new capability snapshot or superseding E01 session invalidates cached E05 admission.

E05 therefore gates platform eligibility but never allocates E02 authority.

## 10. D08 composition

D08 remote Windows/macOS compatibility remains non-executing without E02 DispatchAuthority.

For E05 platform flows, control can mint E02 authority only after the exact target has a current matching E05 admission. D08 then consumes its existing compatibility plus the E02 authority. E05 does not create D08 Application or Display Sessions.

## 11. Android/Device boundary

E05 Android/Device Node admission proves only that a Node endpoint with Android PlatformFacts and required explicit capabilities may participate as a Platform Node.

It does not replace C10 Device Session authority, DPC/ADB/device protocol authority, or physical Device identity. A Device attached to a Linux/Windows/macOS Node remains a Device under existing C08/C10 authority rather than becoming the host Node identity.

## 12. Physical proof boundary

The accepted Phase-0C collector `host/scripts/collect_capabilities.py` may be reused only for facts it actually measures: Linux host identity and its declared host capability profile.

It does not by itself prove GPU, Windows, macOS or Android/Device admission.

Physical proof therefore proceeds in roadmap order and records exact host evidence separately:

1. Linux mini-PC/current Linux Node proof;
2. Linux workstation/GPU proof with explicit GPU capability evidence;
3. Windows Node proof;
4. macOS Node proof;
5. Android/Device Node proof.

A missing physical platform blocks only that proof stage; it must not be simulated and called physically proven.

## 13. Restart and freshness

E05 retains no durable authority independent of owners.

After reconnect/restart:

- current E01 session must be re-established;
- A02 state/capability evidence must be current;
- E05 admission is recomputed;
- stale admission from an older Generation/Epoch cannot authorize placement.

## 14. Nonclaims

E05 does not add:

- E06 discovery, relay selection, offline queues, sync or reconciliation;
- automatic Provider install/upgrade;
- autonomous host replacement;
- hidden vendor preference;
- new Node identity;
- new capability identity family;
- new placement, Reservation, Lease or Fence authority;
- new remote display transport;
- new checkpoint/transfer model;
- Device authority outside C08/C10;
- source deletion or Workspace movement behavior.

## 15. Acceptance obligations

The E05 conformance proof must include at least:

1. exact E04 predecessor ancestry;
2. exact E01/A02 identity-generation-epoch binding;
3. current active/online/healthy Linux admission;
4. stale Generation rejection;
5. stale Connection Epoch rejection;
6. foreign Node rejection;
7. non-active lifecycle rejection;
8. offline/stale/unknown reachability rejection;
9. unknown/unhealthy health rejection;
10. degraded health rejected by strict profile;
11. degraded health admitted only by explicit profile;
12. partial/failed capability snapshot rejection;
13. OS mismatch rejection for every class;
14. architecture mismatch rejection;
15. missing required capability rejection;
16. missing Provider Revision rejection;
17. exact capability snapshot reference required in Node state;
18. always-on Linux admission with explicit role capability;
19. workstation/GPU admission with explicit GPU capability;
20. Windows admission;
21. macOS admission;
22. Android/Device admission with explicit Device capability;
23. rejected admission produces evidence-bound diagnostic advisory;
24. advisory cannot self-approve or authorize upgrade;
25. E05 admission alone cannot mint E02 authority;
26. E05-specific placement excludes non-admitted candidates;
27. new capability snapshot invalidates cached admission;
28. superseding E01 session invalidates cached admission;
29. admitted candidate still must pass unchanged E02 resource/capability checks;
30. D08 remote execution remains dependent on exact E02 authority;
31. C10 authority is not replaced by Android/Device Node admission;
32. E06 scope remains absent;
33. no frozen schema/migration change;
34. inherited E01/E02/E04/D08/C10 regressions remain green;
35. exact-head retained proof artifact binds the final candidate SHA.
