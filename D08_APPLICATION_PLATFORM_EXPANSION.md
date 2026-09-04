# D08 Application Platform Expansion — Durable Proof Record

## Frozen authority

D08 is implemented strictly above the accepted D07 predecessor. The exact predecessor and required `main` head for the frozen D08 proof run is:

`d979e0ecfc6dba3b370206833ac13b3189d725e3`

That commit is the D07 merge (`Security evidence and independent reproduction`).

The roadmap authority recovered for this milestone is `ptah-roadmap-` commit:

`98dc8c4e8639cda80510bee0625db34b4fdf9384`

The frozen D08 design and implementation plan are:

- `docs/superpowers/specs/2026-09-03-d08-application-platform-expansion-design.md`
- `docs/superpowers/plans/2026-09-03-d08-application-platform-expansion.md`

The final pre-proof-artifact implementation tree is branch head:

`bc4165e6979612dec214faa6ae8db24e78d94433`

The permanent exact-head workflow must separately prove the commit containing this durable record and
`.github/workflows/d08-application-platform-expansion-proof.yml` before merge.

D08 does not amend frozen schema catalogs, migrations, or generated contract bindings.

## Architecture boundaries

D08 adds one provider-neutral composition crate:

`crates/ptah-application-runtime`

It composes existing Application, A04 Attempt, A05 native-process, C10 Android, Display/Window and D01 shell truth.
It does not create a parallel Application identity family, a new database, a new network protocol, or a replacement
for the lower-level Providers that own mechanical execution.

### Local Linux two-phase boundary

Linux native and Linux packaged applications are the executable Node-local D08 path.

Preparation requires exact current Application Revision compatibility, exact Node and Provider generation,
materialization generation, A04 Attempt context, privacy policy and launch evidence. A successful preparation creates
one stable `application.session` in `preparing` with unavailable/unknown runtime availability. Preparation does not
claim process, Window, Display or application readiness.

A05 `native-process` remains the mechanical process owner. Spawn acknowledgement or `ProcessState::Running` is
process evidence only.

Graphical verification requires the current matching A05 process plus a fresh same-session visible Application Window
and a fresh same-session streaming Display Session under the same Provider generation/locality. Only then does the
same stable Application Session become `running` with `full` availability.

Headless verification does not invent Window or Display state. Current process/service evidence promotes the same
stable Session only to the deliberately bounded `degraded` + `headless_only` projection.

### C10 Android composition boundary

C10 remains Android execution authority. D08 consumes an already verified C10 Device Session/Application Session pair.

The projection requires the exact Device Session binding, Provider instance/generation and connection epoch, a C10
Application Session in verified `Visible` state, retained frame/semantic/supporting evidence and existing privacy
authority. D08 preserves the C10 `application.session` identity and does not call Android install, launch, input,
stop, lease or fence mutation APIs as part of the projection.

A stale, stopped, crashed, foreign-generation or foreign-epoch Android session cannot be presented as fresh D08 full
availability.

### Application Window and Display lifecycle boundary

D08 preserves stable canonical `application.window` identity independently of backend handles. Backend PID, X11,
Wayland, Win32, macOS, Android, VM, simulator and remote-display identifiers remain scoped aliases/evidence.

Application Window lifecycle is frozen as:

`created → visible | hidden | degraded | replaced | closed | unknown`

Only a fresh current same-generation `visible` Window can satisfy graphical readiness.

Display Session lifecycle is frozen as:

`preparing → streaming | degraded | detached | recovering | closed | failed`

A prepared Display Session is not pixel/readiness proof. `streaming` requires fresh frame/surface evidence from the
same Provider generation and declared stable surface.

Application Session lifecycle is the frozen `application.session.lifecycle`; D08 uses the two-phase
`preparing` → verified `running`/bounded `degraded` distinction rather than treating admission as readiness.

### Remote-node deferral

Before Programme E supplies real remote Node placement/reservation/lease/fence authority:

- Windows Node remains `RequiresRemoteNode`;
- Windows VM remains `RequiresRemoteNode` and retains virtualization requirements;
- macOS Node remains `RequiresRemoteNode`;
- iOS Simulator remains `RequiresRemoteNode` with compatible macOS/Xcode Simulator requirements;
- live remote display for those platforms remains a non-executing Programme E blocker.

D08 does not allocate a remote Node, create a remote Provider, mint a remote lease/fence, synthesize
`remote_service_ref`, create a remote Application Session, create a remote Display Session, or implement
RDP/VNC/WebRTC transport to hide the missing dependency.

### D01 Human Workspace projection

D01 receives only the read-only `ApplicationPlatformView` collection derived from validated D08 snapshots.

A preparing Session renders preparing/unavailable. A running/full or degraded/headless-only Session renders only the
state supplied by validated D08 backing. A remote-node requirement renders a blocker with no Application Session or
Display Session identity.

No D08 launch/stop/input `ControlKind` is added. The D01 authority stamp and existing operation catalogue remain
unchanged. Presentation state cannot authorize runtime work.

## Frozen contract audit

D08 reuses the frozen Phase-0B Application catalog and requires these eight schema identities to remain present in the
generated `ptah-contracts` bindings:

1. `urn:ptah:schema:application:application:0.1.0`
2. `urn:ptah:schema:application:application-revision:0.1.0`
3. `urn:ptah:schema:application:application-compatibility:0.1.0`
4. `urn:ptah:schema:application:application-session:0.1.0`
5. `urn:ptah:schema:application:application-window:0.1.0`
6. `urn:ptah:schema:application:application-window-observation:0.1.0`
7. `urn:ptah:schema:application:display-session:0.1.0`
8. `urn:ptah:schema:application:display-observation:0.1.0`

The three lifecycle-machine names audited through the generated bindings are:

1. `application.session.lifecycle`
2. `application.window.lifecycle`
3. `application.display_session.lifecycle`

## Cargo and lock boundary

Relative to exact D07 predecessor `d979e0ecfc6dba3b370206833ac13b3189d725e3`, the accepted D08 Cargo boundary is:

- add workspace path package `ptah-application-runtime 0.0.0-phase0c`;
- add exactly the `ptah-application-runtime` dependency edge to existing
  `ptah-control 0.0.0-phase0c`;
- remove no package;
- move no external package version, source or checksum.

No external dependency addition is required by D08.

## D08 acceptance corpus — exactly 28 cases

The frozen D08 milestone contains exactly 25 runtime acceptance cases and 3 D01 shell integration cases:

1. frozen Application schema/lifecycle constants match generated bindings;
2. node-local compatibility requires exact current evidence;
3. expired compatibility cannot admit new work;
4. conditional compatibility requires explicit condition evidence;
5. contradictory mandatory requirement results reject compatible decisions;
6. Linux native graphical execution can become Node-local ready only from current evidence;
7. Linux packaged graphical execution can become Node-local ready only from current evidence;
8. Windows Node remains remote-node dependent;
9. Windows VM retains virtualization requirements;
10. macOS Node remains remote-node dependent;
11. iOS Simulator retains macOS/Xcode/display requirements;
12. a remote-node requirement cannot become Node-local authority;
13. local preparation binds exact context and creates one stable preparing Session;
14. stale/incompatible/foreign-revision compatibility is rejected before execution;
15. a running A05 process without Window/Display proof is not graphical readiness;
16. foreign A05 Node/Provider generation rejects verification;
17. current process + visible Window + streaming Display promotes the same Session;
18. backend PID/window aliases remain non-canonical evidence;
19. a verified C10 Device/Application pair projects Android full availability;
20. mismatched C10 Device/Application sessions are rejected;
21. stale C10 Provider generation/connection epoch is rejected;
22. Android projection is read-only and preserves C10 authority;
23. Display preparation requires exact Session/Provider/surface/privacy evidence;
24. stale/foreign Display Observation cannot become streaming;
25. remote-display intent remains a non-executing Programme E blocker;
26. validated local/Android state projects into D01 without launch authority;
27. remote-node blockers project without Application/Display session identity;
28. absent/preparing backing stays unavailable and cannot change D01 authority.

The permanent proof additionally retains targeted B05, A04, A05, C10 and D01 regressions plus the complete locked
workspace test suite.

## Proof evidence before proof-artifact freeze

The Task 4 promotion gate completed successfully in GitHub Actions run `33858138118`.

That gate proved before freezing implementation commit `bc4165e6979612dec214faa6ae8db24e78d94433`:

- exactly 25 runtime + 3 shell = 28 D08 acceptance cases;
- D01, C10 and A14 regressions;
- strict Clippy for `ptah-application-runtime` and `ptah-control` with warnings denied;
- zero D08 lint suppressions in the audited surface;
- byte-stable promoted Cargo.lock;
- exact production-delta review;
- freeze and promotion of the proven Task 4 implementation.

That Task 4 evidence is the reviewed implementation baseline. It is not a substitute for the permanent D08
exact-head proof required for the proof-artifact candidate.

## Explicit deferrals and non-claims

D08 deliberately does not provide or claim:

- Programme E remote Node placement, reservation, lease or fence machinery;
- Windows or macOS remote agents;
- a hypervisor/VM Provider;
- an Xcode Simulator Provider;
- RDP, VNC or WebRTC remote-display transport;
- cross-Node synchronization or remote execution scheduling;
- checkpoint migration;
- automatic application installation;
- compatibility inferred from filenames alone;
- Android authority outside C10;
- D01 runtime launch/stop/input authority;
- a new Application schema family;
- remote Windows/macOS/iOS execution before the required remote authority exists;
- runtime readiness derived from package analysis, spawn acknowledgement, preparing state or UI presentation.

## Shipping gate

This record does not assert that D08 is merged or complete.

The exact commit containing this record and
`.github/workflows/d08-application-platform-expansion-proof.yml` is the D08 proof-artifact candidate. It may be
submitted only after:

1. that exact SHA passes the permanent exact-head workflow from a fresh checkout;
2. the retained artifact `d08-exact-head-${TARGET_SHA}` exists for that exact SHA;
3. the remote implementation branch is still exactly the proven SHA;
4. PR head/base/mergeability and repository rules are verified;
5. merge is constrained by the exact proven head SHA;
6. `main` is independently verified after merge with parents exactly:
   - D07 merge `d979e0ecfc6dba3b370206833ac13b3189d725e3`;
   - the frozen proven D08 candidate SHA.

Any movement after Freeze invalidates proof and requires affected Review → Freeze → Prove again.
