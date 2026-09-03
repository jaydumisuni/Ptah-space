# D08 — Application Platform Expansion Design

## Authority

Roadmap authority: `ptah-roadmap-` commit `98dc8c4e8639cda80510bee0625db34b4fdf9384`.
Accepted predecessor: D07 merge `d979e0ecfc6dba3b370206833ac13b3189d725e3`.

Canonical D08 milestone: **Application platform expansion**.

Roadmap deliverables:

- Linux native/packaged applications;
- Windows Node/VM applications;
- macOS Node applications;
- compatible iOS Simulator applications;
- remote application display.

Roadmap dependencies are D01 + C10 + Programme E foundations where remote Nodes are required. D08 therefore implements the application/runtime truth that current local foundations can mechanically prove and makes the remote-Node dependency explicit rather than manufacturing Windows, macOS, iOS Simulator or remote-display execution before Programme E supplies real remote Node placement, reservation, lease and fence authority.

## Frozen contract boundary

D08 reuses the existing Phase-0B application catalog `urn:ptah:schema-catalog:application:0.1.0`. It does not create a parallel Application identity family.

The primary frozen schemas are:

- `urn:ptah:schema:application:application:0.1.0`;
- `urn:ptah:schema:application:application-revision:0.1.0`;
- `urn:ptah:schema:application:application-installation:0.1.0`;
- `urn:ptah:schema:application:application-compatibility:0.1.0`;
- `urn:ptah:schema:application:application-session:0.1.0`;
- `urn:ptah:schema:application:application-window:0.1.0`;
- `urn:ptah:schema:application:application-window-observation:0.1.0`;
- `urn:ptah:schema:application:display-session:0.1.0`;
- `urn:ptah:schema:application:display-observation:0.1.0`;
- existing semantic-context/action/result schemas;
- existing shell projection/panel/session schemas.

The frozen compatibility contract already distinguishes operation, Provider revision/instance/generation, locality, Node/resource/capability evidence, compatibility decision, per-requirement results, conditions, evaluation time, validity and evidence. D08 preserves that structure instead of reducing compatibility to a boolean.

The frozen Application Session contract already binds Workspace, materialization, Application/Revision, installation, Provider generation, locality, Activity/Operation/Attempt, availability, privacy policy and current execution locality. D08 follows that authority shape.

## Predecessor reconciliation

### B05 — package and executable evidence

B05 is passive static analysis. It can identify PE, ELF, Mach-O, APK, AAB and DEX evidence, but it explicitly owns no loader, installer, emulator, launcher or runtime-success claim.

D08 may consume B05 type/package evidence as compatibility input. It must never reinterpret a B05 static observation as installation, launch, display readiness or execution success.

### A04/A05 — local execution

A04 owns Activity/Operation/Attempt identity and exact physical `AttemptContext`, including Node reference/generation, Provider reference/generation, workload generation and connection epoch.

A05 `native-process` owns mechanical process/PTY execution. Its `ProcessRecord` retains canonical process identity, Node and Provider generation, backend aliases such as OS PID, current process lifecycle and independent exit evidence.

D08 does not create another process launcher. Linux launch is admitted by D08, executed by A05, then promoted to an Application Session only after D08 validates the resulting A05 process evidence together with current application window/display evidence.

### C10 — Android Device/Application Session

C10 already owns Android installation, launch, stop, semantic context, input, evidence and cleanup under C08 Device Lease/Fence authority. Its `ApplicationSession` becomes `Visible` only after current-generation read-back proves process presence, foreground activity/context, a visible frame and semantic readiness.

D08 does not wrap, bypass or weaken those rules. It consumes an already verified C10 Device Session + Application Session pair and projects it into the broader D08 Application/Display model.

### D01 — Human Workspace shell

D01 owns a human-facing projection only. It already contains the structural `applications_devices` panel and deliberately reports missing backing runtime state instead of manufacturing it.

D08 adds a typed read-only application-platform projection for D01 to render. D01 still gains no direct launch authority, no new Grant authority and no ability to turn presentation state into runtime truth.

## Architecture

Add one composition crate: `crates/ptah-application-runtime`.

The crate owns provider-neutral D08 composition and validation only. Low-level process, Android transport/device, virtualization, simulator and remote-display Providers remain outside the crate.

The crate is divided into five focused boundaries:

1. platform/compatibility;
2. local Linux launch and verification;
3. Android composition;
4. application window/display evidence;
5. read-only shell projection.

No new database, schema family or network dependency is introduced.

## Platform model

D08 recognizes these roadmap platform classes:

- `LinuxNative`;
- `LinuxPackaged`;
- `Android`;
- `WindowsNode`;
- `WindowsVm`;
- `MacOsNode`;
- `IosSimulator`.

Platform class is compatibility/execution metadata. It is not Application identity. The same stable Application may have several revisions or compatibility evaluations across platforms.

### Current execution disposition

D08 uses an explicit mechanical disposition:

- `NodeLocalReady` — a current capable local Node/Provider can be named and evidenced;
- `DeviceLocalReady` — an existing owning Device runtime can be named and evidenced;
- `RequiresRemoteNode` — the roadmap platform needs a remote Node capability that current pre-Programme-E authority cannot provide;
- `Unsupported` — the current provider/platform cannot perform the requested operation;
- `Unknown` — evidence is insufficient or stale.

`RequiresRemoteNode` is intentionally not an Application Session state and not a successful frozen `application.compatibility` record. It is a D08-owned typed planning/limitation projection explaining why execution cannot yet be admitted. Once Programme E supplies a real Node and current snapshots, compatibility must be re-evaluated against that exact Node/Provider generation.

## Compatibility evaluation

### Node-local compatibility

A `NodeLocalCompatibility` candidate binds:

- exact Application Revision;
- exact requested frozen compatibility operation;
- Provider revision, instance and generation;
- Node ref and generation;
- Node capability snapshot ref;
- Node resource snapshot ref;
- optional display/input/semantic capability refs;
- exact requirement results;
- compatibility decision;
- condition refs when required;
- evaluation timestamp and valid-until timestamp;
- supporting evidence and limitations.

The accepted compatibility decision vocabulary matches the frozen contract:

- `compatible`;
- `compatible_with_conditions`;
- `compatible_for_partial_scope`;
- `incompatible`;
- `unsupported`;
- `missing_dependency`;
- `missing_capability`;
- `resource_or_policy_blocked`;
- `unknown`;
- `stale`.

Every requirement retains its own result: satisfied, satisfied-with-conditions, unsatisfied, unsupported, unknown or stale. A top-level compatible result cannot overrule an unsatisfied/unsupported/stale mandatory requirement.

Compatibility expires. A stale compatibility evaluation cannot admit a new launch.

### Remote-node requirement

For Windows Node/VM, macOS Node and iOS Simulator before Programme E, D08 produces `RemoteNodeRequirement` evidence containing:

- platform class;
- requested operation;
- required OS/virtualization/simulator class;
- required display/input/semantic capability classes where applicable;
- reason/dependency `Programme E`;
- supporting evidence and limitations.

It does not allocate a Node, create a Provider instance, invent a remote service, mint a lease/fence or create an Application Session.

For iOS Simulator the requirement explicitly includes a compatible macOS/Xcode Simulator Node class. D08 does not claim that an arbitrary Linux/Windows Node can host the simulator.

## Linux local application execution

Linux native and packaged applications are the D08 executable Node-local path.

### Launch admission

`LocalLaunchAdmission` binds:

- Workspace and exact Workspace revision reference;
- Application and exact Application Revision;
- installation reference;
- materialization ref and generation;
- exact A04 Activity/Operation/Attempt references;
- exact A04 `AttemptContext`;
- current compatible `NodeLocalCompatibility` for launch operation;
- privacy policy references;
- command/request evidence;
- request timestamp.

Admission fails before A05 execution when compatibility is stale/incompatible/blocked, Application Revision differs, Node/Provider generation differs, materialization identity/generation is missing, privacy/evidence is absent, or the requested compatibility operation does not cover the launch mode.

### Execution

D08 does not spawn the process itself. The caller uses the already accepted A05 native-process Provider under the admitted A04 Attempt.

An A05 spawn return or `ProcessState::Running` is command/process evidence only. It is not graphical Application readiness.

### Launch verification

`verify_local_launch` consumes the frozen admission plus:

- current A05 `ProcessRecord`;
- one current D08 Application Window observation;
- one current D08 Display observation/session readiness input for graphical launch;
- supporting read-back evidence and observation timestamp.

The process must match the exact admitted Node, Node generation, Provider instance/generation and Application launch Attempt context. Backend PID is retained only in A05 aliases.

For graphical launch, promotion requires:

- a live matching canonical process ref;
- a current canonical Application Window ref;
- a current window observation with `visible` or otherwise explicitly accepted visible state evidence;
- a current display surface/frame observation bound to the same Application Session candidate, Provider generation and execution locality;
- non-empty supporting evidence;
- non-stale observation time.

For headless launch, a display/window is not invented. Availability is `headless_only`, and readiness requires independent process/service post-condition evidence appropriate to the admitted operation. D08 does not claim graphical availability.

Only verification creates the D08 Application Session projection.

## Android composition

D08 accepts C10 as the Android runtime authority.

`project_android_session` consumes:

- current C10 `DeviceSession`;
- current C10 `ApplicationSession`;
- exact Workspace/Application/materialization/Activity/Operation/Attempt references needed by the frozen D08 projection;
- privacy policy/evidence refs where not already carried by C10.

Validation requires:

- `application.device_session_ref == device.session_ref`;
- matching Provider instance/generation and connection epoch;
- C10 Application Session state suitable for the requested projection;
- exact Application and Application Revision refs;
- retained C10 visible-frame and semantic-context evidence for full graphical/semantic availability.

D08 never calls Android install/launch/input/stop APIs as part of this projection. A stale or stopped C10 session cannot be promoted as a fresh fully-visible D08 session.

Backend Android process names, activity strings, package-manager IDs and accessibility node aliases remain evidence/aliases, not D08 identity.

## Application window model

D08 uses stable canonical `application.window` identity and versioned observations.

`ApplicationWindowObservation` binds:

- Application Window ref;
- Application Session ref;
- monotonic window generation;
- Provider generation;
- optional title claim;
- optional geometry with explicit coordinate space;
- state claims matching the frozen vocabulary;
- observed-at and valid-until;
- supporting evidence and limitations.

OS window handles, X11 IDs, Wayland object IDs, Win32 HWND values, macOS accessibility IDs and remote-desktop surface IDs are aliases/evidence only and cannot become `application.window` identity.

A stale/destroyed/foreign-generation window observation cannot prove launch readiness.

## Display Session and observation

D08 defines a provider-neutral Display Session projection matching the frozen contract:

- stable Display Session identity;
- Application Session ref;
- Provider instance/generation;
- locality (`node_local`, `device_local`, or future `remote_service` where legitimately backed);
- current Node/device/remote-service binding appropriate to locality;
- one or more stable surface refs;
- negotiated/display format facts;
- input capability list;
- privacy policy refs;
- current observations/evidence;
- lifecycle timestamps and limitations.

A Display Session is not created merely because a Provider says a remote-desktop or streaming command started. Readiness requires at least one current Display Observation/frame/surface read-back from the same Provider generation and execution locality.

### Pre-Programme-E remote display

The frozen contracts can describe remote display, but D08 must not claim a live remote display without a real remote execution backing.

Before Programme E:

- a remote-display compatibility request for Windows/macOS/iOS Simulator yields `RequiresRemoteNode` when the required remote Node is absent;
- no remote Application Session is created;
- no live remote Display Session is created;
- no synthetic `remote_service_ref` is minted as a substitute for a missing Node;
- shell projection shows the explicit dependency/blocker and supporting evidence.

After Programme E, a later milestone may bind these same frozen contracts to real remote Node/Provider/lease/fence state without changing D08 Application identity.

## Human Workspace integration

D08 extends D01 with a read-only `ApplicationPlatformView` collection derived from validated D08 projections.

Each view may expose:

- Application and exact revision refs;
- platform class;
- execution disposition;
- Application Session ref when one truly exists;
- locality;
- availability (`full`, `headless_only`, `display_only`, `semantic_only`, `partial`, `recovering`, `unavailable`, `unknown`);
- Display Session ref when one truly exists;
- evidence refs;
- limitations/blocker text.

The shell does not create or mutate these records. No D08 launch/stop/input control is added to D01 in this milestone. Runtime controls continue to require their owning Facility/Grant/lease/fence boundary.

An absent validated D08 session remains unavailable. A `RequiresRemoteNode` compatibility projection remains blocked and cannot render as a running Application card.

## Backend-neutral identity rules

The following are never canonical D08 identity:

- Linux/Windows/macOS process IDs;
- Win32 HWND or native window handles;
- Wayland/X11 backend object IDs;
- Android package-manager/process/activity aliases;
- VM hypervisor IDs;
- simulator UDIDs;
- RDP/VNC/WebRTC/session backend IDs;
- remote desktop surface IDs;
- filesystem paths, executable names or package names by themselves.

These may be retained as scoped aliases/evidence under the Provider generation that observed them.

## Failure model

D08 fails closed on:

- B05 static package evidence presented as execution proof;
- compatibility without exact Application Revision;
- compatibility without Provider generation/evidence;
- node-local compatibility without current Node generation/capability/resource snapshots;
- a top-level compatible decision that contradicts mandatory requirement results;
- expired/stale compatibility used for launch;
- Application Revision, Node, Provider or generation mismatch between compatibility, A04 Attempt and A05 read-back;
- missing materialization identity/generation for a Node-local session;
- A05 spawn/process-running acknowledgement presented as graphical readiness;
- backend PID/window/simulator/VM/display IDs used as canonical identity;
- stale/destroyed/foreign-generation window observation;
- Display Session created without privacy/surface evidence;
- display readiness without current frame/surface observation;
- C10 Application Session detached from its Device Session;
- stale C10 Provider generation/connection epoch;
- stopped/crashed Android session presented as newly visible;
- Windows/macOS/iOS Simulator execution attempted without Programme E remote Node authority;
- `remote_service_ref` synthesized to hide a missing remote Node;
- remote-display compatibility intent presented as a live Display Session;
- D01 UI state presented as Application runtime authority.

## Acceptance corpus

D08 freezes exactly 28 milestone cases:

1. D08 schema constants match the frozen Application/Compatibility/Session/Window/Display contract IDs;
2. node-local compatibility requires exact Application Revision, Provider generation, Node generation and capability/resource evidence;
3. stale/expired compatibility cannot admit new work;
4. `compatible_with_conditions` requires explicit condition evidence;
5. contradictory mandatory requirement results reject a top-level compatible decision;
6. Linux native graphical launch can become `NodeLocalReady` only from current local evidence;
7. Linux packaged graphical launch can become `NodeLocalReady` only from current local evidence;
8. Windows Node reports `RequiresRemoteNode` before Programme E remote authority exists;
9. Windows VM reports `RequiresRemoteNode` and retains virtualization requirements;
10. macOS Node reports `RequiresRemoteNode` before Programme E remote authority exists;
11. iOS Simulator reports `RequiresRemoteNode` with a compatible macOS/simulator requirement;
12. `RequiresRemoteNode` cannot create an Application Session;
13. local launch admission binds exact Workspace/materialization/Application/A04 Attempt/current compatibility;
14. incompatible/stale/foreign-revision compatibility is rejected before A05 execution;
15. A05 spawn/`Running` evidence without independent graphical window/display evidence is not Application readiness;
16. A05 Node/Provider generation mismatch rejects local launch verification;
17. current process + visible window + current display observation promotes one stable local Application Session;
18. PID/window-handle aliases remain non-canonical evidence;
19. verified C10 Device/Application Session pair projects to D08 Android full availability;
20. C10 Device Session/Application Session mismatch is rejected;
21. stale C10 Provider generation or connection epoch is rejected;
22. D08 Android projection does not perform install/launch/input/stop and preserves C10 authority;
23. Display Session requires exact Application Session, Provider generation, surface and privacy evidence;
24. stale/foreign Display Observation cannot establish readiness;
25. remote-display intent without a live remote execution backing remains `RequiresRemoteNode` and creates no Display Session;
26. D01 projects a validated local/Android Application Session without gaining launch authority;
27. D01 projects remote-node blockers without manufacturing Application/Display sessions;
28. absent/stale D08 backing remains unavailable and presentation state cannot authorize runtime work.

Targeted B05, A04, A05, C10 and D01 regressions plus the complete locked workspace must remain green.

## Proof and shipping

D08 follows the established milestone lane:

1. approved design + implementation plan;
2. isolated D08 branch from exact D07 merge;
3. TDD implementation with exactly 28 `d08_acceptance` cases;
4. strict formatting and Clippy with warnings denied for D08-touched packages;
5. frozen application-contract ID/hash audit;
6. `Cargo.lock` audit showing only the expected new workspace path-package stanza unless an independently justified existing-package dependency edge is required;
7. targeted B05/A04/A05/C10/D01 regressions;
8. complete `cargo test --workspace --locked`;
9. no TODO/FIXME/`todo!`/`unimplemented!`/unsafe escape in D08 source;
10. permanent D08 exact-head GitHub workflow;
11. immutable exact-head proof manifest/artifact for the frozen candidate SHA;
12. PR head/base/mergeability verification;
13. merge guarded by the exact proven head SHA;
14. independent `main` merge-parent verification.

Any source movement after Freeze invalidates the proof and requires affected Review → Freeze → Prove again.

## Explicit deferrals

D08 does not implement Programme E remote Node placement/reservation/lease/fence machinery, a Windows agent, a macOS agent, a hypervisor/VM Provider, Xcode Simulator Provider, RDP/VNC/WebRTC transport, cross-Node synchronization, checkpoint migration or remote execution scheduling.

D08 does not install applications automatically, infer compatibility from filenames alone, bypass C10 Android authority, turn D01 into a launcher, add a new schema family, or claim remote Windows/macOS/iOS execution before its roadmap dependency exists.
