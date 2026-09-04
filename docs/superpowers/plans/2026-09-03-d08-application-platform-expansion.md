# D08 Application Platform Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement D08 as a provider-neutral Application/Window/Display composition layer that can prove local Linux and already-verified Android application sessions now, while explicitly blocking Windows/macOS/iOS Simulator/remote-display execution until Programme E supplies real remote Node authority.

**Architecture:** Add `ptah-application-runtime`. Reuse frozen WP09 Application contracts, A04 Attempt context, A05 native-process read-back, C10 Android Device/Application Session authority and D01 shell projection. Local Application/Window/Display identities begin in their frozen `preparing`/`created` states and are promoted only by current independent read-back. Remote platforms produce typed `RequiresRemoteNode` evidence only; no synthetic Node, Provider, lease, fence, remote service or runtime session is created.

**Tech Stack:** Rust 2024 workspace, `serde`, `thiserror`, `ptah-identifiers`, `ptah-provider-api`, `ptah-contracts`, `ptah-activity-runtime`, A05 `native-process`, `ptah-android-runtime`, existing `ptah-control` shell.

**Spec:** `docs/superpowers/specs/2026-09-03-d08-application-platform-expansion-design.md`

## Global Constraints

- Accepted predecessor is exact D07 merge `d979e0ecfc6dba3b370206833ac13b3189d725e3`.
- Roadmap authority is `ptah-roadmap-` `98dc8c4e8639cda80510bee0625db34b4fdf9384`.
- No schema, state-machine, migration or generated-contract mutation.
- No new external dependency/version/source.
- No D08 `#[allow(...)]`/`#[expect(...)]` suppression.
- No process/window/VM/simulator/remote-desktop backend ID may become canonical Ptah identity.
- B05 static analysis is compatibility evidence only, never execution proof.
- A05 process spawn/`Running` is not graphical Application readiness.
- C10 remains the Android install/launch/input/stop/Device Lease/Fence authority.
- D01 remains a read-only projection and gains no launch/stop/input authority.
- Application Session lifecycle follows frozen `preparing -> running|degraded|...`; Display Session follows `preparing -> streaming|degraded|...`; Window follows `created -> visible|...`.
- Windows Node/VM, macOS Node, iOS Simulator and their live remote display fail closed as `RequiresRemoteNode` until Programme E authority exists.
- Exactly 28 milestone cases are frozen: 25 runtime cases in `d08_acceptance` plus 3 D01 integration cases in `d08_application_projection`; proof counts the aggregate exactly.

---

### Task 1: Scaffold D08 and Freeze Compatibility / Remote-Node Truth — Cases 1–12

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/ptah-application-runtime/Cargo.toml`
- Create: `crates/ptah-application-runtime/src/lib.rs`
- Create: `crates/ptah-application-runtime/src/error.rs`
- Create: `crates/ptah-application-runtime/src/compatibility.rs`
- Create: `crates/ptah-application-runtime/tests/d08_acceptance.rs`

**Crate dependencies:**

```toml
[dependencies]
native-process = { path = "../../adapters/native-process", version = "=0.0.0-phase0c" }
ptah-activity-runtime = { path = "../ptah-activity-runtime", version = "=0.0.0-phase0c" }
ptah-android-runtime = { path = "../ptah-android-runtime", version = "=0.0.0-phase0c" }
ptah-contracts = { path = "../ptah-contracts", version = "=0.0.0-phase0c" }
ptah-identifiers = { path = "../ptah-identifiers", version = "=0.0.0-phase0c" }
ptah-provider-api = { path = "../ptah-provider-api", version = "=0.0.0-phase0c" }
serde = { workspace = true }
thiserror = { workspace = true }
```

**Public constants:**

```rust
pub const APPLICATION_SCHEMA_ID: &str = "urn:ptah:schema:application:application:0.1.0";
pub const APPLICATION_REVISION_SCHEMA_ID: &str = "urn:ptah:schema:application:application-revision:0.1.0";
pub const APPLICATION_COMPATIBILITY_SCHEMA_ID: &str = "urn:ptah:schema:application:application-compatibility:0.1.0";
pub const APPLICATION_SESSION_SCHEMA_ID: &str = "urn:ptah:schema:application:application-session:0.1.0";
pub const APPLICATION_WINDOW_SCHEMA_ID: &str = "urn:ptah:schema:application:application-window:0.1.0";
pub const APPLICATION_WINDOW_OBSERVATION_SCHEMA_ID: &str = "urn:ptah:schema:application:application-window-observation:0.1.0";
pub const DISPLAY_SESSION_SCHEMA_ID: &str = "urn:ptah:schema:application:display-session:0.1.0";
pub const DISPLAY_OBSERVATION_SCHEMA_ID: &str = "urn:ptah:schema:application:display-observation:0.1.0";
pub const APPLICATION_SESSION_LIFECYCLE: &str = "application.session.lifecycle";
pub const APPLICATION_WINDOW_LIFECYCLE: &str = "application.window.lifecycle";
pub const DISPLAY_SESSION_LIFECYCLE: &str = "application.display_session.lifecycle";
```

**Compatibility interfaces:**

```rust
pub enum PlatformClass {
    LinuxNative,
    LinuxPackaged,
    Android,
    WindowsNode,
    WindowsVm,
    MacOsNode,
    IosSimulator,
}

pub enum ApplicationOperation {
    Install,
    Upgrade,
    Repair,
    Uninstall,
    LaunchHeadless,
    LaunchGraphical,
    RemoteDisplay,
    SemanticInspection,
    SemanticControl,
    VisualControl,
    Checkpoint,
    Restore,
}

pub enum CompatibilityDecision {
    Compatible,
    CompatibleWithConditions,
    CompatibleForPartialScope,
    Incompatible,
    Unsupported,
    MissingDependency,
    MissingCapability,
    ResourceOrPolicyBlocked,
    Unknown,
    Stale,
}

pub enum RequirementOutcome {
    Satisfied,
    SatisfiedWithConditions,
    Unsatisfied,
    Unsupported,
    Unknown,
    Stale,
}

pub struct CompatibilityRequirement {
    pub key: String,
    pub mandatory: bool,
    pub outcome: RequirementOutcome,
    pub condition_refs: Vec<EntityRef>,
    pub evidence_refs: Vec<EntityRef>,
    pub reason: Option<String>,
}

pub struct NodeLocalCompatibility {
    pub compatibility_ref: EntityRef,
    pub application_revision_ref: EntityRef,
    pub operation: ApplicationOperation,
    pub provider_revision_ref: EntityRef,
    pub provider_instance_ref: EntityRef,
    pub provider_generation: ProviderGeneration,
    pub node_ref: EntityRef,
    pub node_generation: u64,
    pub node_capability_snapshot_ref: EntityRef,
    pub node_resource_snapshot_ref: EntityRef,
    pub requirements: Vec<CompatibilityRequirement>,
    pub decision: CompatibilityDecision,
    pub condition_refs: Vec<EntityRef>,
    pub evaluated_at: String,
    pub valid_until: String,
    pub evidence_refs: Vec<EntityRef>,
    pub limitations: Vec<String>,
}

pub struct RemoteNodeRequirement {
    pub platform: PlatformClass,
    pub operation: ApplicationOperation,
    pub required_execution_class: String,
    pub required_capabilities: Vec<String>,
    pub roadmap_dependency: String,
    pub evidence_refs: Vec<EntityRef>,
    pub limitations: Vec<String>,
}

pub enum ExecutionDisposition {
    NodeLocalReady(NodeLocalCompatibility),
    DeviceLocalReady,
    RequiresRemoteNode(RemoteNodeRequirement),
    Unsupported,
    Unknown,
}
```

`NodeLocalCompatibility::validate_at(now: &str)` uses a private strict UTC-`Z` parser modeled on the already accepted A06 `parse_utc_datetime`; no date/time dependency is added. Invalid/non-UTC timestamps fail closed.

`remote_node_requirement(platform, operation, evidence_refs)` accepts only `WindowsNode`, `WindowsVm`, `MacOsNode`, `IosSimulator` and emits exact Programme-E blocker text. `IosSimulator` requires capability strings for `macos`, `xcode_simulator`, and graphical display.

- [ ] **Step 1: Add failing cases 1–12.**

Cases prove frozen contract/lifecycle lookup through `ptah_contracts::generated`, exact local compatibility evidence/freshness/conditions/mandatory requirements, Linux local dispositions and all four remote-node blockers including iOS/macOS dependency.

- [ ] **Step 2: Run RED.**

Run:
`cargo test -p ptah-application-runtime --test d08_acceptance --locked`

Expected: package/API absent.

- [ ] **Step 3: Implement compatibility and remote-node truth.**

Use `ptah_contracts::generated::schema_by_id` / `state_machine` only for metadata audit. Do not treat `ptah-contracts` as runtime authorization.

- [ ] **Step 4: Run GREEN + strict lint.**

Run:
`cargo test -p ptah-application-runtime --test d08_acceptance --locked`
`cargo clippy -p ptah-application-runtime --all-targets --locked -- -D warnings -W clippy::pedantic`

At this point the acceptance target lists exactly 12 tests.

- [ ] **Step 5: Audit lock delta and commit.**

Expected lock change at this stage: one new path package `ptah-application-runtime 0.0.0-phase0c`; no existing external package/version/source changes.

Commit: `feat(d08): add application compatibility boundary`

---

### Task 2: Local Linux Preparing → Verified Application / Window / Display — Cases 13–18 and 23–24

**Files:**
- Create: `crates/ptah-application-runtime/src/session.rs`
- Create: `crates/ptah-application-runtime/src/window.rs`
- Create: `crates/ptah-application-runtime/src/display.rs`
- Modify: `crates/ptah-application-runtime/src/error.rs`
- Modify: `crates/ptah-application-runtime/src/lib.rs`
- Modify: `crates/ptah-application-runtime/tests/d08_acceptance.rs`

**Lifecycle interfaces:**

```rust
pub enum ApplicationSessionLifecycle {
    Preparing,
    Running,
    Degraded,
    Detached,
    Checkpointing,
    Recovering,
    Stopped,
    Failed,
    Uncertain,
}

pub enum ApplicationAvailability {
    Full,
    HeadlessOnly,
    DisplayOnly,
    SemanticOnly,
    Partial,
    Recovering,
    Unavailable,
    Unknown,
}

pub enum LaunchMode {
    Headless,
    Graphical,
}

pub struct LocalLaunchRequest<'a> {
    pub workspace_ref: EntityRef,
    pub workspace_revision_ref: EntityRef,
    pub materialization_ref: EntityRef,
    pub materialization_generation: u64,
    pub application_ref: EntityRef,
    pub application_revision_ref: EntityRef,
    pub installation_ref: EntityRef,
    pub activity_ref: EntityRef,
    pub operation_ref: EntityRef,
    pub attempt_ref: EntityRef,
    pub attempt_context: &'a AttemptContext,
    pub privacy_policy_refs: Vec<EntityRef>,
    pub command_evidence_refs: Vec<EntityRef>,
    pub requested_at: String,
    pub mode: LaunchMode,
}

pub struct ApplicationSessionProjection {
    pub session_ref: EntityRef,
    pub workspace_ref: EntityRef,
    pub workspace_revision_ref: EntityRef,
    pub materialization_ref: EntityRef,
    pub materialization_generation: u64,
    pub application_ref: EntityRef,
    pub application_revision_ref: EntityRef,
    pub installation_ref: EntityRef,
    pub compatibility_ref: Option<EntityRef>,
    pub provider_instance_ref: EntityRef,
    pub provider_generation: ProviderGeneration,
    pub locality: SessionLocality,
    pub node_ref: Option<EntityRef>,
    pub node_generation: Option<u64>,
    pub connection_epoch: Option<u64>,
    pub device_session_ref: Option<EntityRef>,
    pub activity_ref: EntityRef,
    pub operation_ref: EntityRef,
    pub attempt_ref: EntityRef,
    pub process_refs: Vec<EntityRef>,
    pub window_refs: Vec<EntityRef>,
    pub display_session_refs: Vec<EntityRef>,
    pub semantic_context_refs: Vec<EntityRef>,
    pub availability: ApplicationAvailability,
    pub privacy_policy_refs: Vec<EntityRef>,
    pub lifecycle: ApplicationSessionLifecycle,
    pub evidence_refs: Vec<EntityRef>,
    pub limitations: Vec<String>,
    pub started_at: String,
}

pub fn prepare_local_application_session(
    request: LocalLaunchRequest<'_>,
    compatibility: &NodeLocalCompatibility,
    now: &str,
) -> Result<ApplicationSessionProjection, D08Error>;
```

Preparation requires `materialization_generation > 0`, matching Application Revision, launch operation, Node/Provider generation, current compatibility and non-empty privacy/evidence. Result is always one newly minted stable `application.session` in `Preparing` + `Unavailable`; no process/window/display refs exist yet.

**Window interfaces:**

```rust
pub enum WindowLifecycle { Created, Visible, Hidden, Degraded, Replaced, Closed, Unknown }
pub enum WindowStateClaim { Visible, Hidden, Minimized, Maximized, Fullscreen, Focused, Active, Occluded, Offscreen, Destroyed, Unknown }

pub struct ApplicationWindowProjection {
    pub window_ref: EntityRef,
    pub application_session_ref: EntityRef,
    pub provider_generation: ProviderGeneration,
    pub generation: u64,
    pub lifecycle: WindowLifecycle,
    pub aliases: Vec<EndpointAlias>,
    pub evidence_refs: Vec<EntityRef>,
}

pub struct WindowObservation {
    pub provider_generation: ProviderGeneration,
    pub state_claims: Vec<WindowStateClaim>,
    pub evidence_refs: Vec<EntityRef>,
    pub observed_at: String,
    pub valid_until: String,
}

pub fn create_application_window(
    session: &ApplicationSessionProjection,
    aliases: Vec<EndpointAlias>,
    evidence_refs: Vec<EntityRef>,
) -> Result<ApplicationWindowProjection, D08Error>;

pub fn apply_window_observation(
    window: ApplicationWindowProjection,
    observation: WindowObservation,
    now: &str,
) -> Result<ApplicationWindowProjection, D08Error>;
```

Window aliases never determine `window_ref`. Only a current same-generation `Visible` Window may satisfy graphical readiness.

**Display interfaces:**

```rust
pub enum DisplayLifecycle { Preparing, Streaming, Degraded, Detached, Recovering, Closed, Failed }
pub enum InputCapability { None, ObserveOnly, Keyboard, Pointer, Touch, Clipboard, Semantic, OtherRegistered }

pub struct DisplaySessionProjection {
    pub display_session_ref: EntityRef,
    pub application_session_ref: EntityRef,
    pub provider_instance_ref: EntityRef,
    pub provider_generation: ProviderGeneration,
    pub locality: SessionLocality,
    pub node_ref: Option<EntityRef>,
    pub node_generation: Option<u64>,
    pub connection_epoch: Option<u64>,
    pub device_session_ref: Option<EntityRef>,
    pub surface_refs: Vec<EntityRef>,
    pub input_capabilities: Vec<InputCapability>,
    pub privacy_policy_refs: Vec<EntityRef>,
    pub lifecycle: DisplayLifecycle,
    pub observation_refs: Vec<EntityRef>,
    pub evidence_refs: Vec<EntityRef>,
    pub limitations: Vec<String>,
    pub started_at: String,
}

pub struct DisplayObservation {
    pub observation_ref: EntityRef,
    pub provider_generation: ProviderGeneration,
    pub surface_ref: EntityRef,
    pub frame_evidence_ref: EntityRef,
    pub evidence_refs: Vec<EntityRef>,
    pub observed_at: String,
    pub valid_until: String,
}

pub fn prepare_display_session(...) -> Result<DisplaySessionProjection, D08Error>;
pub fn apply_display_observation(...) -> Result<DisplaySessionProjection, D08Error>;
```

`prepare_display_session` requires an existing `Preparing|Running|Degraded` Application Session, exact Provider/locality binding, one or more surfaces and privacy refs. It returns `Preparing`. `apply_display_observation` requires exact Provider generation, one of the declared surfaces, fresh frame/evidence and promotes to `Streaming`.

**Verification interface:**

```rust
pub struct LocalReadBack<'a> {
    pub process: &'a native_process::ProcessRecord,
    pub window: Option<&'a ApplicationWindowProjection>,
    pub display: Option<&'a DisplaySessionProjection>,
    pub readiness_evidence_refs: Vec<EntityRef>,
    pub observed_at: String,
}

pub fn verify_local_application_session(
    preparing: ApplicationSessionProjection,
    read_back: LocalReadBack<'_>,
) -> Result<ApplicationSessionProjection, D08Error>;
```

Graphical: require A05 `Running`, exact Node/Node generation/Provider instance/generation, `Visible` same-session Window, `Streaming` same-session Display and evidence. Promote same `session_ref` to `Running + Full`.

Headless: require A05 `Running`, exact Node/Provider and independent readiness evidence; Window/Display must be absent. Promote same `session_ref` to `Degraded + HeadlessOnly`.

- [ ] **Step 1: Add failing cases 13–18 and 23–24.**

The runtime target now contains 20 tests. Case 15 specifically proves a real A05 `ProcessRecord` in `Running` leaves graphical session `Preparing` when Window/Display proof is absent. Cases 18/23 prove aliases/surfaces are evidence but not stable identity. Case 24 proves stale/foreign Display Observation cannot stream.

- [ ] **Step 2: Run RED.**

Run:
`cargo test -p ptah-application-runtime --test d08_acceptance --locked`

- [ ] **Step 3: Implement minimal lifecycle validation.**

No A05 launch wrapper. No OS/window/display syscalls. No remote transport. Only composition/validation over supplied current evidence.

- [ ] **Step 4: Run GREEN + strict lint.**

Run:
`cargo test -p ptah-application-runtime --test d08_acceptance --locked`
`cargo clippy -p ptah-application-runtime --all-targets --locked -- -D warnings -W clippy::pedantic`

- [ ] **Step 5: Commit.**

Commit: `feat(d08): verify local application and display lifecycle`

---

### Task 3: Compose C10 Android Without Duplicating Authority — Cases 19–22

**Files:**
- Create: `crates/ptah-application-runtime/src/android.rs`
- Modify: `crates/ptah-application-runtime/src/error.rs`
- Modify: `crates/ptah-application-runtime/src/lib.rs`
- Modify: `crates/ptah-application-runtime/tests/d08_acceptance.rs`

**Interface:**

```rust
pub struct AndroidProjectionRequest<'a> {
    pub device_session: &'a ptah_android_runtime::DeviceSession,
    pub application_session: &'a ptah_android_runtime::ApplicationSession,
    pub workspace_ref: EntityRef,
    pub workspace_revision_ref: EntityRef,
    pub materialization_ref: EntityRef,
    pub materialization_generation: u64,
    pub activity_ref: EntityRef,
    pub operation_ref: EntityRef,
    pub attempt_ref: EntityRef,
}

pub fn project_android_application_session(
    request: AndroidProjectionRequest<'_>,
) -> Result<ApplicationSessionProjection, D08Error>;
```

Validation:

- exact Device Session ref match;
- exact Provider instance/generation/connection epoch match;
- C10 state `Visible` for D08 full availability;
- non-empty C10 visible-frame, semantic-context and supporting evidence;
- exact application/application-revision refs carried unchanged;
- C10 `session_ref` becomes the D08 Application Session ref; no alternate Android runtime session identity is minted;
- locality `DeviceLocal`, availability `Full`, lifecycle `Running`;
- D08 never calls C10 mutation APIs.

- [ ] **Step 1: Add failing cases 19–22.**

Build Android fixtures through the public C10 admission/verification APIs, not by manually claiming a successful session. Prove mismatched Device Session and stale Provider generation/connection epoch fail.

- [ ] **Step 2: Run RED.**

Run: `cargo test -p ptah-application-runtime --test d08_acceptance --locked`

- [ ] **Step 3: Implement read-only Android projection.**

Do not add C10 API changes.

- [ ] **Step 4: Run GREEN and count runtime cases.**

Run:
`cargo test -p ptah-application-runtime --test d08_acceptance --locked`
`cargo test -p ptah-android-runtime --test c10 --locked`

Expected runtime acceptance count after Task 3: 24 tests.

- [ ] **Step 5: Commit.**

Commit: `feat(d08): compose verified android application sessions`

---

### Task 4: Remote-Display Gate + D01 Read-Only Application Projection — Cases 25–28

**Files:**
- Modify: `crates/ptah-application-runtime/src/display.rs`
- Modify: `crates/ptah-application-runtime/tests/d08_acceptance.rs`
- Modify: `services/ptah-control/Cargo.toml`
- Modify: `services/ptah-control/src/lib.rs`
- Create: `services/ptah-control/tests/d08_application_projection.rs`

**Runtime remote-display interface:**

```rust
pub fn require_remote_display(
    requirement: &RemoteNodeRequirement,
) -> Result<RemoteNodeRequirement, D08Error>;
```

This function is deliberately non-executing. It rejects any attempt to convert a `RemoteNodeRequirement` into `ApplicationSessionProjection` or `DisplaySessionProjection`; case 25 proves no synthetic remote service/session path exists.

**D01 projection:**

Add to `WorkspaceShellV2Projection`:

```rust
pub applications: Vec<ApplicationPlatformView>,
```

Add:

```rust
pub struct ApplicationPlatformView {
    pub application_id: String,
    pub application_revision: String,
    pub platform: String,
    pub disposition: String,
    pub session_id: Option<String>,
    pub lifecycle: Option<String>,
    pub locality: Option<String>,
    pub availability: String,
    pub display_session_id: Option<String>,
    pub display_lifecycle: Option<String>,
    pub evidence: Vec<String>,
    pub limitations: Vec<String>,
}

pub fn project_application_platform_views(
    shell: &mut WorkspaceShellV2Projection,
    snapshots: &[ptah_application_runtime::ApplicationPlatformSnapshot],
);
```

`ApplicationPlatformSnapshot` is a D08 enum with two allowed source forms:

```rust
pub enum ApplicationPlatformSnapshot {
    Session { platform: PlatformClass, session: ApplicationSessionProjection, display: Option<DisplaySessionProjection> },
    RemoteRequirement { application_ref: EntityRef, application_revision_ref: EntityRef, requirement: RemoteNodeRequirement },
}
```

Rules:

- ordinary `build_workspace_shell_v2_projection` initializes `applications = []`; no backing means unavailable/not supplied, not inferred;
- a `Preparing` session renders preparing/unavailable;
- `Running + Full` renders full;
- `Degraded + HeadlessOnly` renders headless-only;
- RemoteRequirement renders `requires_remote_node`, no session/display IDs;
- no new `ControlKind` is added;
- D01 authority stamp stays unchanged.

`ptah-control` gains one normal path dependency on `ptah-application-runtime`. This is the only justified modification to an existing Cargo.lock package dependency list.

- [ ] **Step 1: Add runtime case 25 and shell cases 26–28 as RED.**

Runtime target reaches 25 tests. Shell target has exactly 3 tests:

1. validated preparing/running/degraded local or Android projection renders without launch authority;
2. RemoteRequirement renders blocker with no Application/Display session IDs;
3. absent/stale backing remains unavailable and shell projection does not alter runtime authority or add controls.

- [ ] **Step 2: Run RED.**

Run:
`cargo test -p ptah-application-runtime --test d08_acceptance --locked`
`cargo test -p ptah-control --test d08_application_projection --locked`

- [ ] **Step 3: Implement projection only.**

Do not modify A14 `HumanSnapshot` canonical input. D08 data is an explicit supplemental validated projection attached after `build_workspace_shell_v2_projection`.

- [ ] **Step 4: Run GREEN + regress D01.**

Run:
`cargo test -p ptah-application-runtime --test d08_acceptance --locked`
`cargo test -p ptah-control --test d08_application_projection --locked`
`cargo test -p ptah-control --test d01_acceptance --locked`
`cargo clippy -p ptah-application-runtime -p ptah-control --all-targets --locked -- -D warnings -W clippy::pedantic`

Count:

```bash
runtime_count="$(cargo test -p ptah-application-runtime --test d08_acceptance --locked -- --list 2>/dev/null | grep -c ': test$')"
shell_count="$(cargo test -p ptah-control --test d08_application_projection --locked -- --list 2>/dev/null | grep -c ': test$')"
test "$runtime_count" -eq 25
test "$shell_count" -eq 3
test "$((runtime_count + shell_count))" -eq 28
```

- [ ] **Step 5: Audit Cargo.lock and commit.**

Allowed final lock delta from D07:

- add path package `ptah-application-runtime 0.0.0-phase0c`;
- existing `ptah-control 0.0.0-phase0c` dependency array gains exactly `ptah-application-runtime`;
- no package removal;
- no external version/source/checksum movement.

Commit: `feat(d08): project application platform into human shell`

---

### Task 5: Review, Durable Milestone Record and Permanent Exact-Head Proof

**Files:**
- Create: `D08_APPLICATION_PLATFORM_EXPANSION.md`
- Create: `.github/workflows/d08-application-platform-expansion-proof.yml`
- Modify if self-review requires: D08 source/tests/spec/plan only

**Durable record must state:**

- accepted predecessor D07 merge;
- exact roadmap authority;
- local Linux two-phase preparing/read-back boundary;
- C10 Android composition boundary;
- frozen Application/Window/Display lifecycle mapping;
- exact remote-node deferral for Windows/macOS/iOS Simulator/live remote display;
- 25+3 = 28 acceptance corpus;
- exact-head proof requirements and merge rule.

**Workflow name:** `D08 Application Platform Expansion Exact Head Proof`.

**Workflow triggers:** push to implementation branch, PR to `main`, workflow_dispatch.

**Exact-head gates:**

1. checkout exact candidate SHA;
2. pin Rust 1.97.1;
3. prove `origin/main == d979e0ecfc6dba3b370206833ac13b3189d725e3` for the frozen proof run and that the branch descends linearly from it;
4. prove approved D08 surface only;
5. forbid schema/migration/generated-contract changes;
6. audit Cargo.lock exact delta described above;
7. audit the eight frozen D08 schema IDs and three lifecycle names through `ptah-contracts` generated bindings;
8. forbid D08 lint suppressions, unsafe, TODO/FIXME, `todo!`, `unimplemented!`;
9. static scan for remote execution/transport implementation surfaces in `ptah-application-runtime` (no socket/RDP/VNC/WebRTC/hypervisor/simulator-launch process code);
10. `cargo fmt --all -- --check`;
11. strict Clippy for `ptah-application-runtime` and `ptah-control`;
12. runtime acceptance count exactly 25;
13. shell integration count exactly 3;
14. aggregate D08 cases exactly 28;
15. `cargo test -p ptah-android-runtime --test c10 --locked`;
16. `cargo test -p native-process --locked`;
17. `cargo test -p ptah-activity-runtime --locked`;
18. B05 package regression: `cargo test -p ptah-archive-decomposition --locked`;
19. D01 regression: `cargo test -p ptah-control --test d01_acceptance --locked`;
20. complete `cargo test --workspace --locked`;
21. clean worktree;
22. immutable proof manifest with exact SHA, predecessor, case counts, schema/lifecycle audit and SHA-256 for Cargo/spec/plan/durable record/workflow;
23. retained artifact `d08-exact-head-${TARGET_SHA}`.

- [ ] **Step 1: Review final diff against spec.**

Check every changed path, public API, error, lifecycle transition and deferral. Remove accidental breadth before Freeze.

- [ ] **Step 2: Run local/repository proof commands where available.**

All targeted and workspace commands above must pass on the candidate before it is called reviewed.

- [ ] **Step 3: Create durable record + permanent workflow and commit.**

Commit: `proof(d08): add permanent exact-head application proof`

- [ ] **Step 4: Freeze candidate SHA.**

Record exact branch head. No source movement after this point without invalidating proof.

- [ ] **Step 5: Run permanent workflow for exact frozen SHA.**

Require all steps green and retained artifact present.

- [ ] **Step 6: Open/update PR against `main`.**

Verify PR head is exactly the proven SHA, base is `main`, mergeable state is clean, and repository rules do not require additional unresolved checks.

- [ ] **Step 7: Merge with expected-head guard.**

Merge only if GitHub still reports the exact proven head SHA. Any movement aborts merge and re-enters Review → Freeze → Prove.

- [ ] **Step 8: Independently verify `main`.**

Require merge commit parents to be exactly:

1. D07 merge `d979e0ecfc6dba3b370206833ac13b3189d725e3`;
2. frozen proven D08 candidate SHA.

Only then mark D08 COMPLETE and recover D09 authority.
