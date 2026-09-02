# D02 AI Project Workspace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `ptah.workspace.ai_project.v1` and the D02-relevant `ptah.workspace.operations.v2` mechanics operative without adding Ptah semantic authority or reopening frozen contracts.

**Architecture:** Add a new `ptah-ai-workspace` composition crate over A03/A04/A06/A07/A13/B06/B07. The crate exposes exact authority-gated retrieval, non-authoritative Session/Artifact/search projections, caller-record encoding, exact admitted-input envelopes, and thin Hunter/Sergeant caller adapters. Existing canonical stores remain authoritative; D02 introduces no new canonical entity family, schema, migration, context compiler, reviewer, approver, scheduler, or truth-ranking subsystem.

**Tech Stack:** Rust 1.97.1, existing Ptah workspace crates, `serde`, `serde_json`, `thiserror`, existing exact-head GitHub Actions conventions.

**Spec:** `docs/superpowers/specs/2026-09-02-d02-ai-project-workspace-design.md`

## Global Constraints

- Base authority is `Ptah-space` D01 merge `8be77210eee2b62eed753151287935bdebc369ae` plus the approved design commit.
- Profile IDs are exactly `ptah.workspace.ai_project.v1` and `ptah.workspace.operations.v2`.
- No WP01–WP14 schema or lifecycle change.
- No new Core entity family and no ledger migration.
- No Ptah context selection, source ranking, Provider semantic choice, approval, review verdict, promotion, result acceptance, or next-action selection.
- Provider permission, Ptah Grant, and caller approval remain separate.
- B07 index/search output is derived evidence and never canonical source truth.
- External reference is never silently represented as materialized local bytes.
- Scheduled/admitted work sees only exact caller-declared input references and configured Grants.
- Hunter and Sergeant remain caller adapters; Sergeant output never becomes a Ptah verdict.
- Historical Phase-0C candidate files retain their non-operative historical status and are not rewritten to authorize runtime.
- TDD is mandatory: production behavior is written only after a test has failed for the intended missing behavior.

---

## File Map

Create:

- `crates/ptah-ai-workspace/Cargo.toml` — crate dependencies and explicit D02 acceptance target.
- `crates/ptah-ai-workspace/src/lib.rs` — public exports and shared `D02Error`.
- `crates/ptah-ai-workspace/src/profile.rs` — immutable runtime profile descriptors.
- `crates/ptah-ai-workspace/src/retrieval.rs` — exact A03/A06 authority-gated canonical retrieval.
- `crates/ptah-ai-workspace/src/sessions.rs` — parallel live Session projection and B06 archived-session lookup.
- `crates/ptah-ai-workspace/src/library.rs` — non-authoritative Artifact Library projection.
- `crates/ptah-ai-workspace/src/caller_records.rs` — caller-owned labels plus exact opaque payload-byte container.
- `crates/ptah-ai-workspace/src/activity_inputs.rs` — exact admitted-input/Grant envelope.
- `crates/ptah-ai-workspace/src/search.rs` — narrow B07 adapter with D02-owned public types.
- `crates/ptah-ai-workspace/src/adapters/mod.rs` — adapter exports.
- `crates/ptah-ai-workspace/src/adapters/hunter.rs` — Hunter caller adapter.
- `crates/ptah-ai-workspace/src/adapters/sergeant.rs` — independent Sergeant caller adapter.
- `crates/ptah-ai-workspace/tests/d02_acceptance.rs` — D02 acceptance corpus.
- `.github/workflows/d02-ai-project-workspace-proof.yml` — exact-head proof lane.
- `D02_AI_PROJECT_WORKSPACE.md` — implementation/proof record.

Modify:

- `Cargo.toml` — add `crates/ptah-ai-workspace` workspace member only.

Do not modify canonical migrations, generated frozen contracts, A06/A07 schemas, or historical candidate status fields.

---

### Task 1: Runtime Profile Descriptors and Crate Boundary

**Files:**
- Create: `crates/ptah-ai-workspace/Cargo.toml`
- Create: `crates/ptah-ai-workspace/src/lib.rs`
- Create: `crates/ptah-ai-workspace/src/profile.rs`
- Create: `crates/ptah-ai-workspace/tests/d02_acceptance.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Produces: `AI_PROJECT_PROFILE_ID`, `OPERATIONS_PROFILE_ID`, `ai_project_profile()`, `operations_profile()`, `RuntimeProfileDescriptor`, `OperationsCompatibilityDescriptor`, `OperationEffectClass`, `AvailabilityState`, `ActivityResultState`, `TimingMode`, and shared `D02Error`.
- Consumes: no new canonical state.

Define the shared error surface in `lib.rs` with exact mechanical variants used by later tasks:

```rust
#[derive(Debug, thiserror::Error)]
pub enum D02Error {
    #[error(transparent)] Identifier(#[from] ptah_identifiers::IdentifierError),
    #[error(transparent)] Ledger(#[from] ptah_ledger::LedgerError),
    #[error(transparent)] Workspace(#[from] ptah_workspace::WorkspaceError),
    #[error(transparent)] Search(#[from] ptah_archive_decomposition::b07::SearchError),
    #[error(transparent)] Json(#[from] serde_json::Error),
    #[error("D02 workspace access denied")] WorkspaceAccessDenied,
    #[error("D02 canonical record not found")] RecordNotFound,
    #[error("D02 canonical record class mismatch")] RecordClassMismatch,
    #[error("D02 canonical record belongs to a different Workspace")] WorkspaceMismatch,
    #[error("D02 archived Session not found")] ArchivedSessionNotFound,
    #[error("D02 caller record is invalid: {0}")] InvalidCallerRecord(&'static str),
    #[error("D02 input reference was not declared by the caller")] InputNotDeclared,
    #[error("D02 Grant reference was not declared by the caller")] GrantNotDeclared,
}
```

- [ ] **Step 1: Write failing profile tests**

Add tests that import the not-yet-existing crate surface and assert exact profile IDs and authority flags:

```rust
#[test]
fn d02_exposes_both_neutral_profile_ids_without_ptah_decision_authority() {
    let ai = ai_project_profile();
    let ops = operations_profile();
    assert_eq!(ai.profile_id, "ptah.workspace.ai_project.v1");
    assert_eq!(ops.profile_id, "ptah.workspace.operations.v2");
    assert!(!ai.decision_authority);
    assert!(!ai.context_selection_authority);
    assert!(!ai.review_authority);
    assert!(!ai.approval_authority);
    assert!(!ai.new_core_entity_required);
}
```

Also assert exact ADR-0037 vocabularies:

```rust
assert_eq!(
    operations_profile().effect_classes,
    vec![Observe, Draft, Simulate, Mutate, Publish, Destructive, ExternalSideEffect]
);
assert_eq!(
    operations_profile().availability_states,
    vec![ExternalReference, IndexedReference, MountedReadOnly, MaterializedCopy, GeneratedArtifact]
);
```

- [ ] **Step 2: Run the targeted test and verify RED**

Run:

```bash
cargo test -p ptah-ai-workspace --test d02_acceptance d02_exposes_both_neutral_profile_ids_without_ptah_decision_authority --locked
```

Expected: Cargo/package/import failure because `ptah-ai-workspace` and the profile API do not exist.

- [ ] **Step 3: Add the crate and minimal profile implementation**

`Cargo.toml` dependencies:

```toml
[dependencies]
ptah-identifiers = { path = "../ptah-identifiers", version = "=0.0.0-phase0c" }
ptah-ledger = { path = "../ptah-ledger", version = "=0.0.0-phase0c" }
ptah-workspace = { path = "../ptah-workspace", version = "=0.0.0-phase0c" }
ptah-activity-runtime = { path = "../ptah-activity-runtime", version = "=0.0.0-phase0c" }
ptah-object-store = { path = "../ptah-object-store", version = "=0.0.0-phase0c" }
ptah-checkpoint = { path = "../ptah-checkpoint", version = "=0.0.0-phase0c" }
ptah-archive-decomposition = { path = "../ptah-archive-decomposition", version = "=0.0.0-phase0c" }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
```

Use D02-owned enums so public consumers do not depend on `ptah-archive-decomposition` types.

- [ ] **Step 4: Run targeted test and verify GREEN**

Run the exact command from Step 2. Expected: PASS.

- [ ] **Step 5: Commit Task 1**

```bash
git add Cargo.toml crates/ptah-ai-workspace
git commit -m "feat(d02): add neutral workspace runtime profiles"
```

---

### Task 2: Exact Authority-Gated Canonical Retrieval

**Files:**
- Create: `crates/ptah-ai-workspace/src/retrieval.rs`
- Modify: `crates/ptah-ai-workspace/src/lib.rs`
- Modify: `crates/ptah-ai-workspace/tests/d02_acceptance.rs`

**Interfaces:**

Produce:

```rust
pub enum RecordClass { Workspace, Session, Activity, Object, Artifact }

pub struct RetrievalRequest {
    pub actor_ref: EntityRef,
    pub source_workspace_ref: EntityRef,
    pub target_workspace_ref: EntityRef,
    pub record_class: RecordClass,
    pub entity_ref: EntityRef,
    pub record_revision: Option<RecordRevision>,
    pub required_scope: String,
    pub grant_ref: Option<EntityRef>,
}

pub struct RetrievedRecord {
    pub entity_ref: EntityRef,
    pub record_revision: RecordRevision,
    pub schema_id: String,
    pub document: serde_json::Value,
}

pub struct WorkspaceReader { /* A06 + A03 handles */ }

impl WorkspaceReader {
    pub fn open(path: impl AsRef<Path>, clock: WorkspaceClock) -> Result<Self, D02Error>;
    pub fn authorize_workspace_access(&self, request: &RetrievalRequest) -> Result<(), D02Error>;
    pub fn retrieve(&self, request: &RetrievalRequest) -> Result<RetrievedRecord, D02Error>;
}
```

Define:

```rust
pub type WorkspaceClock = std::sync::Arc<dyn Fn() -> String + Send + Sync>;
```

This is the exact clock shape already accepted by A06; do not introduce time authority.

- [ ] **Step 1: Write failing exact-retrieval and isolation tests**

Build two durable Workspaces in one temporary ledger. Assert same-Workspace exact Session retrieval succeeds and cross-Workspace retrieval fails without a Grant:

```rust
let denied = reader.retrieve(&RetrievalRequest {
    actor_ref: actor_b.clone(),
    source_workspace_ref: workspace_b.clone(),
    target_workspace_ref: workspace_a.clone(),
    record_class: RecordClass::Session,
    entity_ref: private_session.clone(),
    record_revision: None,
    required_scope: "workspace.read".into(),
    grant_ref: None,
});
assert!(matches!(denied, Err(D02Error::WorkspaceAccessDenied)));
```

Add an exact-revision assertion using `RecordRevision::new(1)` and a wrong-Workspace assertion that returns `WorkspaceMismatch` without returning the protected document.

- [ ] **Step 2: Run targeted tests and verify RED**

Run:

```bash
cargo test -p ptah-ai-workspace --test d02_acceptance workspace_isolation --locked
```

Expected: FAIL because `WorkspaceReader`/retrieval types are absent.

- [ ] **Step 3: Implement minimal retrieval**

Open two read/write connections to the same repository path: `WorkspaceStore` for A06 authority checks and `Ledger` for canonical reads.

For `retrieve`:

```rust
self.authorize_workspace_access(request)?;
let record = match request.record_revision {
    Some(revision) => self.ledger.record(request.entity_ref.entity_id, revision)?,
    None => self.ledger.latest_record(request.entity_ref.entity_id)?,
}.ok_or(D02Error::RecordNotFound)?;
validate_record_class(&record, request.record_class)?;
validate_workspace_ownership(record.document(), request)?;
```

Workspace ownership rules:

- Workspace: requested entity ID must equal target Workspace ID.
- Session/Activity: top-level `workspace_ref` must equal target.
- Object/Artifact: `envelope.workspace_ref` must equal target.

Map A06 `CrossWorkspaceDenied` and `InvalidGrant` to explicit D02 access-denied errors; do not leak document content in the error.

- [ ] **Step 4: Run targeted retrieval tests and verify GREEN**

Run the command from Step 2 plus the exact-revision test. Expected: PASS.

- [ ] **Step 5: Commit Task 2**

```bash
git add crates/ptah-ai-workspace/src/retrieval.rs crates/ptah-ai-workspace/src/lib.rs crates/ptah-ai-workspace/tests/d02_acceptance.rs
git commit -m "feat(d02): add exact authority-gated retrieval"
```

---

### Task 3: Parallel Session Projection and B06 Archived Session Lookup

**Files:**
- Create: `crates/ptah-ai-workspace/src/sessions.rs`
- Modify: `crates/ptah-ai-workspace/src/lib.rs`
- Modify: `crates/ptah-ai-workspace/tests/d02_acceptance.rs`

**Interfaces:**

Produce:

```rust
pub struct SessionThreadProjection {
    pub workspace_ref: EntityRef,
    pub sessions: Vec<SessionProjection>,
    pub authoritative: bool,
}

pub fn project_session_threads(
    workspace: &WorkspaceStore,
    workspace_id: EntityId,
) -> Result<SessionThreadProjection, D02Error>;

pub fn archived_session_by_identity<'a>(
    archive: &'a SessionVaultArchive,
    session_ref: &EntityRef,
) -> Result<&'a SessionVaultSession, D02Error>;
```

- [ ] **Step 1: Write failing tests**

Create two Sessions in one Workspace and assert both are returned without an “active/correct” winner:

```rust
let projection = project_session_threads(&store, workspace_ref.entity_id)?;
assert_eq!(projection.sessions.len(), 2);
assert!(!projection.authoritative);
```

For archived discoverability, construct/use a real B06 `SessionVaultArchive` fixture and assert lookup is by exact canonical `session_ref` string. A missing identity must return `ArchivedSessionNotFound`; do not add an A06 `archive_session` state.

- [ ] **Step 2: Verify RED**

```bash
cargo test -p ptah-ai-workspace --test d02_acceptance archived_session_discoverability --locked
```

Expected: FAIL because the D02 Session projection API does not exist.

- [ ] **Step 3: Implement using A06 recovery plus B06 archive metadata**

`project_session_threads` calls A06 `recovery_projection`; it sorts only by stable identity for deterministic presentation and does not rank relevance.

`archived_session_by_identity` searches `archive.manifest.sessions` for exact `EntityRef::to_string()` equality. It returns metadata only; B06 archive presence is not live Session authority.

- [ ] **Step 4: Verify GREEN**

Run the targeted Session tests. Expected: PASS.

- [ ] **Step 5: Commit Task 3**

```bash
git add crates/ptah-ai-workspace/src/sessions.rs crates/ptah-ai-workspace/src/lib.rs crates/ptah-ai-workspace/tests/d02_acceptance.rs
git commit -m "feat(d02): project live and archived workspace sessions"
```

---

### Task 4: Caller-Owned Record Container and Artifact Library Projection

**Files:**
- Create: `crates/ptah-ai-workspace/src/caller_records.rs`
- Create: `crates/ptah-ai-workspace/src/library.rs`
- Modify: `crates/ptah-ai-workspace/src/lib.rs`
- Modify: `crates/ptah-ai-workspace/tests/d02_acceptance.rs`

**Interfaces:**

Produce caller container:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerRecord {
    pub format_version: String,
    pub author_ref: EntityRef,
    pub labels: Vec<String>,
    pub payload_bytes: Vec<u8>,
}

pub fn encode_caller_record(record: &CallerRecord) -> Result<Vec<u8>, D02Error>;
pub fn decode_caller_record(bytes: &[u8]) -> Result<CallerRecord, D02Error>;
```

Validation is mechanical only: exact supported container version, non-empty unique labels, bounded total encoded size. No label vocabulary or truth ranking.

Produce library types:

```rust
pub struct ArtifactLibraryEntry {
    pub artifact_ref: EntityRef,
    pub object_ref: EntityRef,
    pub promoted_revision_refs: Vec<EntityRef>,
    pub artifact_type: String,
    pub purpose: String,
    pub lifecycle_state: String,
}

pub struct ArtifactLibraryProjection {
    pub workspace_ref: EntityRef,
    pub entries: Vec<ArtifactLibraryEntry>,
    pub exhaustive: bool,
    pub limitations: Vec<String>,
    pub authoritative: bool,
}

pub fn artifact_library(
    workspace: &WorkspaceStore,
    ledger: &Ledger,
    workspace_id: EntityId,
) -> Result<ArtifactLibraryProjection, D02Error>;
```

- [ ] **Step 1: Write failing caller-label tests**

Use contradictory caller labels deliberately:

```rust
let first = CallerRecord {
    format_version: "ptah.caller-record.v1".into(),
    author_ref: hunter_ref.clone(),
    labels: vec!["canonical".into()],
    payload_bytes: b"A".to_vec(),
};
let second = CallerRecord {
    format_version: "ptah.caller-record.v1".into(),
    author_ref: reviewer_ref.clone(),
    labels: vec!["reference".into()],
    payload_bytes: b"B".to_vec(),
};
assert_eq!(decode_caller_record(&encode_caller_record(&first)?)?, first);
assert_eq!(decode_caller_record(&encode_caller_record(&second)?)?, second);
```

Store the encoded bytes through existing A07 registration in the test fixture and prove their canonical digests differ while D02 emits no winner field/function.

- [ ] **Step 2: Write failing Artifact Library test and verify RED**

Create one A07 Object, explicitly promote one Artifact with valid separate A04 production evidence, add the Object reference to A06 scope projection, then assert the not-yet-existing library returns exactly that Artifact and `authoritative == false`.

Run:

```bash
cargo test -p ptah-ai-workspace --test d02_acceptance caller_label_roundtrip --locked
cargo test -p ptah-ai-workspace --test d02_acceptance artifact_library_is_projection_only --locked
```

Expected: FAIL for absent APIs.

- [ ] **Step 3: Implement minimal container and library**

Caller-record encoding uses `serde_json::to_vec`/`from_slice`. Do not normalize or sort labels; preserve caller order exactly.

Artifact library walks only A06's current scope projection, then canonical A07 Object `artifact_refs`, then exact/latest Artifact records. Because A06 scope may be incomplete, return `exhaustive = false` and a limitation explaining that the library reflects the current A06 scope projection.

- [ ] **Step 4: Verify GREEN**

Run both targeted tests. Expected: PASS.

- [ ] **Step 5: Commit Task 4**

```bash
git add crates/ptah-ai-workspace/src/caller_records.rs crates/ptah-ai-workspace/src/library.rs crates/ptah-ai-workspace/src/lib.rs crates/ptah-ai-workspace/tests/d02_acceptance.rs
git commit -m "feat(d02): preserve caller records and project artifact library"
```

---

### Task 5: Exact Admitted Inputs and Narrow B07 Search Adapter

**Files:**
- Create: `crates/ptah-ai-workspace/src/activity_inputs.rs`
- Create: `crates/ptah-ai-workspace/src/search.rs`
- Modify: `crates/ptah-ai-workspace/src/lib.rs`
- Modify: `crates/ptah-ai-workspace/tests/d02_acceptance.rs`

**Interfaces:**

Produce exact input envelope:

```rust
pub struct ActivityInputEnvelope {
    pub workspace_ref: EntityRef,
    pub request_ref: EntityRef,
    pub input_refs: Vec<EntityRef>,
    pub provider_refs: Vec<EntityRef>,
    pub facility_refs: Vec<EntityRef>,
    pub grant_refs: Vec<EntityRef>,
    pub schedule_ref: Option<EntityRef>,
}

impl ActivityInputEnvelope {
    pub fn ensure_declared_input(&self, requested: &EntityRef) -> Result<(), D02Error>;
    pub fn ensure_declared_grant(&self, grant: Option<&EntityRef>) -> Result<(), D02Error>;
}
```

Produce D02-owned search types:

```rust
pub enum WorkspaceSearchDomain { Filename, Metadata, DocumentText, SourceSymbol, Log, Activity, Artifact }

pub struct WorkspaceSearchRequest {
    pub actor_ref: EntityRef,
    pub source_workspace_ref: EntityRef,
    pub target_workspace_ref: EntityRef,
    pub required_scope: String,
    pub grant_ref: Option<EntityRef>,
    pub text: String,
    pub domains: Vec<WorkspaceSearchDomain>,
    pub limit: usize,
}

pub struct WorkspaceSearchResponse {
    pub index_revision: u64,
    pub index_sha256: String,
    pub hits: Vec<WorkspaceSearchHit>,
    pub authoritative: bool,
}

pub fn query_b07(
    reader: &WorkspaceReader,
    index: &SearchIndex,
    request: &WorkspaceSearchRequest,
) -> Result<WorkspaceSearchResponse, D02Error>;
```

No public D02 response type contains B07 crate-specific enums.

- [ ] **Step 1: Write failing scheduled-exact-input test**

Create an envelope with two exact Artifact refs, then request a third:

```rust
assert!(envelope.ensure_declared_input(&artifact_a).is_ok());
assert!(matches!(
    envelope.ensure_declared_input(&artifact_c),
    Err(D02Error::InputNotDeclared)
));
```

Also assert a Grant not in `grant_refs` returns `GrantNotDeclared` before any A06 read.

- [ ] **Step 2: Write failing search authority test**

Build a B07 index containing source-bound hits. Verify D02 access denial occurs before search for an unauthorized Workspace. For an authorized query assert:

```rust
assert!(!response.authoritative);
assert_eq!(response.hits[0].source_ref, exact_source_ref);
assert_eq!(response.hits[0].source_record_revision, exact_revision);
```

- [ ] **Step 3: Run targeted tests and verify RED**

```bash
cargo test -p ptah-ai-workspace --test d02_acceptance scheduled_exact_inputs --locked
cargo test -p ptah-ai-workspace --test d02_acceptance search_is_source_bound_not_authority --locked
```

Expected: FAIL for absent APIs.

- [ ] **Step 4: Implement minimal envelope/search adapter**

The envelope only checks exact membership; it does not infer a replacement input.

`query_b07` first constructs an access-only retrieval/authorization check for the target Workspace, then maps D02 search domains into B07 `SearchDomain`, calls `SearchIndex::query`, and copies source identity/revision/matches into D02-owned output types. Preserve B07 ordering; do not add trust ranking.

- [ ] **Step 5: Verify GREEN and commit Task 5**

Run both targeted tests, then:

```bash
git add crates/ptah-ai-workspace/src/activity_inputs.rs crates/ptah-ai-workspace/src/search.rs crates/ptah-ai-workspace/src/lib.rs crates/ptah-ai-workspace/tests/d02_acceptance.rs
git commit -m "feat(d02): enforce exact inputs and source-bound search"
```

---

### Task 6: Hunter and Sergeant Caller Adapters

**Files:**
- Create: `crates/ptah-ai-workspace/src/adapters/mod.rs`
- Create: `crates/ptah-ai-workspace/src/adapters/hunter.rs`
- Create: `crates/ptah-ai-workspace/src/adapters/sergeant.rs`
- Modify: `crates/ptah-ai-workspace/src/lib.rs`
- Modify: `crates/ptah-ai-workspace/tests/d02_acceptance.rs`

**Interfaces:**

Hunter:

```rust
pub struct HunterAdapter<'a> { reader: &'a WorkspaceReader }
impl<'a> HunterAdapter<'a> {
    pub const fn new(reader: &'a WorkspaceReader) -> Self;
    pub fn retrieve_exact(&self, request: &RetrievalRequest) -> Result<RetrievedRecord, D02Error>;
    pub fn encode_caller_record(&self, record: &CallerRecord) -> Result<Vec<u8>, D02Error>;
}
```

Sergeant:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SergeantReviewPayload {
    pub candidate_ref: EntityRef,
    pub reviewer_ref: EntityRef,
    pub selected_evidence_refs: Vec<EntityRef>,
    pub result_bytes: Vec<u8>,
}

pub struct SergeantAdapter<'a> { reader: &'a WorkspaceReader }
impl<'a> SergeantAdapter<'a> {
    pub const fn new(reader: &'a WorkspaceReader) -> Self;
    pub fn retrieve_candidate(&self, request: &RetrievalRequest) -> Result<RetrievedRecord, D02Error>;
    pub fn encode_review(&self, review: &SergeantReviewPayload) -> Result<Vec<u8>, D02Error>;
}
```

No methods for context choice, authority ranking, approval, promotion, verdict adoption or next-action selection.

- [ ] **Step 1: Write failing model-replacement and Sergeant tests**

Model replacement: attach a second caller/model service to the same A06 Session; assert Workspace/Session IDs and existing Grant reference are unchanged. Hunter adapter retrieval must succeed only under the same pre-existing Grant.

Sergeant: encode/store a review payload through existing A07 test machinery and assert candidate and review Artifact references are distinct. Search all D02 public serialized outputs used by the test and assert there is no Ptah-generated `approved`, `rejected`, `canonical_winner`, or promotion decision.

- [ ] **Step 2: Verify RED**

```bash
cargo test -p ptah-ai-workspace --test d02_acceptance model_independent_resume --locked
cargo test -p ptah-ai-workspace --test d02_acceptance sergeant_review_no_ptah_verdict --locked
```

Expected: FAIL for absent adapters.

- [ ] **Step 3: Implement thin adapters**

Adapters delegate exact reads/encoding only. `SergeantReviewPayload` is caller-owned data; D02 validates structural non-emptiness/bounds, not review correctness.

- [ ] **Step 4: Verify GREEN and commit Task 6**

Run both targeted tests, then:

```bash
git add crates/ptah-ai-workspace/src/adapters crates/ptah-ai-workspace/src/lib.rs crates/ptah-ai-workspace/tests/d02_acceptance.rs
git commit -m "feat(d02): add Hunter and Sergeant caller adapters"
```

---

### Task 7: Complete the Ten Recovered D02 Fixtures and Operations-v2 Compatibility Corpus

**Files:**
- Modify: `crates/ptah-ai-workspace/tests/d02_acceptance.rs`
- Modify only if a failing test proves a missing D02 behavior: `crates/ptah-ai-workspace/src/*.rs`

**Interfaces:**
- Consumes all Task 1–6 APIs.
- Produces the final runtime acceptance corpus.

- [ ] **Step 1: Add explicit test names for every recovered fixture**

The test file must contain these ten behavioral tests:

```text
workspace_isolation
caller_label_roundtrip
conflicting_labels_no_ranking
model_independent_resume
grant_survives_agent_change
scheduled_exact_inputs
private_hunter_public_workspace
archived_session_discoverability
failed_activity_visible
sergeant_review_no_ptah_verdict
```

`failed_activity_visible` must use real A04 APIs: create/admit an Activity, create/start an Operation/Attempt, retain a partial result reference where supported, fail the Attempt/Activity, then prove the failure and retained result identities remain readable. Do not convert failure into success/acceptance.

- [ ] **Step 2: Add operations-v2 compatibility tests**

Add explicit tests for:

```text
operations_v2_vocabularies_match_adr0037
provider_grant_and_approval_are_separate
external_reference_is_not_materialized_path
search_hit_never_becomes_source_truth
library_and_session_views_are_non_authoritative
no_d02_schema_or_migration_is_introduced
```

For the schema/migration test, inspect source-controlled paths at test/build time only if repository test conventions permit it; otherwise make this a CI static assertion in Task 8. Do not add runtime filesystem coupling merely to satisfy the test.

- [ ] **Step 3: Run the full D02 acceptance test and verify any newly added cases RED before code changes**

```bash
cargo test -p ptah-ai-workspace --test d02_acceptance --locked
```

For every new failure, confirm it is a missing D02 behavior rather than malformed fixture setup.

- [ ] **Step 4: Implement only the missing behavior, then rerun until GREEN**

Expected final result: every D02 acceptance case passes with no ignored tests.

- [ ] **Step 5: Run inherited targeted regressions**

```bash
cargo test -p ptah-workspace --test a06_acceptance --locked
cargo test -p ptah-activity-runtime --test a04_acceptance --locked
cargo test -p ptah-object-store --test a07 --locked
cargo test -p ptah-checkpoint --test a13 --locked
cargo test -p ptah-checkpoint --test b06 --locked
cargo test -p ptah-archive-decomposition --test b07 --locked
cargo test -p ptah-control --test a14_acceptance --locked
cargo test -p ptah-control --test d01_acceptance --locked
```

Expected: all PASS.

- [ ] **Step 6: Commit Task 7**

```bash
git add crates/ptah-ai-workspace
git commit -m "test(d02): prove AI project workspace authority boundaries"
```

---

### Task 8: Durable D02 Record, Exact-Head CI, Review, Freeze, and Ship

**Files:**
- Create: `D02_AI_PROJECT_WORKSPACE.md`
- Create: `.github/workflows/d02-ai-project-workspace-proof.yml`
- Modify: no unrelated files.

**Interfaces:**
- CI consumes the exact frozen implementation head.
- Documentation records proof boundaries and non-claims.

- [ ] **Step 1: Write the durable implementation record**

Record:

- base D01 merge and approved design commit;
- exact D02 profile IDs;
- composition crate and dependency boundaries;
- ten fixture outcomes;
- operations-v2 compatibility outcomes;
- explicit non-claims;
- exact commands used for proof.

Do not call D02 complete before frozen-head proof.

- [ ] **Step 2: Add exact-head workflow**

Follow D01 workflow conventions but make D02-specific assertions:

```yaml
- verify checked-out SHA equals pull-request head SHA
- verify approved D02 design is an ancestor
- verify no files under crates/ptah-ledger/migrations changed
- verify no frozen contract/generated schema files changed
- verify historical candidate runtime_implementation_authorized remains false
- cargo fmt --all -- --check
- cargo clippy --workspace --all-targets --locked -- -W clippy::all -W clippy::pedantic
- cargo test -p ptah-ai-workspace --test d02_acceptance --locked
- targeted A04/A06/A07/A13/B06/B07/A14/D01 regressions
- cargo test --workspace --locked
```

No browser UI proof is required unless D02 changes browser/UI code; D02 is substrate/adapters, not D01 presentation.

- [ ] **Step 3: Run static review before freeze**

```bash
git diff --check
git status --short
git diff --name-only <approved-design-base>..HEAD
```

Review every changed file for semantic authority drift. Search for forbidden patterns in production code:

```bash
grep -RInE 'choose_context|rank_sources|canonical_winner|approve_candidate|promote_candidate|decide_next_action|ptah_verdict' crates/ptah-ai-workspace
```

Any matching production API that assigns those functions to Ptah is a blocker.

- [ ] **Step 4: Run formatter, Clippy, D02, targeted regressions, and full workspace before freeze**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -W clippy::all -W clippy::pedantic
cargo test -p ptah-ai-workspace --test d02_acceptance --locked
cargo test --workspace --locked
```

Expected: green under the repository's accepted warning policy; pre-existing warnings may remain only if they are unchanged baseline debt and the accepted gate permits them.

- [ ] **Step 5: Freeze implementation history**

Review commits created by Tasks 1–7. Squash/rewrite only if needed so the final D02 implementation history is reviewable and the design commit remains a clear ancestor. Record the frozen candidate SHA.

- [ ] **Step 6: Prove the exact frozen head locally**

Re-run Step 4 after freeze. Also assert:

```bash
git status --porcelain
```

Expected: empty.

- [ ] **Step 7: Push implementation branch and open PR**

Push only the exact proven head. PR description must distinguish:

- D02 mechanical substrate/adapters;
- caller-owned Hunter/Sergeant semantics;
- no frozen contract reopening;
- no new Core family;
- no D03/D04 scope pulled forward.

- [ ] **Step 8: Follow D02 exact-head CI to completion**

Treat unrelated historical exact-head workflows as historical only after inspecting their failed assertion. Do not dismiss a failure without evidence.

- [ ] **Step 9: Merge only after current D02 proof is green**

Use the repository's current merge convention. After merge, verify `origin/main` contains the exact frozen D02 candidate as a parent/ancestor and recover the next roadmap milestone rather than assuming D03 scope.
