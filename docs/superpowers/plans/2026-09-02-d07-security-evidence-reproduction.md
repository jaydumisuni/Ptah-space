# D07 Security Evidence and Reproduction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement D07 Security evidence and reproduction as a provider-neutral composition layer over existing Ptah authority, with exactly 30 milestone acceptance cases and canonical persistence only for the frozen 18 WP12 security entities.

**Architecture:** Add `ptah-security-evidence`. Assessment Authorization/Target/Plan/Scanner Revision/Run/Coverage are D07-owned mechanical projections over A06/A04/A07/D04/D05 authority; the frozen 18 WP12 entities are persisted canonically through A03. Security tools remain private adapters and never become Finding identity, review authority, remediation approval or release authority.

**Tech Stack:** Rust 2024 workspace, serde/serde_json, sha2, thiserror, A03 `ptah-ledger`, A04 `ptah-activity-runtime`, A06 `ptah-workspace`, A07 `ptah-object-store`, D04 `ptah-recipe-registry`, D05 `ptah-package-plugin`, D06 `ptah-provenance`, frozen `ptah-contracts`.

**Spec:** `docs/superpowers/specs/2026-09-02-d07-security-evidence-reproduction-design.md`

## Global Constraints

- Accepted predecessor is D06 merge `29755a63d3dabeb2a108a14c1a4b9dee97efe98c`.
- Roadmap authority is `ptah-roadmap-` `98dc8c4e8639cda80510bee0625db34b4fdf9384`.
- No new schemas, migrations, canonical entity families, external security-tool dependencies or network schema resolution.
- Exactly 30 `d07_acceptance` tests; canonical-store tests are separate.
- No D07 `#[allow(...)]`/`#[expect(...)]` lint suppressions.
- Scanner/rule/CVE/report/backend IDs stay aliases/evidence.
- Active assessment requires an explicit current A06 Secure Grant; same-Workspace access must not bypass Grant validation.
- Observation != Finding; Claim != Evidence; Proposal != Patch; Patch ACK != Post-Fix Verification; Reproduction Request != execution.
- Negative, disputed, failed, partial and inconclusive history is immutable.
- Evidence Card is derived/sanitized and has no certification, release or acceptance authority.

---

### Task 1: Exact A06 Grant Validation and Frozen WP12 Store

**Files:**
- Modify: `crates/ptah-workspace/src/lib.rs`
- Create: `crates/ptah-security-evidence/Cargo.toml`
- Create: `crates/ptah-security-evidence/src/lib.rs`
- Create: `crates/ptah-security-evidence/src/error.rs`
- Create: `crates/ptah-security-evidence/src/store.rs`
- Create: `crates/ptah-security-evidence/tests/d07_acceptance.rs`
- Modify: root `Cargo.toml`, `Cargo.lock`

**Interfaces:**
- A06 produces:
  `WorkspaceStore::authorize_grant(&self, actor_ref: &EntityRef, subject_ref: &EntityRef, required_scope: &str, grant_ref: &EntityRef) -> Result<(), WorkspaceError>`.
- D07 produces:
  `SecurityEvidenceStore::open(path: impl AsRef<Path>) -> Result<Self, D07Error>`;
  `record_document(&mut self, document: Value) -> Result<EntityRef, D07Error>`;
  `read(&self, entity_ref: &EntityRef) -> Result<Value, D07Error>`.
- Store is bounded to the 18 frozen WP12 schema/kind pairs only.

- [ ] **Step 1: Add failing A06 same-Workspace Grant tests and D07 store-boundary tests.**

```rust
#[test]
fn explicit_security_grant_is_required_even_same_workspace() {
    // issue one `security.assess.active` Grant, prove authorize_grant accepts it,
    // advance the A06 clock beyond expiry, prove InvalidGrant.
}

#[test]
fn d07_store_rejects_non_wp12_schema() {
    // record a known non-WP12 document and require D07Error::UnsupportedSecuritySchema.
}
```

- [ ] **Step 2: Run RED.**

Run:
`cargo test -p ptah-workspace --test a06_acceptance --locked`
then
`cargo test -p ptah-security-evidence --test d07_acceptance --locked`

Expected: A06 fails because `authorize_grant` is absent; D07 package/API is absent.

- [ ] **Step 3: Refactor A06 exact Grant validation without changing retrieval semantics.**

```rust
pub fn authorize_grant(
    &self,
    actor_ref: &EntityRef,
    subject_ref: &EntityRef,
    required_scope: &str,
    grant_ref: &EntityRef,
) -> Result<(), WorkspaceError> {
    require_scope(required_scope)?;
    // load SECURE_GRANT_SCHEMA_ID; require exact subject/grantee, active lifecycle,
    // no revoked_at, expires_at > current clock and exact required scope.
}
```

Refactor `authorize_retrieval` to call the same private exact-Grant predicate for its cross-Workspace Grant path. Preserve the same-Workspace retrieval shortcut only in `authorize_retrieval`.

- [ ] **Step 4: Implement D07 bounded store.**

`SecurityEvidenceStore` must follow D06 `ProvenanceStore`: A03 `Ledger`, `CanonicalRecord::from_document`, exact schema/kind allow-list, no duplicate schema parser.

- [ ] **Step 5: Run GREEN + strict lint.**

Run:
`cargo test -p ptah-workspace --locked`
`cargo test -p ptah-security-evidence --locked`
`cargo clippy -p ptah-security-evidence -p ptah-workspace --all-targets --locked -- -D warnings -W clippy::pedantic`

- [ ] **Step 6: Audit lock delta and commit.**

Require only one new workspace package stanza: `ptah-security-evidence 0.0.0-phase0c`; no existing dependency/version/source movement.

Commit: `feat(d07): add exact security grant and wp12 store`

---

### Task 2: Assessment Authorization, Target, Plan, Run and Coverage — Cases 1–8

**Files:**
- Create: `crates/ptah-security-evidence/src/assessment.rs`
- Modify: `crates/ptah-security-evidence/src/error.rs`
- Modify: `crates/ptah-security-evidence/src/lib.rs`
- Modify: `crates/ptah-security-evidence/tests/d07_acceptance.rs`

**Interfaces:**

```rust
pub enum SecurityTestClass {
    SourceStatic, ArtifactInventory, VulnerabilityMatch, ConfigurationPolicy,
    SecretDetection, LicenceObservation, PassiveDynamic, ActiveDynamic, Fuzz,
    ExploitValidation, OffensiveAgentic, SupplyChainGraphAnalysis, ReproductionOrReplay,
}

pub struct AssessmentTarget {
    pub target_ref: EntityRef,
    pub sha256: String,
    pub locator: Option<String>,
}

pub struct ScannerRevision {
    pub provider_revision_ref: EntityRef,
    pub package_or_plugin_revision_ref: Option<EntityRef>,
    pub ruleset_ref: Option<EntityRef>,
    pub advisory_database_ref: Option<EntityRef>,
    pub policy_ref: Option<EntityRef>,
    pub model_ref: Option<EntityRef>,
    pub configuration_digest: String,
}

pub struct AssessmentAuthorization {
    pub workspace_ref: EntityRef,
    pub actor_ref: EntityRef,
    pub grant_ref: EntityRef,
    pub policy_refs: Vec<EntityRef>,
    pub target_refs: Vec<EntityRef>,
    pub allowed_test_classes: BTreeSet<SecurityTestClass>,
    pub forbidden_action_keys: BTreeSet<String>,
    pub valid_from: String,
    pub expires_at: String,
    pub privacy_policy_refs: Vec<EntityRef>,
    pub emergency_stop_required: bool,
    pub cleanup_readback_required: bool,
}

pub struct AssessmentPlan {
    pub authorization_digest: String,
    pub targets: Vec<AssessmentTarget>,
    pub scanner_revision: ScannerRevision,
    pub recipe_revision_ref: EntityRef,
    pub compiled_plan_ref: EntityRef,
    pub operation_descriptor_digests: Vec<String>,
    pub expected_scope: BTreeSet<String>,
    pub stop_conditions: Vec<String>,
    pub output_policy_refs: Vec<EntityRef>,
}

pub struct CoverageProjection {
    pub expected_scope: BTreeSet<String>,
    pub resolved_scope: BTreeSet<String>,
    pub scanned_scope: BTreeSet<String>,
    pub skipped_scope: BTreeSet<String>,
    pub unsupported_scope: BTreeSet<String>,
    pub error_scope: BTreeMap<String, String>,
    pub limitations: Vec<String>,
    pub complete: bool,
}
pub struct AssessmentRunMapping { pub activity_id: EntityId, pub operation_id: EntityId, pub attempt_id: EntityId }
```

`AssessmentAuthorization::authorize(&self, workspace: &WorkspaceStore, target: &AssessmentTarget, class: SecurityTestClass) -> Result<(), D07Error>` must call A06 `authorize_grant` and then enforce target/class membership.

- [ ] **Step 1: Add cases 1–8 as failing tests.**

Use actual A06 `IssueGrant` fixtures and actual A04 runtime for “no work created before authorization” assertions. Case 6 creates two `ScannerRevision`s differing only in rules/database/config digest and proves distinct deterministic plan/result identity. Case 7 rejects `complete=true` when any expected scope is skipped/unsupported/error/unknown. Case 8 proves raw path/backend ID are aliases only.

- [ ] **Step 2: Run RED.**

Run: `cargo test -p ptah-security-evidence --test d07_acceptance --locked`
Expected: missing assessment symbols.

- [ ] **Step 3: Implement exact target/authorization/plan validation and A04 mapping.**

Use SHA-256 canonical JSON digesting for D07 projection identity. No target discovery or scanner selection is allowed. `AssessmentRunMapping` may create A04 work only after authorization and plan validation succeed.

- [ ] **Step 4: Run GREEN, count 8 cases, strict lint.**

Run:
`cargo test -p ptah-security-evidence --test d07_acceptance --locked`
`cargo clippy -p ptah-security-evidence --all-targets --locked -- -D warnings -W clippy::pedantic`

- [ ] **Step 5: Commit.**

Commit: `feat(d07): add authorized assessment boundary`

---

### Task 3: Observation, Finding, Claim and Evidence — Cases 9–14

**Files:**
- Create: `crates/ptah-security-evidence/src/evidence.rs`
- Modify: `crates/ptah-security-evidence/src/error.rs`
- Modify: `crates/ptah-security-evidence/src/lib.rs`
- Modify: `crates/ptah-security-evidence/tests/d07_acceptance.rs`

**Interfaces:**

```rust
pub enum CorrelationRelation {
    Supports, Contradicts, PossibleDuplicate, SameLocationDifferentRule,
    SamePackageDifferentAdvisory, SourceAndRuntimeRelated, NotComparable, SupersedesObservation,
}

pub struct ObservationProjection {
    pub observation_ref: EntityRef,
    pub subject_refs: Vec<EntityRef>,
    pub evidence_refs: Vec<EntityRef>,
    pub scanner_aliases: Vec<String>,
    pub observed_facts: Vec<String>,
}

pub struct FindingDraft {
    pub subject_refs: Vec<EntityRef>,
    pub observation_refs: Vec<EntityRef>,
    pub correlations: BTreeMap<EntityRef, CorrelationRelation>,
    pub severity: String,
    pub confidence: f64,
    pub exploitability: String,
}

pub struct ClaimProjection {
    pub statement: String,
    pub claimant_ref: EntityRef,
    pub authority_scope: Vec<String>,
    pub subject_refs: Vec<EntityRef>,
    pub evidence_bundle_refs: Vec<EntityRef>,
}

pub struct EvidenceItemBinding {
    pub content_ref: EntityRef,
    pub sha256: String,
    pub collector_ref: EntityRef,
    pub activity_ref: EntityRef,
    pub attempt_ref: EntityRef,
}
```

- [ ] **Step 1: Add failing cases 9–14.**

Require Observation cannot be used as Finding identity; scanner candidate needs explicit bounded review input before a `FindingDraft` can be confirmed; contradictory observations both remain; Claim without claimant/authority scope fails; Evidence Item requires exact Content/Object digest/collector/Activity/Attempt; bundle completeness cannot exceed item/coverage evidence.

- [ ] **Step 2: Run RED, implement minimal separation/validation, run GREEN.**

Run: `cargo test -p ptah-security-evidence --test d07_acceptance --locked`

- [ ] **Step 3: Strict Clippy and commit.**

Commit: `feat(d07): separate findings claims and evidence`

---

### Task 4: Validation, Review, Accepted Risk, Dispute and Disclosure — Cases 15–19

**Files:**
- Create: `crates/ptah-security-evidence/src/review.rs`
- Create: `crates/ptah-security-evidence/src/disclosure.rs`
- Modify: `crates/ptah-security-evidence/src/lib.rs`
- Modify: `crates/ptah-security-evidence/tests/d07_acceptance.rs`

**Interfaces:**

```rust
pub struct ValidationRequest {
    pub finding_refs: Vec<EntityRef>,
    pub claim_refs: Vec<EntityRef>,
    pub environment_refs: Vec<EntityRef>,
    pub prior_attempt_refs: Vec<EntityRef>,
    pub attempt_context: AttemptContext,
}

pub enum ReviewOutcome { Accepted, AcceptedWithLimitations, Rejected, Inconclusive, Disputed }
pub struct AcceptedRiskProjection { pub finding_refs: Vec<EntityRef>, pub authority_ref: EntityRef, pub expires_at: String }
pub struct DisputeProjection { pub finding_refs: Vec<EntityRef>, pub claim_refs: Vec<EntityRef>, pub evidence_bundle_refs: Vec<EntityRef> }
pub struct DisclosurePolicy { pub audience: String, pub redaction_policy_refs: Vec<EntityRef>, pub privacy_policy_refs: Vec<EntityRef>, pub authority_ref: EntityRef }
```

- [ ] **Step 1: Add cases 15–19 RED.**

Validation must reject reused Attempt IDs and empty environment evidence. Review creates a new decision projection but takes immutable Observation/Evidence inputs by reference. Accepted Risk checks expiry and never mutates Finding. Dispute requires all submitted positions/evidence. Public Disclosure rejects restricted evidence unless explicit redacted disclosed content is supplied under audience/privacy authority.

- [ ] **Step 2: Implement, run GREEN + strict lint.**

- [ ] **Step 3: Commit.**

Commit: `feat(d07): add review risk dispute and disclosure`

---

### Task 5: Remediation and Post-Fix Verification — Cases 20–23

**Files:**
- Create: `crates/ptah-security-evidence/src/remediation.rs`
- Modify: `crates/ptah-security-evidence/src/lib.rs`
- Modify: `crates/ptah-security-evidence/tests/d07_acceptance.rs`

**Interfaces:**

```rust
pub struct PatchBinding {
    pub proposal_ref: EntityRef,
    pub patch_object_ref: EntityRef,
    pub base_revision_refs: Vec<EntityRef>,
    pub generator_ref: EntityRef,
    pub path_alias: Option<String>,
}

pub struct RemediationExecutionRequest {
    pub proposal_ref: EntityRef,
    pub patch_ref: EntityRef,
    pub target_refs: Vec<EntityRef>,
    pub backup_refs: Vec<EntityRef>,
    pub activity_request_ref: EntityRef,
    pub authority_ref: EntityRef,
    pub attempt_context: AttemptContext,
}

pub enum PostFixDecision { FixedVerified, MitigatedWithLimitations, NotFixed, Regressed, Inconclusive }
```

- [ ] **Step 1: Add cases 20–23 RED.**

Proposal cannot be cast as Patch; Patch requires exact `core.object_revision`/Artifact-compatible object reference plus base revision and digest-backed evidence, while `path_alias` never becomes identity; application ACK remains `applied_unverified`; post-fix requires a fresh A04 verification Attempt and exact environment/target refs; regression creates new evidence without deleting prior closure.

- [ ] **Step 2: Implement thin D04/A04 execution mapping, run GREEN.**

No `prove_operation_succeeded` call belongs in D07 remediation acknowledgement code. Completion/acceptance remains A04/caller-owned.

- [ ] **Step 3: Run A04/D04 regressions and strict lint; commit.**

Commit: `feat(d07): add remediation verification evidence`

---

### Task 6: Reproduction — Cases 24–28

**Files:**
- Create: `crates/ptah-security-evidence/src/reproduction.rs`
- Modify: `crates/ptah-security-evidence/src/lib.rs`
- Modify: `crates/ptah-security-evidence/tests/d07_acceptance.rs`

**Interfaces:**

```rust
pub struct ReproductionProtocolProjection {
    pub protocol_key: String,
    pub claim_scope: Vec<String>,
    pub required_inputs: Vec<EntityRef>,
    pub environment_requirements: Vec<String>,
    pub independence_requirements: Vec<String>,
    pub success_criteria: Vec<String>,
    pub failure_criteria: Vec<String>,
}

pub struct ReproductionRequestProjection {
    pub claim_refs: Vec<EntityRef>,
    pub finding_refs: Vec<EntityRef>,
    pub protocol_ref: EntityRef,
    pub requested_environment_constraints: Vec<String>,
    pub independence_requirements: Vec<String>,
    pub requested_by_ref: EntityRef,
    pub requested_at: String,
}

pub struct ReproductionRunRequest {
    pub request_ref: EntityRef,
    pub protocol_ref: EntityRef,
    pub environment_refs: Vec<EntityRef>,
    pub independence_evidence_refs: Vec<EntityRef>,
    pub prior_attempt_refs: Vec<EntityRef>,
    pub activity_request_ref: EntityRef,
    pub workspace_ref: EntityRef,
    pub caller_ref: EntityRef,
    pub authority_ref: EntityRef,
    pub intent_ref: EntityRef,
    pub attempt_context: AttemptContext,
}
pub enum ReproductionOutcome { Reproduced, NotReproduced, PartiallyReproduced, Failed, Inconclusive }
pub enum ReproductionComparisonDecision { SupportsClaim, PartiallySupports, ContradictsClaim, Inconclusive }
```

- [ ] **Step 1: Add cases 24–28 RED.**

Protocol digest must change on scope/environment/independence change. Request cannot expose Activity IDs. Same cache/mutable environment/hidden shared authority fails independence. Reused Attempt fails. Negative/partial/inconclusive outcomes remain in immutable comparison/history projections.

- [ ] **Step 2: Implement and run GREEN + strict lint.**

- [ ] **Step 3: Commit.**

Commit: `feat(d07): add independent security reproduction`

---

### Task 7: Evidence Card, Backend Replacement and Canonical Store Proof — Cases 29–30

**Files:**
- Create: `crates/ptah-security-evidence/src/card.rs`
- Create: `crates/ptah-security-evidence/src/adapters.rs`
- Create: `crates/ptah-security-evidence/tests/store_roundtrip.rs`
- Modify: `crates/ptah-security-evidence/Cargo.toml`
- Modify: `crates/ptah-security-evidence/src/lib.rs`
- Modify: `crates/ptah-security-evidence/tests/d07_acceptance.rs`

**Interfaces:**

```rust
pub struct EvidenceCardView {
    pub claim_ref: EntityRef,
    pub allowed_claim_sentence: String,
    pub evidence_refs: Vec<EntityRef>,
    pub result_status: String,
    pub verification_level: String,
    pub reproduction_level: String,
    pub review_status: String,
    pub limitations: Vec<String>,
    pub authoritative: bool,
    pub release_approved: bool,
}

pub struct SecurityAdapterObservation {
    pub backend_alias: String,
    pub provider_revision_ref: EntityRef,
    pub subject_refs: Vec<EntityRef>,
    pub facts: Vec<String>,
    pub evidence_refs: Vec<EntityRef>,
}
```

- [ ] **Step 1: Add cases 29–30 RED.**

Evidence Card must reject raw credential/token/cookie/private payload fields, always set `authoritative=false` and `release_approved=false`. Backend replacement changes provider/work/evidence refs while preserving canonical Finding/Claim subject identity; backend alias cannot be used as Finding EntityRef.

- [ ] **Step 2: Implement and prove exactly 30 D07 acceptance tests.**

Run:
`cargo test -p ptah-security-evidence --test d07_acceptance --locked -- --list`
Count exactly 30 lines ending `: test`.

- [ ] **Step 3: Add a separate canonical-store round-trip.**

Use a real valid frozen `security.observation` document and `SecurityEvidenceStore`; write/read through A03. This test is separate from `d07_acceptance` and must not change its 30 count.

- [ ] **Step 4: Audit all 18 schema/kind pairs against `ptah-contracts` generated bindings, strict Clippy and predecessor regressions.**

Run targeted:
`cargo test -p ptah-ledger -p ptah-activity-runtime -p ptah-workspace -p ptah-object-store -p ptah-recipe-registry -p ptah-package-plugin -p ptah-provenance --locked`

- [ ] **Step 5: Commit.**

Commit: `feat(d07): close security evidence acceptance corpus`

---

### Task 8: Durable Record, Exact-Head Proof and Ship

**Files:**
- Create: `D07_SECURITY_EVIDENCE_REPRODUCTION.md`
- Create: `.github/workflows/d07-security-evidence-reproduction-proof.yml`

- [ ] **Step 1: Run final implementation proof before proof-artifact commit.**

Run:
`cargo fmt --all -- --check`
`cargo clippy -p ptah-security-evidence --all-targets --locked -- -D warnings -W clippy::pedantic`
`cargo test -p ptah-security-evidence --locked`
`cargo test --workspace --locked`

Require only inherited `ptah-control` missing-doc warnings; no D07 warnings/failures.

- [ ] **Step 2: Write `D07_SECURITY_EVIDENCE_REPRODUCTION.md`.**

Record exact predecessor SHA, architecture boundaries, 30-case map, canonical 18-schema audit, A06 helper change, lock delta, predecessor/full-workspace proof and explicit deferrals.

- [ ] **Step 3: Write exact-head workflow.**

Workflow must enforce:
- exact D06 predecessor `29755a63d3dabeb2a108a14c1a4b9dee97efe98c`;
- linear history/no merges in candidate;
- approved D07 surface only (`Cargo.toml`, `Cargo.lock`, A06 helper change, `crates/ptah-security-evidence/**`, D07 spec/plan/record/workflow);
- no contracts/schemas/migrations/generated-binding changes;
- lock adds only `ptah-security-evidence`;
- pinned Rust `1.97.1`;
- exact 18 WP12 schema/kind map;
- no raw secret/public authority methods/lint suppressions;
- exactly 30 D07 acceptance cases + store round-trip;
- targeted predecessor regressions;
- full locked workspace;
- retained exact-head proof artifact.

- [ ] **Step 4: Commit proof artifacts; freeze that SHA.**

Commit: `proof(d07): add exact-head security evidence lane`

- [ ] **Step 5: Re-prove the frozen SHA from scratch.**

Fresh fetch `origin/main`; assert it is still D06 merge. Re-run scope/lock/static/fmt/Clippy/exact-count/package/predecessor/full-workspace gates. Require clean `git status` afterward.

- [ ] **Step 6: Push exact branch and verify remote SHA byte-for-byte.**

- [ ] **Step 7: Open PR against `main`, follow only the D07 exact-head workflow to green, classify predecessor-pinned historical jobs from their logs, inspect repo rulesets/mergeability.**

- [ ] **Step 8: Merge only with `--match-head-commit <frozen-d07-sha>`.**

- [ ] **Step 9: Fetch `origin/main` on KRATOS and verify merge parents are exactly D06 main + frozen D07 head; require clean worktree.**
