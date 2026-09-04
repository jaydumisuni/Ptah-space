# D09 Full Workspace Release Acceptance Design

## Status and authority

D09 is the Programme D release-acceptance milestone. It adds no new Ptah runtime subsystem, canonical entity family, schema, migration, Provider, execution authority or product semantics.

Accepted implementation predecessor:

`ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`

That commit is the independently verified D08 merge (`Application platform expansion`).

Delivery authority is the accepted `jaydumisuni/ptah-roadmap-` checkpoint:

`98dc8c4e8639cda80510bee0625db34b4fdf9384`

The authoritative D09 burden is:

- prove concurrent human and agent operation;
- prove long-running recovery;
- prove Provider replacement without Ptah identity/authority drift;
- prove provenance and security evidence remain independently reviewable;
- prove Plugin rollback remains verified rather than acknowledgement-based;
- prove the complete public/private and licence boundary;
- prove the complete deep Workspace study under human, Hunter and Sergeant use without Ptah gaining semantic context, review, approval, acceptance or next-action authority;
- retain exact-head evidence sufficient for an independent release review.

The release milestone is **Full Workspace Release**.

## Architectural decision

D09 is an acceptance-only composition layer modeled on the accepted A15 exact-head release-acceptance pattern.

D09 does not add a `ptah-d09` Rust crate or any other runtime package. It composes already-proven public acceptance surfaces and produces a retained exact-head release bundle. Product source may change during D09 only if a D09 proof exposes a real defect; any such repair invalidates the frozen candidate and requires Review → Freeze → Prove again.

The normal D09 implementation surface is limited to:

- this design;
- the D09 implementation plan;
- `D09_FULL_WORKSPACE_RELEASE_ACCEPTANCE.md`;
- `conformance/d09/full-workspace-release-cases.v0.1.0.json`;
- `tools/check_d09_full_workspace_release.py`;
- `tools/test_check_d09_full_workspace_release.py`;
- `.github/workflows/d09-full-workspace-release-acceptance.yml`.

No `Cargo.toml`, `Cargo.lock`, schema, migration, generated binding or existing product crate is part of the D09 delta.

### Release-audit proof-hygiene correction

The first permanent D09 exact-head run exposed eight inherited non-immutable GitHub Action references, all confined to completed D07/D08 proof machinery. D09 retains that failed run as evidence and corrects the inherited release-proof surface without changing Ptah runtime behavior:

- `.github/workflows/d07-security-evidence-reproduction-proof.yml` — pin checkout/upload actions and replace the floating Rust action with explicit Rust 1.97.1 installation;
- `.github/workflows/d08-application-platform-expansion-proof.yml` — the same immutable proof correction;
- `.github/workflows/d08-tdd.yml` — retire the completed Task-4 auto-promotion lane entirely rather than carry a write-capable obsolete workflow into the Full Workspace release.

These three paths are the only audited exception to the normal seven-file D09 acceptance surface. The final D08→D09 release delta is therefore exactly ten paths: seven D09 evidence/proof files plus those three inherited proof-hygiene corrections. No Rust product source, Cargo metadata, schema, migration or generated contract changes as part of this remediation.

### Release-audit dependency authority correction

D09 proof also exposed two historical dependency snapshots that are truthful for their original milestones but not suitable as the current Full Workspace baseline:

- A01 scaffold tests freeze the original A01 workspace/member and Cargo snapshot;
- `tools/check_phase0c_scaffold.py` freezes an earlier 81-package external Cargo universe.

The independently accepted D08 predecessor carries the later committed dependency selection: 11 exact workspace direct dependencies, 116 resolved packages, 97 registry packages and zero Git dependencies. D09 must not rewrite that accepted state to satisfy an earlier historical snapshot.

The current D09 dependency/source/licence authority therefore follows the accepted A15 exact-head pattern and strengthens it with predecessor-relative identity:

1. `Cargo.toml`, `Cargo.lock`, `deny.toml`, `dependencies/rust-direct-lock.json`, `dependencies/backend-artifact-lock.json`, `contracts/generated/manifest.json` and `crates/ptah-contracts/src/generated.rs` must be byte-identical to D08;
2. `tools/check_rust_dependency_lock.py` must pass on the current lock;
3. the committed Cargo lock SHA/counts, exact direct dependency set, canonical crates.io source, registry checksums and zero-Git rule must match the current repository state;
4. `deny.toml` must retain the committed source, wildcard, yanked and licence allow-list policy;
5. every external package licence expression reported by `cargo metadata --locked` must remain inside that committed allow-list;
6. retained backend artifact/browser/signature identities remain exact.

Historical A01/Phase-0C package-universe validators remain retained evidence, not the current D09 dependency baseline.

## Reused proof authorities

D09 does not reimplement predecessor semantics. It requires their exact acceptance suites to pass together on one candidate head.

### Human and agent operation

- D01 remains the human Workspace shell authority and exposes `ptah.workspace.operations.v2` as a read-only/mechanical projection.
- D02 remains the AI Project Workspace composition boundary for `ptah.workspace.ai_project.v1` and compatible `ptah.workspace.operations.v2`.
- Hunter and Sergeant remain caller adapters. Ptah does not choose context, trust, review verdict, acceptance or next action.
- A04 remains concurrent Activity/Operation/Attempt execution authority.

### Long-running recovery

- A13 remains checkpoint, restart and verified recovery authority.
- B06 remains Session Vault export/import and compatible-resume authority.
- Recovery must retain stable Ptah identities, result handles, partial work, exact inputs and conflict/uncertainty evidence while rejecting stale leases/generations.

### Provider replacement and plugin rollback

- Provider/backend identifiers remain scoped aliases/evidence.
- Replacement advances Provider/runtime generation without re-keying canonical Ptah identity.
- D05 remains Package/Plugin lifecycle authority. Update decision is not execution; rollback requires fresh A04 identities and independent post-verification.

### Provenance and security evidence

- D06 remains exact provenance/SBOM/signing/proof-bundle authority. Proof domains may disagree and remain separately represented.
- D07 remains authorization, Finding/Claim/Evidence, remediation and independent reproduction authority. Negative, partial, failed, inconclusive and regressed evidence cannot be erased by release acceptance.

### Application platform

- D08 remains Application/Window/Display composition authority.
- Linux/Android verified state may project into the shell; Windows/macOS/iOS Simulator/live remote display remain explicit Programme E deferrals where remote Node authority is absent.
- D09 cannot reinterpret a D08 blocker as availability.

### Public/private and licence boundary

- the accepted Apache-2.0 boundary tooling remains the public/private source-policy authority;
- private Hunter/customer/device/payment/restricted-adapter data cannot become public release evidence merely because D09 is green;
- exact Workspace Grants still govern private Hunter record retrieval;
- D09 report bundles contain only approved public evidence and digests, never raw private content.

## Deep Workspace release burden

D09 must run the accepted deep Workspace corpus and preserve its frozen mechanical profile:

- 22 mechanical capabilities;
- 20 fixtures;
- 26 original positive/adversarial cases;
- exact effect classes;
- explicit reference/materialization states;
- distinct result states;
- exact/flexible/condition timing;
- exact precondition/conflict evidence;
- stable result handles and incremental access;
- external Provider permission, Ptah Grant and caller approval as separate facts;
- no new Core entity requirement;
- no frozen-contract reopening.

The same acceptance candidate must additionally prove that the human D01 surface and D02 Hunter/Sergeant adapters retain caller-owned semantic authority. Passing the mechanical corpus never grants Ptah authority to interpret or accept its result.

## Frozen D09 release cases

D09 freezes exactly ten release-acceptance cases. They are represented in `conformance/d09/full-workspace-release-cases.v0.1.0.json` and mechanically validated by the D09 checker.

1. **Human and agent coexistence** — D01 and D02 profiles coexist on the same candidate without replacing caller authority.
2. **Deep Workspace authority separation** — all 26 deep-study cases pass while context, review, approval, acceptance and next-action authority remain caller-owned for human, Hunter and Sergeant use.
3. **Concurrent Activity operation** — A04 concurrency/failure isolation remains valid while human/agent Workspace acceptance also passes.
4. **Long-running recovery** — A13 and B06 preserve recoverable identity, partial/result-handle/input/conflict evidence and reject stale authority.
5. **Provider replacement** — replacement/fencing evidence advances generation while canonical Workspace/Object/Plugin/proof identity remains stable.
6. **Plugin rollback** — D05 rollback uses a fresh Attempt and requires independent post-verification; acknowledgement alone cannot satisfy release acceptance.
7. **Provenance reviewability** — D06 proof domains, exact subjects and independent reproduction remain independently reviewable and cannot self-approve release.
8. **Security reproduction history** — D07 authorization/remediation/reproduction preserves contradictory, negative, partial, failed, inconclusive and regressed evidence.
9. **Application truth** — D08 local/Android projections stay evidence-bound and read-only while unresolved remote-platform dependencies remain explicit blockers.
10. **Public/private release audit** — Apache/source-policy checks and D02 private-Workspace denial pass, with no release bundle path allowed to elevate private data or inferred authority.

A D09 candidate is invalid if the corpus count is not exactly ten or if any case weakens these boundaries.

## D09 checker contract

`tools/check_d09_full_workspace_release.py` is a stdlib-only mechanical validator. It does not execute Ptah runtimes or decide whether a release is semantically desirable.

It must:

- load the frozen D09 JSON corpus;
- require schema version `0.1.0` and record type `ptah.d09.full_workspace_release_corpus`;
- require exactly ten unique case IDs and the exact ten required release categories;
- require participants `human`, `hunter`, and `sergeant` across the corpus;
- require every case to declare `ptah_semantic_authority: false`;
- require the corpus to declare `new_core_entity_required: false`, `frozen_contract_change_required: false`, and `runtime_feature_added: false`;
- validate report-bundle inputs as present, regular, non-empty files;
- generate deterministic SHA-256 report-file metadata for the exact-head workflow.

The checker must fail closed on missing, duplicate, unknown or authority-widening corpus content.

## Exact-head workflow

Workflow name:

`D09 Full Workspace Release Exact Head Acceptance`

It runs for pushes to the D09 implementation branch, pull requests to `main`, and manual dispatch.

The proof must:

1. checkout the exact candidate SHA;
2. pin Python 3.13 and Rust/Cargo 1.97.1;
3. prove `origin/main` is exact D08 merge `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d` for the frozen proof run;
4. prove linear D09 history and remote branch equality;
5. prove the D08→D09 delta is exactly the seven D09 acceptance files plus the three audited D07/D08 proof-hygiene paths described above;
6. prove Cargo/schema/migration/generated-contract/product-runtime trees are unchanged from D08 and byte-compare the dependency/contract authority set to D08;
7. prove every remaining external GitHub Action reference is an immutable 40-hex commit pin;
8. prove the D08-bound current dependency/source/licence identity, exact Rust dependency lock and retained backend identities;
9. run D09 checker unit tests and validate the exact ten-case corpus;
10. run the accepted deep Workspace 26-case validator and require 22 capabilities/20 fixtures/no new Core/no contract reopening;
11. run the AI Project Workspace validator and its regressions, requiring no Ptah decision/context/review authority;
12. run D01 human acceptance and D02 AI Workspace acceptance;
13. run A04 Activity runtime acceptance/concurrency coverage;
14. run A13 and B06 checkpoint/recovery acceptance;
15. run D05 Package/Plugin acceptance including rollback/replacement cases;
16. run D06 provenance acceptance and store round-trip;
17. run D07 security evidence acceptance and store round-trip;
18. run D08 25 runtime + 3 shell integration cases exactly;
19. run Apache/public-private boundary checks;
20. run `cargo fmt --all -- --check` and complete `cargo test --workspace --locked`;
21. require a clean worktree;
22. create a D09 report bundle containing exact candidate/predecessor identities, dependency counts, frozen counts, explicit limitations and SHA-256 for every required report;
23. verify the report bundle digest;
24. upload retained artifact `d09-full-workspace-release-${TARGET_SHA}`.

Green status without the retained bundle is not D09 acceptance.

## Release and merge rule

A D09 candidate may be merged only when:

- one exact candidate SHA passes the permanent D09 workflow;
- the retained artifact exists for that exact SHA;
- the implementation branch still equals the proven SHA;
- the PR base is exact D08 merge `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`;
- no unresolved review or repository rule blocks merge;
- merge uses an expected-head guard for the proven SHA.

After merge, `main` must be independently verified. The merge commit must have exactly these parents:

1. D08 merge `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`;
2. frozen proven D09 candidate SHA.

Only after that independent verification may D09 be marked COMPLETE and Programme D be called the **Full Workspace Release** milestone.

## Explicit non-claims

D09 does not claim:

- Programme E multi-Node placement, leases, remote platform Nodes or distributed acceptance;
- Programme F OS-ready packaging;
- semantic correctness of Hunter or Sergeant output;
- automatic release approval;
- automatic remediation or Plugin update authority;
- that proof success erases negative/partial/inconclusive evidence;
- that a hosted CI machine is a separately pinned physical production Node;
- that an unavailable deferred D08 platform became available;
- that public release evidence grants access to private records.
