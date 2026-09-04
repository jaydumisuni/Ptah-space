# D09 — Full Workspace Release Acceptance

## Status

Programme D09 release-acceptance candidate.

This record defines the D09 acceptance boundary and release procedure. It does not self-approve D09 and does not claim the Full Workspace Release milestone is complete before the permanent exact-head proof, guarded merge and independent `main` verification succeed.

## Frozen authority

Accepted implementation predecessor:

`ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`

That commit is the independently verified D08 merge (`Application platform expansion`).

Accepted delivery authority:

- repository: `jaydumisuni/ptah-roadmap-`
- commit: `98dc8c4e8639cda80510bee0625db34b4fdf9384`
- package: Programme D09 — Full Workspace release acceptance
- milestone: **Full Workspace Release**

The roadmap burden is concurrent human and agent operation, long-running recovery, Provider replacement, provenance, security evidence, Plugin rollback, complete public/private audit and the complete deep Workspace corpus under human, Hunter and Sergeant use without Ptah authority drift.

## Acceptance-only architecture

D09 introduces no new runtime crate, Core entity family, schema, migration, generated contract, Provider, execution engine, Cargo dependency or semantic decision authority.

Its normal implementation surface is limited to:

- `docs/superpowers/specs/2026-09-04-d09-full-workspace-release-acceptance-design.md`;
- `docs/superpowers/plans/2026-09-04-d09-full-workspace-release-acceptance.md`;
- this durable record;
- `conformance/d09/full-workspace-release-cases.v0.1.0.json`;
- `tools/check_d09_full_workspace_release.py`;
- `tools/test_check_d09_full_workspace_release.py`;
- `.github/workflows/d09-full-workspace-release-acceptance.yml`.

The D09 release audit also identified and corrected inherited proof hygiene only:

- `.github/workflows/d07-security-evidence-reproduction-proof.yml` now uses immutable checkout/upload Action pins and explicit Rust 1.97.1 installation;
- `.github/workflows/d08-application-platform-expansion-proof.yml` now uses the same immutable proof pattern;
- the obsolete write-capable `.github/workflows/d08-tdd.yml` promotion lane is retired.

Those three workflow-path changes do not alter Ptah product code, Cargo state, schemas, migrations or predecessor semantics.

The D09 proof composes already-proven milestone authorities on one exact candidate. A green D09 workflow cannot redefine a predecessor contract.

## Release-audit corrections discovered during D09 proof

The first D09 exact-head audit exposed eight inherited floating GitHub Action references in completed D07/D08 proof machinery. Those references were corrected or retired rather than weakening the D09 policy.

A later proof attempt exposed that `tools/test_check_a01_scaffold.py` and `tools/check_a01_scaffold.py` encode the original A01 workspace/member and Cargo snapshot. Repository history already records those legacy A01/A02 exact-head checks as carrying historical workspace/dependency assumptions after later milestones legitimately expanded the workspace.

The next proof showed the same distinction for `tools/check_phase0c_scaffold.py`: that historical retained-evidence checker freezes an earlier 81-package external Cargo universe and therefore is not the current Full Workspace dependency baseline.

The following exact-head run recovered the final distinction inside `dependencies/rust-direct-lock.json`: its 11 exact direct-dependency selections, purposes, expected licences, toolchain, registry and policy remain applicable, but its nested `cargo_lock` object is an older historical snapshot. The accepted D08-identical `Cargo.lock` itself, verified by the current `tools/check_rust_dependency_lock.py`, is:

- SHA-256 `329f485f352afa35f3f6cb4df76ebf0c6e8b589a555386072f4a8750a5349987`;
- 130 resolved packages;
- 97 registry packages;
- 0 Git dependencies;
- 11 exact workspace direct dependencies.

D09 therefore does **not** mutate the accepted D08 workspace or dependency files to satisfy earlier historical snapshots. The current release dependency/source/licence proof follows the accepted A15 exact-head dependency pattern and strengthens it relative to D08:

- `Cargo.toml`, `Cargo.lock`, `deny.toml`, `dependencies/rust-direct-lock.json`, `dependencies/backend-artifact-lock.json`, the generated-contract manifest and generated Rust bindings must be byte-identical to the independently accepted D08 merge;
- `tools/check_rust_dependency_lock.py` validates the current D08-identical lock, exact selected direct dependencies, canonical crates.io source, registry checksums and zero Git dependencies;
- D09 cross-checks the current verifier report against the exact D08 lock identity `329f485f…` / 130 / 97 / 0 and the 11 exact direct selections;
- the older nested `cargo_lock` object in `rust-direct-lock.json` is retained and reported as historical evidence but is explicitly not used as the current D09 gate;
- `deny.toml` source/bans/licence policy and every external package licence expression exposed by `cargo metadata --locked` must remain within the committed allow-list;
- retained backend artifact/browser/signature identities remain exact;
- every external GitHub Action reference must be a full 40-hex immutable pin;
- the Apache-2.0 boundary validator and adversarial tests remain the operative public/private repository boundary.

The A01, Phase-0C package-universe and older nested Cargo snapshot remain historical evidence. They are not reinterpreted as the current D09 dependency baseline.

## Frozen D09 release corpus

The D09 corpus contains exactly ten cases:

1. `d09-01-human-agent-coexistence` — D01 human and D02 AI Workspace surfaces coexist without replacing caller authority.
2. `d09-02-deep-workspace-authority-separation` — the complete deep Workspace corpus remains mechanical under human, Hunter and Sergeant use.
3. `d09-03-concurrent-activity-operation` — A04 concurrency and failure isolation remain valid alongside Workspace use.
4. `d09-04-long-running-recovery` — A13/B06 recovery retains exact state and fails stale authority closed.
5. `d09-05-provider-replacement` — Provider/runtime generation may change without re-keying canonical Ptah identity.
6. `d09-06-plugin-rollback` — D05 rollback requires a fresh Attempt and independent post-verification.
7. `d09-07-provenance-reviewability` — D06 proof domains, exact subjects and reproduction evidence remain independently reviewable.
8. `d09-08-security-reproduction-history` — D07 preserves contradictory, negative, partial, failed, inconclusive and regressed security evidence.
9. `d09-09-application-truth` — D08 local/Android Application truth remains evidence-bound while deferred remote platforms remain blockers.
10. `d09-10-public-private-release-audit` — source/licence policy and private Workspace denial remain effective at release acceptance.

Every case declares `ptah_semantic_authority: false`. The checker rejects case-count drift, category drift, missing human/Hunter/Sergeant participation, widened Ptah authority, new Core requirements, frozen-contract changes or runtime-feature additions.

## Deep Workspace acceptance burden

The exact candidate must preserve the accepted deep Workspace study:

- 22 mechanical capabilities;
- 20 fixtures;
- 26 original positive/adversarial cases;
- 28 gap mappings;
- no new Core entity requirement;
- no frozen-contract reopening;
- no runtime-implementation authorization derived from the study.

The same candidate must pass D01 human acceptance and D02 AI Project Workspace acceptance. Hunter and Sergeant remain caller-side adapters; Ptah does not choose semantic context, trust, review verdict, approval, result acceptance or next action.

## Concurrent human and agent operation

D09 re-proves D01 Human Workspace shell v2 acceptance, D02 AI Project Workspace acceptance, A04 Activity runtime concurrency/failure isolation, the deep Workspace mechanical profile and the AI Workspace authority validator.

Worker completion, Activity success, UI status and Sergeant output remain distinct from caller/reviewer acceptance.

## Long-running recovery

D09 re-proves A13 checkpoint/restart/verified recovery and B06 Session Vault acceptance.

Recovery must preserve or explicitly reconcile canonical Workspace/Session identity, new Provider/Node Generations after replacement/restart, stable result handles, retained partial Artifacts, exact admitted/scheduled inputs, conflict/uncertain-effect evidence, and missing-capability or incompatible-target failures.

Checkpoint existence is not restore success. Stale Lease, Fence, Session or Provider authority may not survive recovery.

## Provider replacement and Plugin rollback

D09 re-proves D05 Package/Plugin lifecycle acceptance and replacement evidence retained by D06/D07.

Release acceptance preserves these laws:

- backend IDs and process handles are Aliases/evidence, not Ptah identity;
- Plugin installation is not activation;
- update decision is not execution;
- provider acknowledgement is not post-condition verification;
- stale/revoked Grants and stale Provider/Instance generations fail closed;
- rollback creates fresh A04 execution identities and requires independent post-verification;
- host/backend replacement advances generation/evidence without re-keying canonical Plugin/Finding/Claim/proof identity.

## Provenance and security evidence

D09 re-proves D06 and D07 acceptance plus canonical-store round trips.

Release acceptance does not collapse proof domains. SBOM existence is not vulnerability, licence or release approval; signature validity is exact-subject binding under one Trust Policy, not semantic correctness; reproduction requires fresh independent execution evidence; Observation, Finding, Claim, Evidence, review and reproduction remain distinct; remediation acknowledgement is not post-fix verification; contradictory, negative, partial, failed, inconclusive and regressed evidence remains retained.

D09 itself has no autonomous release-verdict authority.

## Application platform truth

D09 re-proves the exact D08 corpus:

- 25 `ptah-application-runtime` acceptance cases;
- 3 D01 shell projection integration cases;
- 28 aggregate D08 cases.

Linux local/packaged and proven Android composition may be represented only at their supported evidence boundary. Windows Node/VM, macOS Node, compatible iOS Simulator and live remote display remain explicit Programme E/remote-Node deferrals where required authority/capability does not exist. D09 cannot convert those deferrals into availability.

## Public/private, licence and source audit

The exact candidate must pass:

- byte identity to D08 for current Cargo/dependency/licence/backend/generated-contract authority files;
- immutable 40-hex pin audit for every external GitHub Action;
- exact `Cargo.lock` capture plus `cargo metadata --locked`;
- `tools/check_rust_dependency_lock.py` exact direct-dependency/source/checksum/no-Git validation;
- current D08 lock identity: SHA `329f485f352afa35f3f6cb4df76ebf0c6e8b589a555386072f4a8750a5349987`, 130 resolved, 97 registry, 0 Git, 11 direct selections;
- explicit non-use of the historical nested 116-package `cargo_lock` snapshot as the current gate;
- `deny.toml` source, wildcard, yanked and licence-policy consistency;
- current external dependency licence expressions constrained to the committed allow-list;
- retained backend identity and evidence-count validation;
- Apache-2.0 owner-acceptance adversarial tests and validator;
- D02 private-Workspace/private-Hunter access denial through its acceptance suite.

The Apache boundary must remain `owner_accepted_operative_verified` with `runtime_implementation_authorized: false` in its historical Phase-0C sense. D09 release acceptance does not rewrite that historical record.

Private THETECHGUY systems, customer/device/payment data, restricted adapters, proprietary donor material and private Hunter records remain outside public release evidence unless independently released and granted under their owning authority.

## Permanent exact-head proof

Workflow:

`D09 Full Workspace Release Exact Head Acceptance`

The permanent workflow must prove on one exact candidate SHA:

1. exact D08 predecessor and linear branch history;
2. remote implementation branch equals the candidate SHA;
3. exact seven-file D09 acceptance surface plus the three audited D07/D08 proof-hygiene path changes only;
4. no Cargo/product/schema/migration/generated-contract movement and exact D08 bytes for the dependency/contract authority set;
5. all external GitHub Actions immutably pinned;
6. current D08-bound dependency/source/licence identity, exact Rust dependency verification and retained backend identities;
7. D09 checker regressions and exact ten-case corpus;
8. deep Workspace 22/20/26 burden and non-authorizing AI validator;
9. D01, D02 and A04 concurrent operation acceptance;
10. A13 and B06 recovery acceptance;
11. D05 Plugin lifecycle/rollback/replacement acceptance;
12. D06 provenance acceptance and store round-trip;
13. D07 security evidence acceptance and store round-trip;
14. exact D08 25+3 acceptance corpus;
15. Apache/public-private/licence boundary;
16. `cargo fmt --all -- --check` and complete `cargo test --workspace --locked`;
17. clean exact worktree;
18. explicit retained release limitations;
19. immutable report-bundle digest;
20. retained artifact `d09-full-workspace-release-${TARGET_SHA}`.

A green workflow without the retained report bundle is not D09 acceptance.

## Merge rule

Promotion requires:

- permanent D09 workflow successful on one exact frozen SHA;
- retained artifact present for that SHA;
- branch head still equals that SHA;
- PR base is exact D08 merge `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`;
- changed paths remain exactly within the reviewed D09 release surface;
- repository review/rules expose no unresolved blocker;
- merge is constrained with `expected_head_sha` equal to the proven candidate.

After merge, independently verify `main`. The D09 merge commit must have exactly these parents:

1. D08 merge `ca6b3526ce9b58ffce11f8582be8fbf860dfa53d`;
2. the frozen proven D09 candidate SHA.

Only then may D09 be marked COMPLETE and Programme D be described as reaching the **Full Workspace Release** milestone.

## Rollback

Before merge, any failed or moved candidate remains unpromoted; retain failed evidence and return to the accepted D08 predecessor.

After merge, rollback is a normal reviewed revert of the D09 merge. Do not force-move `main`, delete retained evidence or reinterpret failed/inconclusive evidence as success.

## Explicit limitations and deferrals

- GitHub-hosted Ubuntu proof is CI-host evidence, not proof of a separately pinned production machine.
- D09 does not complete Programme E distributed Ptah.
- D09 does not complete Programme F OS-ready packaging.
- D09 does not make deferred D08 remote platforms available.
- D09 does not grant Ptah semantic context, review, approval, result-acceptance or next-action authority.
- D09 does not erase negative, partial, failed, inconclusive, contradictory or regressed evidence.
- D09 does not widen public access to private records or restricted adapters.
