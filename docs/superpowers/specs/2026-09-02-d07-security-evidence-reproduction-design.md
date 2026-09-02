# D07 — Security Evidence and Reproduction Design

## Authority

Roadmap authority: `ptah-roadmap-` commit `98dc8c4e8639cda80510bee0625db34b4fdf9384`.
Accepted predecessor: D06 merge `29755a63d3dabeb2a108a14c1a4b9dee97efe98c`.

D07 implements the accepted Phase-0A security-assessment boundary plus frozen WP12 Security/Finding/Claim/Evidence/remediation/reproduction contracts. It must preserve the core law that scanner, vulnerability-database, rule, CVE, report, workflow, model and backend identifiers are evidence/aliases rather than Ptah authority or canonical Finding identity.

WP12 authority is the frozen security catalog `urn:ptah:schema-catalog:security:0.1.0`: 18 canonical entity schemas plus shared definitions, five lifecycle machines, 24 cross-machine invariants and 40 frozen conformance scenarios.

## Architecture

Add one composition crate: `crates/ptah-security-evidence`.

The crate composes:

- A03 ledger for canonical WP12 records;
- A04 Activity/Operation/Attempt identities for assessment, validation, remediation and reproduction work;
- A06 Workspace/Secure Grant authority for assessment admission and private evidence access;
- A07 Object/Revision/Artifact truth for raw reports, evidence bytes, patches and disclosed outputs;
- D04 Recipe/Plan/service/precondition machinery for caller-authored assessment and remediation plans;
- D05 Package/Plugin exact revision evidence for scanner/workload identity;
- D06 provenance, SBOM, trust and proof-bundle evidence where security work consumes supply-chain proof;
- `ptah-contracts` frozen WP12 schema identities.

Semgrep, Syft/Grype, Trivy, GUAC, ZAP, Strix-like workers, ReproZip and ClaimBound-like renderers remain replaceable workloads/adapters. D07 does not install, privilege or select them automatically.

## Contract reconciliation

Phase-0A defines assessment-facing names such as `security.authorization`, `security.assessment_plan`, `security.assessment_run`, `security.coverage`, `security.scanner_revision`, `security.raw_report` and `security.finding_observation`. These tokens are not present in the frozen generated WP12 schema catalog in Ptah-space.

D07 therefore **does not add new canonical schemas or entity kinds**. Assessment Authorization, Plan, Target, Scanner Revision, Run and Coverage are D07-owned typed mechanical envelopes/projections whose real authority and identity come from existing A06/A04/A07/D04/D05 records. They may be serialized, hashed and retained as ordinary A07 evidence where callers need durable bytes, but their existence never creates new authority.

The 18 WP12 records remain the only D07-owned canonical A03 security records:

- `security.observation`
- `security.finding`
- `security.claim`
- `security.evidence_item`
- `security.evidence_bundle`
- `security.validation_run`
- `security.review_decision`
- `security.accepted_risk`
- `security.dispute`
- `security.disclosure_record`
- `security.remediation_proposal`
- `security.patch`
- `security.remediation_run`
- `security.post_fix_verification`
- `security.reproduction_protocol`
- `security.reproduction_request`
- `security.reproduction_run`
- `security.reproduction_comparison`

## Components

### 1. Canonical security store

`SecurityEvidenceStore` persists complete frozen WP12 documents through `CanonicalRecord::from_document` and A03. Its ingest surface is bounded to the 18 exact schema/kind pairs. D07 does not duplicate JSON-Schema validation or fetch schemas from the network.

Negative, partial, stale, disputed, rejected, failed and inconclusive records remain immutable history. Backend replacement creates new evidence/work records rather than rewriting existing records.

### 2. Assessment authorization

`AssessmentAuthorization` is a D07-owned projection over explicit caller authority. It binds:

- Workspace and authority subject;
- current A06 Secure Grant/Policy references;
- exact target references and digests;
- included/excluded scope;
- allowed test classes;
- forbidden/destructive action classes;
- credential/network/resource/time/rate limits;
- required isolation and privacy/redaction policy references;
- emergency-stop and cleanup/read-back requirements;
- validity window.

A URL, repository, image, customer request, scanner configuration or discovered host cannot authorize itself. Expired/revoked Grants fail before A04 work is created. Newly discovered targets remain out of scope until caller authority is extended.

### 3. Assessment plan, target and machinery

`AssessmentTarget` binds an exact Ptah revision/Artifact/Object plus SHA-256 digest and a scoped locator when needed. Mutable URL, branch, tag, deployment name, package name, issue ID or hostname is a resolution input only.

`ScannerRevision` separately retains exact provider/package/plugin/ruleset/advisory-database/policy/model/configuration identities. Machinery drift creates a distinct assessment/result evidence identity even if target bytes are unchanged.

`AssessmentPlan` binds one Authorization projection, exact Targets, exact Scanner Revision, D04 plan/operation descriptor references, coverage expectation, failure/stop policy and output-evidence policy. D07 never chooses a scanner semantically.

### 4. Assessment execution and coverage

`AssessmentRun` binds exact A04 Activity/Operation/Attempt identities. Active/fuzz/exploit/agentic work is admitted only under matching Authorization scope and A06 Grants. Retries require new A04 Attempts.

`CoverageProjection` retains expected, resolved, scanned, skipped, disabled, unsupported and error scope plus timeout/resource/crawl/auth limitations. `complete` is mechanical and cannot be inferred from “zero findings.”

Raw scanner/workload reports remain immutable restricted A07 Objects/Artifacts. Report paths and backend run IDs are aliases only.

### 5. Observation, Evidence, Finding and Claim

Scanner/manual/agent outputs first become bounded `security.observation` and `security.evidence_item` records. Evidence Item binds exact Content/Object bytes, digest, collector, Activity and Attempt.

`security.finding` is a reviewed correlation/interpretation over one or more Observations. Scanner output cannot create a confirmed Finding by itself. Correlation may support, contradict, split or merge interpretations but never deletes source Observations.

`security.claim` stays separate from Evidence. Claimant identity, bounded authority scope, exact subjects, evidence bundles, confidence and limitations are mandatory. A Claim cannot self-declare acceptance or verification.

Severity, confidence, exploitability, operational/business impact, remediation priority, policy effect and caller acceptance remain separate dimensions.

### 6. Validation, review, accepted risk and dispute

Validation Run uses new A04 Attempts and exact environment evidence. Review Decision records a reviewer/authority decision and may not rewrite Observation or Evidence history.

Accepted Risk requires authority, scope, rationale, conditions and expiry. Expiry returns the issue to review and never deletes the Finding.

Dispute retains all positions, Claims and contradictory Evidence. No automatic winner is selected by Ptah.

### 7. Disclosure and Evidence Cards

Disclosure Record binds audience, redaction/privacy policy, exact disclosed content, authority and time. Private evidence cannot enter a public disclosure merely because its hash/reference exists.

`EvidenceCardView` is a D07-derived sanitized view inspired by ClaimBound-style presentation. It may expose exact claim boundary, allowed claim sentence, result status, verification/reproduction/review levels, source/evidence references, hashes, limitations and public-safe summaries. It is **not** a canonical WP12 entity, certification, release approval or universal truth.

Raw credentials, cookies, tokens, exploit payloads, proprietary source, private hosts/topology and customer/private data never enter a public Evidence Card.

### 8. Remediation

Remediation Proposal, Patch, Remediation Run and Post-Fix Verification stay separate.

A Proposal does not create a Patch. A Patch binds an exact A07 Object and exact base revision(s); a filesystem path cannot become Patch identity. Patch/tool/application acknowledgement only yields `applied_unverified` evidence.

Remediation Run uses caller-approved D04/A04 work with backups and retained uncertain/rollback evidence. `fixed_verified` requires a separate Post-Fix Verification run under exact target/machinery/environment refs. Regression remains representable and cannot rewrite the original Finding/closure history.

### 9. Reproduction

Reproduction Protocol freezes claim scope, required inputs, environment requirements, independence requirements, success/failure criteria and version.

Reproduction Request is not execution. Reproduction Run requires new A04 Activity/Operation/Attempt identities, exact environment evidence and explicit independence evidence. Same cache, same mutable environment, hidden shared authority, retry of the same Attempt or simple re-verification cannot claim independence.

Reproduction Comparison is separate from the Run outcome and original Claim. `supports_claim`, `partially_supports`, `contradicts_claim` and `inconclusive` remain distinct. Failed, negative, partial and inconclusive reproduction remains immutable history.

### 10. Optional workload adapters

D07 exposes a narrow provider-neutral normalization boundary for security workload observations. Private adapters may translate Semgrep-, Trivy-, Grype-, ZAP-, GUAC- or agent-style results into D07 Observation/Coverage inputs, but no external type leaks through D07's public API.

Adapters cannot widen target scope, network/credential Grants, isolation, rate/time budgets, severity/acceptance authority or Finding lifecycle. Backend replacement preserves canonical security identities while creating fresh provider/work/evidence records.

## Failure model

D07 fails closed on:

- assessment work without current exact A06 authority;
- out-of-scope target, method, host, path, service, account or test class;
- expired/revoked authority;
- mutable coordinates presented as exact Target identity;
- scanner/rule/database/model drift hidden behind an old revision;
- zero-findings presented without Coverage evidence;
- report path/backend IDs used as canonical identities;
- Observation presented as reviewed Finding;
- scanner output presented as confirmed Finding;
- Claim without authority scope;
- Evidence Item without exact content/digest/collector/Attempt binding;
- Evidence Bundle overclaiming coverage;
- validation/reproduction Attempt reuse;
- Review rewriting evidence;
- expired Accepted Risk remaining active;
- Dispute deleting a competing position;
- private evidence disclosed publicly without policy/authority;
- Proposal presented as Patch;
- Patch path presented as identity;
- patch/application ACK presented as verified remediation;
- reproduction without demonstrable independence;
- negative/inconclusive reproduction deletion;
- public Evidence Card containing raw restricted evidence;
- security adapter/backend alias replacing Ptah identity.

## Acceptance corpus

D07 freezes exactly 30 milestone cases:

1. exact target + current Authorization/Grant required before assessment work;
2. expired/revoked Authorization blocks new A04 work;
3. out-of-scope test class/target fails before workload invocation;
4. newly discovered target does not extend its own authorization;
5. Assessment Plan binds exact Authorization, Target and Scanner Revision;
6. scanner/rules/database drift creates distinct result evidence;
7. zero-findings cannot claim complete coverage without complete Coverage;
8. raw report path/backend run ID remains alias, not identity;
9. Observation is not a Finding;
10. scanner result cannot become confirmed Finding without bounded review;
11. contradictory Observations remain visible;
12. bounded Claim requires claimant + authority scope and stays separate from Evidence;
13. Evidence Item binds exact content/digest/collector/Activity/Attempt;
14. Evidence Bundle cannot overclaim partial/unknown coverage;
15. Validation Run requires a fresh Attempt and exact environment evidence;
16. Review Decision cannot rewrite Observation/Evidence history;
17. Accepted Risk expires without deleting the Finding;
18. Dispute retains all competing positions/evidence;
19. public Disclosure requires explicit audience/redaction/privacy authority;
20. Remediation Proposal is not a Patch;
21. Patch requires exact A07 Object + base revision; path is alias only;
22. patch/application ACK cannot satisfy Post-Fix Verification;
23. regression remains visible after prior verified closure;
24. Reproduction Protocol freezes scope/environment/independence criteria;
25. Reproduction Request is not execution;
26. same cache/mutable environment cannot claim independent reproduction;
27. reproduction retry requires fresh A04 Attempt;
28. negative/partial/inconclusive reproduction remains retained;
29. Evidence Card is sanitized derived presentation with no acceptance/release authority;
30. scanner/reproduction backend replacement preserves Ptah identities and creates new work/evidence.

A separate canonical-store test must round-trip frozen WP12 records without changing the 30-case count. Targeted A03/A04/A06/A07/D04/D05/D06 regressions and the complete locked workspace must remain green.

## Proof and shipping

D07 follows the established milestone lane: design/plan commits, bounded TDD implementation commits, strict fmt/Clippy with no D07 warnings or suppressions, frozen-contract and Cargo-lock audits, exactly 30 milestone cases, canonical WP12 store proof, targeted predecessor regressions, complete `cargo test --workspace --locked`, exact-head GitHub workflow, frozen candidate SHA, PR, D07-specific CI, merge only the proven SHA and independent merge-parent verification.

## Explicit deferrals

D07 does not install or select Semgrep, Trivy, Grype, ZAP, GUAC, Strix, ReproZip, ClaimBound or any offensive framework. It does not create new security schema families, vulnerability databases, CVE truth, automatic remediation approval, release authority, global risk scoring, D08 application-platform expansion, D09 Full Workspace acceptance, Programme E distribution or Programme F OS-ready mechanics.
