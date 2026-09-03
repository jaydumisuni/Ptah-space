# D07 Security Evidence & Reproduction — Durable Proof Record

## Frozen authority

D07 is implemented strictly above the frozen Phase 0C predecessor contracts. The exact predecessor and required `main` head for candidate proof is:

`29755a63d3dabeb2a108a14c1a4b9dee97efe98c`

That commit is the D06 merge (`Provenance, SBOM, signing and proof bundles`). D07 does not amend the frozen schema catalogs, generated contract bindings, migrations, or predecessor ownership boundaries.

The frozen D07 design and implementation plan are:

- `docs/superpowers/specs/2026-09-02-d07-security-evidence-reproduction-design.md`
- `docs/superpowers/plans/2026-09-02-d07-security-evidence-reproduction.md`

The final pre-proof-artifact implementation tree was proved on branch head `1e96558680da718a33160563eed7c256e135cc5b`. The permanent exact-head workflow must separately prove the proof-artifact candidate SHA before merge.

## Architecture boundaries

D07 composes existing authorities; it does not replace them.

- **A03 Ledger** remains canonical persistence. `SecurityEvidenceStore` uses `Ledger` and `CanonicalRecord::from_document` and admits only the exact frozen WP12 security schema/kind allow-list.
- **A04 Activity / Operation / Attempt** remains execution authority. D07 may create mapped assessment work only after target, authorization and plan validation succeed. D07 does not redefine A04 success proof.
- **A06 Workspace / Secure Grant** remains authority truth. D07 consumes an exact current Secure Grant for an exact subject and scope; target discovery never expands authorization.
- **A07 Object / Revision / Artifact** remains content and immutable revision identity. Patch paths and backend paths are aliases only.
- **D04 Recipes**, **D05 Package/Plugin lifecycle**, and **D06 Provenance/SBOM/signing** remain predecessor-owned inputs and evidence authorities.
- D07 does not select targets, scanners, rules, advisory databases, providers, recipes, policies, permissions, or remediation authority for the caller.
- Private backend identifiers, paths and run aliases never become Ptah identity or authority.

### Security interpretation separation

- Observation is immutable evidence and is never Finding identity.
- Finding, Claim, Evidence Item, Evidence Bundle, Validation Run and Review Decision remain distinct records.
- Contradictory observations are retained rather than erased by correlation or review.
- Coverage cannot be declared complete when skipped, unsupported, errored or otherwise unscanned expected scope remains.
- Accepted Risk expires independently and never deletes the underlying Finding.
- Dispute retains competing Claims and Evidence Bundles.
- Disclosure requires explicit audience, redaction and privacy authority.

### Remediation separation

- Remediation Proposal is not Patch identity.
- Patch is bound to exact A07 content/revision, exact base revision(s), generator revision and canonical digest; a path is only an alias.
- Provider acknowledgement remains `applied_unverified` and cannot satisfy post-fix verification.
- Post-Fix Verification requires a fresh A04 Attempt and exact target/environment/evidence bindings.
- Regression is appended to history rather than rewriting a prior verified result.

### Independent reproduction separation

- Reproduction Protocol freezes claim scope, required inputs, environment constraints, independence requirements and success/failure criteria.
- Reproduction Request is intent only and exposes no A04 Activity identity.
- Reproduction Run requires fresh Attempt identity and mechanical independence evidence.
- Same cache, mutable environment or hidden shared authority cannot claim independence.
- Reproduction Comparison retains negative, partial, failed and inconclusive outcomes without rewriting the original Claim.

### Evidence Card and backend replacement

- Evidence Card is a sanitized derived presentation only. It is always `authoritative = false` and `release_approved = false`.
- Restricted raw field families are rejected at the card boundary and are not retained in the card.
- Replacing a private security backend creates a new provider revision/evidence trail while preserving canonical Finding and Claim identity when the canonical subjects remain the same.

## A06 exact Grant helper

D07 adds the bounded A06 helper:

`WorkspaceStore::authorize_grant(&self, actor_ref, subject_ref, required_scope, grant_ref) -> Result<(), WorkspaceError>`

The helper applies the existing exact Secure Grant subject, grantee, lifecycle, revocation, expiry and scope checks without the same-Workspace retrieval shortcut. `authorize_retrieval` reuses the same exact Grant predicate for its cross-Workspace Grant path while retaining its same-Workspace shortcut only for retrieval.

The only A06 files in the D07 surface are:

- `crates/ptah-workspace/src/lib.rs`
- `crates/ptah-workspace/tests/a06_acceptance.rs`

## Cargo and lock boundary

D07 adds the workspace member `crates/ptah-security-evidence`.

The lock delta is exactly one new local package:

`ptah-security-evidence 0.0.0-phase0c`

The pre-artifact implementation proof compared Cargo.lock package maps against exact D06 and proved:

- no predecessor package entry was removed;
- no predecessor package entry changed;
- no additional package other than `ptah-security-evidence` was added.

## Canonical WP12 security store audit

The D07 A03 store admits exactly these 18 schema/kind pairs:

| # | Frozen schema URN | Canonical entity kind |
|---:|---|---|
| 1 | `urn:ptah:schema:security:accepted-risk:0.1.0` | `security.accepted_risk` |
| 2 | `urn:ptah:schema:security:claim:0.1.0` | `security.claim` |
| 3 | `urn:ptah:schema:security:disclosure-record:0.1.0` | `security.disclosure_record` |
| 4 | `urn:ptah:schema:security:dispute:0.1.0` | `security.dispute` |
| 5 | `urn:ptah:schema:security:evidence-bundle:0.1.0` | `security.evidence_bundle` |
| 6 | `urn:ptah:schema:security:evidence-item:0.1.0` | `security.evidence_item` |
| 7 | `urn:ptah:schema:security:finding:0.1.0` | `security.finding` |
| 8 | `urn:ptah:schema:security:observation:0.1.0` | `security.observation` |
| 9 | `urn:ptah:schema:security:patch:0.1.0` | `security.patch` |
| 10 | `urn:ptah:schema:security:post-fix-verification:0.1.0` | `security.post_fix_verification` |
| 11 | `urn:ptah:schema:security:remediation-proposal:0.1.0` | `security.remediation_proposal` |
| 12 | `urn:ptah:schema:security:remediation-run:0.1.0` | `security.remediation_run` |
| 13 | `urn:ptah:schema:security:reproduction-comparison:0.1.0` | `security.reproduction_comparison` |
| 14 | `urn:ptah:schema:security:reproduction-protocol:0.1.0` | `security.reproduction_protocol` |
| 15 | `urn:ptah:schema:security:reproduction-request:0.1.0` | `security.reproduction_request` |
| 16 | `urn:ptah:schema:security:reproduction-run:0.1.0` | `security.reproduction_run` |
| 17 | `urn:ptah:schema:security:review-decision:0.1.0` | `security.review_decision` |
| 18 | `urn:ptah:schema:security:validation-run:0.1.0` | `security.validation_run` |

The audit checks every schema URN against `ptah-contracts` generated `SchemaBinding` data and independently verifies the frozen schema-slug to `security.<kind>` mapping. The generated security catalog contains 19 schema bindings; D07 intentionally admits the 18 WP12 canonical records listed above.

## D07 acceptance corpus — exactly 30 cases

| # | Acceptance case |
|---:|---|
| 1 | `exact_target_and_current_grant_are_required_before_assessment_work` |
| 2 | `expired_authorization_blocks_before_a04_activity_creation` |
| 3 | `out_of_scope_test_class_or_target_fails_before_workload_invocation` |
| 4 | `newly_discovered_target_never_extends_its_own_authorization` |
| 5 | `assessment_plan_binds_exact_authorization_target_and_scanner_revision` |
| 6 | `scanner_rules_database_or_configuration_drift_changes_plan_identity` |
| 7 | `zero_findings_cannot_claim_complete_coverage_with_gaps` |
| 8 | `raw_report_path_and_backend_run_id_are_aliases_not_identity` |
| 9 | `observation_is_not_a_finding_identity` |
| 10 | `scanner_candidate_requires_explicit_bounded_review_before_confirmation` |
| 11 | `contradictory_observations_both_remain_visible` |
| 12 | `bounded_claim_requires_claimant_authority_scope_and_evidence` |
| 13 | `evidence_item_binds_exact_content_digest_collector_activity_and_attempt` |
| 14 | `evidence_bundle_cannot_overclaim_partial_or_unknown_coverage` |
| 15 | `validation_run_requires_fresh_attempt_and_exact_environment_evidence` |
| 16 | `review_decision_references_but_never_rewrites_observation_or_evidence_history` |
| 17 | `accepted_risk_expires_without_deleting_the_finding` |
| 18 | `dispute_retains_all_competing_claims_and_evidence` |
| 19 | `public_disclosure_requires_explicit_redacted_content_and_privacy_authority` |
| 20 | `remediation_proposal_is_not_a_patch` |
| 21 | `patch_requires_exact_a07_object_base_revision_and_digest_while_path_is_alias_only` |
| 22 | `patch_application_acknowledgement_remains_applied_unverified` |
| 23 | `post_fix_verification_requires_fresh_attempt_and_retains_regression_after_prior_closure` |
| 24 | `reproduction_protocol_digest_changes_with_scope_environment_or_independence` |
| 25 | `reproduction_request_is_not_execution_and_exposes_no_activity_identity` |
| 26 | `same_cache_mutable_environment_or_hidden_shared_authority_cannot_claim_independence` |
| 27 | `reproduction_retry_requires_a_fresh_a04_attempt` |
| 28 | `negative_partial_failed_and_inconclusive_reproduction_history_is_retained` |
| 29 | `evidence_card_is_sanitized_derived_presentation_without_acceptance_or_release_authority` |
| 30 | `backend_replacement_preserves_ptah_identity_and_creates_new_provider_and_evidence` |

The canonical-store round-trip is intentionally separate from this 30-case count and proves a real frozen `security.observation` can be written/read through A03 while a canonical non-WP12 document is rejected.

## Proof evidence before proof-artifact freeze

The corrected Task 7 proof completed green in GitHub Actions run `33728216378`. That gate first reproduced the previously hidden single D07 lint suppression, removed it by introducing the bounded `EvidenceCardContent` input shape, and then proved:

- exactly 30 D07 acceptance cases;
- separate canonical store round-trip;
- strict D07 Clippy with pedantic warnings denied;
- explicit zero `#[allow(...)]` / `#[expect(...)]` suppressions in `ptah-security-evidence`;
- exact 18 WP12 schema/kind audit;
- targeted predecessor regressions.

The final pre-artifact implementation proof completed green in GitHub Actions run `33728733181` and proved from a clean checkout:

- `origin/main` still equals exact D06 predecessor `29755a63d3dabeb2a108a14c1a4b9dee97efe98c`;
- D06 is the merge base and D07 candidate history is linear;
- final implementation diff is limited to the approved D07 surface;
- no schema, migration or generated-binding changes;
- Cargo.lock adds only `ptah-security-evidence` and preserves every predecessor package entry;
- static D07 security boundaries and exact 18 WP12 mapping;
- `cargo fmt --all -- --check`;
- strict D07 Clippy;
- D07 package and exact 30-case acceptance corpus;
- separate canonical store round-trip;
- targeted predecessor regressions;
- `cargo test --workspace --locked`;
- clean Git status after proof.

## Explicit deferrals and non-claims

D07 deliberately does **not** provide or claim:

- automatic target discovery or authorization expansion;
- scanner, rule, advisory database, model, provider, recipe or policy selection;
- new canonical schema, lifecycle, migration or generated contract binding;
- release certification, release approval or authority derived from an Evidence Card;
- identity or authority derived from backend-local run IDs, paths, URLs or aliases;
- D07-owned execution success proof; A04 remains execution authority;
- a frozen private scanner/backend implementation in the public contract;
- automatic remediation authority; execution remains explicitly caller/A04-authorized;
- deletion or rewriting of contradictory, disputed, negative, failed, inconclusive or regressed evidence history.

## Shipping gate

This record does not by itself assert D07 is merged. The commit containing this record and `.github/workflows/d07-security-evidence-reproduction-proof.yml` is the proof-artifact candidate. It may be submitted only after that exact SHA passes the permanent exact-head workflow from a fresh checkout, the remote branch is verified to the same SHA, PR mergeability/rules are inspected, and merge is constrained to that frozen head.
