# Ptah universal PR admission and historical phase applicability
Date: 2026-10-16. Governing scope: Ptah repository PR admission; **not** Search activation.

## Exact-head evidence and non-waiver rule

Hosted Search PR #121 at `581431356691f4e6bbbd7679ce7e1b03a35650cd`
has 13 successful and 22 failed workflow runs. Every failed workflow stops at its
**phase-specific predecessor/scope/dependency-universe** check before substantive
phase tests. These are real failing historical checks, not Search failures and
**not passing phase proofs**. Evidence from GitHub workflow job step results is
retained by GitHub, not erased or re-labelled.

## Changes

1. Add `.github/workflows/current-head-universal-admission.yml`, **no PR paths
   filter**: every pull request to `main` must qualify its actual checked-out
   `pull_request.head.sha` against the PR's pinned base SHA.
2. Require fail-closed `tools/check_current_pr_admission.py`: root commit
   relationship, exact diff, frozen 22-phase workflow event-only integrity,
   phase-owned change rejection, scope classification, and zero runtime activation.
3. Run the existing current-head Rust direct-lock, A01 evolved/frozen scaffold,
   Phase 0C no-build validator, pinned Git source manifest custody tests,
   and formatting checks. If the Search adapter is changed, separately invoke
   the strict Search A05 exact-scope checker and its bridge tests.
4. Update **only `pull_request` trigger applicability** for 22 historical
   workflows. Their original signed/predecessor/scope proof steps and phase
   push/dispatch events remain byte-identical. A01/Phase 0C/security/signed
   artifact workflows continue to run for *all* pull requests.
5. Exclude **shared Cargo.toml, Cargo.lock, dependencies/** from triggering
   old frozen A/C/D phase-specific historical proof workflows on otherwise
   unrelated PRs. Such shared dependencies are validated by the **universal
   current-head baseline plus dedicated always-on Rust dependency-policy
   workflow**, not by re-running a predecessor-locked historical proof.
6. E01–E05 PR triggers are narrowed to phase-specific sources, conformance
   tools or self-workflow edits; their original strict test bodies and owned
   phase-branch push/manual requalification paths remain intact.

## Individual historical workflows, classified against Search #121

All 22 were checked through GitHub's *actual failed job step* on the same commit:

| Historical proof | Failed precondition observed on Search #121 |
|---|---|
| A02 | Old dependency-universe count and selection |
| A07 | A07 exact head and path scope |
| A08 | A08 exact head and path scope |
| A09 | A09 exact head and path scope |
| A11 | A11 exact predecessor and path scope |
| A14 | A13 predecessor and A14 scope |
| C08 | C08 base/protected path scope |
| C09 | C09 base/protected path scope |
| C10 | C10 base/protected path scope |
| C11 | C11 base/path and Cargo construction |
| D02 | D01 predecessor and D02 scope |
| D03 | D02 predecessor and D03 scope |
| D04 | D03 predecessor and D04 scope |
| D05 | D04 predecessor and D05 scope |
| D06 | D05 predecessor and D06 scope |
| D07 | D07 exact SHA, predecessor and linear history |
| D08 | D08 exact SHA, predecessor and linear history |
| E01 | E01 predecessor and reviewed delta |
| E02 | E02 predecessor and reviewed delta |
| E03 | E03 predecessor and reviewed delta |
| E04 | E04 predecessor and reviewed delta |
| E05 | E05 predecessor and reviewed path set |

The old workflows remain authoritative **only** for their phase-specific change
sets. Their previous failing historical run records remain truthful.
The new universal gate reports `NOT_APPLICABLE_NOT_TESTED` for irrelevant
phase checks; it never creates substitute green status checks.

## Required GitHub merge policy (to be enabled and physically verified)

- `Current-head universal admission / exact-head-current-pr` — mandatory on
  all PRs targeting main. Never filtered by paths or skipped by an
  outside-branch `if`.
- `Phase 0C Rust dependency policy` — mandatory, validating RustSec advisories,
  bans, license and source constraints without ignoring advisories.
- `A01 reproducible scaffold proof` and `Phase 0C scaffold` — mandatory.
- `Phase 0C backend artifact evidence` and `Phase 0C backend signature
  evidence` — mandatory on exact head, preserving signature chain and hashes.
- `Search A05 exact-head scope proof (additive)` is supplemental and cannot
  replace a universal check or become permission to activate the A05 provider.
- Separate E07/node enrollment, production signing and physical activation
  remain outside this PR admission; search runtime is not switched on.

**Branch protection/ruleset configuration must actually enforce these required
contexts**; a document alone is not enforcement. Never merge PR #121 merely
because GitHub says `mergeable=true`. Reconcile main and Search branch only
after the governance PR is qualified and merged under this policy.

## Security and validity constraints

- No code or test body of the 22 historical proof workflows changed, except
  PR applicability triggers.
- Historical branch push proofs and manual dispatch remain unchanged.
- If a PR edits phase-owned files, universal policy **fails closed**, requiring
  the owning proof/phase governance rather than treating older results as valid.
- If a PR tries to alter any historic workflow code with trigger-only approval,
  it fails; full proof changes require new audited governance authority.
- Rust `deny.toml`, signed artifact custody, frozen phase history, source
  trust anchors, enrollment and Browser Provider runtime are not weakened.
- ZMW 0 for Search; no paid API, trial, paid overflow or activation.

## Acceptance receipts

Source qualification: `python3 -m unittest tools/test_check_current_pr_admission.py -q`;
Phase 0C/A01/dependency checks independently run. Use a new GitHub Actions
run at the **actual governance and Search PR heads** before merge. GitHub
required-status rule application must be independently inspected after write.

**Disposition before required-check configuration:** candidate only, not full
admission. The phase-proofs remain distinct and no phase status is spoofed.
