# A15 — Online Ptah Alpha acceptance

Status: release candidate; acceptance is valid only for the exact implementation head proven by the A15 workflow.

## Authority

- A14 accepted implementation base: `db74eccbd988fc1e30349412aa08b4464ca8d3c1`.
- Phase 0B frozen contract checkpoint: `dc2db457f1705d0cba80f17ab76e5e93f808aee0`.
- WP14 frozen corpus/proof-plan merge: `fef387c4f074af7fcf86f2d99f7f9b7637e91f88`.
- Frozen WP14 corpus SHA-256: `809dc89e848737d1b2fa7cc3e6aecf92cf7ffe008dee8c2fb3b7cf3cd9e3baaa`.

This closeout does not reopen A01–A14 runtime semantics. It binds and proves the accepted implementation against the already frozen WP13/WP14 burden.

## Acceptance obligations

The exact-head workflow must retain evidence for all of the following before the candidate can be promoted:

1. the frozen 16-case WP14 golden/negative corpus passes unchanged;
2. the corrected AI Project Workspace/Hunter boundary validator and its regressions pass;
3. the deep Workspace operations validator and its 26 adversarial regressions pass with 22 mechanical capabilities, 20 fixtures and the ten-primary/ten-verifier study formation intact;
4. frozen generated contract metadata remains bound to 14 catalogs, 346 schemas, 99 lifecycle machines and the WP14 merge;
5. local generated schema lookups pass with Cargo forced offline after the exact dependency universe is fetched;
6. the inherited A14 human control acceptance suite passes without modifying the A14 runtime surface;
7. the full inherited Rust workspace suite passes at the exact candidate head;
8. dependency locks, backend-artifact lock metadata, reports and logs are digest-bound in one report bundle;
9. a missing or empty required report makes bundle construction fail even when preceding commands were green;
10. Ptah retains no caller-work selection, semantic context selection, review, result-acceptance or autonomous-upgrade authority.

## Release rule

Promotion is allowed only when all of these are true for one exact pull-request head:

- the A15 workflow conclusion is successful;
- `report-bundle.json` exists and names that exact head;
- `report-bundle.sha256` verifies the bundle bytes;
- every required report named by the bundle is present, non-empty and SHA-256 bound;
- the pull-request head has not moved since proof;
- review finds no scope drift outside the A15 acceptance surface.

A green GitHub status without the retained report bundle is not acceptance.

## Limitations

- A15 is an acceptance and handback milestone, not a new Provider or execution feature.
- GitHub-hosted Ubuntu proof is accepted CI-host evidence only; it is not represented as proof of a separately pinned physical machine.
- The backend-artifact lock and previously retained Phase 0C artifact evidence remain the backend identity authority; A15 does not silently redownload or replace those artifacts.
- `authorized_for_dispatch` remains permission to dispatch, not proof that an external side effect succeeded.
- Worker completion remains separate from caller/reviewer acceptance.
- Diagnostic advice remains evidence-backed input to a caller decision; it cannot approve or execute its own recommendation.

## Rollback

If exact-head A15 proof fails before promotion, do not promote the candidate; retain the failed reports and continue from the last accepted A14 implementation base `db74eccbd988fc1e30349412aa08b4464ca8d3c1`.

If a promoted A15 merge must be rolled back, create a normal reviewed revert of the A15 merge. The rollback target is the A14 product state above; do not force-move `main`, delete retained evidence or reinterpret a failed/inconclusive A15 report as success.

This document records procedure only. It does not self-approve the release candidate.