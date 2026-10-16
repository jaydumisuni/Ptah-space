# Search A05 exact-head CI applicability — additive governance candidate (16 October 2026)

## Why this exists

Search PR #121 changed only eight Search A05 adapter/documentation files at original head `9c0327f`. Remediation head `a306444` additionally changed five Rust dependency-policy files, applying the independently qualified fix from draft PR #123. **All five exact-head E01–E05 historic phase-proof workflows remain bound to different phase-specific change sets.** Their attempts to interpret any unrelated PR as their phase's exact set generate non-applicability failures rather than evidence of a Search regression.

This checker proves the exact Search diff (and optionally the **complete** five-file dependency remediation) without changing phase-owned workflows, inventing PASS statuses, or bypassing signed evidence. It must not be substituted for any required phase gate without explicit repository governance review and branch-protection validation.

## Qualification rules

- Verifies the actual checked-out Git commit equals `pull_request.head.sha`; ensures main is an ancestor.
- Only eight frozen Search A05 paths or those eight **plus exactly five** dependency remediation paths are allowed. Any subset of remediation files, unexpected workflow/trust/contract change, or unrelated source is rejected.
- Verifies checked-in Search documents include a concrete 64-character pinned wheel checksum and zero-cash commitment.
- On a remediation branch, reruns the existing strict Rust direct-lock checker; it does not edit `deny.toml` or suppress advisories.
- Runs Search adapter contract tests with the existing read-only bridge and no production A05 Node enrollment.
- The output explicitly says `SEARCH_SCOPE_VERIFIED_ONLY_OTHER_INDEPENDENT_GATES_REMAIN`; it is **not a production admission receipt**.

## Baseline and pending work

On 16 October 2026, direct GitHub inspection of PR #121 exact head `a30644418ca1cd55682055e94ac0ec081902ee7a` established:
- Phase 0C Rust dependency-policy **SUCCESS on exact Search head**, with Rustls 0.23.46 and original cargo-deny policy.
- Other broader Ptah phase workflows fail because old phase-specific change-set assumptions are run against Search; A01 and Phase 0C no-build have independently reproducible current-main baseline discrepancies.
- Git source static backend evidence fails an immutable signed manifest digest comparison. This **cannot** be cleared by silently replacing the signed manifest checksum: require authentic signature verification, approved custody, and a new exact-head signer evidence receipt.
- Existing E01–E05 proofs must remain immutable on their owned phase heads. The repository's required-check governance must decide which checks apply to future unrelated PRs, and make a universal current-head baseline/security gate mandatory before any scope-specific skip can be accepted.

**Do not merge Search PR #121, auto-enroll providers, modify the live browser, or activate Production** based on this additive checker. Continue issue #122 until independently authorized admission conditions are actually met. No payments or paid Search providers.

### Exact-head scope evolution (16 October)
The Search branch also contains the complete independently validated Rust remediation and the exact signed-manifest/A01/Phase 0C custody changes. The Search A05 additive verifier accepts only the complete enumerated governance file set, runs the real Rust lock, A01, Phase 0C and signed-manifest tests, and rejects all other workflow/frozen authority modifications. Its own four governance files are individually pinned in the allowlist. This remains **scope verification**, not an E01–E05 proof substitute, merger authorization or production activation.
