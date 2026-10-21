# Ptah Formula WorkCell receiving adapter (candidate integration)

Consumes exactly versioned Formula-owned director envelopes. Pure validation of the canonical sender manifest/work-cell identities, capability references, resource/stop policy and side-effect prohibition. A04 dispatch MUST call preflight_with_custody with independently supplied expected manifest, work-cell, and mathematical authority identities; plain validate_handoff is only untrusted syntax/integrity inspection. Produces only an untrusted candidate receipt.

- This adapter does not parse natural-language mathematics, select a solver, execute a WorkCell, authorize admission, or issue proofs.
- Dispatch must use Ptah's existing A04 Activity/Operation/Attempt, E02 placement/lease fencing and qualified execution Provider without expanding Formula's allowed side effects.
- The fixture in tests/fixtures is emitted by Formula's Rust director integration test, not manufactured on Ptah.
- P13 is not qualified by envelope acceptance. Canonical P13 requires an actual Ptah workload and equivalent independent Formula-checked mathematical results versus the local path.

Test: cargo test --locked --offline -p ptah-formula-work-cells

## P13 canonical implementation (2026-10-21)

The actual Formula-owned QueryIR for the canonical P9 COUNT target is embedded in the canonical work-cell handoff with its digest and known input digest. Ptah validates query identity, side effects and finite resource contract before offering work to existing Ptah E01/E02/A05 facilities.

Control's optional Formula preflight is built into the existing ptah-e07-control-dispatch binary. Its three independent inputs must be supplied together: --formula-handoff, --formula-work-cell and --formula-authority. A malformed or unauthorized packet is rejected before binding a listener. The non-Formula E07 control path is unaffected.

Tests: cargo test --locked -p ptah-formula-work-cells; cargo test --locked -p ptah-node --test formula_p13_e07; cargo test --locked -p ptah-control --bin ptah-e07-control-dispatch.

Physical KRATOS-to-ATHENA one-shot E01/E02/A05 with Formula Control preflight passed with durable physical Node exit 0 and output digest sha256:2e6d31a5983a91251bfae5aefa1c0a19d8ba3cf601d0e8a706b4cfa9661a6b8a. The persistent ATHENA Ptah worker was untouched. The physical ack is NOT an independent signed effect witness and does not transfer arbitrary result bytes; the Node durable journal supplies corroborating output digest.

Only the canonical P9 count work-cell local-vs-Ptah equivalence has been qualified here. Formula, not Ptah, runs the independent semantic checker, and neither Ptah process success nor its manifest hash can promote mathematical authority. See Formula's existing docs/integration/2026-10-21-mathematical-director-ptah-boundary.md for exact evidence and limitations.

### Post-review P1 type separation

- validate_handoff returns InspectedFormulaWorkCell, a structurally inspected but UNTRUSTED value that cannot be passed to candidate_only_receipt.
- preflight_with_custody returns the distinct ValidatedFormulaWorkCell with private construction after checking the caller-owned expected manifest, work cell and authority identities. Only the custody-approved type can emit candidate receipts or be used as approved dispatch work.

### Exact additive Ptah workspace admission

Historical A01 (18 workspace members), E06 and E07 lock bytes remain immutable. The P13 adapter adds one reviewed local workspace member and exact Control/Node Cargo.lock dependencies; tools/check_e06_dependency_evolution.py reverses only these allowlisted byte sequences, after which the original historic checksum must still match. A01, retained Phase 0C and all 20 A01/E06/P13 negative tests pass. The new GitHub workflow uses the repository-approved immutable checkout action pin.

### P13 current-head admission and TLS vulnerability repair

The current-head admission classifier requires the exact Formula WorkCell interface, custody-bound Control binary and real E02/A05 regression tests. It identifies historical A14, D08 and E01 proofs as **not rerun** and instead requires P13-owned proof plus the universal exact-head workspace tests. Changes beyond the declared P13 paths continue to fail closed.

RUSTSEC-2026-0382: the already-present transitive rustls-webpki dependency was upgraded from 0.103.15 to 0.103.16. The Cargo.lock inverse checker accepts exactly the reviewed version/checksum pair while reconstructing the pre-P13 frozen E07/E06 byte stream. No external dependency was added and no historical checkpoint was rewritten.
