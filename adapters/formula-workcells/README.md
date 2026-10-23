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

### Native signed candidate-readback gate

Ptah Control now combines the existing A04-custody-approved Formula WorkCell,
completed E03 candidate bytes/full SHA-256, durable E02/A05 Node completion
and the existing Ed25519 independent-effect witness verifier. Conflicting
attempts, forged signatures, changed result bytes, failed exits and altered
request digests are rejected. The returned receipt remains candidate-only
and Formula must independently check its mathematics.

The exact current readback implementation and negative tests are in
services/ptah-control/src/formula_readback.rs. CI also exercises the
existing native E03 TLS full/range-resume suite. This is a structural/local
integration qualification, not a new physical two-machine transfer or a
live external-witness deployment. E03 current-ticket issuance and recovery
remain native Ptah transport responsibility.


### Optional durable Node candidate for E03 (2026-10-22)

The existing native E07 Node worker now accepts an optional caller-owned
existing `candidate_dir`. When supplied, only a zero-exit process with
complete (not truncated) A05 stdout produces a bounded (16 KiB maximum),
atomically created, attempt-and-digest-named candidate file. Persisting and
opening this source occurs before journal completion; the exact resulting
SHA-256 must match the journal output. Byte-equivalent retries reuse the
same artifact; conflicts, truncation, altered data, unsafe directories,
or nonzero exits fail closed. The old worker configuration is unchanged
when `candidate_dir` is omitted.

`DurableCandidateSource` implements Ptah's original E03
`ExactRangeSource` using the persisted file, with readback SHA-256 and
bounded ranges. No alternate transfer engine, dispatch permission, math
authority, or autonomous cross-Node dependency was created. This supports
an actual E03 byte source; full physical KRATOS/ATHENA transfer and
independent external-witness deployment still require distinct observed
receipts before general P13 physical acceptance can be marked complete.

### Current E03 geometry and candidate-to-witness acceptance

A native Ptah P13 regression now exercises the full **hermetic** chain:
E01 current-session identities, Control-issued E03 ticket, both Node
ticket guards, the durable original A05 candidate file, authenticated
TLS 1.3 transfer interrupted between two exact authorized byte ranges,
resumed cursor verification, whole-file SHA-256 and the existing signed
Control readback. It rejects changed signatures and revoked tickets.
Native E03 now enforces each ticket's exact range geometry at both peers
instead of silently using the global byte ceiling. The pre-existing E03
TLS tests were corrected to declare their previously assumed MAX_RANGE_BYTES
ticket geometry.

**Qualification boundary:** this integration test uses two distinct
in-process Ptah NodeAgents and a fixture-owned Ed25519 key, all on the
same test host. It does NOT claim physical KRATOS-to-ATHENA E03 data
transfer or an independently operated witness service. Native workload
math promotion still belongs only to Formula.

### Isolated two-host E03 validation runner (2026-10-23)

The opt-in `p13_physical_e03_crossnode` native test runner (never a
production service) executes the unmodified DirectSourceSession and
DirectTargetSession over TCP/mTLS and verifies a genuine one-range
interruption followed by exact-byte resume. Formula canonical candidate
`9\n` is used; a Control-issued short-lived E03 ticket is created
under fresh **test-owned** E01 identities. The runner can be compiled on
Windows by the one-day GitHub CI artifact. This test intentionally embeds
only the repository's public **test fixture** mTLS certificates; its
results are proof of physical wire interoperability, not authorization
to admit that PKI to the production Control plane.

No standing remote dispatch, shared development machine dependency,
firewall change or new transfer protocol is introduced. A subsequently
separate independent witness verification is required to claim a fully
witnessed cross-host Formula execution. The runner's test artifacts
must be cleaned when the qualification is complete.
