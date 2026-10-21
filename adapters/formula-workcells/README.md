# Ptah Formula WorkCell receiving adapter (candidate integration)

Consumes exactly versioned Formula-owned director envelopes. Pure validation of the canonical sender manifest/work-cell identities, capability references, resource/stop policy and side-effect prohibition. A04 dispatch MUST call preflight_with_custody with independently supplied expected manifest, work-cell, and mathematical authority identities; plain validate_handoff is only untrusted syntax/integrity inspection. Produces only an untrusted candidate receipt.

- This adapter does not parse natural-language mathematics, select a solver, execute a WorkCell, authorize admission, or issue proofs.
- Dispatch must use Ptah's existing A04 Activity/Operation/Attempt, E02 placement/lease fencing and qualified execution Provider without expanding Formula's allowed side effects.
- The fixture in tests/fixtures is emitted by Formula's Rust director integration test, not manufactured on Ptah.
- P13 is not qualified by envelope acceptance. Canonical P13 requires an actual Ptah workload and equivalent independent Formula-checked mathematical results versus the local path.

Test: cargo test --locked --offline -p ptah-formula-work-cells
