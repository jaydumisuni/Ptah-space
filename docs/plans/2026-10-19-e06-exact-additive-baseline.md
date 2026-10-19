# E06 exact-additive historic baseline evolution

Date: 2026-10-19. Classification: engineering candidate / no production grant.

This submission retains both the A01 frozen contract digest and the E01-evolved
Cargo.lock digest in dependencies/rust-direct-lock.json unchanged.

The current E06 candidate adds exactly one private workspace-only member,
crates/ptah-offline-intent, immediately before crates/ptah-transfer.
Cargo.lock adds one exactly specified local package stanza requiring only the
existing, pinned rusqlite and serde_json crates. Removing that exact stanza
byte-for-byte reconstructs the historic E01 lock and historical SHA-256.
Any change outside that one stanza, duplicate stanza, dependency swap,
extra external package, or unknown workspace member must fail closed.
No historical phase receipt is silently promoted to a current-head pass.

KRATOS exact candidate worktree:
- check_a01_scaffold.py: PASS, 39 total and 18 frozen A01 members.
- check_phase0c_scaffold.py: PASS with original historical digest intact.
- check_rust_dependency_lock.py: PASS.
- full cargo test --workspace --locked --offline: PASS.
- test_check_a01_scaffold and new negative lock-evolution checks: PASS (16).
- current PR admission/search/manifest test suite: PASS (31).
- ptah-offline-intent tests and strict Clippy: PASS.
- Oracle transport and Ptah workspace remain distinct.

This is not E06-03 live authenticated reconnect, E06-07 release,
or E07 native two-Node production acceptance. E01-E05 package proofs,
production keys, owner decisions and reviewer signoff remain separately owned.


## E06 reconnect reference evidence — October 20 implementation

The E06 envelope can now atomically persist a versioned optional
ReconnectDependencies record with exact creation timestamp, observed E01
session, E02 fence, E03 object digest/generation, E04 checkpoint digest and
E05 host-profile digest/admission generation. The origin Node and monotonic
sequence already persist as ordering evidence. Replayed intent identity
includes all supplied references, so mismatched/replaced references are
never idempotent. Older unbound queued intents remain explicitly unbound
and cannot become trusted simply because a new observer supplies values.
The SQLite schema upgrade adds the new column with JSON null defaults:
it never invents missing reference evidence. No credentials or executable
permissions are encoded. Follow-up reconnect checks must compare current
genuine observations against this immutable saved evidence; raw references
never grant a Ptah task permission. The caller decides the work and Oracle
only transports the workspace access. No Knights code is involved.
