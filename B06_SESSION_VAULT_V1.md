# B06 — Session Vault v1

Status: BUILD / REVIEW candidate

Accepted base: `0325b67884cc60971e005dee90ea82ed944906c4` (B05 merge)

Authority: Ptah Implementation Roadmap 1.1.0, Programme B / B06.

## Scope

B06 is a portability and recovery-export layer over A13 checkpoint/recovery truth. It does not create a second restore engine, bypass A13 verification, or manufacture live Session authority from archived metadata.

Delivered candidate surface:

- Workspace-scoped Session Vault archive/export/import;
- exact current Workspace Revision plus ordered Workspace version history;
- portable Session descriptors without live authority claims;
- Object/Revision and Artifact manifest;
- explicit retained conflicts and required target capabilities;
- exact public A13 checkpoint bundle bound to opaque A13 durable engine state;
- deterministic archive digest over manifest, checkpoint bundle and durable A13 bytes;
- readable recovery export that omits captured component bytes while retaining digests, lengths, requirements and limitations;
- destination import through A13 `import_state`;
- destination checkpoint re-verification before restore authorization is re-earned;
- exact cross-Node compatibility report with missing capabilities and restore conflicts;
- restore delegated to A13 and independently verified through A13 recovery postconditions;
- durable restore-Attempt fencing preserved inside exported/imported A13 state.

## Truth boundaries

- Archive existence is not checkpoint verification and is never restore success.
- A13 remains sole authority for checkpoint integrity, compatibility binding, restore execution, Attempt fencing and independent recovery verification.
- B06 consumes A13 only through its public durable-state, verification, compatibility, restore and recovery APIs.
- Export requires the selected A13 checkpoint to be currently independently verified.
- The supplied checkpoint verification must enumerate the exact checkpoint component set and successful readback/integrity evidence.
- One Session Vault carries exactly one A13 checkpoint bundle; unrelated engine bundles are rejected rather than silently exported.
- Import validates archive digest and checkpoint-state binding, then deliberately loses prior in-memory restore authorization.
- Required B06 capabilities tighten A13 compatibility; a missing Vault requirement produces an incompatible decision and cannot be bypassed by mutating the caller-visible report.
- Session descriptors are historical portability metadata, not live Session/attachment authority.
- Retained conflicts remain explicit and are never rewritten as success.
- Readable recovery exports omit raw checkpoint component bytes by design.

## Acceptance corpus

The exact candidate must pass all 12 B06 cases covering:

1. export requires current independent A13 checkpoint verification;
2. archive roundtrip preserves Workspace versions, Sessions, Objects and Artifacts;
3. readable recovery export omits raw checkpoint bytes while retaining digest evidence;
4. import drops restore authorization until destination re-verification;
5. compatible other-Node resume plus independent recovery verification;
6. missing B06 capability is exact and cannot restore;
7. missing A13 component capability remains explicit;
8. archive digest tamper fails before an imported engine exists;
9. current Workspace version must match exact checkpoint Revision/generation;
10. Artifact manifest cannot reference an unlisted Object Revision;
11. retained conflicts survive portability without becoming hidden success;
12. used restore Attempt fencing survives export/import.

## Exact-head proof gate

Promotion requires one exact PR head that passes:

- accepted B05 base and bounded six-file B06 scope lock;
- pinned Rust/Cargo 1.97.1;
- `cargo fmt --all -- --check`;
- B06 acceptance: 12/12;
- strict `ptah-checkpoint` Clippy with `-D warnings`;
- inherited A13 checkpoint/recovery regressions;
- inherited B01 transfer/storage regressions;
- inherited B05 executable/package regressions;
- full locked workspace regression;
- clean working tree;
- immutable exact-head proof manifest and retained artifact.

Any source movement invalidates Freeze and requires affected Review → Freeze → Prove again.

## Exit

B06 is COMPLETE only when the exact proven candidate is merged to `main`. A proved canonical B06 candidate must not remain parked in an open PR.
