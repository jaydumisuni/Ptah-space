# D01 — Human Workspace shell v2

## Status

Implementation candidate for Programme D01, built directly on the accepted C11 merge:

`3526acd0c6d28a2fd97497f99bc1798259b47433`

The exact candidate commit will be frozen before proof and recorded by the D01 exact-head proof lane. This document does not grant runtime authority and does not convert a rendered View into canonical state.

## Roadmap boundary

D01 is the first Full Workspace Release milestone after Firmware and Device Beta. It matures the A14 human-control shell without replacing A14's canonical authority, protected-control fencing, or caller/reviewer acceptance boundary.

D01 delivers:

- a typed operation catalog with effect class, Grant/materialization requirement visibility, caller-confirmation requirement, Provider-permission relationship, and explicit limitations;
- reference/materialization truth for current Objects and Artifacts without inventing local paths;
- stable Activity result handles while keeping runtime completion separate from caller/reviewer acceptance;
- explicit timing modes without manufacturing schedule instances when canonical schedule state is absent;
- unresolved worker/precondition conflicts that remain caller/reviewer decisions;
- replaceable typed Views that never become runtime authority;
- mature Human Workspace panels for operations, results, availability, editor, applications/devices, media/documents, schedules, conflicts, approvals/control transfer, and limits;
- presentation-only panel ordering and one/two-column layout persistence;
- keyboard-accessible panel reordering, focus-visible treatment, skip navigation, and preserved critical controls across desktop/tablet/mobile layouts;
- a read-only `/api/shell-v2` projection derived from the same validated A14 snapshot used by `/api/state`.

## Authority and honesty invariants

The D01 shell is a projection. It does not:

- select semantic context;
- approve caller work or worker results;
- choose the caller's next action;
- infer a current Grant, operation-specific Grant requirement, materialization requirement, or external Provider permission when A14 does not expose that fact;
- infer a local materialized path from a materialization label;
- manufacture schedules, editor sessions, Application/Device sessions, or media/document backing records;
- claim result paging/search/partial-retention support when the current A14 projection does not expose it;
- reconcile conflicting worker evidence;
- treat authorization-for-dispatch as operation completion.

A14 does not expose operation-specific Grant or materialization requirement policy. D01 therefore reports those requirement fields as `not_exposed`; it does not reinterpret missing policy as `required` or `not_required`.

The browser rejects a `/api/state` + `/api/shell-v2` pair when their complete authority stamps differ.

## Presentation-only persistence

`localStorage['ptah.layout.v2']` may contain only:

- `panel_order`
- `layout_mode`

It contains no workspace revision, session revision, node generation, Provider generation, fence, Grant, approval, or runtime authority. Corrupt presentation state is discarded before the application boots. Changing or resetting layout cannot authorize or submit work.

## Specialized backing-state boundary

The shell exposes explicit unavailable/projection-boundary text when current canonical state does not provide:

- an editor session;
- Application/Device session backing from the owning C10/C11 runtime;
- typed Object/Artifact backing required for media/document viewers.

This is deliberate. D01 supplies mature shell structure without claiming runtime integrations that are not present in the current A14 snapshot contract.

## Proof contract

The D01 exact-head proof lane requires all of the following on the frozen candidate:

1. exact C11 predecessor and one-commit D01 scope;
2. unchanged `Cargo.lock`;
3. locked dependency universe;
4. `cargo fmt --all -- --check`;
5. `cargo clippy -p ptah-control --all-targets --locked -- -D clippy::all -D clippy::pedantic`;
6. no new TODO/FIXME/`todo!`/`unimplemented!`/unsafe source escapes;
7. exactly 13 D01 acceptance tests;
8. exactly 11 inherited A14 acceptance tests;
9. the complete locked `ptah-control` package suite;
10. the complete locked workspace regression suite;
11. loopback-only service binding;
12. physical Chromium proof at desktop, tablet, and mobile viewports;
13. exact `/api/state` ↔ `/api/shell-v2` authority equality;
14. presentation-only layout persistence/recovery and no-submission proof;
15. exact-head proof artifact with commit/tree identity and repository hashes.

Warnings already present in the accepted A14 source under the repository's `missing_docs` warning policy are not reclassified as D01 failures. The accepted strict lint gate remains `clippy::all + clippy::pedantic`; D01 adds no new missing-doc warning in its acceptance crate.

## Evidence interpretation

Passing tests and physical execution confirm the frozen implementation. They do not create authority that is absent from the contracts. Any future runtime-backed editor, schedule, Application/Device, or media/document integration must bring its own canonical identity, revision/generation, Provider/Grant/approval requirements, and independent read-back evidence before this shell may present it as available.
