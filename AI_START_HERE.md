# AI Start Here

This file is the recovery entry point for every human or AI session working on Ptah Space.

## Project identity

Ptah Space is an independent, open-source, online-first execution world. It provides persistent workspaces, concurrent activities, storage, repositories, terminals, browsers, containers, applications, devices, firmware, media, documents, sessions, and artifacts.

Ptah provides the environment and machinery. It does not supply business reasoning, an assistant identity, approval judgement, or a universal policy brain.

## Mandatory reading order

Before planning, editing, building, reviewing, or claiming progress, read:

1. `README.md`
2. `docs/CURRENT_PROGRESS.md`
3. `docs/ROADMAP.md`
4. `docs/ARCHITECTURE.md`
5. `docs/DECISIONS.md`
6. `docs/DO_NOT_BREAK.md`
7. `docs/CHAT_WORK_PROTOCOL.md`
8. `docs/REQUIREMENT_CLOSURE_MATRIX.md`
9. `docs/EXTERNAL_DONOR_POOL.md` when donor or dependency work is involved

Then inspect the files, commits, issues, pull requests, and evidence connected to the active roadmap item.

## Mandatory recovery questions

Before proposing work, answer from repository evidence:

- What phase is active?
- What exact roadmap item is active?
- What has already been implemented?
- What is documented but not implemented?
- What has been reviewed, frozen, and proved?
- What existing internal or external work overlaps?
- What decision or do-not-break rule applies?
- What evidence is required before completion can be claimed?

Do not ask the user to repeat information that is recoverable from the repository.

## Work authority

A roadmap item may move into implementation only when:

1. its dependencies are complete;
2. its design or contract is documented;
3. the active task is recorded in `docs/CURRENT_PROGRESS.md`;
4. the user has approved proceeding when approval is required;
5. the work is performed on an appropriate branch;
6. the required proof is defined before execution.

## Truth vocabulary

Use these meanings consistently:

- **Planned** — documented, not implemented.
- **In progress** — implementation or recovery work is active.
- **Implemented** — code exists, but may not be reviewed or proved.
- **Reviewed** — implementation was inspected against its contract.
- **Frozen** — the reviewed checkpoint is the accepted baseline.
- **Proved** — the frozen checkpoint passed its declared evidence gate.
- **Complete** — all phase exit gates are satisfied.
- **Blocked** — progress cannot continue until a named dependency is resolved.

Never use “done,” “working,” or “complete” without stating the evidence boundary.

## End-of-session requirement

Every accepted work session must update the repository before handoff:

- `docs/CURRENT_PROGRESS.md`
- the relevant roadmap checklist or phase record;
- `docs/DECISIONS.md` when an architectural decision changed;
- the requirement-closure or donor record when external research was used;
- links to commits, tests, screenshots, logs, artifacts, or other evidence.

A chat summary is not canonical project memory. The repository is.

## Current starting point

The project begins in **Phase 0A — External and Internal Donor Recovery**. No Ptah runtime implementation is yet accepted.
