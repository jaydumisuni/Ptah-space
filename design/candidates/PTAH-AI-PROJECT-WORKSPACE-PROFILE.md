# Ptah AI Project Workspace substrate profile candidate

Status: corrected candidate, non-operative — frozen-contract composition only

Profile identity:

```text
ptah.workspace.ai_project.v1
```

## Purpose

This profile composes existing Ptah primitives into a durable project **platform** where humans, Hunter, Sergeant, other agents and ordinary applications may store and run work across Sessions, files, tools, Activities and restarts.

It is a profile over frozen primitives, not a new Ptah Core entity and not an intelligence, coordinator, reviewer or approval system.

## Primary rule

> Ptah is the world and machinery, not the thinker.

Ptah supplies neutral workspace capabilities. The caller decides what the work means, which records matter, what is authoritative, what should happen next and whether a result is accepted.

Hunter, Sergeant, a human, a local model, an OpenAI model or another application may use the same Ptah Workspace. Ptah does not become any of them and does not agree with, rank or approve their conclusions.

## Workspace substrate

The profile exposes mechanical composition for:

- stable Workspace identity;
- configured membership and access Grants;
- parallel Sessions;
- caller-created Activities and Attempts;
- Events, Receipts and logs;
- Objects, Revisions, Views and Artifacts;
- Facilities and Providers;
- schedules and triggers submitted by callers;
- checkpoints, snapshots, exports and recovery;
- arbitrary caller-owned metadata and labels.

Ptah may store purpose, objective, policy, decision, authority, blocker, approval or handoff records as bytes and metadata. It does not interpret those records or decide their truth.

## Caller-built context

Ptah Core does not compile context for an agent.

A caller such as Hunter, Sergeant, a human-facing application or another agent may:

1. request specific Workspace records;
2. search or index records through an explicitly selected Facility;
3. choose which records are relevant;
4. assign its own authority or trust labels;
5. construct a bounded prompt, review packet or handoff;
6. store the resulting packet as an Artifact when useful.

Ptah returns requested records and enforces configured mechanical access. It does not resolve objectives, select accepted decisions, rank sources, identify blockers, choose a next action or explain why a caller included or excluded a record.

## Caller-owned labels

Labels such as:

- `canonical`
- `accepted_evidence`
- `recovery_copy`
- `reference`
- `generated_candidate`
- `temporary_context`
- `rejected`
- `superseded`

may be stored by applications as ordinary metadata.

Ptah preserves the supplied label, author, revision and provenance. It does not decide whether the label is correct and does not make one labelled record override another.

## Session model

Each project thread may be represented as a Ptah `Session`.

A Session mechanically links caller-supplied references such as:

- Workspace identity;
- participant identities;
- Activity and Event history;
- Object and Artifact references;
- Facility and Provider references;
- Grants applied by the configured access system;
- checkpoints and caller-produced handoffs.

Parallel Sessions share the same Workspace substrate without Ptah deciding that they share one purpose, truth hierarchy or objective.

## Artifact Library composition

The Workspace library is a View over Ptah Objects, Revisions and Artifacts. It may expose:

- Workspace-owned Artifacts;
- explicitly shared Artifacts;
- private or restricted Artifacts;
- generated outputs;
- evidence bundles;
- archived revisions;
- external references without copied bytes.

Every reusable Artifact retains stable identity, owner, Workspace, digest, revision, source, licence, audience, retention, provenance and configured Grants where those fields are supplied or required by the contract.

Ptah stores and retrieves the Artifact. The caller decides whether it is useful, correct, accepted, authoritative or safe to reuse.

## Mechanical access enforcement

Tool availability is not global. Ptah enforces Grants, Leases, Fences and other access records configured by the operator or calling application.

Examples:

```text
GitHub read               permitted when the configured Grant allows it
GitHub branch creation    permitted when the configured Grant allows it
Payment refund            executed only when the caller supplies required authorization state
Device destructive action executed only within configured adapter and access boundaries
Private export            blocked when the configured access rule denies it
```

Ptah does not decide who deserves a Grant or whether an approval is wise. It only enforces the configured mechanical condition.

Changing the active agent does not implicitly change the configured Grant set.

## Scheduled Activities

A caller may submit a scheduled or condition-triggered Activity with exact inputs, Artifact references, Provider references and access requirements.

Ptah may persist the schedule and execute or dispatch it when the configured trigger fires. Ptah does not choose the task, infer the desired context or decide which Artifacts are relevant.

A timer or condition does not expand configured access.

## Handoffs

A human, Hunter, Sergeant or another application may create a handoff Artifact containing fields such as:

```yaml
completed: []
current_state: []
next_action: null
blockers: []
authority: []
generated_artifacts: []
```

Ptah stores, versions and retrieves that Artifact. It does not generate the next action, verify the authority list or decide that the handoff is accepted.

## Hunter and Sergeant use

Hunter may use Ptah to store project state, run tools, create Activities, retrieve records and persist outputs. Hunter owns its planning, context selection, source ranking, coordination and approval requests.

Sergeant may use Ptah to obtain a frozen candidate, run independent review Facilities, retain findings and publish its own review result. Ptah does not perform the review, issue the verdict or approve the candidate.

A human or another configured process decides what to do with Hunter or Sergeant outputs.

## Proof obligations

The corrected fixture set requires proof for:

- cross-Workspace access isolation;
- exact caller-requested record retrieval;
- preservation of caller-supplied labels without Ptah interpretation;
- provider-independent state and Artifact resume;
- Grant stability across agent replacement;
- scheduled execution limited to caller-specified inputs;
- private/public Workspace separation;
- archived Session discoverability without automatic relevance judgment;
- visible failed Activities and partial Artifacts;
- Artifact-to-Activity lineage;
- no Ptah context, authority, approval, review or next-action decision.

## Contract-gap conclusion

The project/workspace experience can be built by applications using existing frozen Ptah primitives. No WP01–WP14 reopening is proposed.

The behavioural donor informs application and user-experience design. It does not transfer context selection, source authority, approval or coordination into Ptah Core.

If implementation discovers a missing mechanical primitive, work must stop and request a versioned reopening ADR with migration, fixtures and conformance evidence.

## Non-claims

This candidate:

- does not implement a Workspace runtime;
- does not implement a Ptah context compiler;
- does not make Ptah an agent, coordinator, reviewer or approver;
- does not change frozen schemas or lifecycles;
- does not authorize T01 or any WP14 runtime proof;
- does not depend on OpenAI;
- does not copy proprietary product internals;
- does not authorize runtime implementation.
