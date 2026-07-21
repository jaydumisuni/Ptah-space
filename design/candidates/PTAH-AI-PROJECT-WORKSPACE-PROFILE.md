# Ptah AI Project Workspace Profile candidate

Status: candidate, non-operative — frozen-contract composition only

Profile identity:

```text
ptah.workspace.ai_project.v1
```

## Purpose

This profile composes existing Ptah primitives into one durable project environment where a human, Hunter and other compatible agents can continue work across Sessions, files, tools, Activities and restarts without rebuilding context manually.

It is a profile over frozen primitives, not a new Ptah Core entity.

## Primary rule

> Workspace truth belongs to Ptah and the owner, not to the active model provider.

Hunter, Sergeant, an OpenAI model, a local model or a specialist Provider may consume the same bounded context packet. None becomes the owner of Workspace memory.

## Workspace envelope

An AI Project Workspace binds:

- purpose and objectives;
- members, roles and Grants;
- accepted policies and decisions;
- authoritative and reference sources;
- parallel Sessions;
- active, pending and completed Activities;
- uploaded, generated and retained Artifacts;
- Workspace-scoped Knowledge Views;
- Facilities and Providers;
- approvals, Receipts and evidence requirements;
- handoff and recovery checkpoints.

## Context compiler

Before an agent begins or resumes an Activity, Ptah should compile a bounded context packet from explicit Workspace records.

Required packet fields are frozen in:

```text
design/candidates/ai-project-workspace-profile.json
```

The compiler must:

1. identify the Workspace and actor role;
2. resolve current purpose, objective and blockers;
3. select accepted decisions and authoritative sources;
4. retrieve only relevant Sessions and Activities;
5. include pending approvals and Facility Grants;
6. retain source authority, revision and provenance;
7. include the last accepted handoff;
8. record why sources were included or excluded;
9. refuse cross-Workspace private retrieval;
10. remain exportable across model Providers.

The compiler must not silently concatenate all historical messages.

## Source authority

Every source used by the compiler has one authority class:

- `canonical`
- `accepted_evidence`
- `recovery_copy`
- `reference`
- `generated_candidate`
- `temporary_context`
- `rejected`
- `superseded`

A lower-authority record cannot silently override a higher-authority record. Conflicts remain visible and evidenced.

## Session model

Each project thread is a Ptah `Session`.

Sessions inherit:

- Workspace purpose;
- accepted policies;
- authoritative source index;
- member role;
- Facility Grants;
- privacy boundary.

Sessions keep local:

- Activity and Event history;
- temporary reasoning context;
- draft Artifacts;
- unresolved questions;
- handoff checkpoint.

Parallel Sessions may work on different concerns while sharing the same accepted Workspace truth.

## Artifact Library composition

The Workspace library is a View over Ptah Objects, Revisions and Artifacts. It should support:

- Workspace-owned Artifacts;
- explicitly shared Artifacts;
- private/restricted Artifacts;
- generated candidates;
- accepted evidence bundles;
- archived revisions;
- external references without copied bytes.

Every reusable Artifact must retain stable identity, owner, Workspace, digest, revision, source, licence, audience, retention, provenance and Grants.

## Facility Grants

Tool availability is not global.

Examples:

```text
GitHub read               allowed by Workspace Grant
GitHub branch creation    allowed by maintainer role
GitHub merge              protected action / owner policy
Payment read              finance role
Payment refund            explicit owner approval
Device destructive action technician role + evidence + approval
Private Hunter export     denied unless explicitly released
```

Changing the active agent must not change the Workspace Grant set.

## Scheduled Activities

A scheduled or condition-triggered Activity may receive only:

- explicitly granted Workspace Artifacts;
- its prior accepted run state;
- relevant Provider Grants;
- the minimum Workspace context required by its Recipe.

A timer or condition does not expand authority.

## Handoff

Every resumable Session or long-running Activity should produce a handoff containing:

```yaml
completed: []
current_state: []
next_action: null
blockers: []
authority: []
generated_artifacts: []
```

A handoff is an Artifact with provenance, not an untracked summary string.

## Hunter role

Hunter acts as a Workspace participant and coordinator:

- reads the bounded context packet;
- proposes or starts Activities within Grants;
- chooses compatible specialist Providers;
- creates candidate Artifacts and Receipts;
- requests approval for protected actions;
- writes explicit handoffs;
- never silently promotes a candidate into canonical truth.

Sergeant or another reviewer should receive an independently compiled review packet and cannot silently edit Hunter's result.

## Proof obligations

The candidate fixture set requires proof for:

- cross-Workspace memory isolation;
- accepted-decision inheritance;
- superseded-source handling;
- provider-independent resume;
- Grant stability across agent replacement;
- least-privilege scheduled Activities;
- private Hunter/public Workspace separation;
- archived Session selection;
- visible failed Activities;
- Artifact-to-Activity lineage.

## Contract-gap conclusion

The gap map concludes that the donor behaviours can be expressed with existing frozen primitives and profile composition. No WP01–WP14 reopening is proposed.

If implementation discovers a missing primitive, work must stop and request a versioned reopening ADR with migration, fixtures and conformance evidence.

## Non-claims

This candidate:

- does not implement a Workspace runtime;
- does not implement a context compiler;
- does not change frozen schemas or lifecycles;
- does not authorize T01 or any WP14 runtime proof;
- does not depend on OpenAI;
- does not copy proprietary product internals;
- does not authorize runtime implementation.
