# Ptah Workspace Operations Profile V2

Status: candidate, non-operative  
Source: deep observable study of the current ChatGPT Workspace plus official public product documentation  
Relationship: compatible supplement to the accepted neutral AI Project Workspace profile

## Fixed product boundary

**Ptah is the world and machinery, not the thinker.**

Ptah provides the neutral Workspace and mechanical capabilities needed by humans, Hunter, Sergeant, applications and other agents. It does not choose the job, interpret intent, rank sources, decide truth, approve results, issue a review verdict or choose the next action.

## What this supplement adds

The first AI Project Workspace profile concentrated on the project envelope: chats, files, instructions, project memory, shared work, long-running work, Canvas and schedules.

This supplement studies the deeper operating contract visible in the workspace:

1. typed and incrementally discoverable operation schemas;
2. mechanical effect classes for observe, draft, simulate, mutate, publish, destructive and external-side-effect operations;
3. separation between external Provider permission and local confirmation policy;
4. explicit external-reference, indexed, mounted, materialized and generated-file states;
5. progress Events, failed Attempts and partial Artifact retention;
6. stable handles for results too large for one active Session;
7. replaceable cards, tables, charts and previews as Views;
8. one-off, recurring and condition-dependent schedules with exact or flexible timing semantics;
9. exact Revision and target-head preconditions for safe mutation;
10. distinct succeeded, failed, declined, cancelled, not-run and partially-completed results;
11. staged observe/draft/simulate/execute/verify workflows;
12. source, account and permission provenance for connected systems;
13. stable cross-device and cross-provider continuation;
14. honest product, Provider and execution-limit reporting.

## Operation descriptor

A Facility or Provider operation should expose mechanically inspectable metadata such as:

- operation identity and schema version;
- argument and result schemas;
- effect class;
- required Grant;
- exact supported preconditions;
- expected Receipt states;
- limits and timeout behaviour;
- source Provider and account boundary;
- whether it can be discovered lazily;
- whether it creates or requires materialized bytes.

This is a profile-level contract over existing primitives. It does not create a new Core entity.

## File truth

Ptah must distinguish a reference from bytes it actually holds:

```text
external_reference
→ indexed_reference
→ mounted_read_only or materialized_copy
→ generated_artifact where applicable
```

A connector file reference must never be presented as a local path until an explicit mount or materialization Activity has succeeded and produced a Receipt.

## Action truth

A submitted operation is not proof of its effect.

```text
submitted Activity
→ Attempt
→ Provider response or failure
→ optional independent post-condition verification
→ final Receipt
```

Draft and publish remain separate. Approval and external permission remain separate. Retry creates a new Attempt and preserves the failed Attempt.

## View truth

A message card, table, chart, file preview, mobile record or progress widget is a View over an underlying Object, Artifact, Activity or Receipt.

The View may be replaced without changing the record. A green card cannot accept a candidate. A hidden card cannot erase a failure. Applications may render the same record differently while retaining one identity and provenance chain.

## Scheduling truth

Ptah may mechanically run schedules supplied by a caller:

- one-off;
- recurring;
- condition watch;
- exact time;
- flexible window;
- condition-dependent checks.

Each scheduled Activity receives exact caller-specified Workspace, Recipe, input Revision, Provider and Grant references. It does not inherit hidden context. The caller owns the schedule's purpose and desired outcome.

## Semantic and authority ownership

The following remain outside Ptah:

- intent interpretation;
- job definition;
- context and source selection;
- source trust and authority;
- Provider and tool choice where more than one is compatible;
- semantic worker-output reconciliation;
- approval or rejection;
- result acceptance and canonical promotion;
- next-action choice.

Ptah can execute a submitted search, merge, review or approval workflow. It does not supply the semantic decision.

## Contract conclusion

The deep study found:

- 16 behaviours covered directly by the neutral substrate;
- 6 behaviours composed by caller applications;
- 0 justified Core extensions;
- 6 product behaviours explicitly rejected or not adopted.

No frozen WP01–WP14 contract is reopened. No runtime implementation is authorized. The supplement should be used later as an implementation and conformance profile for Workspace shells, Facility adapters, Activity progress, Artifact delivery and recovery interfaces.
