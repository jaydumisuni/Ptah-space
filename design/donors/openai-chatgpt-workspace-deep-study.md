# OpenAI ChatGPT Workspace — Deep Observable Behaviour Donor Study

Status: Phase 0C candidate study  
Classification: hosted-service and observable-interaction donor  
Code reuse: none  
Private source dependency: none  
Existing authority: supplements `openai-chatgpt-projects-work.md`; it does not replace the neutral-substrate correction

## Purpose

This study answers a narrow question: **what can Ptah borrow from the workspace behaviour visible to its users and from OpenAI's public product documentation, without copying proprietary code or changing what Ptah is?**

The source product proves useful interaction and operating patterns. It does not prove OpenAI's private implementation, internal data model, infrastructure, security architecture or algorithms. No hidden implementation is inferred.

Ptah remains the already-decided product:

- Ptah is a neutral Workspace, storage, execution, Facility, access, event, Artifact, checkpoint and recovery substrate.
- Hunter or another caller supplies intelligence, context selection, planning, coordination and next-action proposals.
- Sergeant independently reviews frozen candidates using Ptah resources.
- Humans or calling applications own intent, approval, acceptance, rejection and release.

## Study method — ten for two

The study used ten primary specialist lanes and ten independent verification lanes. This is an assistant execution method, not a Ptah or Sergeant architecture.

| Pair | Primary observation lane | Independent contract check |
|---|---|---|
| 01 | Workspace envelope and cross-device continuity | Workspace isolation and identity stability |
| 02 | Files, Library and generated Artifacts | Reference/materialization and provenance |
| 03 | Tool/plugin discovery and typed schemas | Facility/Provider neutrality |
| 04 | Read/write actions and permission prompts | Grant boundary and external access preservation |
| 05 | Work progress, partial outputs and interruption | Activity/Attempt/Event/Receipt fidelity |
| 06 | Connected apps and synced sources | Source permission and account provenance |
| 07 | Cards, tables, previews and interactive output | View independence from authority |
| 08 | One-off, recurring and conditional tasks | Exact scheduled inputs and timing semantics |
| 09 | Drafting, mutation, exact-head updates and retries | Preconditions, concurrency and retained failures |
| 10 | Product limits, long results and conversation continuation | Honest limits, resource handles and recovery |

The reconciled result is encoded in:

- `workspace-operations-profile-v2.json`
- `workspace-operations-gap-map-v2.json`
- `fixtures/workspace-operations-fixtures-v2.json`

## Public and observable sources

Official documentation inspected:

- https://help.openai.com/en/articles/10169521-projects-in-chatgpt
- https://help.openai.com/en/articles/11487775-connectors-in-chatgpt
- https://help.openai.com/en/articles/10847137
- https://help.openai.com/en/articles/20001052-file-storage-and-library-in-chatgpt
- https://help.openai.com/en/articles/10291617-tasks-in-chatgpt
- https://help.openai.com/en/articles/20001275-chatgpt-work-and-codex
- https://help.openai.com/en/articles/9213685-extracting-insights-with-chatgpt-data-analysis
- https://help.openai.com/en/articles/11509118-admin-controls-security-and-compliance-for-plugins-and-apps
- https://help.openai.com/en/articles/20001256-plugins-in-chatgpt-and-codex
- https://help.openai.com/en/articles/20001247

Direct observable behaviour was also studied through this workspace's typed tools, connector references, sandboxed execution, generated Artifacts, incremental resource access, scheduled-task contracts, progress messages and exact mutation operations.

## Improvement 1 — make operation capabilities discoverable and typed

The workspace does not expose every possible operation as one unrestricted shell. Capabilities are grouped into tools and connectors with typed inputs and distinct operations.

Ptah should expose a mechanical operation catalog for each Facility and Provider:

- stable operation identity and schema version;
- required arguments and result type;
- effect class;
- required Grant;
- supported preconditions;
- expected Receipt states;
- resource limits;
- Provider and account boundary;
- whether the operation can be discovered lazily.

A caller may query only the relevant capability schemas instead of loading the complete platform surface. Ptah returns descriptors; it does not choose the operation.

Suggested effect classes:

- `observe`
- `draft`
- `simulate`
- `mutate`
- `publish`
- `destructive`
- `external_side_effect`

These are mechanical metadata used by Grants and application UIs. They are not Ptah judgments about whether the work should happen.

## Improvement 2 — separate external access from confirmation policy

A connected app's external permissions and the workspace's confirmation policy are different boundaries.

Ptah should preserve this distinction:

1. the external Provider/account determines what data or action is actually accessible;
2. a Ptah Grant determines whether the submitted operation may proceed locally;
3. a caller-owned approval application may create the decision record required by that Grant;
4. approval cannot expand the Provider's external permission;
5. denial, missing permission and execution failure produce different Receipts.

This avoids a dangerous ambiguity where clicking “approve” appears to create access the connected account never had.

## Improvement 3 — distinguish references from materialized bytes

This workspace exposes an important operational truth: a connector file reference is not automatically a file inside the active execution environment.

Ptah should expose explicit availability states:

- `external_reference`
- `indexed_reference`
- `mounted_read_only`
- `materialized_copy`
- `generated_artifact`

A local path may be claimed only after an explicit mount or materialization Activity produced a Receipt. The resulting Object/Revision must retain:

- source Provider;
- external object identity;
- source revision or freshness marker where available;
- materialization Activity and Attempt;
- content digest;
- destination Environment or storage location;
- retention and deletion rule.

This improves connector correctness, reproducibility and security without adding a new Core entity.

## Improvement 4 — retain large results behind stable handles

Tool and connector results can exceed the useful size of one chat response or one active context window. A workspace therefore benefits from stable result references that support incremental access.

Ptah should allow a Receipt or Artifact to expose:

- stable result identity;
- content digest;
- result size and media type;
- bounded line/range reads;
- paging cursor where appropriate;
- exact search within the retained result;
- source operation and Attempt;
- expiration or retention policy.

The Session receives a View or excerpt. The full result remains a durable Artifact or Provider-backed reference. This prevents repeated downloads, truncation masquerading as completeness and conversation length from becoming data loss.

## Improvement 5 — progress and partial outputs are first-class

Long work should emit normal operational progress rather than vague “AI activity.”

A submitted Activity may expose:

- current stage;
- completed and pending sub-Activities;
- last Event;
- current Attempt;
- blocker or wait reason;
- partial Artifacts;
- questions requiring caller input;
- whether a configured confirmation is outstanding;
- truthful estimate only when one is available.

Failure after partial production must retain both the failed Attempt and every valid partial Artifact. Retry creates a new Attempt linked to the failed one; it does not erase history.

Ptah records and streams this mechanical state. Hunter or another application explains meaning and recommends what to do next.

## Improvement 6 — use Views as replaceable renderings

The workspace can show one result as a message, card, table, chart, preview, file link or interactive widget.

Ptah should make this explicit:

- the authoritative item is an Object, Revision, Artifact, Activity or Receipt;
- a View describes how an application renders or interacts with it;
- multiple Views may refer to the same underlying identity;
- deleting or replacing a View does not delete the underlying record;
- visual colour, success styling or placement cannot create authority;
- accessibility and mobile/desktop representations may differ without changing state.

This supports rich interfaces while preventing UI cards from becoming a hidden operational database.

## Improvement 7 — model schedules by execution semantics

The observed workspace distinguishes one-off, recurring and condition-dependent tasks, including exact times, broader windows and checks that notify only when a condition becomes true.

Ptah should retain both schedule kind and timing semantics:

Schedule kind:

- one-off;
- recurring;
- condition watch.

Timing mode:

- exact;
- flexible window;
- condition dependent.

A scheduled Activity receives an explicit caller-owned input set:

- Workspace identity;
- Recipe revision;
- immutable Object/Revision inputs;
- Provider connections or references;
- Grant;
- schedule definition;
- desired output or notification contract.

It does not silently inherit unavailable chat context or unrelated Workspace files. If an input is absent, Ptah reports the missing dependency rather than inventing context.

## Improvement 8 — make mutation preconditions explicit

Reliable workspace actions frequently depend on the target still being the version that was inspected.

Ptah should support exact preconditions such as:

- Object Revision digest;
- document draft revision;
- repository branch head;
- message/thread identity;
- calendar event version;
- current state-machine state;
- Provider freshness token where available.

If the target moved, the Activity fails closed with a conflict Receipt containing expected and observed identities. It must not silently overwrite newer work.

This pattern is especially important for:

- Git operations;
- collaborative documents;
- configuration changes;
- payment/order state;
- approvals;
- device policies;
- generated release Artifacts.

## Improvement 9 — separate read, draft, simulate, execute and verify

A capable workspace should not collapse every request into an immediate external mutation.

The useful lifecycle is:

```text
observe
→ draft or simulate
→ caller decision where configured
→ execute
→ verify post-condition
→ retain Receipt and Artifacts
```

Examples:

- drafting an email is not sending it;
- creating a patch is not merging it;
- preparing an event is not inviting attendees;
- generating a payment request is not confirming payment;
- requesting a device action is not proof the device reached the desired state.

Ptah can enforce this mechanical lifecycle through Recipes, Activities, Grants, Attempts and Receipts. It does not decide whether the draft is correct or the result should be accepted.

## Improvement 10 — preserve honest result states and limits

A workspace must distinguish:

- `succeeded`
- `failed`
- `declined`
- `cancelled`
- `not_run`
- `partially_completed`

Invocation alone is not success. A missing tool response is not proof that the external mutation happened. Where high assurance is required, a separate verification Activity checks the post-condition.

Ptah should also report limits explicitly:

- file size or count;
- context or result budget;
- schedule frequency;
- execution duration;
- CPU, memory, storage or network quota;
- Provider plan restriction;
- unavailable capability;
- retention expiry.

It must not silently change the user's semantic scope to fit a limit.

## Improvement 11 — keep synced knowledge permission-aware and provider-independent

Connected and synced sources demonstrate the value of reducing context switching while retaining the source system's permissions.

Ptah should support:

- indexed Provider references;
- source account and tenant identity;
- permission-aware retrieval;
- freshness markers and sync checkpoints;
- deletion and access-revocation propagation;
- exact citations back to source Objects;
- an explicit difference between an index and canonical source bytes;
- replacement of one indexing Provider without losing the Workspace's caller-owned records.

Hunter or the calling application chooses the query, relevance policy and context packet. Ptah only performs the configured retrieval and returns evidence-bearing results.

## Improvement 12 — preserve continuity independently of one interface or model

A strong workspace lets work continue across phone, web, desktop, different interfaces and replaceable intelligence Providers.

Ptah should preserve stable identities for:

- Workspace;
- Session;
- Activity;
- Attempt;
- Object and Revision;
- Artifact;
- Provider connection;
- Receipt;
- caller-owned handoff or checkpoint.

The application may render the same records differently on each device. A model change or Session compaction must not rewrite operational history.

For long conversations, the caller may create a semantic handoff Artifact. Ptah stores it, links it to its source records and exposes it to the next Session. Ptah does not authoritatively decide what the handoff means.

## What this study does not borrow

The following are explicitly rejected:

- assistant identity or personality as Workspace identity;
- hidden model reasoning as operational authority;
- hidden provider memory as canonical state;
- implicit global access to tools or external services;
- transcript text as the sole database;
- automatic context selection treated as truth;
- silent file copying or materialization;
- success inferred from invocation;
- provider-specific hosted assumptions as mandatory architecture;
- a UI preview, card or green badge as approval;
- Ptah choosing work, ranking truth, issuing verdicts or deciding the next action.

## Contract impact

The study found **no justified new Core entity** and **no reason to reopen WP01–WP14**.

The improvements compose from frozen Ptah records and profile rules:

- Workspace, Session and Grant for the bounded envelope;
- Object, Revision, Artifact and View for files and renderings;
- Recipe, Activity, Attempt, Event and Receipt for work and progress;
- Facility and Provider for typed external and local capabilities;
- Knowledge and View for retrieval and incremental result access.

Some implementation details become profile requirements or operation metadata, including effect class, precondition, materialization state, timing mode, result state and stable resource-handle behaviour. These are implementation and conformance concerns, not new product authority.

## Final recommendation

Adopt the observable workspace patterns as a **deep behavioural profile supplement**:

- borrow the bounded project envelope;
- borrow typed, discoverable capabilities;
- borrow explicit action effects and confirmation boundaries;
- borrow reusable files and generated Artifacts;
- improve reference/materialization truth;
- improve progress and partial-result retention;
- improve exact mutation preconditions;
- improve scheduling semantics;
- improve render-independent Views;
- improve honest failure and limit reporting;
- keep every semantic and authority decision outside Ptah.

This donor study is non-operative. It does not authorize runtime implementation, reopen frozen contracts, accept ADR-0033 or claim P01 physical-host proof.
