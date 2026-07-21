# Hunter–Ptah Workspace Bridge candidate

Status: candidate, non-operative — interface and evidence design only

## Purpose

Define how Hunter may use `ptah.workspace.ai_project.v1` without storing project truth inside one model prompt, one provider account or one private chat history.

## Responsibility split

### Ptah

Ptah owns and enforces:

- Workspace identity and membership;
- authoritative source index;
- Objects, Revisions, Views and Artifacts;
- Activities, Attempts, Events and Receipts;
- Knowledge Views and context-selection evidence;
- Facilities, Providers and Grants;
- privacy, audience and retention policy;
- checkpoints, handoffs and recovery.

### Hunter

Hunter provides:

- intent interpretation;
- planning and coordination;
- relevant context requests;
- Activity proposals;
- Provider selection;
- candidate Artifact production;
- approval requests;
- handoff summaries grounded in Ptah records.

### Human owner

The owner provides:

- goals and acceptance criteria;
- protected-action approval;
- authority decisions;
- candidate acceptance or rejection;
- licence/private-release decisions;
- final runtime authorization.

## Candidate bridge operations

The bridge is described behaviourally; names are not frozen APIs.

### `open_workspace`

Input:

- Workspace identity;
- actor identity;
- requested role;
- intended Activity class.

Output:

- Workspace access decision;
- bounded context packet reference;
- available Facility Grants;
- active blockers;
- pending approvals;
- last accepted handoff.

### `request_context`

Input:

- Workspace and Session identity;
- objective;
- relevance query;
- maximum context budget;
- required authority classes.

Output:

- selected source revisions;
- exclusion reasons;
- context packet Artifact;
- selection Receipt.

### `propose_activity`

Input:

- objective;
- Recipe or Activity class;
- requested Facilities;
- expected Artifacts;
- approval requirements;
- evidence plan.

Output:

- candidate Activity;
- Grant decision;
- required approvals;
- accepted proof obligations.

### `record_progress`

Input:

- Activity and Attempt identity;
- progress Event;
- produced partial Artifacts;
- new blockers;
- owner questions.

Output:

- retained Event/Artifact references;
- updated handoff candidate.

### `request_protected_action`

Input:

- exact proposed action;
- target;
- justification;
- expected side effects;
- rollback or containment;
- evidence to retain.

Output:

- pending approval or denial;
- approval policy;
- immutable decision Receipt.

### `complete_activity`

Input:

- result state;
- produced Artifacts;
- source and dependency revisions;
- proof results;
- remaining blockers;
- next-action proposal.

Output:

- final Receipt;
- candidate handoff;
- candidate authority promotion request.

### `handoff_session`

Input:

- completed work;
- current state;
- next action;
- blockers;
- authority references;
- generated Artifacts.

Output:

- versioned handoff Artifact suitable for another compatible agent.

## Context packet rule

Hunter must receive references and bounded content, not unrestricted Workspace storage access.

Every packet must identify:

- compiler version;
- Workspace and Session;
- actor and role;
- source identities and revisions;
- authority classes;
- privacy labels;
- Grants applied;
- selection/exclusion reasons;
- creation time and expiry or invalidation conditions.

## Candidate-to-truth rule

Hunter-created output begins as `generated_candidate`.

Promotion requires the Workspace's applicable acceptance policy. Depending on the Artifact, acceptance may require:

- owner approval;
- independent Sergeant review;
- passing exact-head workflows;
- licence review;
- privacy review;
- physical evidence;
- a merged control-book decision.

No model response directly changes canonical truth.

## Provider replacement

A Provider change must not change:

- Workspace identity;
- canonical decisions;
- Facility Grants;
- privacy policy;
- Artifact lineage;
- pending approvals;
- handoff state.

The new Provider receives a newly compiled packet and its identity is recorded in the Attempt.

## Local-first and offline behaviour

The bridge must allow Hunter to continue with:

- local Workspace metadata;
- local authoritative files;
- local search/index state;
- local model Providers;
- queued Activities and handoffs.

Cloud Facilities may be unavailable without invalidating local truth. Only actions that require the missing Facility are blocked.

## Public/private boundary

A public Ptah Workspace must not receive private Hunter memory, THETECHGUY Domain Packs, customer/device/payment records or restricted adapters unless an explicit release decision creates a properly licensed and audience-scoped Artifact.

## Proof requirements

Before this bridge becomes operative, implementation must prove the fixtures in:

```text
design/candidates/fixtures/ai-project-workspace-fixtures.json
```

It must also prove:

- exact packet source lineage;
- deterministic authority conflict handling;
- no privilege increase on Provider replacement;
- recovery after process and machine restart;
- failure and partial-Artifact retention;
- human approval enforcement;
- no cross-Workspace private retrieval.

## Non-claims

This document defines no network API, persistence format or runtime implementation. It does not authorize Hunter integration work before Phase 0C closure and ADR-0033 authorization.
