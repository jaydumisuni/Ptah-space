# Hunter–Ptah Workspace Bridge candidate

Status: corrected candidate, non-operative — interface and evidence design only

## Purpose

Define how Hunter may use `ptah.workspace.ai_project.v1` as a neutral platform without assigning Hunter’s intelligence, Sergeant’s review authority or a human’s decisions to Ptah.

## Responsibility split

### Ptah

Ptah provides and mechanically enforces configured platform capabilities:

- stable Workspace, Session, Activity, Object and Artifact identities;
- storage, revisions, locations, transfers and recovery;
- Processes, terminals, browsers, containers, Devices and other Facilities;
- caller-created Activities, Attempts, Events and Receipts;
- Provider registration and exact Generation identity;
- configured Grants, Leases and Fences;
- logs, checkpoints, snapshots, exports and retained failure state;
- retrieval of exact records requested by an authorized caller.

Ptah does not interpret intent, select context, rank sources, identify authority, choose Providers, decide blockers, approve actions, review results or select a next action.

### Hunter

Hunter provides:

- intent interpretation;
- planning and coordination;
- context search and selection;
- source and authority judgments;
- Activity definitions submitted to Ptah;
- Provider selection;
- candidate Artifact production;
- approval requests to the applicable human or application;
- next-action proposals;
- handoff summaries grounded in records retrieved from Ptah.

### Sergeant

Sergeant is an independent application that may run on Ptah. Sergeant:

- receives a frozen candidate and explicitly selected evidence;
- requests review Facilities and execution environments;
- performs its own analysis and adversarial checks;
- creates its own findings and verdict;
- retains review evidence through Ptah.

Ptah supplies the platform. Ptah does not perform the review, agree with the findings or approve the candidate.

### Human or calling application

The human or calling application provides:

- goals and acceptance criteria;
- access and approval configuration;
- authority decisions;
- candidate acceptance or rejection;
- licence and release decisions;
- final runtime authorization.

## Candidate bridge operations

The bridge is described behaviourally; names are not frozen APIs.

### `open_workspace`

Input:

- Workspace identity;
- actor identity;
- requested Session or Activity references.

Output:

- mechanical access result under configured Grants;
- Workspace metadata;
- requested Session, Object, Artifact and Activity references;
- available Facilities and Providers visible to that caller.

Ptah does not return “the active blocker,” “the accepted handoff” or “the correct objective” unless the caller explicitly requests records carrying those caller-owned labels.

### `list_records`

Input:

- Workspace identity;
- exact record classes, identifiers or query constraints;
- pagination and byte limits.

Output:

- matching records the caller is mechanically permitted to read;
- exact revisions, locations and provenance;
- access failures where configured Grants deny retrieval.

The caller decides relevance and authority.

### `create_activity`

Input:

- caller-defined Activity payload;
- selected Recipe or Facility calls;
- exact input Object and Artifact references;
- selected Provider constraints;
- configured access references;
- requested evidence and retention settings.

Output:

- stored Activity identity;
- accepted or rejected mechanical admission under configured capacity and access constraints;
- Attempt, Event and Receipt references as execution proceeds.

Ptah does not decide whether the Activity is strategically useful or whether its proof plan is sufficient.

### `record_progress`

Input:

- Activity and Attempt identity;
- caller or Provider-supplied progress Event;
- produced partial Artifacts;
- caller-supplied labels such as blocker or question.

Output:

- retained Event and Artifact references.

Ptah does not infer blockers or generate a handoff.

### `submit_approval_request`

A caller may store an approval request and route it to a human or approval application.

Ptah may enforce a configured rule that prevents a protected Facility action until a required Grant, Lease, Fence or approval record exists. Ptah does not decide whether approval should be granted.

### `complete_activity`

Input:

- caller or Provider-supplied result state;
- produced Artifacts;
- source and dependency revisions;
- test or proof outputs;
- any caller-supplied remaining-work metadata.

Output:

- retained final Events, Receipts and Artifact references.

Ptah does not promote the result into truth or decide the next action.

### `store_handoff`

Input:

- a handoff Artifact created by Hunter, Sergeant, a human or another application.

Output:

- stable Artifact identity, revision, digest, provenance and retrieval reference.

Ptah stores the handoff. It does not verify that the handoff’s conclusions, authority list or next action are correct.

## Context construction rule

Hunter constructs its own bounded context packet from records it explicitly retrieves from Ptah.

A Hunter packet may identify:

- Hunter compiler version;
- Workspace and Session;
- actor and role;
- source identities and revisions;
- Hunter-assigned authority labels;
- privacy labels;
- Grants applied by Ptah;
- Hunter’s selection and exclusion reasons;
- creation time and invalidation conditions.

Those are Hunter records stored on Ptah, not decisions made by Ptah Core.

Sergeant constructs a separate review packet. It should not reuse Hunter’s unchallenged conclusions as review authority.

## Candidate and acceptance rule

Hunter may label its output `generated_candidate`. Sergeant may label its output as a review result. A human or another configured application may accept, reject or supersede either output.

Ptah preserves the supplied records, labels and provenance. Ptah does not promote a candidate, issue a verdict or define canonical truth.

## Provider replacement

Changing a Provider must not erase mechanically durable Ptah state:

- Workspace and Session identity;
- Object and Artifact lineage;
- Activities, Events and Receipts;
- configured Grants;
- retained caller metadata;
- stored handoffs.

Hunter or Sergeant decides what context to rebuild for the new Provider. Ptah returns the requested records and records the Provider identity in the Attempt.

## Local-first and offline behaviour

The bridge allows applications to continue using:

- local Workspace metadata;
- local files and Artifacts;
- local indexes selected by the application;
- local model Providers;
- queued Activities and stored handoffs.

Cloud Facilities may be unavailable. Ptah reports the mechanical unavailability; the calling application decides how to adapt.

## Public/private boundary

Configured access rules must prevent a public Workspace caller from reading private Hunter memory, THETECHGUY Domain Packs, customer/device/payment records or restricted adapters unless an authorized operator or application has explicitly created an appropriately scoped release Artifact and Grant.

Ptah enforces the configured boundary. It does not decide what should be public.

## Proof requirements

Before this bridge becomes operative, implementation must prove the fixtures in:

```text
design/candidates/fixtures/ai-project-workspace-fixtures.json
```

It must also prove:

- exact requested-record lineage;
- no Ptah-owned context selection or authority ranking;
- no privilege increase on Provider replacement;
- recovery after process and machine restart;
- failure and partial-Artifact retention;
- mechanical enforcement of configured Grants;
- no cross-Workspace private retrieval;
- Sergeant review outputs remain Sergeant outputs, not Ptah verdicts.

## Non-claims

This document defines no network API, persistence format or runtime implementation. It does not authorize Hunter or Sergeant integration work before Phase 0C closure and ADR-0033 authorization. It does not make Ptah an intelligence, coordinator, reviewer or approval authority.
