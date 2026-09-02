# D02 — AI Project Workspace substrate and application adapters

## Status

Implementation candidate for Programme D02, built on the shipped D01 merge:

`8be77210eee2b62eed753151287935bdebc369ae`

D02 makes the accepted `ptah.workspace.ai_project.v1` profile mechanically operative while exposing the D02-compatible subset of `ptah.workspace.operations.v2`. The exact candidate head is frozen only after review and is then proven by the D02 exact-head CI lane.

This document records implementation and proof boundaries. It grants no semantic authority.

## Roadmap boundary

D02 is the AI Project Workspace substrate and application-adapter milestone. It composes already-proven Ptah primitives rather than creating a new Core family or control plane.

The implementation adds `crates/ptah-ai-workspace`, which composes:

- A03 canonical ledger reads;
- A04 Activity/Attempt/result and retained partial-work truth;
- A06 Workspace/Session/Secure Grant authority;
- A07 Object/Revision/Artifact identity and promotion evidence;
- A13/B06 recovery and archived Session Vault truth;
- B07 derived source-bound search.

D02 does not alter frozen WP01–WP14 schemas or add a ledger migration.

## Delivered runtime surface

The D02 composition crate provides:

- exact neutral profile identities for `ptah.workspace.ai_project.v1` and `ptah.workspace.operations.v2`;
- typed caller-owned semantic-authority boundaries and an existing-Core-only entity policy;
- exact authority-gated Workspace, Session, Activity, Object and Artifact retrieval;
- bounded caller-record encoding/decoding that preserves caller labels, order and payload bytes without ranking meaning;
- non-authoritative live Session/thread projection;
- exact archived Session discovery through B06 Session Vault manifests;
- non-authoritative Artifact Library projection over A06 scope plus canonical A07 Object/Artifact records;
- immutable exact admitted-input and Grant envelopes;
- a D02-owned search API over B07 with authorization before query execution and exact source revision binding;
- thin Hunter and Sergeant caller adapters.

## Authority invariants

Ptah remains machinery, not the thinker. D02 does not:

- choose semantic context or relevance;
- rank conflicting caller labels into a winner;
- choose trust/source authority;
- approve caller work or worker results;
- adopt a Sergeant finding as a Ptah verdict;
- promote a candidate because a review exists;
- choose remediation or next action;
- widen Grants when an intelligence/provider changes;
- treat external Provider permission as a Ptah Grant;
- treat a Ptah Grant as caller/human approval;
- turn B07 search/index output into canonical source truth;
- turn a Session, Artifact Library, or search result View into authority;
- equate an external/indexed reference with a materialized local copy;
- infer a local path from an Artifact reference;
- implement the later D04 scheduler/Recipe registry.

The runtime profile expresses decision, context-selection, review-verdict and approval authority as caller-owned typed boundaries. It composes existing Core entities only.

## Retrieval and isolation

`WorkspaceReader` validates exact identifiers, performs A06 retrieval authorization first, reads canonical truth through A03 only after authorization, and verifies Workspace ownership before returning protected record bytes.

Cross-Workspace access therefore fails closed before protected data is returned. Private Hunter records remain private unless the configured Workspace/Grant boundary explicitly permits access.

Canonical Object/Artifact metadata retrieval is distinct from A07 materialization. D02 never converts an Object/Artifact reference into local bytes or a local path by assumption.

## Caller records and conflicting labels

Caller metadata and handoffs remain caller-authored A07 bytes. D02 validates bounded structure only; it does not validate semantic truth.

Contradictory labels such as caller-supplied source/trust states remain independently retained. D02 emits no synthesized winner and does not rewrite caller meaning.

## Sessions, library, search and recovery

Live project threads are non-authoritative projections over durable A06 Sessions. Replacing a model/provider does not replace Workspace or Session identity and does not rewrite configured Grants.

Archived Session discovery uses exact B06 Session Vault manifest identity. D02 adds no invented A06 archive lifecycle.

The Artifact Library is a deterministic read-only projection over exact Workspace-scoped Object references and their canonical Artifact links. It cannot promote, accept, rank or delete Artifacts and does not claim exhaustive truth when the underlying scope is incomplete.

B07 is hidden behind D02-owned request/response types. D02 authorizes the Workspace boundary before B07 query execution. Results retain exact canonical source/reference bindings and remain non-authoritative.

## Exact admitted inputs

`ActivityInputEnvelope` carries only exact caller-submitted input and Grant references for one invocation. A later request for an undeclared input or undeclared Grant fails mechanically even when another search could discover that reference.

A schedule, recurrence or condition does not add context or access. D02 intentionally does not implement D04 scheduling/Recipe authority.

## Hunter and Sergeant adapters

The Hunter adapter delegates already-selected exact reads, caller-record encoding and input-envelope operations. It has no `choose_context`, `select_authority`, `approve`, `promote` or `decide_next_action` surface.

The Sergeant adapter retrieves the explicitly supplied frozen candidate/evidence and encodes Sergeant-authored review bytes. Candidate and review Artifacts remain distinct identities. No Ptah approval/rejection field is created from Sergeant output.

## Recovered acceptance fixtures

The frozen D02 acceptance corpus contains exactly 18 tests. It includes all recovered AI Project Workspace fixtures:

1. Workspace isolation;
2. caller-label exact round-trip;
3. conflicting labels with no ranking;
4. model-independent resume;
5. Grant stability across agent/model replacement;
6. exact scheduled/admitted inputs;
7. private Hunter versus public Workspace denial;
8. archived Session discoverability;
9. failed Activity visibility with retained partial worker output;
10. Sergeant review with no Ptah verdict.

It also proves the D02 `operations.v2` vocabulary/boundaries, external-reference versus materialized-copy separation, non-authoritative Session/Library Views, source-bound search and exact neutral profile identities.

## Proof contract

The D02 exact-head proof lane requires all of the following on the frozen candidate:

1. exact D01 predecessor `8be77210eee2b62eed753151287935bdebc369ae`;
2. changes restricted to the approved D02 crate, workspace membership/lock stanza, design/plan/implementation records and D02 proof workflow;
3. no WP01–WP14 schema, migration, historical Phase-0C candidate, donor or frozen-contract mutation;
4. `Cargo.lock` changes only by adding the `ptah-ai-workspace` package stanza with existing locked dependencies;
5. `cargo fmt --all -- --check`;
6. `cargo clippy -p ptah-ai-workspace --all-targets --locked -- -D clippy::all -D clippy::pedantic`;
7. no TODO/FIXME/`todo!`/`unimplemented!`/unsafe source escape in the D02 crate;
8. exactly 18 D02 acceptance tests;
9. complete locked `ptah-ai-workspace` package suite;
10. complete locked workspace regression suite;
11. static adapter-surface guard against semantic-authority methods;
12. exact-head evidence containing commit/tree identity and hashes of every D02 changed file.

The existing `ptah-control` missing-documentation warnings are inherited D01/A14 baseline debt and are not D02 failures. D02 itself passes the strict `clippy::all + clippy::pedantic` gate without suppression.

## Evidence interpretation

Passing tests prove the mechanical implementation at the frozen revision. They do not create authority outside the accepted contracts. Hunter, Sergeant, humans and other caller applications remain responsible for semantic context, trust, review meaning, approval, acceptance and next action.
