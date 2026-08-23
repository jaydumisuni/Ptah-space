# B03 — Documents and structured text

Status: candidate; promotion is valid only for an exact implementation head proven by the B03 workflow.

## Authority

- Accepted B02 merge base: `af4f7dbb87fb5ab4674d2509577dca0003ad2740`.
- B03 roadmap dependency: B02.
- B02 remains authoritative for detector evidence, declared-versus-observed type comparison and disagreement truth.
- A12/B02 remain authoritative for progressive decomposition and child provenance.
- A07 remains authoritative for Object, Revision, View and Artifact identity.

B03 adds passive document interpretation. It does not execute document active content and does not reopen B02 or A07 identity semantics.

## Delivered surface

B03 adds the following to `ptah-archive-decomposition`:

1. passive document adapter contract selected only from a non-disputed B02 agreed media type;
2. explicit adapter isolation declaration requiring active-content execution, network access and external-resource loading to be denied;
3. built-in safe structured-text adapter for text/plain, JSON, CSV and Markdown-style text;
4. built-in safe HTML adapter that removes script/style/embedded active regions and emits passive text only;
5. replaceable passive PDF/office adapter boundary for lawful provider integrations;
6. metadata and text extraction with exact source-Revision anchoring and byte/page anchors where provable;
7. bounded page/render View payloads with exact source-Revision anchors;
8. passive text/plain preview generation;
9. explicit extraction/render warnings, limitations and unknown gaps;
10. safe conversion output carrying source digest, output digest and exact source Revision;
11. A07 View specifications whose source is frozen from the inspected report and cannot be rebound by a later caller context;
12. A07 converted-object registration specification using `RevisionRole::Converted` and the conversion's frozen exact source Revision;
13. resource limits for retained text, pages, page-render bytes, preview bytes and converted bytes;
14. generic HTML event-handler observation plus passive removal of executable attributes from preview text;
15. safe handling of void embedded elements without discarding following benign document text.

## Acceptance proofs

The exact-head B03 workflow must prove:

- structured text retains exact source byte and Revision anchors;
- malicious HTML script/event/external-resource content is not present in the passive preview or converted text and source bytes remain unchanged;
- detector disagreement prevents adapter selection and remains explicit;
- unsupported agreed document types remain explicit rather than claiming extraction success;
- an adapter that allows active execution, network or external-resource loading is rejected before inspection;
- ambiguous adapters fail closed without choosing a winner;
- passive PDF and office adapter boundaries retain rendering limitations and source Revision anchors;
- resource limits downgrade coverage and expose truncation/omission instead of overclaiming completeness;
- reaching an exact page-count boundary does not invent truncation when no page was omitted;
- preview truncation independently downgrades coverage and records the exact limiting policy;
- converted output registration creates a new converted Revision plan whose source is the exact original Revision;
- a later mismatched caller context cannot rebind converted-output provenance;
- declared-type mismatch cannot override the B02-agreed observed type;
- canonical View specifications remain bound to the report's exact source Revision even if a later caller context names another Revision;
- generic event-handler attributes are observed without execution;
- self-closing embedded active elements do not erase benign content that follows them;
- inherited B02 and A12 acceptance suites still pass;
- the complete inherited Rust workspace still passes at the exact B03 head.

## Non-claims

- B03 does not execute JavaScript, macros, embedded applications or document event handlers.
- B03 does not fetch external document resources.
- A passive preview is not a fidelity claim for office/PDF/HTML layout.
- Adapter success is bounded mechanical evidence, not semantic authority.
- A converted output is a new derived Revision; it never overwrites or mutates the source Revision.
- Missing adapters, disputed types, truncation and unsupported regions remain explicit.
- B03 does not claim OCR capability.

## Promotion rule

Promote only the exact PR head for which the B03 exact-head workflow succeeds, all Review findings are resolved, and the retained proof manifest names that same implementation commit. If the head moves after proof, the proof is obsolete and must be rerun.
