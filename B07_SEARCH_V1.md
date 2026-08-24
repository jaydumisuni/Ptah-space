# B07 — Search v1

Status: BUILD / REVIEW candidate

Accepted base: `84340971d03bb3ed9780fbb73f4a7ecf1589072d` (B06 merge)

Authority: Ptah Implementation Roadmap 1.1.0, Programme B / B07.

## Scope

B07 is a derived, rebuildable search projection over canonical and evidence-bound Ptah truth. It is not a new canonical database and receives no A03/A07 mutation capability.

Delivered candidate surface:

- filename search;
- B02 evidence-derived metadata search;
- B03 source-anchored document text search;
- source-symbol search adapter;
- log search adapter;
- Activity search adapter;
- Artifact search adapter;
- exact local index revision and deterministic content digest;
- full clear/rebuild semantics;
- exact source-bound results carrying Workspace, canonical source entity, canonical source record revision and optional exact Object Revision;
- Workspace filter applied before matching;
- bounded document, field, query and result resources;
- deterministic result ordering and domain filtering.

## Truth boundaries

- Search index state is derived projection state only; index revision is not an Object Revision or canonical record revision.
- B07 owns no ledger or ObjectStore mutator.
- Clearing or rebuilding the index mutates only private derived copies and cannot mutate caller/canonical documents.
- Same canonicalized source input rebuilt later produces the same content digest even though the local index revision advances.
- Every indexed document binds one exact Workspace, canonical source entity and positive canonical source record revision.
- Byte/content-derived documents may additionally bind one exact `object.revision`; when present that kind is enforced.
- B03 text is accepted only when every anchor binds the exact supplied Object Revision.
- B02 metadata preserves its evidence source instead of becoming an unqualified semantic fact.
- Queries are Workspace-scoped before text matching; private content from another Workspace is not eligible for a result.
- Search hits expose canonical source bindings, never index-local surrogate identity.
- Unsupported, malformed or over-limit input fails closed rather than silently truncating indexed truth.

## Acceptance corpus

The exact candidate must pass all 14 B07 cases covering:

1. filename and B02 metadata search with evidence source;
2. B03 anchored document text and exact Object Revision binding;
3. source-symbol search over an exact source revision;
4. independent log, Activity and Artifact domain search;
5. private Workspace isolation before matching;
6. exact canonical source record and Object Revision in every result;
7. clear/rebuild non-mutation and reproducible content digest;
8. duplicate exact index-document identity rejection;
9. malformed Workspace/Object Revision/record-revision binding rejection;
10. field, document, query and result resource bounds;
11. domain filtering without cross-domain false positives;
12. deterministic result limiting and ordering;
13. mismatched B03 source-anchor rejection;
14. case-insensitive all-term query semantics.

## Exact-head proof gate

Promotion requires one exact PR head that passes:

- accepted B06 base and bounded six-file B07 scope lock;
- pinned Rust/Cargo 1.97.1;
- `cargo fmt --all -- --check`;
- B07 acceptance: 14/14;
- strict `ptah-archive-decomposition` Clippy with `-D warnings`;
- inherited B02 type/search-metadata regressions;
- inherited B03 document/anchoring regressions;
- inherited B05 executable/package regressions;
- inherited B06 Session Vault regressions;
- full locked workspace regression;
- clean working tree;
- immutable exact-head proof manifest and retained artifact.

Any source movement invalidates Freeze and requires affected Review → Freeze → Prove again.

## Exit

B07 is COMPLETE only when the exact proven candidate is merged to `main`. That merge establishes the Programme B **Object World Beta** milestone; a proved canonical B07 candidate must not remain parked in an open PR.
