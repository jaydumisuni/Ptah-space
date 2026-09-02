# D03 — Knowledge, Data and Search v2 — Design

Status: design approved in chat; implementation not started

Date: 2026-09-02

Base: `Ptah-space` `main` at `aa933d9d42ac451c941fa359711e949df8d8cd8d` (D02 merge)

Roadmap authority: `ptah-roadmap-` Programme D / D03 — Knowledge, Data and Search v2

Primary dependencies: B07 Search v1 plus Programme C evidence/runtime packs

Exit milestone: General Beta with database support

## 1. Objective

D03 expands Ptah's derived knowledge/search machinery from B07 text/source-bound search into a provider-neutral Knowledge, Data and Search v2 substrate that can mechanically locate, normalize, query, cite, visualize and export documents, source symbols, firmware manifests, partition data, structured datasets/tables and database snapshots/read-only query results.

D03 remains neutral machinery.

> Ptah may preserve, retrieve, query and prove source-bound information. It does not decide what information should be believed, what work should be done, or what result should be accepted.

Every D03 query/index/result/citation is derived from an exact source binding. The derived layer never replaces A03/A07 canonical truth, Programme C source evidence, or an external database's own source truth.

## 2. Recovered D03 deliverables

D03 must deliver:

- a D03-owned public knowledge/search API;
- normalized source descriptors for six source classes: Document, SourceSymbol, FirmwareManifest, PartitionData, Dataset and Database;
- revision/hash/provenance-bound citation evidence;
- Search v2 text/symbol/metadata routing over B07 without leaking B07 public types;
- structured Dataset/Table snapshots and deterministic bounded queries;
- a provider-neutral relational database query contract;
- a qualified read-only SQLite reference provider;
- deterministic query-plan and result-set projections;
- Database Domain Pack composition for ingestion, query planning, result visualization and export;
- source-bound export plans/Artifacts without source mutation;
- exact stale-source detection;
- explicit no-mutation/no-semantic-authority boundaries.

D03 proof must establish General Beta database support without adding database administration, arbitrary SQL mutation, device mutation or a second canonical truth store.

## 3. Architectural decision

Create a new composition crate:

```text
crates/ptah-knowledge-search
```

The crate owns D03 public vocabulary and derived projections. It does not own a new canonical database and does not define a new Core entity family.

Primary composition:

```text
ptah-knowledge-search
  -> ptah-contracts
       frozen knowledge-catalog identities
  -> ptah-archive-decomposition::b07
       B07 derived text/source-symbol search
  -> ptah-archive-decomposition::b03
       exact document/structured-text source anchors
  -> ptah-archive-decomposition::c01/c03/c04/c05/c06
       Programme C read-first firmware/partition evidence
  -> ptah-object-store
       A07 Object/Revision/Artifact/View truth
  -> ptah-workspace
       A06 Workspace/Grant authority
  -> ptah-ledger
       A03 exact canonical record retrieval
```

Database execution is isolated behind a D03-owned provider contract. The initial qualified implementation is:

```text
adapters/database-sqlite
```

The adapter uses SQLite in read-only/query-only mode and exposes no write/DDL/admin capability through D03.

### Alternatives rejected

**Extend `ptah-archive-decomposition` into Search v2.** Rejected. B07 remains a frozen Programme B subsystem. D03 composes it but does not turn the archive/decomposition crate into an unbounded knowledge/database platform.

**Implement D03 inside `ptah-ai-workspace`.** Rejected. D03 is general Ptah machinery consumed by AI and non-AI callers alike. Hunter/Sergeant remain callers.

**Create a second durable knowledge database.** Rejected. D03 indexes and snapshots are derived/rebuildable. Canonical Ptah truth remains A03/A07, while an external database remains authoritative for its source data.

## 4. Frozen knowledge contract bindings

`ptah-contracts` already exposes a frozen knowledge schema catalog. D03 binds to those existing schema identities and does not mint replacement schema families merely for runtime convenience.

Relevant frozen identities include:

```text
urn:ptah:schema:data:database-connection-reference:0.1.0
urn:ptah:schema:data:database-snapshot:0.1.0
urn:ptah:schema:data:dataset:0.1.0
urn:ptah:schema:data:dataset-revision:0.1.0
urn:ptah:schema:data:processing-run:0.1.0
urn:ptah:schema:data:schema-observation:0.1.0
urn:ptah:schema:knowledge:citation:0.1.0
urn:ptah:schema:knowledge:coverage:0.1.0
urn:ptah:schema:data:export:0.1.0
urn:ptah:schema:data:quality-report:0.1.0
urn:ptah:schema:data:table-observation:0.1.0
urn:ptah:schema:knowledge:index:0.1.0
urn:ptah:schema:knowledge:index-revision:0.1.0
urn:ptah:schema:knowledge:ingestion-request:0.1.0
urn:ptah:schema:knowledge:ingestion-run:0.1.0
urn:ptah:schema:knowledge:query:0.1.0
urn:ptah:schema:knowledge:query-run:0.1.0
urn:ptah:schema:knowledge:result:0.1.0
urn:ptah:schema:knowledge:result-set:0.1.0
urn:ptah:schema:knowledge:segment:0.1.0
urn:ptah:schema:knowledge:source:0.1.0
urn:ptah:schema:knowledge:source-revision:0.1.0
urn:ptah:schema:knowledge:verification:0.1.0
```

D03 may mechanically bind runtime records to `ptah_contracts::schema_by_id` metadata. It must not claim full JSON-Schema validation unless the exact schema body is available to and actually validated by the implementation.

If implementation discovers that a required D03 invariant cannot be represented without changing a frozen canonical contract, work stops and opens the appropriate versioned ADR/contract-reopening process.

## 5. Source model

D03 owns neutral `KnowledgeSourceRef` and `KnowledgeSourceRevision` vocabulary.

Supported source classes are Document, SourceSymbol, FirmwareManifest, PartitionData, Dataset and Database.

Every source revision carries, as mechanically applicable:

- Workspace identity;
- canonical source entity reference;
- positive canonical source record revision;
- exact A07 Object Revision where byte-backed;
- content SHA-256 or provider snapshot digest;
- source class;
- provenance/evidence reference;
- source-specific locator namespace;
- verification/coverage state.

A source is not considered current merely because its identifier matches a previous query. Revision/hash identity is part of the source binding.

## 6. Locator and citation model

`evidence.rs` defines D03-owned locators rather than returning B07 or Programme-C internal types.

Initial locator variants:

```text
ByteRange
LineRange
DocumentAnchor
SourceSymbol
FirmwareComponent
PartitionRange
DatasetCell
DatasetRow
DatabaseCell
DatabaseRow
```

A `CitationEvidence` contains the exact source revision binding, one exact locator, extraction/query mechanism, optional B07 index revision/digest, optional query-run identity, evidence/coverage qualifiers and a non-authoritative marker.

Citation construction fails closed when the requested locator cannot be proven against the exact source revision.

A stale source revision is returned as `StaleSourceRevision`; D03 does not silently refresh the citation against newer bytes or a newer database snapshot.

## 7. Derived index architecture

D03 does not replace B07. `KnowledgeIndex` composes two derived layers:

1. a D03 source registry containing normalized exact source descriptors;
2. a private B07 `SearchIndex` for textual fields, source symbols and searchable metadata.

The source registry is rebuildable projection state, not canonical storage.

Rebuild properties:

- deterministic ordering and content digest for the same normalized source set;
- Workspace filtering before matching;
- no A03/A07 mutator capability;
- no source mutation;
- exact source-revision validation before admission;
- duplicate exact source-revision identity rejection;
- bounded source, field and index resources.

B07 types are private implementation details. No public D03 request, result or error exposes `ptah_archive_decomposition::b07::*`.

## 8. Document and source-symbol adapters

Documents compose existing B03 exact byte/revision anchors. D03 accepts only source-bound B03 output or an equivalent exact A07 source revision. It preserves line/byte anchors and never treats extracted text as independent truth.

Source-symbol search composes the accepted B07 exact-source-revision symbol constructor. D03 maps B07 symbol hits into `CitationEvidence::SourceSymbol`, retaining exact source identity/revision and symbol locator.

D03 does not infer symbol correctness, call-graph truth, semantic ownership or code authority.

## 9. Programme C firmware and partition adapters

Programme C remains authoritative for the read-first evidence it produces. D03 adapters normalize published Programme C reports into D03 source descriptors; they do not copy Programme-C control authority.

Initial evidence families:

- C01 disk image / MBR / GPT partition reports;
- C03 Generic Android image, OTA manifest and dynamic-partition reports;
- C04 Apple IPSW/OTA/IMG4 manifest/inventory evidence;
- C05 MediaTek package/scatter/partition evidence;
- C06 Unisoc and Qualcomm static package/partition evidence.

D03 public types do not expose `c01`/`c03`/`c04`/`c05`/`c06` structs.

Firmware/partition search results may expose mechanically retained facts such as source digest, component name, partition name/index, exact byte/LBA/range, manifest linkage, storage/LUN and evidence qualifiers.

They may not flash, erase, repartition, unlock, select a programmer/loader, infer device compatibility, approve a firmware package, claim signing/Verified-Boot trust, or convert a static manifest flag into write authority.

C08-C11 device/application/workload authorities remain outside the D03 query contract. If later D03 evidence needs one of those observations, it must be added through a separately reviewed read-only adapter rather than a generic device-runtime dependency.

## 10. Structured Dataset and Table model

`structured.rs` provides bounded immutable snapshots.

Core types:

```text
DatasetSnapshot
TableSnapshot
ColumnSchema
Row
CellValue
StructuredQuery
StructuredResultSet
```

`CellValue` is a D03-owned tagged value with explicit Null, Boolean, Integer, decimal/text-safe numeric representation, Text and Bytes/Digest-reference variants. No lossy type coercion is allowed merely to make a query succeed.

Every dataset/table snapshot binds to one exact source revision and deterministic snapshot digest.

Initial ingestion adapters support caller-supplied typed table snapshots, JSON array/object records, JSON Lines records and bounded CSV/delimited tables.

Ingestion produces a derived snapshot plus quality/coverage evidence. It does not overwrite the originating Object or external source.

Structured queries support deterministic projection, equality/ordering predicates, null predicates, bounded membership predicates, deterministic sort and limit/offset.

No query may silently truncate input truth. Resource limits are explicit and failures are reported.

## 11. Database provider contract

D03 defines a provider-neutral, read-only `DatabaseQueryProvider` interface.

A connection is represented by a `DatabaseConnectionReference`, never by D03-owned plaintext credentials.

Connection metadata may contain provider kind, endpoint/path reference, logical database name, credential-reference handle when required and configured read-only capability statement. Secrets remain in caller/provider secret authority and are not copied into query/citation evidence.

The provider contract exposes only:

- inspect schema;
- capture bounded source snapshot identity;
- execute a typed read-only query plan;
- return typed rows plus provider evidence.

It exposes no write, DDL, migration, transaction-mutation, extension-loading or administration method.

## 12. SQLite reference provider

`adapters/database-sqlite` is the first qualified D03 database provider.

It opens databases with SQLite read-only semantics and enforces `query_only` behavior.

The adapter receives a D03 typed relational plan and compiles it into parameterized SQL. Callers do not submit arbitrary SQL through the D03 General Beta contract.

The provider rejects non-read-only connection mode, unsupported expressions, multiple statements, DDL/DML/PRAGMA mutation, ATTACH/DETACH, extension loading and unbounded result plans.

The qualified General Beta citation path is **exact snapshot mode**: the SQLite database is supplied as an exact materialized A07 Object Revision, its bytes are SHA-256 revalidated before query execution, and the provider opens only that validated snapshot read-only. The durable database source identity is the exact Object Revision plus content digest and schema-observation digest. A newer database copy is a different source revision and makes an old citation mechanically stale when a caller asks to validate it as current.

A future/live mutable SQLite path may be inspected only through an explicitly `Ephemeral` read-only evidence mode. Ephemeral results may carry query-run evidence but cannot claim durable snapshot identity or produce a persistent exact citation. Live mutable mode is not required for D03 completion and must not be used to satisfy the General Beta database proof.

## 13. Relational query plan

`database.rs` defines a provider-neutral typed plan.

General Beta plan surface:

```text
TableRef
ColumnRef
Projection
Predicate
Join
Aggregate
Order
LimitOffset
RelationalQueryPlan
```

Supported composition includes one or more explicit tables, inner and left joins, parameterized comparison predicates, null predicates, bounded `IN`, projection, count/sum/min/max/avg aggregates where the provider can preserve type evidence, grouping, deterministic ordering, explicit row limit and offset.

The plan contains no semantic relevance/ranking decision. It is a mechanical execution description. Query plans are validated before reaching a provider and have explicit complexity/resource bounds.

## 14. Query routing and result model

`query.rs` exposes one D03 query facade with explicit query families:

```text
TextSearch
SymbolSearch
MetadataSearch
StructuredQuery
RelationalQuery
```

Routing is deterministic from the query variant, not model-selected.

Results are returned as `KnowledgeResultSet` Views containing query identity, query-plan digest, exact source revision bindings, result rows/hits, citation evidence per result, provider/index evidence, completeness/limit state and `authoritative = false`.

A caller may later persist a result through normal A07 mechanics. D03 does not make every query result canonical automatically.

## 15. Database Domain Pack

D03 provides a Database Domain Pack as composition, not a Core authority family.

It has four mechanical stages:

```text
ingestion -> query planning -> result visualization -> export
```

**Ingestion** captures connection/source metadata, schema/table observations and a bounded snapshot identity. It does not copy credentials or mutate source data.

**Query planning** builds/validates the typed relational plan supplied by the caller or compatible application. D03 validates mechanics and limits; it does not invent business intent.

**Result visualization** produces a derived table-oriented View specification suitable for D01/compatible clients. Visualization may describe columns, rows, truncation, provenance and citation affordances. It does not change result truth.

**Export** produces deterministic export bytes plus source/query provenance for caller-requested JSON, JSON Lines and CSV formats. Export is a derived output. Promotion into an A07 Object/Artifact requires the existing A04/A07 production-evidence path; D03 does not bypass it.

## 16. Authority and mutation boundary

D03 MAY normalize exact evidence, rebuild derived indexes, perform mechanically authorized reads, execute bounded read-only queries, produce derived result Views, and generate provenance-bound export bytes/plans.

D03 MUST NOT:

- choose what work should happen;
- rank one source as canonical truth;
- silently replace stale evidence with newer evidence;
- mutate source databases;
- flash/erase/repartition devices;
- inherit Programme-C write authority;
- grant Workspace access;
- reinterpret caller trust/approval labels;
- promote query results into canonical truth without existing A04/A07 evidence;
- turn a Domain Pack into a Core family;
- expose B07/Programme-C implementation types through D03 public APIs.

## 17. Workspace and Grant boundary

All D03 source admission and query operations are Workspace-scoped.

Where a source is protected by A06, the mechanical order is:

1. validate identifiers;
2. authorize the exact Workspace/source boundary;
3. retrieve exact source metadata/revision;
4. verify exact revision/hash/provenance;
5. only then admit/query it.

Cross-Workspace search is filtered before matching/execution. A query that can name another Workspace cannot bypass A06 by discovering its source through an index.

Database providers receive only the exact connection/snapshot reference admitted for the current operation.

## 18. Error model

D03 errors are mechanical and D03-owned. Required categories include unsupported source class, invalid source binding, source revision not found, stale source revision, source digest mismatch, Workspace access denied, unsupported locator, invalid citation binding, index rebuild/input limit violation, B07 adapter failure, Programme C adapter failure, structured ingestion/query failure, database provider unavailable, database snapshot mismatch, invalid relational plan, read-only policy violation, result/resource limit exceeded, export failure and underlying A03/A06/A07 failure.

There are intentionally no semantic errors such as `WrongSource`, `UntrustedAnswer`, `BadFirmwareChoice`, `IncorrectConclusion` or `BadBusinessDecision`.

## 19. Resource limits

D03 defines explicit defaults and configurable hard ceilings for indexed sources, fields per source, source metadata bytes, document/symbol matches, dataset tables/columns/rows, cell bytes, JSON/CSV input bytes, relational tables/joins/predicates/projections/groups, query parameters, result rows/cells/bytes, citation count and export bytes.

Over-limit input fails closed. Input is never silently truncated and then represented as complete truth. Result limits are explicit in `KnowledgeResultSet` and carry incomplete/bounded-result evidence.

## 20. Proposed crate layout

```text
crates/ptah-knowledge-search/
  Cargo.toml
  src/
    lib.rs
    source.rs
    evidence.rs
    index.rs
    query.rs
    structured.rs
    database.rs
    domain_pack.rs
    error.rs
    adapters/
      mod.rs
      b07.rs
      b03.rs
      programme_c.rs
  tests/
    d03_acceptance.rs

adapters/database-sqlite/
  Cargo.toml
  src/
    lib.rs
    provider.rs
    compiler.rs
  tests/
    d03_sqlite.rs
```

Keep the provider adapter physically separate so `ptah-knowledge-search` remains provider-neutral and SQLite-specific error/types cannot leak into D03 public contracts.

## 21. Acceptance corpus

D03 receives one exact-head acceptance corpus covering at minimum:

1. all six source classes normalize with exact revision/provenance;
2. document citation preserves exact byte/line anchor and Object Revision;
3. source-symbol citation preserves exact source revision and symbol locator;
4. C03 firmware manifest evidence preserves exact source/component/manifest binding;
5. C01 partition evidence preserves exact partition range and source digest;
6. C05/C06 firmware partition evidence remains static/read-only and non-authoritative;
7. stale Object/source revision is rejected rather than silently refreshed;
8. B07 type leakage is absent from D03 public API;
9. Programme-C type leakage is absent from D03 public API;
10. B07 ranking/order changes cannot alter source/citation truth;
11. cross-Workspace search is denied before matching;
12. typed dataset ingestion preserves deterministic snapshot digest;
13. JSON/JSONL/CSV ingestion reports incomplete/malformed input rather than inventing rows;
14. structured query projection/filter/order/limit is deterministic;
15. database connection reference retains no plaintext secret;
16. SQLite provider proves read-only/query-only behavior;
17. typed relational projection/filter/join/group/aggregate/order/limit works deterministically;
18. SQL mutation/DDL/ATTACH/extension-loading surfaces are absent or rejected;
19. database result rows bind to exact database snapshot/query evidence;
20. changed database snapshot makes previous citation stale/detectable;
21. visualization output is a derived non-authoritative View;
22. JSON/JSONL/CSV export is deterministic and provenance-bound;
23. export cannot become an A07 Artifact without normal production/promotion evidence;
24. no device flash/erase/repartition authority exists on the D03 API;
25. frozen knowledge schema catalog IDs are reused and no new Core schema family/migration is introduced;
26. D02 AI Project Workspace search integration remains compatible;
27. B07 16/16 acceptance remains green;
28. C01/C03/C04/C05/C06 targeted regressions remain green;
29. D01/D02/A06/A07 regressions remain green;
30. full locked Ptah workspace passes.

## 22. Static proof guards

The D03 exact-head workflow must additionally prove:

- exact accepted D02 merge base;
- bounded D03 changed-file surface;
- no pre-existing dependency version movement;
- any new dependency delta is explicitly reviewed;
- no new ledger migration;
- no modification of frozen generated contract catalog;
- no public `ptah_archive_decomposition` types in D03;
- no public Programme-C implementation types in D03;
- no public database mutation/admin operation vocabulary;
- no device mutation operation vocabulary;
- no plaintext credential field in D03 source/query evidence;
- `cargo fmt --all -- --check`;
- accepted strict Clippy gate with zero D03 warnings;
- exact D03 acceptance count;
- full `cargo test --workspace --locked`;
- clean working tree and retained proof manifest.

## 23. Scope explicitly deferred

D03 does not implement arbitrary caller-submitted SQL, database writes/migrations/administration, PostgreSQL/MySQL/network database providers unless separately qualified after the provider-neutral contract is proven, vector/embedding semantic ranking as authority, autonomous source trust ranking, firmware compatibility decisions, device mutation, D04 Recipe/service-registry execution, D05 plugin lifecycle, D06 release/SBOM/signing expansion, D07 security Finding/reproduction workflow, D08 general Application platform expansion, or D09 full Workspace release acceptance.

The provider-neutral database contract must allow later read-only providers without changing D03 public query/citation truth.

## 24. Completion criterion

D03 is complete only when one frozen exact implementation head proves the complete D03 acceptance corpus, preserves B07 and Programme C authority boundaries, provides real qualified read-only database support, reuses the frozen knowledge catalog, preserves D01/D02 and all inherited regressions, exposes no source/database/device mutation authority, and is merged to canonical `main`.

Passing tests prove that the implementation conforms to the frozen design. Tests do not invent or replace the authority contracts that define D03.
