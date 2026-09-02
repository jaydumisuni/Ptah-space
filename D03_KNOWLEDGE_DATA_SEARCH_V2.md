# D03 — Knowledge, Data and Search v2

## Status

Programme D03 implementation and exact-head proof record.

Accepted predecessor:

`aa933d9d42ac451c941fa359711e949df8d8cd8d`

That predecessor is the verified D02 merge on `main`. D03 adds a provider-neutral knowledge/data/search substrate and a qualified exact-snapshot read-only SQLite provider without adding a new Core family, ledger migration, semantic authority, database mutation authority, or device mutation authority.

This document records mechanical implementation/proof boundaries only.

## Roadmap boundary

D03 is **Knowledge, Data and Search v2**. It composes the accepted B03/B07 and Programme-C machinery into one D03-owned public contract for:

- documents;
- source symbols;
- firmware manifests/components;
- partition/layout evidence;
- structured datasets/tables;
- exact database snapshots and typed read-only query results.

All index/search/query/visualization/export outputs are derived Views. Source identity, source revision, exact digest and provenance remain the underlying truth.

## Delivered packages

D03 adds:

- `crates/ptah-knowledge-search` — provider-neutral D03 source/citation/index/query/database/domain-pack contract;
- `adapters/database-sqlite` — qualified exact-snapshot SQLite implementation of the D03 database-provider boundary.

The SQLite adapter is physically separate so SQLite-specific types and errors do not enter the D03 public contract.

## Source and citation contract

`KnowledgeSourceRevision` binds one D03 source to:

- owning Workspace;
- canonical source entity;
- exact source-record revision;
- exact A07 `object.revision` where byte-backed;
- lowercase SHA-256;
- source class;
- provenance reference;
- existing frozen knowledge schema identity.

The six source classes are:

1. `Document`;
2. `SourceSymbol`;
3. `FirmwareManifest`;
4. `PartitionData`;
5. `Dataset`;
6. `Database`.

A stale revision or digest fails closed. D03 never silently refreshes an old citation against newer bytes.

`CitationEvidence` is always non-authoritative and retains the exact source plus a source-local locator such as a document anchor, source symbol, firmware component, partition range, dataset cell/row, or database cell/row.

## Frozen schema reuse

D03 reuses the already-frozen knowledge catalog, including the existing database connection/snapshot, dataset/table, query/result, citation, index, ingestion and export identities. No frozen generated catalog, schema family or migration is modified by D03.

Examples include:

- `urn:ptah:schema:data:database-connection-reference:0.1.0`;
- `urn:ptah:schema:data:database-snapshot:0.1.0`.

The runtime acceptance corpus verifies the required frozen identities through `ptah-contracts` lookups.

## B03/B07 boundary

B03 exact anchors and B07 derived search are consumed behind D03-owned types.

B07 remains a private implementation dependency:

- D03 authorizes/filter-scopes before matching;
- exact source revision/hash/provenance is retained independently of ranking;
- D03 metadata families for one exact source are merged before the B07 projection boundary;
- B07 ranking/order changes cannot rewrite citation truth;
- no `ptah_archive_decomposition` search type or B07 error leaks through the D03 public API.

Search/index state is never promoted to independent source authority.

## Programme-C firmware and partition evidence

D03 owns minimal normalized projections for C01/C03/C04/C05/C06. Real Programme-C report types remain private to the conversion module.

The private conversion proof runs actual C01/C03/C04/C05/C06 parsers and verifies:

- exact C01 partition byte/LBA ranges;
- C03 exact component and manifest-digest binding;
- C04 exact DER/archive component binding;
- C05 scatter/layout fields as static evidence only;
- C06 Qualcomm/Unisoc component/range/LUN evidence as static evidence only.

D03 intentionally omits `is_download`, flash, erase, programmer, FDL execution, repartition and similar mutation semantics from its public evidence model. Observing such source metadata does not grant device authority.

## Structured datasets

D03 supplies bounded deterministic ingestion for:

- JSON object/array records;
- JSON Lines;
- UTF-8 comma-delimited RFC4180-style CSV.

Normalized dataset snapshots have deterministic column ordering, typed values, inferred schema, exact source binding and deterministic snapshot SHA-256.

Structured query supports caller-supplied projection, typed predicates, deterministic ordering and bounded limit/offset. Truncation is explicit through `complete=false`; malformed input fails closed rather than inventing rows.

Dataset result citations bind exact source/table/row/column positions and remain non-authoritative.

## Provider-neutral database contract

`DatabaseConnectionReference` contains only mechanical source/provider metadata:

- provider kind;
- canonical source reference;
- exact `object.revision`;
- expected lowercase SHA-256;
- logical name;
- optional external `credential_ref`;
- mandatory `read_only=true`.

It contains no password, token, DSN or raw credential value.

The public `DatabaseQueryProvider` boundary provides only:

- schema inspection;
- exact snapshot evidence;
- execution of a typed read-only `RelationalQueryPlan`.

The relational plan contains validated identifiers and typed expressions/predicates/joins/aggregates/groups/order/limit/offset. Callers cannot submit arbitrary SQL through this contract.

D03 exposes no insert/update/delete, DDL, raw-SQL, ATTACH/DETACH, generic PRAGMA, extension-loading or administration method.

## Exact-snapshot SQLite qualification

`adapters/database-sqlite` qualifies the General Beta database path.

A caller/materializer binds one exact `KnowledgeSourceRevision` and exact `object.revision` to a provider-local materialized file. The filesystem path remains provider-local and is not added to the provider-neutral D03 public connection contract.

Before every schema/query operation, the provider streams and verifies the file SHA-256 against the bound exact source digest. Changed bytes return `DatabaseSnapshotMismatch`.

SQLite opens with:

- `SQLITE_OPEN_READ_ONLY`;
- `SQLITE_OPEN_NO_MUTEX`;
- internal `PRAGMA query_only = ON`.

The typed compiler produces one parameterized `SELECT` only. Caller values become parameters; validated identifiers are quoted. There is no raw-SQL input method and no extension-loading feature in the adapter dependency surface.

The provider converts SQLite values to D03 typed values. Blob values are represented as SHA-256 plus exact byte size. Query execution fetches at most one probe row beyond the caller limit so truncation is mechanically reported rather than silently labeled complete.

Live mutable SQLite is intentionally not the durable D03 citation path. Durable citation requires the exact materialized snapshot described above.

## Database Domain Pack

D03 provides the mechanical Database Domain Pack stages required by the roadmap:

`ingestion -> query planning -> result visualization -> export`

`KnowledgeQueryAuthority` delegates the exact Workspace retrieval boundary to A06 `WorkspaceStore::authorize_retrieval`. Same-Workspace access succeeds mechanically; cross-Workspace access requires existing A06 membership/Grant authority. D03 does not invent or widen access.

`ResultTableView` is a shape-preserving derived projection of typed values/citations.

`ExportBundle` deterministically supports:

- JSON;
- JSON Lines;
- CSV with LF line endings.

Every export carries exact source refs and the query-plan SHA-256 and is explicitly `authoritative=false`. The bundle has no A07 Artifact identity and no promotion method. Promotion still requires the ordinary A04/A07 production-evidence path.

## D02 compatibility

D02 remains unchanged and does not acquire D03 semantic/context authority.

The D03 acceptance corpus proves D02 can retain D03 source-reference bytes as an opaque `CallerRecord` payload without interpreting, ranking or promoting them. The full D02 acceptance suite remains green.

## Dependency delta

D03 introduces no new external dependency version.

The root workspace already pinned `rusqlite = 0.37.0`; the SQLite adapter reuses that exact lock.

From the D02 predecessor, `Cargo.lock` changes only by adding:

- `ptah-knowledge-search` and its existing workspace dependency edges;
- `ptah-database-sqlite` and its existing workspace dependency edges.

`ptah-ai-workspace` is present only as a D03 test/dev dependency used for the D02 opaque-consumption compatibility proof. No pre-existing package/version/source entry moves.

## Acceptance and regression evidence

The D03 runtime proof is split deliberately by responsibility:

- `ptah-knowledge-search` acceptance: **23 tests**;
- private real Programme-C conversion unit proof: **6 tests**;
- qualified SQLite acceptance: **4 tests**.

The 30 design acceptance requirements map as follows:

1. six source classes — D03 acceptance;
2. exact document anchor — D03 acceptance;
3. source-symbol locator — D03 acceptance;
4. C03 source/component/manifest — D03 + private C03 parser proof;
5. C01 partition/source digest — private C01 parser proof;
6. C05/C06 static/non-authoritative evidence — D03 + private C05/C06 parser proof;
7. stale source rejection — D03 acceptance;
8. B07 public-type leakage absent — static exact-head guard;
9. Programme-C public-type leakage absent — static exact-head guard;
10. ranking cannot alter truth — D03 acceptance;
11. cross-Workspace denial before query — D03 real A06 fixture;
12. deterministic dataset digest — D03 acceptance;
13. malformed JSON/JSONL/CSV fails closed — D03 acceptance;
14. deterministic structured query — D03 acceptance;
15. no plaintext database secret — D03 acceptance + static guard;
16. SQLite read-only/query-only — SQLite acceptance/static provider inspection;
17. deterministic typed relational query — D03 + SQLite acceptance;
18. mutation/DDL/ATTACH/extension-loading absent — static exact-head guard + SQLite compiler acceptance;
19. DB result bound to exact snapshot/query evidence — SQLite acceptance;
20. changed DB snapshot detected — SQLite acceptance;
21. visualization is derived/non-authoritative — D03 acceptance;
22. deterministic provenance-bound JSON/JSONL/CSV export — D03 acceptance;
23. export not A07 Artifact/promotion — D03 acceptance + static guard;
24. no device flash/erase/repartition authority — static exact-head guard;
25. frozen knowledge IDs reused/no migration/catalog edit — D03 acceptance + Git scope guard;
26. D02 integration compatible — D03 compatibility test + D02 regression;
27. B07 regression — **14/14 green**;
28. C01/C03/C04/C05/C06 regression — **20/20 each, 100/100 total green**;
29. D01/D02/A06/A07 regression — **13/13, 18/18, 7/7, 27/27 green**;
30. full locked Ptah workspace — green before candidate freeze and required again on exact frozen head.

The complete locked workspace also preserves all other accepted Programme A–C/D01/D02 behavior. The historical `ptah-control` missing-documentation warnings remain inherited baseline warning debt; D03 packages pass the strict warning/clippy gates.

## Exact-head proof contract

The D03 exact-head workflow must prove all of the following on the final frozen SHA:

1. exact predecessor `aa933d9d42ac451c941fa359711e949df8d8cd8d`;
2. linear D03 history from that predecessor;
3. changed paths restricted to the D03 crate/adapter, root workspace bookkeeping, D03 spec/plan/record and D03 proof workflow;
4. no `contracts/`, `schemas/`, migration or generated-catalog mutation;
5. `Cargo.lock` only adds the two D03 workspace package stanzas and reviewed dependency edges, with no pre-existing package/version/source mutation;
6. no git dependency;
7. pinned Rust/Cargo 1.97.1;
8. `cargo fmt --all -- --check`;
9. strict Clippy for `ptah-knowledge-search` and `ptah-database-sqlite`;
10. no TODO/FIXME/`todo!`/`unimplemented!`/unsafe escape in D03 source/test surfaces;
11. no public B07/Programme-C implementation type leakage;
12. no public database/device mutation or raw-SQL/admin surface;
13. no plaintext connection-secret field or SQLite extension-loading feature;
14. exactly 23 D03 acceptance tests, 6 D03 library conversion tests and 4 SQLite acceptance tests;
15. targeted B07/Programme-C/D01/D02/A06/A07 regressions;
16. complete locked workspace regression;
17. exact candidate commit/tree identity and SHA-256 for every D03 changed file retained as CI proof evidence.

Passing these checks proves D03 mechanics at that exact revision. It does not grant semantic trust, business intent, approval, promotion, database mutation, device mutation or source-authority powers outside the accepted contracts.

## Explicit limitations

D03 intentionally does not provide:

- source/trust winner selection;
- semantic context selection;
- database writes, migrations, DDL or administration;
- arbitrary SQL input;
- SQLite extension loading;
- durable citations over a mutable live SQLite file;
- device flash/erase/repartition or transport-control authority;
- automatic Artifact promotion;
- new Core identity/schema families;
- hidden refreshing of stale citations.

Those omissions are authority and evidence boundaries, not missing implementation shortcuts.
