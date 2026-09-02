# D03 Knowledge, Data and Search v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build D03 Knowledge, Data and Search v2 as a provenance-bound derived-query facade over B03/B07, Programme C evidence and a qualified read-only SQLite provider, reaching General Beta with database support without adding semantic or mutation authority.

**Architecture:** Add a provider-neutral `ptah-knowledge-search` crate that owns all D03 public types, keeps B07 and Programme-C types private, and binds every result/citation to exact source revision/hash/provenance. Add a physically separate `database-sqlite` adapter that consumes only typed D03 read-only plans over exact materialized database snapshots. No new ledger migration or frozen contract-catalog edit is permitted.

**Tech Stack:** Rust 1.97.1, existing workspace crates, `serde`, `serde_json`, `sha2`, `thiserror`, `rusqlite = 0.37.0` from the existing workspace lock.

**Spec:** `docs/superpowers/specs/2026-09-02-d03-knowledge-data-search-v2-design.md`

## Global Constraints

- Base implementation work on the accepted D02 merge `aa933d9d42ac451c941fa359711e949df8d8cd8d` plus the approved D03 design/plan commits.
- Reuse the frozen knowledge schema IDs exposed by `ptah_contracts::schema_by_id`; do not modify `contracts/generated`, `crates/ptah-contracts/src/generated.rs`, or any ledger migration.
- `ptah-knowledge-search` owns every public D03 request/result/error type. No public type may expose `ptah_archive_decomposition::*` or Programme-C report structs.
- All index/query/citation/database results are derived Views and must state `authoritative = false`.
- Cross-Workspace access must call A06 `WorkspaceStore::authorize_retrieval` before source admission/query.
- Database General Beta is read-only exact-snapshot mode. The SQLite adapter receives an exact A07 `object.revision`, expected SHA-256 and materialized path; it rehashes before query.
- No arbitrary caller SQL; D03 uses typed plans compiled to parameterized SQL by the SQLite adapter.
- No database write/DDL/admin, device flash/erase/repartition, context selection, source-trust ranking, approval, promotion or next-action authority.
- Resource-limit failures are explicit; never silently truncate input and call it complete.
- Follow red → green TDD for every new behavior and commit each reviewable task separately.

---

## File map

### New provider-neutral crate

- `crates/ptah-knowledge-search/Cargo.toml` — D03 dependency boundary and acceptance test target.
- `crates/ptah-knowledge-search/src/lib.rs` — public exports only.
- `crates/ptah-knowledge-search/src/source.rs` — source classes, exact revision/provenance and frozen schema binding.
- `crates/ptah-knowledge-search/src/evidence.rs` — locators, citations and stale-source validation.
- `crates/ptah-knowledge-search/src/index.rs` — D03 source registry + private B07 index adapter.
- `crates/ptah-knowledge-search/src/query.rs` — unified deterministic query facade/result types.
- `crates/ptah-knowledge-search/src/structured.rs` — datasets/tables, ingestion and deterministic structured query.
- `crates/ptah-knowledge-search/src/database.rs` — provider-neutral relational plan/provider interfaces and snapshot evidence.
- `crates/ptah-knowledge-search/src/domain_pack.rs` — database ingestion/visualization/export composition.
- `crates/ptah-knowledge-search/src/error.rs` — D03-owned mechanical error model.
- `crates/ptah-knowledge-search/src/adapters/mod.rs` — private adapter module exports.
- `crates/ptah-knowledge-search/src/adapters/b07.rs` — B07 mapping only.
- `crates/ptah-knowledge-search/src/adapters/b03.rs` — B03 anchored-text normalization only.
- `crates/ptah-knowledge-search/src/adapters/programme_c.rs` — C01/C03/C04/C05/C06 read-only evidence normalization.
- `crates/ptah-knowledge-search/tests/d03_acceptance.rs` — milestone acceptance corpus.

### New reference provider

- `adapters/database-sqlite/Cargo.toml` — SQLite provider dependencies/test target.
- `adapters/database-sqlite/src/lib.rs` — exports only.
- `adapters/database-sqlite/src/provider.rs` — exact snapshot verification, schema inspection and query execution.
- `adapters/database-sqlite/src/compiler.rs` — typed plan → parameterized SQLite SQL compiler.
- `adapters/database-sqlite/tests/d03_sqlite.rs` — provider qualification corpus.

### Workspace/proof files

- `Cargo.toml` — add both workspace members only.
- `Cargo.lock` — add package stanzas only; no pre-existing version movement.
- `D03_KNOWLEDGE_DATA_SEARCH_V2.md` — durable milestone implementation/proof record.
- `.github/workflows/d03-knowledge-data-search-v2-proof.yml` — exact-head D03 proof lane.

---

### Task 1: Scaffold D03 source/citation contract and frozen schema bindings

**Files:**
- Create: `crates/ptah-knowledge-search/Cargo.toml`
- Create: `crates/ptah-knowledge-search/src/lib.rs`
- Create: `crates/ptah-knowledge-search/src/source.rs`
- Create: `crates/ptah-knowledge-search/src/evidence.rs`
- Create: `crates/ptah-knowledge-search/src/error.rs`
- Create: `crates/ptah-knowledge-search/tests/d03_acceptance.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`

**Interfaces:**
- Produces:
  - `pub enum KnowledgeSourceClass { Document, SourceSymbol, FirmwareManifest, PartitionData, Dataset, Database }`
  - `pub struct KnowledgeSourceRevision { workspace_ref: EntityRef, source_ref: EntityRef, source_record_revision: u64, object_revision_ref: Option<EntityRef>, content_sha256: String, class: KnowledgeSourceClass, provenance_ref: EntityRef, schema_id: String }`
  - `pub enum KnowledgeLocator { ByteRange { start: u64, end_exclusive: u64 }, LineRange { start: u64, end_inclusive: u64 }, DocumentAnchor { page: Option<u32>, byte_start: Option<u64>, byte_end_exclusive: Option<u64> }, SourceSymbol { symbol: String }, FirmwareComponent { component: String }, PartitionRange { name: Option<String>, byte_start: u64, byte_end_exclusive: u64 }, DatasetCell { table: String, row: u64, column: String }, DatasetRow { table: String, row: u64 }, DatabaseCell { table: String, row: u64, column: String }, DatabaseRow { table: String, row: u64 } }`
  - `pub struct CitationEvidence { source: KnowledgeSourceRevision, locator: KnowledgeLocator, mechanism: String, evidence_ref: Option<EntityRef>, index_revision: Option<u64>, index_sha256: Option<String>, query_run_ref: Option<EntityRef>, authoritative: bool }`
  - `pub struct KnowledgeLimits { max_sources: usize, max_fields_per_source: usize, max_field_bytes: usize, max_query_bytes: usize, max_results: usize, max_tables: usize, max_columns: usize, max_rows: usize, max_cell_bytes: usize, max_input_bytes: usize, max_joins: usize, max_predicates: usize, max_projection_items: usize, max_export_bytes: usize }` with non-zero defaults and validation.
  - `pub fn require_knowledge_schema(schema_id: &str) -> Result<&'static ptah_contracts::SchemaBinding, D03Error>`
  - `pub fn validate_current_source(expected: &KnowledgeSourceRevision, actual_revision: u64, actual_sha256: &str) -> Result<(), D03Error>`

- [ ] **Step 1: Write failing source/citation tests**

Add tests that construct all six source classes, require `authoritative == false`, reject zero record revision, reject wrong `object.revision` kind, resolve the frozen citation/database/dataset/query/result schema IDs through `schema_by_id`, and reject stale revision/hash.

```rust
#[test]
fn all_six_sources_are_revision_bound_and_non_authoritative() {
    for class in ALL_SOURCE_CLASSES {
        let source = fixture_source(class);
        assert!(source.source_record_revision > 0);
        let citation = CitationEvidence::new(source, fixture_locator(class), "d03.fixture", None)
            .expect("citation");
        assert!(!citation.authoritative);
    }
}

#[test]
fn stale_source_is_not_silently_refreshed() {
    let source = fixture_source(KnowledgeSourceClass::Document);
    assert!(matches!(
        validate_current_source(&source, source.source_record_revision + 1, &source.content_sha256),
        Err(D03Error::StaleSourceRevision)
    ));
}
```

- [ ] **Step 2: Run RED proof**

Run: `cargo test -p ptah-knowledge-search --test d03_acceptance --locked`

Expected: Cargo reports missing `ptah-knowledge-search` package / missing symbols.

- [ ] **Step 3: Implement minimal source/evidence/error contract**

Implement canonical identifier checks, SHA-256 text validation (`64` lowercase hex chars), frozen schema lookups and citation construction. `CitationEvidence::new` must hard-code `authoritative: false`; callers cannot set it.

- [ ] **Step 4: Regenerate lockfile offline and inspect delta**

Run: `cargo generate-lockfile --offline`

Expected lock delta: only new `ptah-knowledge-search` package stanza and its existing workspace dependencies.

- [ ] **Step 5: Run GREEN proof**

Run: `cargo test -p ptah-knowledge-search --test d03_acceptance --locked`

Expected: Task-1 tests pass.

- [ ] **Step 6: Format/review/commit**

Run: `cargo fmt --all -- --check && git diff --check`

Commit: `feat(d03): add source and citation contract`

---

### Task 2: Add private B03/B07 adapters and deterministic KnowledgeIndex

**Files:**
- Create: `crates/ptah-knowledge-search/src/index.rs`
- Create: `crates/ptah-knowledge-search/src/query.rs`
- Create: `crates/ptah-knowledge-search/src/adapters/mod.rs`
- Create: `crates/ptah-knowledge-search/src/adapters/b07.rs`
- Create: `crates/ptah-knowledge-search/src/adapters/b03.rs`
- Modify: `crates/ptah-knowledge-search/src/lib.rs`
- Modify: `crates/ptah-knowledge-search/tests/d03_acceptance.rs`

**Interfaces:**
- Produces:
  - `pub enum KnowledgeSearchDomain { Filename, Metadata, DocumentText, SourceSymbol, Firmware, Partition }`
  - `pub struct KnowledgeField { domain: KnowledgeSearchDomain, key: Option<String>, value: String, evidence_source: String }`
  - `pub struct AnchoredTextInput { text: String, object_revision_ref: EntityRef, page: Option<u32>, byte_start: Option<u64>, byte_end_exclusive: Option<u64> }`
  - `pub enum KnowledgeSearchDocument { B07ObjectMetadata { source: KnowledgeSourceRevision, filename: Option<String>, metadata: Vec<KnowledgeField> }, B03DocumentText { source: KnowledgeSourceRevision, spans: Vec<AnchoredTextInput> }, SourceSymbols { source: KnowledgeSourceRevision, symbols: Vec<String> }, FirmwareFields { source: KnowledgeSourceRevision, fields: Vec<KnowledgeField> }, PartitionFields { source: KnowledgeSourceRevision, fields: Vec<KnowledgeField> } }`
  - `pub struct KnowledgeIndexRevision { revision: u64, content_sha256: String, source_count: usize }`
  - `pub struct KnowledgeTextQuery { workspace_ref: EntityRef, text: String, domains: Vec<KnowledgeSearchDomain>, limit: usize }`
  - `pub enum KnowledgeValue { Null, Boolean(bool), Integer(i64), Decimal(String), Text(String), BytesDigest { sha256: String, size: u64 } }`
  - `pub struct KnowledgeResultRow { values: Vec<KnowledgeValue>, citations: Vec<CitationEvidence> }`
  - `pub struct KnowledgeResultSet { columns: Vec<String>, rows: Vec<KnowledgeResultRow>, source_refs: Vec<KnowledgeSourceRevision>, query_plan_sha256: String, complete: bool, authoritative: bool }`
  - `pub struct KnowledgeIndex` with private B07/index-registry fields; callers can only use constructor/rebuild/search methods.
  - `pub fn KnowledgeIndex::new(limits: KnowledgeLimits) -> Result<Self, D03Error>`
  - `pub fn KnowledgeIndex::rebuild(&mut self, docs: &[KnowledgeSearchDocument]) -> Result<KnowledgeIndexRevision, D03Error>`
  - `pub fn KnowledgeIndex::search(&self, request: &KnowledgeTextQuery) -> Result<KnowledgeResultSet, D03Error>`

`AnchoredTextInput` is D03-owned and contains exact text plus page/byte anchors and exact `object.revision`; the private B03 adapter converts it to/from B03 structures without exposing those structures publicly.

- [ ] **Step 1: Write failing B07/B03 tests**

Cover deterministic rebuild digest, exact source/citation retention, source-symbol locator, ordering changes not altering source truth, and cross-Workspace filtering.

```rust
#[test]
fn b07_hit_becomes_d03_citation_without_public_b07_identity() {
    let mut index = KnowledgeIndex::new(KnowledgeLimits::default()).unwrap();
    index.rebuild(&[fixture_symbol_document("Widget::open")]).unwrap();
    let result = index.search(&KnowledgeTextQuery::symbols(workspace(), "widget", 10)).unwrap();
    assert_eq!(result.rows[0].citations[0].source, fixture_source(KnowledgeSourceClass::SourceSymbol));
    assert!(matches!(result.rows[0].citations[0].locator, KnowledgeLocator::SourceSymbol { .. }));
    assert!(!result.authoritative);
}
```

- [ ] **Step 2: Verify RED**

Run the named new tests; expected missing `KnowledgeIndex`/adapter symbols.

- [ ] **Step 3: Implement private adapters and registry**

Use B07 `SearchIndex`, `SearchQuery`, `filename_metadata_document`, `document_text_search_document`, and `source_symbol_search_document` only inside `adapters/b07.rs`. Map all B07 errors with a private `map_b07_error(&SearchError) -> D03Error` so no B07 error type appears publicly.

`KnowledgeIndex` keeps a private `BTreeMap<SourceKey, KnowledgeSourceRevision>` and private B07 index. Rebuild validates every source before B07 document construction.

- [ ] **Step 4: GREEN and public-leak scan**

Run Task-2 tests plus:

`grep -R "pub .*ptah_archive_decomposition\|pub use ptah_archive_decomposition" crates/ptah-knowledge-search/src`

Expected grep: no matches.

- [ ] **Step 5: Commit**

Commit: `feat(d03): add source-bound knowledge index`

---

### Task 3: Normalize Programme-C firmware and partition evidence without control authority

**Files:**
- Create: `crates/ptah-knowledge-search/src/adapters/programme_c.rs`
- Modify: `crates/ptah-knowledge-search/src/index.rs`
- Modify: `crates/ptah-knowledge-search/src/lib.rs`
- Modify: `crates/ptah-knowledge-search/tests/d03_acceptance.rs`

**Interfaces:**
- Produces D03-owned functions:
  - `pub fn from_c01_partition_report(source: KnowledgeSourceRevision, report: &C01InputProjection) -> Result<Vec<KnowledgeSearchDocument>, D03Error>`
  - `pub fn from_c03_android_report(source: KnowledgeSourceRevision, report: &C03InputProjection) -> Result<Vec<KnowledgeSearchDocument>, D03Error>`
  - `pub fn from_c04_apple_report(source: KnowledgeSourceRevision, report: &C04InputProjection) -> Result<Vec<KnowledgeSearchDocument>, D03Error>`
  - `pub fn from_c05_mediatek_report(source: KnowledgeSourceRevision, report: &C05InputProjection) -> Result<Vec<KnowledgeSearchDocument>, D03Error>`
  - `pub fn from_c06_firmware_report(source: KnowledgeSourceRevision, report: &C06InputProjection) -> Result<Vec<KnowledgeSearchDocument>, D03Error>`

The `C0xInputProjection` structs are D03-owned minimal normalized inputs produced by private conversion functions from actual Programme-C reports. Public callers may construct only the D03 projections; actual C types remain private module details.

- [ ] **Step 1: Write failing firmware/partition tests**

Use real C01/C03/C05/C06 parsers in the acceptance fixture to produce reports, pass them through private D03 conversion helpers, then assert exact source/component/partition ranges and `authoritative == false`.

Also use compile/static scans to assert D03 public files contain no `pub use crate::c0` or public Programme-C types.

- [ ] **Step 2: Verify RED**

Expected missing Programme-C adapter symbols.

- [ ] **Step 3: Implement minimal normalization**

Only copy mechanically proven report fields: source digest/format, manifest/component identity, partition index/name/LBA/byte range, linked component digest, LUN/storage and evidence qualifier. Do not expose `is_download` or transport/service evidence as mutation authority.

- [ ] **Step 4: Run D03 tests + C01/C03/C04/C05/C06 targeted regressions**

Expected all green.

- [ ] **Step 5: Commit**

Commit: `feat(d03): normalize firmware and partition evidence`

---

### Task 4: Add deterministic structured datasets, ingestion and query

**Files:**
- Create: `crates/ptah-knowledge-search/src/structured.rs`
- Modify: `crates/ptah-knowledge-search/src/query.rs`
- Modify: `crates/ptah-knowledge-search/src/lib.rs`
- Modify: `crates/ptah-knowledge-search/tests/d03_acceptance.rs`

**Interfaces:**
- Produces:
  - `pub type CellValue = KnowledgeValue`
  - `pub enum ColumnType { Boolean, Integer, Decimal, Text, BytesDigest, Mixed }`
  - `pub struct ColumnRef { table: Option<String>, column: String }`
  - `pub struct StructuredOrder { column: ColumnRef, descending: bool }`
  - `pub struct ColumnSchema { name: String, data_type: ColumnType, nullable: bool }`
  - `pub struct TableSnapshot { name: String, columns: Vec<ColumnSchema>, rows: Vec<Vec<CellValue>> }`
  - `pub struct DatasetSnapshot { source: KnowledgeSourceRevision, tables: Vec<TableSnapshot>, content_sha256: String, complete: bool }`
  - `pub enum StructuredPredicate { Eq(ColumnRef, CellValue), Ne(ColumnRef, CellValue), Lt(ColumnRef, CellValue), Le(ColumnRef, CellValue), Gt(ColumnRef, CellValue), Ge(ColumnRef, CellValue), IsNull(ColumnRef), IsNotNull(ColumnRef), In(ColumnRef, Vec<CellValue>) }`
  - `pub struct StructuredQuery { table: String, projection: Vec<String>, predicates: Vec<StructuredPredicate>, order: Vec<StructuredOrder>, limit: usize, offset: usize }`
  - `pub fn ingest_json(source: KnowledgeSourceRevision, table_name: &str, bytes: &[u8], limits: KnowledgeLimits) -> Result<DatasetSnapshot, D03Error>`
  - `pub fn ingest_json_lines(source: KnowledgeSourceRevision, table_name: &str, bytes: &[u8], limits: KnowledgeLimits) -> Result<DatasetSnapshot, D03Error>`
  - `pub fn ingest_csv(source: KnowledgeSourceRevision, table_name: &str, bytes: &[u8], limits: KnowledgeLimits) -> Result<DatasetSnapshot, D03Error>`
  - `pub fn query_dataset(snapshot: &DatasetSnapshot, query: &StructuredQuery, limits: KnowledgeLimits) -> Result<KnowledgeResultSet, D03Error>`

- [ ] **Step 1: Write failing structured-data tests**

Cover deterministic digest independent of JSON object key order, malformed JSONL/CSV failure, typed values, filter/order/projection/limit determinism and explicit incomplete result when result limit is smaller than matches.

- [ ] **Step 2: Verify RED**

Expected missing structured types/functions.

- [ ] **Step 3: Implement bounded ingestion/query**

Use `serde_json`; implement CSV parser locally with RFC4180-compatible quote handling sufficient for comma-delimited UTF-8 input so no new crate/version is introduced. Preserve decimal numeric text when exact integer conversion is not possible.

- [ ] **Step 4: Run GREEN + format/clippy**

Run D03 tests and `cargo clippy -p ptah-knowledge-search --all-targets --locked -- -D warnings -W clippy::all -W clippy::pedantic`.

- [ ] **Step 5: Commit**

Commit: `feat(d03): add structured dataset query`

---

### Task 5: Define provider-neutral relational database contract

**Files:**
- Create: `crates/ptah-knowledge-search/src/database.rs`
- Modify: `crates/ptah-knowledge-search/src/query.rs`
- Modify: `crates/ptah-knowledge-search/src/lib.rs`
- Modify: `crates/ptah-knowledge-search/tests/d03_acceptance.rs`

**Interfaces:**
- Produces:
  - `pub struct DatabaseConnectionReference { provider_kind: String, source_ref: EntityRef, object_revision_ref: EntityRef, expected_sha256: String, logical_name: String, credential_ref: Option<EntityRef>, read_only: bool }`
  - `pub struct DatabaseSnapshotEvidence { source: KnowledgeSourceRevision, schema_sha256: String, provider_kind: String }`
  - `pub struct TableRef { name: String, alias: Option<String> }`
  - `pub enum JoinKind { Inner, Left }`
  - `pub struct SelectItem { expr: RelationalExpr, alias: Option<String>, aggregate: Option<AggregateKind> }`
  - `pub struct RelationalOrder { expr: RelationalExpr, descending: bool }`
  - `pub struct DatabaseColumnObservation { name: String, declared_type: String, nullable: bool, primary_key: bool }`
  - `pub struct DatabaseTableObservation { name: String, columns: Vec<DatabaseColumnObservation> }`
  - `pub struct DatabaseSchemaObservation { snapshot: DatabaseSnapshotEvidence, tables: Vec<DatabaseTableObservation> }`
  - `pub struct DatabaseQueryResult { snapshot: DatabaseSnapshotEvidence, columns: Vec<String>, rows: Vec<Vec<KnowledgeValue>>, query_plan_sha256: String, complete: bool, authoritative: bool }`
  - `pub enum RelationalExpr { Column(ColumnRef), Value(CellValue) }`
  - `pub enum RelationalPredicate { Eq(RelationalExpr, RelationalExpr), Ne(RelationalExpr, RelationalExpr), Lt(RelationalExpr, RelationalExpr), Le(RelationalExpr, RelationalExpr), Gt(RelationalExpr, RelationalExpr), Ge(RelationalExpr, RelationalExpr), IsNull(ColumnRef), IsNotNull(ColumnRef), In(ColumnRef, Vec<CellValue>), And(Vec<RelationalPredicate>), Or(Vec<RelationalPredicate>) }`
  - `pub enum AggregateKind { Count, Sum, Min, Max, Avg }`
  - `pub struct JoinSpec { kind: JoinKind, table: TableRef, on: RelationalPredicate }`
  - `pub struct RelationalQueryPlan { from: TableRef, joins: Vec<JoinSpec>, projection: Vec<SelectItem>, predicate: Option<RelationalPredicate>, group_by: Vec<ColumnRef>, order: Vec<RelationalOrder>, limit: usize, offset: usize }`
  - `pub trait DatabaseQueryProvider { fn inspect_schema(&self, connection: &DatabaseConnectionReference) -> Result<DatabaseSchemaObservation, D03Error>; fn snapshot_evidence(&self, connection: &DatabaseConnectionReference) -> Result<DatabaseSnapshotEvidence, D03Error>; fn execute(&self, connection: &DatabaseConnectionReference, plan: &RelationalQueryPlan, limits: KnowledgeLimits) -> Result<DatabaseQueryResult, D03Error>; }`

- [ ] **Step 1: Write failing provider-neutral tests**

Test connection references require `object.revision`, lowercase SHA-256, `read_only=true`, and JSON serialization contains no `password`, `secret`, `token`, `dsn`, or raw credential field; only `credential_ref` is allowed.

Test invalid plans: zero/oversized limit, duplicate aliases, empty projection, excessive joins/predicates, unsafe identifiers.

- [ ] **Step 2: Verify RED**

Expected missing database types.

- [ ] **Step 3: Implement typed validation and digests**

Identifiers accept only explicit SQL identifier grammar `[A-Za-z_][A-Za-z0-9_]*`; providers quote validated identifiers anyway. Query-plan digest uses canonical JSON/struct ordering and SHA-256.

- [ ] **Step 4: GREEN + public mutation vocabulary scan**

Scan public D03 API for forbidden methods/variants `insert|update|delete|drop|alter|attach|detach|pragma|execute_sql|raw_sql|flash|erase|repartition` and inspect any lexical hits manually.

- [ ] **Step 5: Commit**

Commit: `feat(d03): define read-only database query contract`

---

### Task 6: Qualify exact-snapshot SQLite provider

**Files:**
- Create: `adapters/database-sqlite/Cargo.toml`
- Create: `adapters/database-sqlite/src/lib.rs`
- Create: `adapters/database-sqlite/src/provider.rs`
- Create: `adapters/database-sqlite/src/compiler.rs`
- Create: `adapters/database-sqlite/tests/d03_sqlite.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`

**Interfaces:**
- Consumes Task-5 `DatabaseQueryProvider`, `DatabaseConnectionReference`, `RelationalQueryPlan`, `DatabaseQueryResult`, `KnowledgeLimits`.
- Produces `pub struct SqliteDatabaseProvider` implementing `DatabaseQueryProvider`.

- [ ] **Step 1: Write failing SQLite qualification tests**

Create a temporary SQLite DB fixture with `users` and `orders`, materialize it as a test file, calculate exact SHA-256, use an exact `object.revision`, then prove:

```rust
#[test]
fn exact_snapshot_projection_filter_join_group_order_limit_is_read_only() {
    let provider = SqliteDatabaseProvider::new();
    let result = provider.execute(&connection(), &joined_aggregate_plan(), KnowledgeLimits::default()).unwrap();
    assert_eq!(result.rows.len(), 2);
    assert!(!result.authoritative);
}
```

Also test changed bytes → `DatabaseSnapshotMismatch`; read/write connection request rejected; extension-loading unavailable; the typed compiler produces one SELECT statement only.

- [ ] **Step 2: Verify RED**

Expected missing adapter package/provider symbols.

- [ ] **Step 3: Implement exact snapshot verification**

Before each schema/query operation, stream-hash the database file and compare exact expected SHA-256. Open with `rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX`; execute `PRAGMA query_only = ON` internally; do not expose a generic pragma API.

- [ ] **Step 4: Implement typed compiler**

Compile validated plan to parameterized SELECT SQL. Every literal becomes `?N`; identifiers are validated/quoted. No caller string is appended as an SQL operator or clause keyword.

- [ ] **Step 5: Execute rows with typed conversion**

Map SQLite Null/Integer/Real/Text/Blob to D03 values. Real values are rendered to stable decimal text; blobs become SHA-256+size evidence unless explicitly bounded for inline export.

- [ ] **Step 6: GREEN proof**

Run `cargo test -p ptah-database-sqlite --test d03_sqlite --locked` and strict clippy for both D03 packages.

- [ ] **Step 7: Lock delta review and commit**

Expected dependency versions unchanged; only new package stanzas and existing `rusqlite` dependency edge.

Commit: `feat(d03): qualify read-only sqlite provider`

---

### Task 7: Add Database Domain Pack visualization/export and A06 authority facade

**Files:**
- Create: `crates/ptah-knowledge-search/src/domain_pack.rs`
- Modify: `crates/ptah-knowledge-search/src/query.rs`
- Modify: `crates/ptah-knowledge-search/src/lib.rs`
- Modify: `crates/ptah-knowledge-search/tests/d03_acceptance.rs`

**Interfaces:**
- Produces:
  - `pub struct KnowledgeQueryAuthority<'a> { workspace: &'a WorkspaceStore }`
  - `pub fn authorize(&self, actor_ref: &EntityRef, source_workspace_ref: &EntityRef, target_workspace_ref: &EntityRef, required_scope: &str, grant_ref: Option<&EntityRef>) -> Result<(), D03Error>`
  - `pub struct ResultTableView { columns: Vec<String>, rows: Vec<Vec<CellValue>>, citations: Vec<Vec<CitationEvidence>>, complete: bool, authoritative: bool }`
  - `pub enum ExportFormat { Json, JsonLines, Csv }`
  - `pub struct ExportBundle { bytes: Vec<u8>, sha256: String, media_type: String, source_refs: Vec<KnowledgeSourceRevision>, query_plan_sha256: String, authoritative: bool }`
  - `pub fn visualize(result: &KnowledgeResultSet) -> Result<ResultTableView, D03Error>`
  - `pub fn export(result: &KnowledgeResultSet, format: ExportFormat, limits: KnowledgeLimits) -> Result<ExportBundle, D03Error>`

- [ ] **Step 1: Write failing authority/domain-pack tests**

Prove cross-Workspace query denied before search execution using real A06 fixtures; same-Workspace succeeds. Prove visualization/export are deterministic derived outputs, `authoritative=false`, and JSON/JSONL/CSV export digests are stable.

Prove `ExportBundle` contains no Artifact identity and cannot itself call A07 promotion.

- [ ] **Step 2: Verify RED**

Expected missing authority/domain-pack API.

- [ ] **Step 3: Implement authority wrapper and deterministic output**

`authorize` delegates exactly to `WorkspaceStore::authorize_retrieval`. Export quoting is deterministic; CSV uses CRLF or LF consistently (choose LF and freeze it in tests).

- [ ] **Step 4: D02 compatibility regression**

Run D02 acceptance and add one integration test showing D02 can consume D03 source-bound result refs without D03 acquiring AI/context authority.

- [ ] **Step 5: Commit**

Commit: `feat(d03): add database domain pack outputs`

---

### Task 8: Complete D03 acceptance corpus, regressions, durable record and exact-head proof lane

**Files:**
- Modify: `crates/ptah-knowledge-search/tests/d03_acceptance.rs`
- Modify: `adapters/database-sqlite/tests/d03_sqlite.rs`
- Create: `D03_KNOWLEDGE_DATA_SEARCH_V2.md`
- Create: `.github/workflows/d03-knowledge-data-search-v2-proof.yml`

**Interfaces:**
- No new runtime API unless a test reveals a missing mechanical primitive already authorized by the spec.

- [ ] **Step 1: Close all 30 design acceptance cases**

Map each numbered spec acceptance case to one named test or static workflow assertion. The runtime test suite must print/count a frozen exact expected count; workflow static guards cover public-type leakage, migrations/catalog edits and forbidden authority surfaces.

- [ ] **Step 2: Run targeted inherited regressions**

Run:

```bash
cargo test -p ptah-archive-decomposition --test b07 --locked
cargo test -p ptah-archive-decomposition --test c01 --locked
cargo test -p ptah-archive-decomposition --test c03 --locked
cargo test -p ptah-archive-decomposition --test c04 --locked
cargo test -p ptah-archive-decomposition --test c05 --locked
cargo test -p ptah-archive-decomposition --test c06 --locked
cargo test -p ptah-ai-workspace --test d02_acceptance --locked
cargo test -p ptah-workspace --test a06_acceptance --locked
cargo test -p ptah-object-store --test a07 --locked
cargo test -p ptah-control --test d01_acceptance --locked
```

Expected: all pass.

- [ ] **Step 3: Strict review gates**

Run:

```bash
cargo fmt --all -- --check
cargo clippy -p ptah-knowledge-search --all-targets --locked -- -D warnings -W clippy::all -W clippy::pedantic
cargo clippy -p ptah-database-sqlite --all-targets --locked -- -D warnings -W clippy::all -W clippy::pedantic
git diff --check
```

- [ ] **Step 4: Complete locked workspace proof**

Run: `cargo test --workspace --locked`

Expected: PASS, with only pre-existing accepted warning debt outside D03 if any.

- [ ] **Step 5: Write durable D03 implementation record**

`D03_KNOWLEDGE_DATA_SEARCH_V2.md` records exact base, source classes, frozen knowledge IDs, B07/C boundaries, database exact-snapshot mode, acceptance count, dependency delta and explicit limitations.

- [ ] **Step 6: Write exact-head workflow**

The workflow pins Rust 1.97.1 and asserts:

- base is D02 merge `aa933d9d42ac451c941fa359711e949df8d8cd8d` or the exact then-current accepted `main` if main advanced only by approved design/plan commits;
- changed paths are D03-only;
- no ledger migration or generated-contract catalog change;
- lockfile only adds D03 packages/edges;
- no public B07/Programme-C types;
- no database/device mutation surface;
- no plaintext secret fields;
- exact D03/SQLite test counts;
- strict fmt/clippy;
- full locked workspace;
- clean exact-head proof manifest.

- [ ] **Step 7: Commit proof contract**

Commit: `test(d03): add exact-head knowledge data search proof`

- [ ] **Step 8: Freeze/reprove/ship**

Treat the last commit as the candidate SHA. Rerun all exact-head guards and full workspace from a clean tree. Push the exact branch, open a PR against current `main`, follow the D03 exact-head workflow to green, classify predecessor-pinned historical failures by reading their assertions, and merge only if the frozen D03 proof passes and GitHub reports the PR mergeable.

- [ ] **Step 9: Verify canonical merge**

Fetch `origin/main`; verify its merge parent is the exact frozen D03 SHA and the pre-merge accepted main SHA. Verify local D03 worktree clean.

- [ ] **Step 10: Advance roadmap**

Recover D04 from canonical `ptah-roadmap-`/current roadmap evidence. Do not infer D04 from naming alone. Continue automatically because the Owner has authorized roadmap execution without intermediate approval gates.
