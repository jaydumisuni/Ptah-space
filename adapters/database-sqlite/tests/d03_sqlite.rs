//! D03 exact-snapshot `SQLite` qualification tests.

use ptah_database_sqlite::SqliteDatabaseProvider;
use ptah_identifiers::EntityRef;
use ptah_knowledge_search::{
    AggregateKind, CellValue, ColumnRef, D03Error, DatabaseConnectionReference,
    DatabaseQueryProvider, JoinKind, JoinSpec, KnowledgeLimits, KnowledgeSourceClass,
    KnowledgeSourceRevision, KnowledgeSourceRevisionInput, RelationalExpr, RelationalOrder,
    RelationalPredicate, RelationalQueryPlan, SelectItem, TableRef,
};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("fixture reference")
}

fn fixture_path() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("ptah-d03-sqlite-{}-{stamp}.db", std::process::id()))
}

fn create_fixture(path: &Path) {
    let connection = Connection::open(path).expect("create fixture database");
    connection
        .execute_batch(
            "CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT NOT NULL);\n\
             CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, amount REAL NOT NULL);\n\
             INSERT INTO users(id,name) VALUES(1,'alpha'),(2,'beta'),(3,'gamma');\n\
             INSERT INTO orders(id,user_id,amount) VALUES(1,1,10.5),(2,1,4.5),(3,2,20.0),(4,3,1.0);",
        )
        .expect("fixture schema/data");
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).expect("read fixture");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn database_source(hash: &str, object_revision_ref: EntityRef) -> KnowledgeSourceRevision {
    KnowledgeSourceRevision::new(KnowledgeSourceRevisionInput {
        workspace_ref: reference("core.workspace"),
        source_ref: reference("knowledge.source"),
        source_record_revision: 1,
        object_revision_ref: Some(object_revision_ref),
        content_sha256: hash.to_owned(),
        class: KnowledgeSourceClass::Database,
        provenance_ref: reference("core.evidence"),
        schema_id: "urn:ptah:schema:data:database-snapshot:0.1.0".to_owned(),
    })
    .expect("database source")
}

fn connection(
    hash: &str,
    source_ref: EntityRef,
    object_revision_ref: EntityRef,
) -> DatabaseConnectionReference {
    DatabaseConnectionReference {
        provider_kind: "sqlite".to_owned(),
        source_ref,
        object_revision_ref,
        expected_sha256: hash.to_owned(),
        logical_name: "fixture_db".to_owned(),
        credential_ref: None,
        read_only: true,
    }
}

fn joined_aggregate_plan() -> RelationalQueryPlan {
    RelationalQueryPlan {
        from: TableRef {
            name: "users".to_owned(),
            alias: Some("u".to_owned()),
        },
        joins: vec![JoinSpec {
            kind: JoinKind::Left,
            table: TableRef {
                name: "orders".to_owned(),
                alias: Some("o".to_owned()),
            },
            on: RelationalPredicate::Eq(
                RelationalExpr::Column(ColumnRef {
                    table: Some("u".to_owned()),
                    column: "id".to_owned(),
                }),
                RelationalExpr::Column(ColumnRef {
                    table: Some("o".to_owned()),
                    column: "user_id".to_owned(),
                }),
            ),
        }],
        projection: vec![
            SelectItem {
                expr: RelationalExpr::Column(ColumnRef {
                    table: Some("u".to_owned()),
                    column: "name".to_owned(),
                }),
                alias: Some("user_name".to_owned()),
                aggregate: None,
            },
            SelectItem {
                expr: RelationalExpr::Column(ColumnRef {
                    table: Some("o".to_owned()),
                    column: "amount".to_owned(),
                }),
                alias: Some("total".to_owned()),
                aggregate: Some(AggregateKind::Sum),
            },
        ],
        predicate: Some(RelationalPredicate::Gt(
            RelationalExpr::Column(ColumnRef {
                table: Some("o".to_owned()),
                column: "amount".to_owned(),
            }),
            RelationalExpr::Value(CellValue::Decimal("2.0".to_owned())),
        )),
        group_by: vec![ColumnRef {
            table: Some("u".to_owned()),
            column: "name".to_owned(),
        }],
        order: vec![RelationalOrder {
            expr: RelationalExpr::Column(ColumnRef {
                table: Some("u".to_owned()),
                column: "name".to_owned(),
            }),
            descending: false,
        }],
        limit: 2,
        offset: 0,
    }
}

#[test]
fn exact_snapshot_projection_filter_join_group_order_limit_is_read_only() {
    let path = fixture_path();
    create_fixture(&path);
    let before = fs::read(&path).expect("before bytes");
    let hash = sha256_file(&path);
    let revision = reference("object.revision");
    let source = database_source(&hash, revision.clone());
    let mut provider = SqliteDatabaseProvider::new();
    provider
        .bind_materialized_snapshot(source.clone(), &path)
        .expect("bind exact snapshot");
    let result = provider
        .execute(
            &connection(&hash, source.source_ref.clone(), revision),
            &joined_aggregate_plan(),
            KnowledgeLimits::default(),
        )
        .expect("read-only joined query");
    assert_eq!(result.rows.len(), 2);
    assert_eq!(result.columns, vec!["user_name", "total"]);
    assert!(!result.authoritative);
    assert_eq!(before, fs::read(&path).expect("after bytes"));
    fs::remove_file(path).ok();
}

#[test]
fn changed_snapshot_and_writable_connection_are_rejected() {
    let path = fixture_path();
    create_fixture(&path);
    let hash = sha256_file(&path);
    let revision = reference("object.revision");
    let source = database_source(&hash, revision.clone());
    let mut provider = SqliteDatabaseProvider::new();
    provider
        .bind_materialized_snapshot(source.clone(), &path)
        .expect("bind snapshot");
    fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("open append")
        .write_all(b"changed")
        .expect("mutate fixture");
    assert_eq!(
        provider.snapshot_evidence(&connection(
            &hash,
            source.source_ref.clone(),
            revision.clone()
        )),
        Err(D03Error::DatabaseSnapshotMismatch)
    );
    let mut writable = connection(&sha256_file(&path), source.source_ref.clone(), revision);
    writable.read_only = false;
    assert!(matches!(
        provider.execute(
            &writable,
            &joined_aggregate_plan(),
            KnowledgeLimits::default()
        ),
        Err(D03Error::ReadOnlyPolicyViolation(_))
    ));
    fs::remove_file(path).ok();
}

#[test]
fn compiler_emits_one_parameterized_select_and_schema_is_observed() {
    let path = fixture_path();
    create_fixture(&path);
    let hash = sha256_file(&path);
    let revision = reference("object.revision");
    let source = database_source(&hash, revision.clone());
    let mut provider = SqliteDatabaseProvider::new();
    provider
        .bind_materialized_snapshot(source.clone(), &path)
        .expect("bind snapshot");
    let compiled = provider
        .compile_for_inspection(&joined_aggregate_plan(), KnowledgeLimits::default())
        .expect("compile");
    let sql = compiled.sql().to_ascii_lowercase();
    assert!(sql.starts_with("select "));
    assert_eq!(sql.matches(';').count(), 0);
    assert!(sql.contains("?1"));
    for forbidden in [
        "insert", "update", "delete", "drop", "alter", "attach", "detach", "pragma",
    ] {
        assert!(!sql.contains(forbidden));
    }
    let schema = provider
        .inspect_schema(&connection(&hash, source.source_ref.clone(), revision))
        .expect("schema");
    assert_eq!(schema.tables.len(), 2);
    assert!(schema.tables.iter().any(|table| table.name == "users"));
    assert!(schema.tables.iter().any(|table| table.name == "orders"));
    fs::remove_file(path).ok();
}

#[test]
fn bounded_sqlite_result_reports_incomplete_when_more_rows_match() {
    let path = fixture_path();
    create_fixture(&path);
    let hash = sha256_file(&path);
    let revision = reference("object.revision");
    let source = database_source(&hash, revision.clone());
    let mut provider = SqliteDatabaseProvider::new();
    provider
        .bind_materialized_snapshot(source.clone(), &path)
        .expect("bind snapshot");
    let plan = RelationalQueryPlan {
        from: TableRef {
            name: "users".to_owned(),
            alias: None,
        },
        joins: Vec::new(),
        projection: vec![SelectItem {
            expr: RelationalExpr::Column(ColumnRef {
                table: None,
                column: "name".to_owned(),
            }),
            alias: Some("name".to_owned()),
            aggregate: None,
        }],
        predicate: None,
        group_by: Vec::new(),
        order: vec![RelationalOrder {
            expr: RelationalExpr::Column(ColumnRef {
                table: None,
                column: "id".to_owned(),
            }),
            descending: false,
        }],
        limit: 1,
        offset: 0,
    };
    let result = provider
        .execute(
            &connection(&hash, source.source_ref.clone(), revision),
            &plan,
            KnowledgeLimits::default(),
        )
        .expect("bounded query");
    assert_eq!(result.rows.len(), 1);
    assert!(!result.complete);
    fs::remove_file(path).ok();
}
