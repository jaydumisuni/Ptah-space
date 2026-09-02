use crate::compiler::{CompiledSelect, compile_select};
use ptah_knowledge_search::{
    D03Error, DatabaseColumnObservation, DatabaseConnectionReference, DatabaseQueryProvider,
    DatabaseQueryResult, DatabaseSchemaObservation, DatabaseSnapshotEvidence,
    DatabaseTableObservation, KnowledgeLimits, KnowledgeSourceClass, KnowledgeSourceRevision,
    KnowledgeValue, RelationalQueryPlan,
};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, params_from_iter};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Qualified D03 exact-snapshot `SQLite` provider.
#[derive(Debug, Default)]
pub struct SqliteDatabaseProvider {
    snapshots: BTreeMap<String, MaterializedSnapshot>,
}

#[derive(Debug, Clone)]
struct MaterializedSnapshot {
    source: KnowledgeSourceRevision,
    path: PathBuf,
}

impl SqliteDatabaseProvider {
    /// Construct an empty provider. Exact materialized Object Revisions must be explicitly bound.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind one exact materialized A07 Object Revision to local snapshot bytes.
    ///
    /// # Errors
    /// Rejects non-database sources, missing revision identity, changed bytes, or duplicate conflicting bindings.
    pub fn bind_materialized_snapshot(
        &mut self,
        source: KnowledgeSourceRevision,
        path: impl AsRef<Path>,
    ) -> Result<(), D03Error> {
        if source.class != KnowledgeSourceClass::Database {
            return Err(D03Error::InvalidRelationalPlan(
                "SQLite binding requires database source class".to_owned(),
            ));
        }
        let revision = source.object_revision_ref.as_ref().ok_or_else(|| {
            D03Error::InvalidRelationalPlan(
                "SQLite binding requires exact object.revision".to_owned(),
            )
        })?;
        let path = path.as_ref().to_path_buf();
        let actual = sha256_file(&path)?;
        if actual != source.content_sha256 {
            return Err(D03Error::DatabaseSnapshotMismatch);
        }
        let key = revision.entity_id.to_string();
        if let Some(existing) = self.snapshots.get(&key)
            && (existing.path != path || existing.source != source)
        {
            return Err(D03Error::InvalidRelationalPlan(
                "conflicting materialized snapshot binding".to_owned(),
            ));
        }
        self.snapshots
            .insert(key, MaterializedSnapshot { source, path });
        Ok(())
    }

    /// Compile one validated typed plan for inspection. The provider still exposes no raw-SQL input API.
    ///
    /// # Errors
    /// Returns mechanical plan/limit errors.
    pub fn compile_for_inspection(
        &self,
        plan: &RelationalQueryPlan,
        limits: KnowledgeLimits,
    ) -> Result<CompiledSelect, D03Error> {
        compile_select(plan, limits)
    }

    fn resolve<'a>(
        &'a self,
        connection: &DatabaseConnectionReference,
    ) -> Result<&'a MaterializedSnapshot, D03Error> {
        connection.validate()?;
        if connection.provider_kind != "sqlite" {
            return Err(D03Error::DatabaseProviderUnavailable(
                connection.provider_kind.clone(),
            ));
        }
        let key = connection.object_revision_ref.entity_id.to_string();
        let snapshot = self.snapshots.get(&key).ok_or_else(|| {
            D03Error::DatabaseProviderUnavailable("materialized SQLite snapshot".to_owned())
        })?;
        if snapshot.source.source_ref != connection.source_ref
            || snapshot.source.object_revision_ref.as_ref() != Some(&connection.object_revision_ref)
            || snapshot.source.content_sha256 != connection.expected_sha256
        {
            return Err(D03Error::DatabaseSnapshotMismatch);
        }
        let actual = sha256_file(&snapshot.path)?;
        if actual != connection.expected_sha256 {
            return Err(D03Error::DatabaseSnapshotMismatch);
        }
        Ok(snapshot)
    }

    fn open_read_only(snapshot: &MaterializedSnapshot) -> Result<Connection, D03Error> {
        let connection = Connection::open_with_flags(
            &snapshot.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(database_error)?;
        connection
            .execute_batch("PRAGMA query_only = ON")
            .map_err(database_error)?;
        Ok(connection)
    }

    fn inspect_schema_inner(
        &self,
        connection_ref: &DatabaseConnectionReference,
        limits: KnowledgeLimits,
    ) -> Result<DatabaseSchemaObservation, D03Error> {
        let snapshot = self.resolve(connection_ref)?;
        let connection = Self::open_read_only(snapshot)?;
        let mut statement = connection
            .prepare(
                "SELECT name FROM sqlite_schema \
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .map_err(database_error)?;
        let table_names = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        if table_names.len() > limits.max_tables {
            return Err(D03Error::InvalidRelationalPlan(
                "SQLite table limit exceeded".to_owned(),
            ));
        }
        let mut tables = Vec::with_capacity(table_names.len());
        for table_name in table_names {
            validate_identifier(&table_name)?;
            let mut column_statement = connection
                .prepare(
                    "SELECT name, type, \"notnull\", pk FROM pragma_table_info(?1) ORDER BY cid",
                )
                .map_err(database_error)?;
            let columns = column_statement
                .query_map([&table_name], |row| {
                    let name: String = row.get(0)?;
                    let declared_type: String = row.get(1)?;
                    let not_null: i64 = row.get(2)?;
                    let primary_key: i64 = row.get(3)?;
                    Ok(DatabaseColumnObservation {
                        name,
                        declared_type,
                        nullable: not_null == 0,
                        primary_key: primary_key != 0,
                    })
                })
                .map_err(database_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(database_error)?;
            if columns.len() > limits.max_columns {
                return Err(D03Error::InvalidRelationalPlan(
                    "SQLite column limit exceeded".to_owned(),
                ));
            }
            tables.push(DatabaseTableObservation {
                name: table_name,
                columns,
            });
        }
        let schema_sha256 = schema_digest(&tables);
        let evidence = DatabaseSnapshotEvidence {
            source: snapshot.source.clone(),
            schema_sha256,
            provider_kind: "sqlite".to_owned(),
        };
        let observation = DatabaseSchemaObservation {
            snapshot: evidence,
            tables,
        };
        observation.validate(limits)?;
        Ok(observation)
    }
}

impl DatabaseQueryProvider for SqliteDatabaseProvider {
    fn inspect_schema(
        &self,
        connection: &DatabaseConnectionReference,
    ) -> Result<DatabaseSchemaObservation, D03Error> {
        self.inspect_schema_inner(connection, KnowledgeLimits::default())
    }

    fn snapshot_evidence(
        &self,
        connection: &DatabaseConnectionReference,
    ) -> Result<DatabaseSnapshotEvidence, D03Error> {
        Ok(self
            .inspect_schema_inner(connection, KnowledgeLimits::default())?
            .snapshot)
    }

    fn execute(
        &self,
        connection_ref: &DatabaseConnectionReference,
        plan: &RelationalQueryPlan,
        limits: KnowledgeLimits,
    ) -> Result<DatabaseQueryResult, D03Error> {
        limits.validate()?;
        let snapshot = self.resolve(connection_ref)?;
        let schema = self.inspect_schema_inner(connection_ref, limits)?;
        let compiled = compile_select(plan, limits)?;
        let connection = Self::open_read_only(snapshot)?;
        let mut statement = connection.prepare(compiled.sql()).map_err(database_error)?;
        let params = params_from_iter(compiled.params().iter());
        let mut query = statement.query(params).map_err(database_error)?;
        let mut rows = Vec::new();
        let mut truncated = false;
        while let Some(row) = query.next().map_err(database_error)? {
            if rows.len() >= plan.limit {
                truncated = true;
                break;
            }
            let mut values = Vec::with_capacity(compiled.columns().len());
            for index in 0..compiled.columns().len() {
                values.push(value_ref(row.get_ref(index).map_err(database_error)?)?);
            }
            rows.push(values);
        }
        let result = DatabaseQueryResult {
            snapshot: schema.snapshot,
            columns: compiled.columns().to_vec(),
            rows,
            query_plan_sha256: plan.query_plan_sha256()?,
            complete: !truncated,
            authoritative: false,
        };
        result.validate(limits)?;
        Ok(result)
    }
}

fn sha256_file(path: &Path) -> Result<String, D03Error> {
    let mut file = File::open(path).map_err(database_error)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer).map_err(database_error)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn schema_digest(tables: &[DatabaseTableObservation]) -> String {
    let mut hasher = Sha256::new();
    for table in tables {
        digest_text(&mut hasher, &table.name);
        for column in &table.columns {
            digest_text(&mut hasher, &column.name);
            digest_text(&mut hasher, &column.declared_type);
            hasher.update([u8::from(column.nullable), u8::from(column.primary_key)]);
        }
    }
    format!("{:x}", hasher.finalize())
}

fn digest_text(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn value_ref(value: ValueRef<'_>) -> Result<KnowledgeValue, D03Error> {
    match value {
        ValueRef::Null => Ok(KnowledgeValue::Null),
        ValueRef::Integer(value) => Ok(KnowledgeValue::Integer(value)),
        ValueRef::Real(value) => Ok(KnowledgeValue::Decimal(value.to_string())),
        ValueRef::Text(value) => String::from_utf8(value.to_vec())
            .map(KnowledgeValue::Text)
            .map_err(|error| D03Error::DatabaseProvider(error.to_string())),
        ValueRef::Blob(value) => {
            let mut hasher = Sha256::new();
            hasher.update(value);
            Ok(KnowledgeValue::BytesDigest {
                sha256: format!("{:x}", hasher.finalize()),
                size: u64::try_from(value.len()).map_err(|_| {
                    D03Error::DatabaseProvider("SQLite blob size overflow".to_owned())
                })?,
            })
        }
    }
}

fn validate_identifier(value: &str) -> Result<(), D03Error> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(D03Error::InvalidRelationalPlan(
            "SQLite identifier is empty".to_owned(),
        ));
    };
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(D03Error::InvalidRelationalPlan(
            "SQLite identifier grammar rejected".to_owned(),
        ));
    }
    Ok(())
}

fn database_error(error: impl std::fmt::Display) -> D03Error {
    D03Error::DatabaseProvider(error.to_string())
}
