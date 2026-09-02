use crate::{
    D03Error, KnowledgeLimits, KnowledgeSourceClass, KnowledgeSourceRevision, KnowledgeValue,
    RelationalQueryPlan,
};
use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Reference to one exact provider-backed database source.
///
/// Credentials remain external references; raw connection secrets are not part of this contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseConnectionReference {
    /// Provider family such as `sqlite`.
    pub provider_kind: String,
    /// Canonical source record.
    pub source_ref: EntityRef,
    /// Exact immutable Object Revision containing database bytes/snapshot material.
    pub object_revision_ref: EntityRef,
    /// Exact lowercase SHA-256 expected for that revision.
    pub expected_sha256: String,
    /// Stable caller-facing database name.
    pub logical_name: String,
    /// Optional external credential/evidence reference. No raw secret is retained here.
    pub credential_ref: Option<EntityRef>,
    /// Must always be true for D03.
    pub read_only: bool,
}

impl DatabaseConnectionReference {
    /// Validate the provider-neutral database reference.
    ///
    /// # Errors
    /// Rejects writable requests, non-revision objects, malformed digests or unsafe identifiers.
    pub fn validate(&self) -> Result<(), D03Error> {
        if !self.read_only {
            return Err(D03Error::ReadOnlyPolicyViolation(
                "database connection must be read-only".to_owned(),
            ));
        }
        if self.object_revision_ref.entity_kind.as_str() != "object.revision" {
            return Err(invalid("object_revision_ref must be object.revision"));
        }
        crate::query::validate_sql_identifier(&self.provider_kind)?;
        crate::query::validate_sql_identifier(&self.logical_name)?;
        if !crate::source::is_sha256(&self.expected_sha256) {
            return Err(invalid("expected_sha256 must be lowercase SHA-256"));
        }
        Ok(())
    }
}

/// Exact snapshot evidence established by a database provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseSnapshotEvidence {
    /// Canonical D03 source revision bound to the database snapshot.
    pub source: KnowledgeSourceRevision,
    /// Deterministic provider schema digest.
    pub schema_sha256: String,
    /// Provider family establishing this snapshot.
    pub provider_kind: String,
}

impl DatabaseSnapshotEvidence {
    /// Validate exact snapshot evidence.
    ///
    /// # Errors
    /// Rejects non-database sources, malformed digests or provider identifiers.
    pub fn validate(&self) -> Result<(), D03Error> {
        if self.source.class != KnowledgeSourceClass::Database {
            return Err(invalid("snapshot source must use database class"));
        }
        if !crate::source::is_sha256(&self.schema_sha256) {
            return Err(invalid("schema_sha256 must be lowercase SHA-256"));
        }
        crate::query::validate_sql_identifier(&self.provider_kind)
    }
}

/// One observed database column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseColumnObservation {
    /// Exact column name.
    pub name: String,
    /// Provider-declared type text retained as evidence.
    pub declared_type: String,
    /// Provider nullability observation.
    pub nullable: bool,
    /// Provider primary-key observation.
    pub primary_key: bool,
}

/// One observed database table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseTableObservation {
    /// Exact table name.
    pub name: String,
    /// Bounded observed columns.
    pub columns: Vec<DatabaseColumnObservation>,
}

/// Source-bound database schema observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseSchemaObservation {
    /// Exact snapshot evidence.
    pub snapshot: DatabaseSnapshotEvidence,
    /// Deterministically ordered provider table observations.
    pub tables: Vec<DatabaseTableObservation>,
}

impl DatabaseSchemaObservation {
    /// Validate schema bounds, identifiers and uniqueness.
    ///
    /// # Errors
    /// Rejects duplicate/unsafe tables or columns and configured resource overflows.
    pub fn validate(&self, limits: KnowledgeLimits) -> Result<(), D03Error> {
        limits.validate()?;
        self.snapshot.validate()?;
        if self.tables.len() > limits.max_tables {
            return Err(invalid("database table limit exceeded"));
        }
        let mut table_names = BTreeSet::new();
        for table in &self.tables {
            crate::query::validate_sql_identifier(&table.name)?;
            if !table_names.insert(table.name.as_str()) {
                return Err(invalid("duplicate database table"));
            }
            if table.columns.is_empty() || table.columns.len() > limits.max_columns {
                return Err(invalid("database column limit invalid"));
            }
            let mut columns = BTreeSet::new();
            for column in &table.columns {
                crate::query::validate_sql_identifier(&column.name)?;
                if !columns.insert(column.name.as_str()) {
                    return Err(invalid("duplicate database column"));
                }
                if column.declared_type.trim().is_empty()
                    || column.declared_type != column.declared_type.trim()
                    || column.declared_type.len() > limits.max_field_bytes
                    || column.declared_type.contains('\0')
                {
                    return Err(invalid("invalid database declared type"));
                }
            }
        }
        Ok(())
    }
}

/// Provider-neutral result over one exact database snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseQueryResult {
    /// Exact snapshot evidence used for execution.
    pub snapshot: DatabaseSnapshotEvidence,
    /// Stable result column labels.
    pub columns: Vec<String>,
    /// Bounded typed rows.
    pub rows: Vec<Vec<KnowledgeValue>>,
    /// Deterministic typed query-plan digest.
    pub query_plan_sha256: String,
    /// True only when the provider proves the bounded result is complete.
    pub complete: bool,
    /// Always false: a query result is derived evidence.
    pub authoritative: bool,
}

impl DatabaseQueryResult {
    /// Validate result shape and the non-authoritative invariant.
    ///
    /// # Errors
    /// Rejects malformed snapshot/digest, duplicate columns, row-width mismatch or result bounds.
    pub fn validate(&self, limits: KnowledgeLimits) -> Result<(), D03Error> {
        limits.validate()?;
        self.snapshot.validate()?;
        if self.authoritative {
            return Err(invalid("database query result cannot be authoritative"));
        }
        if !crate::source::is_sha256(&self.query_plan_sha256) {
            return Err(invalid("invalid database query-plan digest"));
        }
        if self.columns.is_empty() || self.columns.len() > limits.max_projection_items {
            return Err(invalid("database result column limit invalid"));
        }
        if self.rows.len() > limits.max_results {
            return Err(invalid("database result row limit exceeded"));
        }
        let mut columns = BTreeSet::new();
        for column in &self.columns {
            crate::query::validate_sql_identifier(column)?;
            if !columns.insert(column.as_str()) {
                return Err(invalid("duplicate database result column"));
            }
        }
        if self.rows.iter().any(|row| row.len() != self.columns.len()) {
            return Err(invalid("database result row width mismatch"));
        }
        Ok(())
    }
}

/// Replaceable read-only database query provider boundary.
pub trait DatabaseQueryProvider {
    /// Inspect exact bounded database schema evidence.
    ///
    /// # Errors
    /// Returns a mechanical provider or snapshot error.
    fn inspect_schema(
        &self,
        connection: &DatabaseConnectionReference,
    ) -> Result<DatabaseSchemaObservation, D03Error>;

    /// Establish exact source/snapshot evidence before query execution.
    ///
    /// # Errors
    /// Returns a mechanical provider or snapshot error.
    fn snapshot_evidence(
        &self,
        connection: &DatabaseConnectionReference,
    ) -> Result<DatabaseSnapshotEvidence, D03Error>;

    /// Execute one validated typed read-only query plan.
    ///
    /// # Errors
    /// Returns a mechanical provider, snapshot, plan or resource error.
    fn execute(
        &self,
        connection: &DatabaseConnectionReference,
        plan: &RelationalQueryPlan,
        limits: KnowledgeLimits,
    ) -> Result<DatabaseQueryResult, D03Error>;
}

fn invalid(message: &str) -> D03Error {
    D03Error::InvalidRelationalPlan(message.to_owned())
}
