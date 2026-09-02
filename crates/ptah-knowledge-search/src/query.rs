use crate::{CitationEvidence, D03Error, KnowledgeLimits, KnowledgeSourceRevision};
use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Public D03 search/query domains. Firmware and partition fields are privately mapped to B07 metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeSearchDomain {
    /// Filename/logical path fields.
    Filename,
    /// Evidence-derived metadata fields.
    Metadata,
    /// Exact B03 anchored text.
    DocumentText,
    /// Exact source symbols.
    SourceSymbol,
    /// Firmware/package manifest fields.
    Firmware,
    /// Partition/layout fields.
    Partition,
}

/// Typed value returned by D03 derived query results.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum KnowledgeValue {
    /// SQL/structured null.
    Null,
    /// Boolean value.
    Boolean(bool),
    /// Signed integer value.
    Integer(i64),
    /// Decimal/real value retained as deterministic text.
    Decimal(String),
    /// UTF-8 text.
    Text(String),
    /// Byte value retained as digest and size rather than opaque inline bytes.
    BytesDigest {
        /// Exact lowercase SHA-256.
        sha256: String,
        /// Exact byte size.
        size: u64,
    },
}

/// Shared source-local column reference for structured and relational queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnRef {
    /// Optional table qualifier.
    pub table: Option<String>,
    /// Exact column name.
    pub column: String,
}

/// Workspace-scoped textual query request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeTextQuery {
    /// Workspace within which sources may match.
    pub workspace_ref: EntityRef,
    /// Case-insensitive AND query text inherited from B07 semantics.
    pub text: String,
    /// D03 domains eligible for matching.
    pub domains: Vec<KnowledgeSearchDomain>,
    /// Bounded result limit.
    pub limit: usize,
}

impl KnowledgeTextQuery {
    /// Construct a validated textual query.
    ///
    /// # Errors
    /// Returns a mechanical query error for invalid Workspace/text/domain/result bounds.
    pub fn new(
        workspace_ref: EntityRef,
        text: &str,
        domains: Vec<KnowledgeSearchDomain>,
        limit: usize,
    ) -> Result<Self, D03Error> {
        if workspace_ref.entity_kind.as_str() != "core.workspace" {
            return Err(D03Error::InvalidQuery("workspace_ref"));
        }
        if text.trim().is_empty() || text != text.trim() {
            return Err(D03Error::InvalidQuery("text"));
        }
        if domains.is_empty() || limit == 0 {
            return Err(D03Error::InvalidQuery("domains/limit"));
        }
        Ok(Self {
            workspace_ref,
            text: text.to_owned(),
            domains,
            limit,
        })
    }

    pub(crate) fn validate_limits(&self, limits: KnowledgeLimits) -> Result<(), D03Error> {
        if self.text.len() > limits.max_query_bytes || self.limit > limits.max_results {
            return Err(D03Error::InvalidQuery("resource limit"));
        }
        Ok(())
    }
}

/// One derived query row/hit and its exact citations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeResultRow {
    /// Mechanically returned values.
    pub values: Vec<KnowledgeValue>,
    /// Exact provenance/citation evidence supporting this row.
    pub citations: Vec<CitationEvidence>,
}

/// D03 derived result View. It can never be source authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeResultSet {
    /// Stable output column labels.
    pub columns: Vec<String>,
    /// Bounded result rows.
    pub rows: Vec<KnowledgeResultRow>,
    /// Exact source revisions represented in this result.
    pub source_refs: Vec<KnowledgeSourceRevision>,
    /// Deterministic digest of query family/request and derived index identity.
    pub query_plan_sha256: String,
    /// True only when the adapter can mechanically prove the bounded result was not cut at its limit.
    pub complete: bool,
    /// Always false: query results are derived Views.
    pub authoritative: bool,
}

pub(crate) fn query_digest<T: Serialize>(value: &T, extra: &str) -> Result<String, D03Error> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| D03Error::Serialization(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.update((extra.len() as u64).to_le_bytes());
    hasher.update(extra.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

/// Provider-neutral table reference used by relational query plans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableRef {
    /// Exact table name.
    pub name: String,
    /// Optional query-local alias.
    pub alias: Option<String>,
}

/// Supported read-only join families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinKind {
    /// Inner join.
    Inner,
    /// Left outer join.
    Left,
}

/// Typed relational expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationalExpr {
    /// Validated column reference.
    Column(ColumnRef),
    /// Parameterized literal value.
    Value(crate::CellValue),
}

/// Typed relational predicate tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationalPredicate {
    /// Equality comparison.
    Eq(RelationalExpr, RelationalExpr),
    /// Inequality comparison.
    Ne(RelationalExpr, RelationalExpr),
    /// Less-than comparison.
    Lt(RelationalExpr, RelationalExpr),
    /// Less-than-or-equal comparison.
    Le(RelationalExpr, RelationalExpr),
    /// Greater-than comparison.
    Gt(RelationalExpr, RelationalExpr),
    /// Greater-than-or-equal comparison.
    Ge(RelationalExpr, RelationalExpr),
    /// Null check.
    IsNull(ColumnRef),
    /// Non-null check.
    IsNotNull(ColumnRef),
    /// Membership check.
    In(ColumnRef, Vec<crate::CellValue>),
    /// Boolean conjunction.
    And(Vec<RelationalPredicate>),
    /// Boolean disjunction.
    Or(Vec<RelationalPredicate>),
}

/// Supported aggregate families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateKind {
    /// Count non-null values.
    Count,
    /// Sum numeric values.
    Sum,
    /// Minimum value.
    Min,
    /// Maximum value.
    Max,
    /// Average numeric value.
    Avg,
}

/// One projected relational expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectItem {
    /// Typed expression.
    pub expr: RelationalExpr,
    /// Optional stable result alias.
    pub alias: Option<String>,
    /// Optional aggregate applied to `expr`.
    pub aggregate: Option<AggregateKind>,
}

/// One read-only relational join.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinSpec {
    /// Join family.
    pub kind: JoinKind,
    /// Joined table.
    pub table: TableRef,
    /// Typed join condition.
    pub on: RelationalPredicate,
}

/// One relational result ordering expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationalOrder {
    /// Typed expression to order by.
    pub expr: RelationalExpr,
    /// Descending order when true.
    pub descending: bool,
}

/// Bounded provider-neutral read-only relational query plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationalQueryPlan {
    /// Primary source table.
    pub from: TableRef,
    /// Bounded joins.
    pub joins: Vec<JoinSpec>,
    /// Non-empty output projection.
    pub projection: Vec<SelectItem>,
    /// Optional typed filter predicate.
    pub predicate: Option<RelationalPredicate>,
    /// Bounded grouping columns.
    pub group_by: Vec<ColumnRef>,
    /// Bounded result ordering.
    pub order: Vec<RelationalOrder>,
    /// Maximum returned rows.
    pub limit: usize,
    /// Matching rows skipped before the limit is applied.
    pub offset: usize,
}

impl RelationalQueryPlan {
    /// Validate identifiers, aliases and resource bounds without consulting a provider.
    ///
    /// # Errors
    /// Returns [`D03Error::InvalidRelationalPlan`] for malformed or unbounded plans.
    pub fn validate(&self, limits: KnowledgeLimits) -> Result<(), D03Error> {
        limits.validate()?;
        validate_table_ref(&self.from)?;
        if self.joins.len() > limits.max_joins {
            return Err(relational_error("join limit exceeded"));
        }
        if self.projection.is_empty() || self.projection.len() > limits.max_projection_items {
            return Err(relational_error("projection limit invalid"));
        }
        if self.group_by.len() > limits.max_columns || self.order.len() > limits.max_columns {
            return Err(relational_error("group/order limit exceeded"));
        }
        if self.limit == 0 || self.limit > limits.max_results || self.offset > limits.max_rows {
            return Err(relational_error("row bound invalid"));
        }

        let mut table_aliases = BTreeSet::new();
        insert_table_identity(&self.from, &mut table_aliases)?;
        let mut predicate_nodes = 0_usize;
        for join in &self.joins {
            validate_table_ref(&join.table)?;
            insert_table_identity(&join.table, &mut table_aliases)?;
            validate_predicate(&join.on, limits, &mut predicate_nodes)?;
        }

        let mut result_aliases = BTreeSet::new();
        for item in &self.projection {
            validate_expr(&item.expr)?;
            if let Some(alias) = &item.alias {
                validate_sql_identifier(alias)?;
                if !result_aliases.insert(alias.as_str()) {
                    return Err(relational_error("duplicate projection alias"));
                }
            }
        }
        if let Some(predicate) = &self.predicate {
            validate_predicate(predicate, limits, &mut predicate_nodes)?;
        }
        for column in &self.group_by {
            validate_column_ref(column)?;
        }
        for order in &self.order {
            validate_expr(&order.expr)?;
        }
        Ok(())
    }

    /// Compute a deterministic SHA-256 over the canonical typed plan.
    ///
    /// # Errors
    /// Returns a serialization failure if canonical JSON cannot be produced.
    pub fn query_plan_sha256(&self) -> Result<String, D03Error> {
        query_digest(self, "d03.relational.plan")
    }
}

fn insert_table_identity<'a>(
    table: &'a TableRef,
    identities: &mut BTreeSet<&'a str>,
) -> Result<(), D03Error> {
    let identity = table.alias.as_deref().unwrap_or(&table.name);
    if !identities.insert(identity) {
        return Err(relational_error("duplicate table alias"));
    }
    Ok(())
}

fn validate_table_ref(table: &TableRef) -> Result<(), D03Error> {
    validate_sql_identifier(&table.name)?;
    if let Some(alias) = &table.alias {
        validate_sql_identifier(alias)?;
    }
    Ok(())
}

fn validate_column_ref(reference: &ColumnRef) -> Result<(), D03Error> {
    if let Some(table) = &reference.table {
        validate_sql_identifier(table)?;
    }
    validate_sql_identifier(&reference.column)
}

fn validate_expr(expr: &RelationalExpr) -> Result<(), D03Error> {
    match expr {
        RelationalExpr::Column(reference) => validate_column_ref(reference),
        RelationalExpr::Value(value) => validate_relational_value(value),
    }
}

fn validate_relational_value(value: &crate::CellValue) -> Result<(), D03Error> {
    match value {
        crate::CellValue::Decimal(value) if value.trim().is_empty() => {
            Err(relational_error("empty decimal literal"))
        }
        crate::CellValue::Text(value) if value.contains('\0') => {
            Err(relational_error("text literal contains NUL"))
        }
        crate::CellValue::BytesDigest { sha256, .. } if !crate::source::is_sha256(sha256) => {
            Err(relational_error("invalid bytes digest"))
        }
        _ => Ok(()),
    }
}

fn validate_predicate(
    predicate: &RelationalPredicate,
    limits: KnowledgeLimits,
    nodes: &mut usize,
) -> Result<(), D03Error> {
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| relational_error("predicate count overflow"))?;
    if *nodes > limits.max_predicates {
        return Err(relational_error("predicate limit exceeded"));
    }
    match predicate {
        RelationalPredicate::Eq(left, right)
        | RelationalPredicate::Ne(left, right)
        | RelationalPredicate::Lt(left, right)
        | RelationalPredicate::Le(left, right)
        | RelationalPredicate::Gt(left, right)
        | RelationalPredicate::Ge(left, right) => {
            validate_expr(left)?;
            validate_expr(right)
        }
        RelationalPredicate::IsNull(reference) | RelationalPredicate::IsNotNull(reference) => {
            validate_column_ref(reference)
        }
        RelationalPredicate::In(reference, values) => {
            validate_column_ref(reference)?;
            if values.is_empty() || values.len() > limits.max_predicates {
                return Err(relational_error("IN value count invalid"));
            }
            for value in values {
                validate_relational_value(value)?;
            }
            Ok(())
        }
        RelationalPredicate::And(children) | RelationalPredicate::Or(children) => {
            if children.is_empty() {
                return Err(relational_error("boolean predicate group is empty"));
            }
            for child in children {
                validate_predicate(child, limits, nodes)?;
            }
            Ok(())
        }
    }
}

pub(crate) fn validate_sql_identifier(value: &str) -> Result<(), D03Error> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(relational_error("SQL identifier is empty"));
    };
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(relational_error("SQL identifier grammar rejected"));
    }
    Ok(())
}

fn relational_error(message: &str) -> D03Error {
    D03Error::InvalidRelationalPlan(message.to_owned())
}
