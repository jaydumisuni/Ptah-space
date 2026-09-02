use crate::{
    CitationEvidence, ColumnRef, D03Error, KnowledgeLimits, KnowledgeLocator, KnowledgeResultRow,
    KnowledgeResultSet, KnowledgeSourceClass, KnowledgeSourceRevision, KnowledgeValue,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::str;

/// Structured dataset cell value.
pub type CellValue = KnowledgeValue;

/// Mechanically inferred structured column type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColumnType {
    /// Boolean values only.
    Boolean,
    /// Signed integers only.
    Integer,
    /// Non-integer JSON/structured numeric values retained as exact decimal text.
    Decimal,
    /// UTF-8 text values only.
    Text,
    /// Digest-and-size byte references.
    BytesDigest,
    /// More than one non-null type was observed.
    Mixed,
}

/// Deterministic structured sort request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredOrder {
    /// Column to order by.
    pub column: ColumnRef,
    /// Reverse the natural typed ordering when true.
    pub descending: bool,
}

/// Inferred table-column schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnSchema {
    /// Exact column name.
    pub name: String,
    /// Mechanically inferred non-null value type.
    pub data_type: ColumnType,
    /// True when at least one row is null or omitted this column.
    pub nullable: bool,
}

/// One deterministic table snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableSnapshot {
    /// Exact table name.
    pub name: String,
    /// Stable column order and inferred schema.
    pub columns: Vec<ColumnSchema>,
    /// Rows aligned exactly with `columns`.
    pub rows: Vec<Vec<CellValue>>,
}

/// Source-bound deterministic structured dataset snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetSnapshot {
    /// Exact source revision from which the snapshot was derived.
    pub source: KnowledgeSourceRevision,
    /// Deterministically normalized tables.
    pub tables: Vec<TableSnapshot>,
    /// SHA-256 of canonical normalized table content.
    pub content_sha256: String,
    /// True when ingestion consumed the complete bounded input.
    pub complete: bool,
}

/// Typed structured predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredPredicate {
    /// Exact typed equality.
    Eq(ColumnRef, CellValue),
    /// Exact typed inequality.
    Ne(ColumnRef, CellValue),
    /// Typed less-than comparison.
    Lt(ColumnRef, CellValue),
    /// Typed less-than-or-equal comparison.
    Le(ColumnRef, CellValue),
    /// Typed greater-than comparison.
    Gt(ColumnRef, CellValue),
    /// Typed greater-than-or-equal comparison.
    Ge(ColumnRef, CellValue),
    /// Null predicate.
    IsNull(ColumnRef),
    /// Non-null predicate.
    IsNotNull(ColumnRef),
    /// Exact typed membership predicate.
    In(ColumnRef, Vec<CellValue>),
}

/// Bounded deterministic query over one table snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredQuery {
    /// Exact source table name.
    pub table: String,
    /// Output column names in requested order.
    pub projection: Vec<String>,
    /// AND-composed typed predicates.
    pub predicates: Vec<StructuredPredicate>,
    /// Stable sort keys, evaluated left to right.
    pub order: Vec<StructuredOrder>,
    /// Maximum rows returned.
    pub limit: usize,
    /// Number of matching rows skipped before `limit` is applied.
    pub offset: usize,
}

/// Ingest one JSON object or array of objects into a deterministic table snapshot.
///
/// # Errors
/// Fails closed for malformed/nested JSON, invalid source/table identity or configured bounds.
pub fn ingest_json(
    source: KnowledgeSourceRevision,
    table_name: &str,
    bytes: &[u8],
    limits: KnowledgeLimits,
) -> Result<DatasetSnapshot, D03Error> {
    validate_ingest_request(&source, table_name, bytes, limits)?;
    let value: Value = serde_json::from_slice(bytes).map_err(structured_error)?;
    let objects = match value {
        Value::Object(object) => vec![object],
        Value::Array(values) => values
            .into_iter()
            .map(|value| match value {
                Value::Object(object) => Ok(object),
                _ => Err(structured("JSON dataset rows must be objects")),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(structured(
                "JSON dataset must be an object or array of objects",
            ));
        }
    };
    table_snapshot_from_objects(source, table_name, &objects, limits)
}

/// Ingest newline-delimited JSON objects into a deterministic table snapshot.
///
/// # Errors
/// Fails closed for malformed/non-object lines, invalid source/table identity or configured bounds.
pub fn ingest_json_lines(
    source: KnowledgeSourceRevision,
    table_name: &str,
    bytes: &[u8],
    limits: KnowledgeLimits,
) -> Result<DatasetSnapshot, D03Error> {
    validate_ingest_request(&source, table_name, bytes, limits)?;
    let text = str::from_utf8(bytes).map_err(structured_error)?;
    let mut objects = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if objects.len() >= limits.max_rows {
            return Err(structured("JSONL row limit exceeded"));
        }
        let value: Value = serde_json::from_str(line).map_err(structured_error)?;
        let Value::Object(object) = value else {
            return Err(structured("JSONL rows must be objects"));
        };
        objects.push(object);
    }
    if objects.is_empty() {
        return Err(structured("JSONL dataset has no rows"));
    }
    table_snapshot_from_objects(source, table_name, &objects, limits)
}

/// Ingest comma-delimited RFC4180-style UTF-8 data into a deterministic table snapshot.
///
/// Quoted cells remain text; unquoted cells are mechanically parsed as null/boolean/integer/
/// decimal where exact lexical parsing succeeds.
///
/// # Errors
/// Fails closed for malformed quoting, duplicate headers, row-width mismatch or configured bounds.
pub fn ingest_csv(
    source: KnowledgeSourceRevision,
    table_name: &str,
    bytes: &[u8],
    limits: KnowledgeLimits,
) -> Result<DatasetSnapshot, D03Error> {
    validate_ingest_request(&source, table_name, bytes, limits)?;
    let records = parse_csv(bytes, limits)?;
    let (header, data) = records
        .split_first()
        .ok_or_else(|| structured("CSV has no header row"))?;
    if header.is_empty() || header.len() > limits.max_columns {
        return Err(structured("CSV header column limit invalid"));
    }
    let mut names = BTreeSet::new();
    let mut columns = Vec::with_capacity(header.len());
    for field in header {
        validate_name(&field.value, limits.max_field_bytes, "CSV header")?;
        if !names.insert(field.value.clone()) {
            return Err(structured("CSV contains duplicate header"));
        }
        columns.push(field.value.clone());
    }
    if data.len() > limits.max_rows {
        return Err(structured("CSV row limit exceeded"));
    }
    let mut rows = Vec::with_capacity(data.len());
    for record in data {
        if record.len() != columns.len() {
            return Err(structured("CSV row width does not match header"));
        }
        rows.push(
            record
                .iter()
                .map(|field| csv_cell(field, limits))
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    snapshot_from_rows(source, table_name, columns, rows, limits)
}

/// Query one deterministic structured snapshot.
///
/// # Errors
/// Fails closed for unknown/unsafe columns, type-incompatible ordered predicates or resource bounds.
pub fn query_dataset(
    snapshot: &DatasetSnapshot,
    query: &StructuredQuery,
    limits: KnowledgeLimits,
) -> Result<KnowledgeResultSet, D03Error> {
    limits.validate()?;
    validate_query_shape(query, limits)?;
    let table = snapshot
        .tables
        .iter()
        .find(|table| table.name == query.table)
        .ok_or_else(|| structured("structured query table not found"))?;
    let column_map = column_map(table)?;
    let projection = query
        .projection
        .iter()
        .map(|name| {
            column_map
                .get(name.as_str())
                .copied()
                .ok_or_else(|| structured("structured projection column not found"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for predicate in &query.predicates {
        validate_predicate_columns(predicate, table, &column_map)?;
    }
    let order = query
        .order
        .iter()
        .map(|request| {
            validate_column_ref(&request.column, table)?;
            let index = *column_map
                .get(request.column.column.as_str())
                .ok_or_else(|| structured("structured order column not found"))?;
            Ok((index, request.descending))
        })
        .collect::<Result<Vec<_>, D03Error>>()?;

    let mut matched = Vec::<(usize, &Vec<CellValue>)>::new();
    for (row_index, row) in table.rows.iter().enumerate() {
        if query
            .predicates
            .iter()
            .try_fold(true, |accepted, predicate| {
                if accepted {
                    evaluate_predicate(predicate, table, row, &column_map)
                } else {
                    Ok(false)
                }
            })?
        {
            matched.push((row_index, row));
        }
    }
    matched.sort_by(|left, right| {
        for (column, descending) in &order {
            let ordering = total_value_cmp(&left.1[*column], &right.1[*column]);
            if ordering != Ordering::Equal {
                return if *descending {
                    ordering.reverse()
                } else {
                    ordering
                };
            }
        }
        left.0.cmp(&right.0)
    });

    let remaining = matched.len().saturating_sub(query.offset);
    let complete = snapshot.complete && remaining <= query.limit;
    let selected = matched.iter().skip(query.offset).take(query.limit);
    let mut rows = Vec::with_capacity(remaining.min(query.limit));
    for (row_index, row) in selected {
        let mut values = Vec::with_capacity(projection.len());
        let mut citations = Vec::with_capacity(projection.len());
        for (output_index, source_column) in projection.iter().enumerate() {
            values.push(row[*source_column].clone());
            let locator = KnowledgeLocator::DatasetCell {
                table: table.name.clone(),
                row: u64::try_from(*row_index).map_err(|_| structured("row index overflow"))?,
                column: query.projection[output_index].clone(),
            };
            citations.push(CitationEvidence::new(
                snapshot.source.clone(),
                locator,
                "d03.structured.snapshot",
                None,
            )?);
        }
        rows.push(KnowledgeResultRow { values, citations });
    }
    let query_plan_sha256 = crate::query::query_digest(query, &snapshot.content_sha256)?;
    Ok(KnowledgeResultSet {
        columns: query.projection.clone(),
        rows,
        source_refs: vec![snapshot.source.clone()],
        query_plan_sha256,
        complete,
        authoritative: false,
    })
}

fn table_snapshot_from_objects(
    source: KnowledgeSourceRevision,
    table_name: &str,
    objects: &[Map<String, Value>],
    limits: KnowledgeLimits,
) -> Result<DatasetSnapshot, D03Error> {
    if objects.is_empty() || objects.len() > limits.max_rows {
        return Err(structured("structured row limit invalid"));
    }
    let mut columns = BTreeSet::new();
    for object in objects {
        for key in object.keys() {
            validate_name(key, limits.max_field_bytes, "structured column")?;
            columns.insert(key.clone());
        }
    }
    if columns.is_empty() || columns.len() > limits.max_columns {
        return Err(structured("structured column limit invalid"));
    }
    let columns = columns.into_iter().collect::<Vec<_>>();
    let rows = objects
        .iter()
        .map(|object| {
            columns
                .iter()
                .map(|column| match object.get(column) {
                    Some(value) => json_cell(value, limits),
                    None => Ok(CellValue::Null),
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    snapshot_from_rows(source, table_name, columns, rows, limits)
}

fn snapshot_from_rows(
    source: KnowledgeSourceRevision,
    table_name: &str,
    column_names: Vec<String>,
    rows: Vec<Vec<CellValue>>,
    limits: KnowledgeLimits,
) -> Result<DatasetSnapshot, D03Error> {
    if column_names.len() > limits.max_columns || rows.len() > limits.max_rows {
        return Err(structured("structured snapshot bounds exceeded"));
    }
    let mut columns = Vec::with_capacity(column_names.len());
    for (index, name) in column_names.into_iter().enumerate() {
        let mut inferred = None;
        let mut nullable = false;
        for row in &rows {
            let value = row
                .get(index)
                .ok_or_else(|| structured("structured row width mismatch"))?;
            match column_type(value) {
                None => nullable = true,
                Some(kind) => {
                    inferred = Some(match inferred {
                        None => kind,
                        Some(existing) if existing == kind => existing,
                        Some(_) => ColumnType::Mixed,
                    });
                }
            }
        }
        columns.push(ColumnSchema {
            name,
            data_type: inferred.unwrap_or(ColumnType::Mixed),
            nullable,
        });
    }
    for row in &rows {
        if row.len() != columns.len() {
            return Err(structured("structured row width mismatch"));
        }
    }
    let table = TableSnapshot {
        name: table_name.to_owned(),
        columns,
        rows,
    };
    let digest_bytes = serde_json::to_vec(&table).map_err(structured_error)?;
    let mut hasher = Sha256::new();
    hasher.update(digest_bytes);
    Ok(DatasetSnapshot {
        source,
        tables: vec![table],
        content_sha256: format!("{:x}", hasher.finalize()),
        complete: true,
    })
}

fn json_cell(value: &Value, limits: KnowledgeLimits) -> Result<CellValue, D03Error> {
    match value {
        Value::Null => Ok(CellValue::Null),
        Value::Bool(value) => Ok(CellValue::Boolean(*value)),
        Value::Number(value) => {
            if let Some(integer) = value.as_i64() {
                Ok(CellValue::Integer(integer))
            } else {
                let text = value.to_string();
                validate_cell_text(&text, limits)?;
                Ok(CellValue::Decimal(text))
            }
        }
        Value::String(value) => {
            validate_cell_text(value, limits)?;
            Ok(CellValue::Text(value.clone()))
        }
        Value::Array(_) | Value::Object(_) => {
            Err(structured("nested structured values are unsupported"))
        }
    }
}

fn csv_cell(field: &CsvField, limits: KnowledgeLimits) -> Result<CellValue, D03Error> {
    validate_cell_text(&field.value, limits)?;
    if field.quoted {
        return Ok(CellValue::Text(field.value.clone()));
    }
    if field.value.is_empty() {
        return Ok(CellValue::Null);
    }
    if field.value.eq_ignore_ascii_case("true") {
        return Ok(CellValue::Boolean(true));
    }
    if field.value.eq_ignore_ascii_case("false") {
        return Ok(CellValue::Boolean(false));
    }
    if let Ok(integer) = field.value.parse::<i64>() {
        return Ok(CellValue::Integer(integer));
    }
    if let Ok(Value::Number(number)) = serde_json::from_str::<Value>(&field.value) {
        return Ok(CellValue::Decimal(number.to_string()));
    }
    Ok(CellValue::Text(field.value.clone()))
}

fn column_type(value: &CellValue) -> Option<ColumnType> {
    match value {
        CellValue::Null => None,
        CellValue::Boolean(_) => Some(ColumnType::Boolean),
        CellValue::Integer(_) => Some(ColumnType::Integer),
        CellValue::Decimal(_) => Some(ColumnType::Decimal),
        CellValue::Text(_) => Some(ColumnType::Text),
        CellValue::BytesDigest { .. } => Some(ColumnType::BytesDigest),
    }
}

fn validate_ingest_request(
    source: &KnowledgeSourceRevision,
    table_name: &str,
    bytes: &[u8],
    limits: KnowledgeLimits,
) -> Result<(), D03Error> {
    limits.validate()?;
    if source.class != KnowledgeSourceClass::Dataset {
        return Err(structured(
            "structured ingestion requires dataset source class",
        ));
    }
    validate_name(table_name, limits.max_field_bytes, "table name")?;
    if bytes.is_empty() || bytes.len() > limits.max_input_bytes {
        return Err(structured("structured input byte limit invalid"));
    }
    Ok(())
}

fn validate_query_shape(query: &StructuredQuery, limits: KnowledgeLimits) -> Result<(), D03Error> {
    validate_name(&query.table, limits.max_field_bytes, "query table")?;
    if query.projection.is_empty() || query.projection.len() > limits.max_projection_items {
        return Err(structured("structured projection limit invalid"));
    }
    if query.predicates.len() > limits.max_predicates
        || query.order.len() > limits.max_columns
        || query.limit == 0
        || query.limit > limits.max_results
        || query.offset > limits.max_rows
    {
        return Err(structured("structured query resource limit invalid"));
    }
    let mut projected = BTreeSet::new();
    for column in &query.projection {
        validate_name(column, limits.max_field_bytes, "projection column")?;
        if !projected.insert(column.as_str()) {
            return Err(structured("duplicate structured projection column"));
        }
    }
    Ok(())
}

fn column_map(table: &TableSnapshot) -> Result<BTreeMap<&str, usize>, D03Error> {
    let mut map = BTreeMap::new();
    for (index, column) in table.columns.iter().enumerate() {
        if map.insert(column.name.as_str(), index).is_some() {
            return Err(structured("snapshot contains duplicate columns"));
        }
    }
    Ok(map)
}

fn validate_column_ref(reference: &ColumnRef, table: &TableSnapshot) -> Result<(), D03Error> {
    validate_name(&reference.column, usize::MAX, "column reference")?;
    if reference
        .table
        .as_deref()
        .is_some_and(|qualifier| qualifier != table.name)
    {
        return Err(structured("column table qualifier mismatch"));
    }
    Ok(())
}

fn validate_predicate_columns(
    predicate: &StructuredPredicate,
    table: &TableSnapshot,
    columns: &BTreeMap<&str, usize>,
) -> Result<(), D03Error> {
    let reference = match predicate {
        StructuredPredicate::Eq(reference, _)
        | StructuredPredicate::Ne(reference, _)
        | StructuredPredicate::Lt(reference, _)
        | StructuredPredicate::Le(reference, _)
        | StructuredPredicate::Gt(reference, _)
        | StructuredPredicate::Ge(reference, _)
        | StructuredPredicate::In(reference, _)
        | StructuredPredicate::IsNull(reference)
        | StructuredPredicate::IsNotNull(reference) => reference,
    };
    validate_column_ref(reference, table)?;
    if !columns.contains_key(reference.column.as_str()) {
        return Err(structured("structured predicate column not found"));
    }
    Ok(())
}

fn evaluate_predicate(
    predicate: &StructuredPredicate,
    table: &TableSnapshot,
    row: &[CellValue],
    columns: &BTreeMap<&str, usize>,
) -> Result<bool, D03Error> {
    let value = |reference: &ColumnRef| -> Result<&CellValue, D03Error> {
        validate_column_ref(reference, table)?;
        let index = *columns
            .get(reference.column.as_str())
            .ok_or_else(|| structured("predicate column not found"))?;
        row.get(index)
            .ok_or_else(|| structured("predicate row width mismatch"))
    };
    match predicate {
        StructuredPredicate::Eq(reference, expected) => {
            Ok(values_equal(value(reference)?, expected))
        }
        StructuredPredicate::Ne(reference, expected) => {
            Ok(!values_equal(value(reference)?, expected))
        }
        StructuredPredicate::Lt(reference, expected) => {
            Ok(ordered_cmp(value(reference)?, expected)? == Ordering::Less)
        }
        StructuredPredicate::Le(reference, expected) => Ok(matches!(
            ordered_cmp(value(reference)?, expected)?,
            Ordering::Less | Ordering::Equal
        )),
        StructuredPredicate::Gt(reference, expected) => {
            Ok(ordered_cmp(value(reference)?, expected)? == Ordering::Greater)
        }
        StructuredPredicate::Ge(reference, expected) => Ok(matches!(
            ordered_cmp(value(reference)?, expected)?,
            Ordering::Greater | Ordering::Equal
        )),
        StructuredPredicate::IsNull(reference) => Ok(matches!(value(reference)?, CellValue::Null)),
        StructuredPredicate::IsNotNull(reference) => {
            Ok(!matches!(value(reference)?, CellValue::Null))
        }
        StructuredPredicate::In(reference, expected) => {
            let actual = value(reference)?;
            Ok(expected
                .iter()
                .any(|candidate| values_equal(actual, candidate)))
        }
    }
}

fn values_equal(left: &CellValue, right: &CellValue) -> bool {
    match (left, right) {
        (CellValue::Integer(left), CellValue::Decimal(right)) => {
            compare_decimal(&left.to_string(), right) == Some(Ordering::Equal)
        }
        (CellValue::Decimal(left), CellValue::Integer(right)) => {
            compare_decimal(left, &right.to_string()) == Some(Ordering::Equal)
        }
        (CellValue::Decimal(left), CellValue::Decimal(right)) => {
            compare_decimal(left, right) == Some(Ordering::Equal)
        }
        _ => left == right,
    }
}

fn ordered_cmp(left: &CellValue, right: &CellValue) -> Result<Ordering, D03Error> {
    match (left, right) {
        (CellValue::Integer(left), CellValue::Integer(right)) => Ok(left.cmp(right)),
        (CellValue::Integer(left), CellValue::Decimal(right)) => {
            compare_decimal(&left.to_string(), right)
                .ok_or_else(|| structured("invalid decimal comparison"))
        }
        (CellValue::Decimal(left), CellValue::Integer(right)) => {
            compare_decimal(left, &right.to_string())
                .ok_or_else(|| structured("invalid decimal comparison"))
        }
        (CellValue::Decimal(left), CellValue::Decimal(right)) => {
            compare_decimal(left, right).ok_or_else(|| structured("invalid decimal comparison"))
        }
        (CellValue::Text(left), CellValue::Text(right)) => Ok(left.cmp(right)),
        (CellValue::Boolean(left), CellValue::Boolean(right)) => Ok(left.cmp(right)),
        (CellValue::Null, _) | (_, CellValue::Null) => {
            Err(structured("ordered comparison with null is undefined"))
        }
        (CellValue::BytesDigest { .. }, CellValue::BytesDigest { .. }) => Ok(left.cmp(right)),
        _ => Err(structured("ordered comparison uses incompatible types")),
    }
}

fn total_value_cmp(left: &CellValue, right: &CellValue) -> Ordering {
    match (left, right) {
        (CellValue::Integer(left), CellValue::Decimal(right)) => {
            compare_decimal(&left.to_string(), right).unwrap_or_else(|| left.to_string().cmp(right))
        }
        (CellValue::Decimal(left), CellValue::Integer(right)) => {
            compare_decimal(left, &right.to_string())
                .unwrap_or_else(|| left.cmp(&right.to_string()))
        }
        (CellValue::Decimal(left), CellValue::Decimal(right)) => {
            compare_decimal(left, right).unwrap_or_else(|| left.cmp(right))
        }
        _ => left.cmp(right),
    }
}

#[derive(Debug)]
struct DecimalParts {
    negative: bool,
    digits: String,
    power: i64,
}

fn compare_decimal(left: &str, right: &str) -> Option<Ordering> {
    let left = parse_decimal(left)?;
    let right = parse_decimal(right)?;
    let left_zero = left.digits == "0";
    let right_zero = right.digits == "0";
    if left_zero && right_zero {
        return Some(Ordering::Equal);
    }
    if left.negative != right.negative {
        return Some(if left.negative {
            Ordering::Less
        } else {
            Ordering::Greater
        });
    }
    let ordering = compare_decimal_magnitude(&left, &right)?;
    Some(if left.negative {
        ordering.reverse()
    } else {
        ordering
    })
}

fn parse_decimal(value: &str) -> Option<DecimalParts> {
    let (negative, unsigned) = value
        .strip_prefix('-')
        .map_or((false, value), |value| (true, value));
    let (mantissa, exponent_text) = unsigned
        .split_once(['e', 'E'])
        .map_or((unsigned, None), |(mantissa, exponent)| {
            (mantissa, Some(exponent))
        });
    let exponent = exponent_text.map_or(Some(0_i64), parse_signed_i64)?;
    let (integer, fractional) = mantissa
        .split_once('.')
        .map_or((mantissa, ""), |parts| parts);
    if integer.is_empty() && fractional.is_empty() {
        return None;
    }
    if !integer.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let mut digits = format!("{integer}{fractional}");
    let first_nonzero = digits.find(|character: char| character != '0');
    digits = first_nonzero.map_or_else(|| "0".to_owned(), |index| digits[index..].to_owned());
    let fractional_len = i64::try_from(fractional.len()).ok()?;
    let power = exponent.checked_sub(fractional_len)?;
    Some(DecimalParts {
        negative: negative && digits != "0",
        digits,
        power,
    })
}

fn parse_signed_i64(value: &str) -> Option<i64> {
    if value.is_empty() {
        return None;
    }
    value.parse::<i64>().ok()
}

fn compare_decimal_magnitude(left: &DecimalParts, right: &DecimalParts) -> Option<Ordering> {
    let left_len = i64::try_from(left.digits.len())
        .ok()?
        .checked_add(left.power)?;
    let right_len = i64::try_from(right.digits.len())
        .ok()?
        .checked_add(right.power)?;
    match left_len.cmp(&right_len) {
        Ordering::Equal => {
            let width = left.digits.len().max(right.digits.len());
            for index in 0..width {
                let left_digit = left.digits.as_bytes().get(index).copied().unwrap_or(b'0');
                let right_digit = right.digits.as_bytes().get(index).copied().unwrap_or(b'0');
                match left_digit.cmp(&right_digit) {
                    Ordering::Equal => {}
                    ordering => return Some(ordering),
                }
            }
            Some(Ordering::Equal)
        }
        ordering => Some(ordering),
    }
}

#[derive(Debug, Clone)]
struct CsvField {
    value: String,
    quoted: bool,
}

fn parse_csv(bytes: &[u8], limits: KnowledgeLimits) -> Result<Vec<Vec<CsvField>>, D03Error> {
    str::from_utf8(bytes).map_err(structured_error)?;
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = Vec::new();
    let mut quoted = false;
    let mut in_quotes = false;
    let mut after_quote = false;
    let mut at_field_start = true;
    let mut index = 0_usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_quotes {
            if byte == b'"' {
                if bytes.get(index + 1) == Some(&b'"') {
                    field.push(b'"');
                    index += 2;
                    continue;
                }
                in_quotes = false;
                after_quote = true;
                index += 1;
                continue;
            }
            field.push(byte);
            index += 1;
            continue;
        }
        if after_quote && !matches!(byte, b',' | b'\r' | b'\n') {
            return Err(structured("CSV has characters after closing quote"));
        }
        match byte {
            b'"' if at_field_start => {
                quoted = true;
                in_quotes = true;
                at_field_start = false;
                index += 1;
            }
            b'"' => return Err(structured("CSV has quote inside unquoted field")),
            b',' => {
                record.push(finish_csv_field(&mut field, quoted, limits)?);
                quoted = false;
                after_quote = false;
                at_field_start = true;
                index += 1;
            }
            b'\n' | b'\r' => {
                record.push(finish_csv_field(&mut field, quoted, limits)?);
                push_csv_record(&mut records, &mut record, limits)?;
                quoted = false;
                after_quote = false;
                at_field_start = true;
                if byte == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
                    index += 2;
                } else {
                    index += 1;
                }
            }
            _ => {
                field.push(byte);
                at_field_start = false;
                index += 1;
            }
        }
    }
    if in_quotes {
        return Err(structured("CSV has unterminated quoted field"));
    }
    if !field.is_empty() || quoted || !record.is_empty() || !at_field_start {
        record.push(finish_csv_field(&mut field, quoted, limits)?);
        push_csv_record(&mut records, &mut record, limits)?;
    }
    while records
        .last()
        .is_some_and(|record| record.len() == 1 && record[0].value.is_empty() && !record[0].quoted)
    {
        records.pop();
    }
    Ok(records)
}

fn finish_csv_field(
    bytes: &mut Vec<u8>,
    quoted: bool,
    limits: KnowledgeLimits,
) -> Result<CsvField, D03Error> {
    if bytes.len() > limits.max_cell_bytes {
        return Err(structured("CSV cell byte limit exceeded"));
    }
    let value = String::from_utf8(std::mem::take(bytes)).map_err(structured_error)?;
    Ok(CsvField { value, quoted })
}

fn push_csv_record(
    records: &mut Vec<Vec<CsvField>>,
    record: &mut Vec<CsvField>,
    limits: KnowledgeLimits,
) -> Result<(), D03Error> {
    if records.len() > limits.max_rows {
        return Err(structured("CSV row limit exceeded"));
    }
    if record.len() > limits.max_columns {
        return Err(structured("CSV column limit exceeded"));
    }
    records.push(std::mem::take(record));
    Ok(())
}

fn validate_cell_text(value: &str, limits: KnowledgeLimits) -> Result<(), D03Error> {
    if value.len() > limits.max_cell_bytes || value.contains('\0') {
        return Err(structured("structured cell text is invalid"));
    }
    Ok(())
}

fn validate_name(value: &str, max: usize, field: &str) -> Result<(), D03Error> {
    if value.trim().is_empty() || value != value.trim() || value.len() > max || value.contains('\0')
    {
        return Err(structured(&format!("invalid {field}")));
    }
    Ok(())
}

fn structured(message: &str) -> D03Error {
    D03Error::StructuredData(message.to_owned())
}

fn structured_error(error: impl std::fmt::Display) -> D03Error {
    D03Error::StructuredData(error.to_string())
}
