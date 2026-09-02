use ptah_knowledge_search::{
    AggregateKind, CellValue, D03Error, JoinKind, KnowledgeLimits, RelationalExpr,
    RelationalPredicate, RelationalQueryPlan,
};
use rusqlite::types::Value;

/// One validated, parameterized, read-only SELECT statement compiled from a D03 typed plan.
#[derive(Debug, Clone)]
pub struct CompiledSelect {
    sql: String,
    params: Vec<Value>,
    columns: Vec<String>,
}

impl CompiledSelect {
    /// Inspect the single generated SELECT statement. Callers still cannot submit raw SQL.
    #[must_use]
    pub fn sql(&self) -> &str {
        &self.sql
    }

    pub(crate) fn params(&self) -> &[Value] {
        &self.params
    }

    pub(crate) fn columns(&self) -> &[String] {
        &self.columns
    }
}

pub(crate) fn compile_select(
    plan: &RelationalQueryPlan,
    limits: KnowledgeLimits,
) -> Result<CompiledSelect, D03Error> {
    plan.validate(limits)?;
    let mut compiler = Compiler {
        sql: String::new(),
        params: Vec::new(),
    };
    let columns = compiler.compile_projection(plan)?;
    compiler.compile_from_and_joins(plan)?;
    compiler.compile_tail(plan)?;
    if compiler.sql.contains(';') || !compiler.sql.starts_with("SELECT ") {
        return Err(D03Error::InvalidRelationalPlan(
            "compiled statement is not one SELECT".to_owned(),
        ));
    }
    Ok(CompiledSelect {
        sql: compiler.sql,
        params: compiler.params,
        columns,
    })
}

struct Compiler {
    sql: String,
    params: Vec<Value>,
}

impl Compiler {
    fn compile_projection(&mut self, plan: &RelationalQueryPlan) -> Result<Vec<String>, D03Error> {
        self.sql.push_str("SELECT ");
        let mut columns = Vec::with_capacity(plan.projection.len());
        for (index, item) in plan.projection.iter().enumerate() {
            if index > 0 {
                self.sql.push_str(", ");
            }
            let mut expr = String::new();
            self.compile_expr_into(&item.expr, &mut expr)?;
            if let Some(aggregate) = item.aggregate {
                self.sql.push_str(aggregate_function(aggregate));
                self.sql.push('(');
                self.sql.push_str(&expr);
                self.sql.push(')');
            } else {
                self.sql.push_str(&expr);
            }
            let name = item
                .alias
                .clone()
                .unwrap_or_else(|| output_name(&item.expr, item.aggregate, index));
            self.sql.push_str(" AS ");
            self.sql.push_str(&quote_identifier(&name)?);
            columns.push(name);
        }
        Ok(columns)
    }

    fn compile_from_and_joins(&mut self, plan: &RelationalQueryPlan) -> Result<(), D03Error> {
        self.sql.push_str(" FROM ");
        self.sql.push_str(&quote_identifier(&plan.from.name)?);
        if let Some(alias) = &plan.from.alias {
            self.sql.push_str(" AS ");
            self.sql.push_str(&quote_identifier(alias)?);
        }
        for join in &plan.joins {
            self.sql.push(' ');
            self.sql.push_str(match join.kind {
                JoinKind::Inner => "INNER JOIN ",
                JoinKind::Left => "LEFT JOIN ",
            });
            self.sql.push_str(&quote_identifier(&join.table.name)?);
            if let Some(alias) = &join.table.alias {
                self.sql.push_str(" AS ");
                self.sql.push_str(&quote_identifier(alias)?);
            }
            self.sql.push_str(" ON ");
            self.compile_predicate(&join.on)?;
        }
        Ok(())
    }

    fn compile_tail(&mut self, plan: &RelationalQueryPlan) -> Result<(), D03Error> {
        if let Some(predicate) = &plan.predicate {
            self.sql.push_str(" WHERE ");
            self.compile_predicate(predicate)?;
        }
        if !plan.group_by.is_empty() {
            self.sql.push_str(" GROUP BY ");
            for (index, column) in plan.group_by.iter().enumerate() {
                if index > 0 {
                    self.sql.push_str(", ");
                }
                self.sql.push_str(&qualified_column(column)?);
            }
        }
        if !plan.order.is_empty() {
            self.sql.push_str(" ORDER BY ");
            for (index, order) in plan.order.iter().enumerate() {
                if index > 0 {
                    self.sql.push_str(", ");
                }
                let mut expr = String::new();
                self.compile_expr_into(&order.expr, &mut expr)?;
                self.sql.push_str(&expr);
                self.sql
                    .push_str(if order.descending { " DESC" } else { " ASC" });
            }
        }
        let fetch_limit = plan
            .limit
            .checked_add(1)
            .ok_or_else(|| D03Error::InvalidRelationalPlan("limit overflow".to_owned()))?;
        let limit = i64::try_from(fetch_limit)
            .map_err(|_| D03Error::InvalidRelationalPlan("limit overflow".to_owned()))?;
        let offset = i64::try_from(plan.offset)
            .map_err(|_| D03Error::InvalidRelationalPlan("offset overflow".to_owned()))?;
        let limit_placeholder = self.push_param(Value::Integer(limit));
        let offset_placeholder = self.push_param(Value::Integer(offset));
        self.sql.push_str(" LIMIT ");
        self.sql.push_str(&limit_placeholder);
        self.sql.push_str(" OFFSET ");
        self.sql.push_str(&offset_placeholder);
        Ok(())
    }

    fn compile_expr_into(
        &mut self,
        expr: &RelationalExpr,
        output: &mut String,
    ) -> Result<(), D03Error> {
        match expr {
            RelationalExpr::Column(column) => output.push_str(&qualified_column(column)?),
            RelationalExpr::Value(value) => {
                let parameter = self.push_param(sqlite_value(value)?);
                output.push_str(&parameter);
            }
        }
        Ok(())
    }

    fn compile_predicate(&mut self, predicate: &RelationalPredicate) -> Result<(), D03Error> {
        match predicate {
            RelationalPredicate::Eq(left, right) => self.binary(left, " = ", right),
            RelationalPredicate::Ne(left, right) => self.binary(left, " <> ", right),
            RelationalPredicate::Lt(left, right) => self.binary(left, " < ", right),
            RelationalPredicate::Le(left, right) => self.binary(left, " <= ", right),
            RelationalPredicate::Gt(left, right) => self.binary(left, " > ", right),
            RelationalPredicate::Ge(left, right) => self.binary(left, " >= ", right),
            RelationalPredicate::IsNull(column) => {
                self.sql.push_str(&qualified_column(column)?);
                self.sql.push_str(" IS NULL");
                Ok(())
            }
            RelationalPredicate::IsNotNull(column) => {
                self.sql.push_str(&qualified_column(column)?);
                self.sql.push_str(" IS NOT NULL");
                Ok(())
            }
            RelationalPredicate::In(column, values) => {
                self.sql.push_str(&qualified_column(column)?);
                self.sql.push_str(" IN (");
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        self.sql.push_str(", ");
                    }
                    let parameter = self.push_param(sqlite_value(value)?);
                    self.sql.push_str(&parameter);
                }
                self.sql.push(')');
                Ok(())
            }
            RelationalPredicate::And(children) => self.boolean_group(" AND ", children),
            RelationalPredicate::Or(children) => self.boolean_group(" OR ", children),
        }
    }

    fn binary(
        &mut self,
        left: &RelationalExpr,
        operator: &str,
        right: &RelationalExpr,
    ) -> Result<(), D03Error> {
        let mut left_sql = String::new();
        let mut right_sql = String::new();
        self.compile_expr_into(left, &mut left_sql)?;
        self.compile_expr_into(right, &mut right_sql)?;
        self.sql.push_str(&left_sql);
        self.sql.push_str(operator);
        self.sql.push_str(&right_sql);
        Ok(())
    }

    fn boolean_group(
        &mut self,
        operator: &str,
        children: &[RelationalPredicate],
    ) -> Result<(), D03Error> {
        self.sql.push('(');
        for (index, child) in children.iter().enumerate() {
            if index > 0 {
                self.sql.push_str(operator);
            }
            self.compile_predicate(child)?;
        }
        self.sql.push(')');
        Ok(())
    }

    fn push_param(&mut self, value: Value) -> String {
        self.params.push(value);
        format!("?{}", self.params.len())
    }
}

fn quote_identifier(value: &str) -> Result<String, D03Error> {
    validate_identifier(value)?;
    Ok(format!("\"{value}\""))
}

fn qualified_column(column: &ptah_knowledge_search::ColumnRef) -> Result<String, D03Error> {
    let quoted = quote_identifier(&column.column)?;
    if let Some(table) = &column.table {
        Ok(format!("{}.{}", quote_identifier(table)?, quoted))
    } else {
        Ok(quoted)
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

fn aggregate_function(aggregate: AggregateKind) -> &'static str {
    match aggregate {
        AggregateKind::Count => "COUNT",
        AggregateKind::Sum => "SUM",
        AggregateKind::Min => "MIN",
        AggregateKind::Max => "MAX",
        AggregateKind::Avg => "AVG",
    }
}

fn output_name(expr: &RelationalExpr, aggregate: Option<AggregateKind>, index: usize) -> String {
    let base = match expr {
        RelationalExpr::Column(column) => column.column.clone(),
        RelationalExpr::Value(_) => format!("value_{}", index + 1),
    };
    match aggregate {
        Some(AggregateKind::Count) => format!("count_{base}"),
        Some(AggregateKind::Sum) => format!("sum_{base}"),
        Some(AggregateKind::Min) => format!("min_{base}"),
        Some(AggregateKind::Max) => format!("max_{base}"),
        Some(AggregateKind::Avg) => format!("avg_{base}"),
        None => base,
    }
}

fn sqlite_value(value: &CellValue) -> Result<Value, D03Error> {
    match value {
        CellValue::Null => Ok(Value::Null),
        CellValue::Boolean(value) => Ok(Value::Integer(i64::from(*value))),
        CellValue::Integer(value) => Ok(Value::Integer(*value)),
        CellValue::Decimal(value) => value
            .parse::<f64>()
            .map(Value::Real)
            .map_err(|_| D03Error::InvalidRelationalPlan("invalid decimal literal".to_owned())),
        CellValue::Text(value) => Ok(Value::Text(value.clone())),
        CellValue::BytesDigest { .. } => Err(D03Error::InvalidRelationalPlan(
            "bytes digest is evidence, not a SQLite literal".to_owned(),
        )),
    }
}
