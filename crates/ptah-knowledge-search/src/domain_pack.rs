use crate::{
    CellValue, CitationEvidence, D03Error, KnowledgeLimits, KnowledgeResultSet,
    KnowledgeSourceRevision,
};
use ptah_identifiers::EntityRef;
use ptah_workspace::WorkspaceStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Workspace-reference resolution for caller-selected D03 queries.
/// Knights/trusted ingress owns admission, not Ptah's query provider.
pub struct KnowledgeQueryAuthority<'a> {
    workspace: &'a WorkspaceStore,
}

impl<'a> KnowledgeQueryAuthority<'a> {
    /// Bind D03 workspace integrity checks to one existing A06 store.
    #[must_use]
    pub fn new(workspace: &'a WorkspaceStore) -> Self {
        Self { workspace }
    }

    /// Resolve explicit Workspace identities without demanding a second Ptah
    /// owner membership, cross-workspace Grant, or per-tool approval.
    /// Caller-selected scope and actor fields are compatibility metadata only.
    ///
    /// # Errors
    /// Returns a mechanical error for invalid or missing Workspace records.
    pub fn authorize(
        &self,
        _actor_ref: &EntityRef,
        source_workspace_ref: &EntityRef,
        target_workspace_ref: &EntityRef,
        _required_scope: &str,
        _grant_ref: Option<&EntityRef>,
    ) -> Result<(), D03Error> {
        if source_workspace_ref.entity_kind.as_str() != "core.workspace"
            || target_workspace_ref.entity_kind.as_str() != "core.workspace"
        {
            return Err(D03Error::WorkspaceAdapter(
                "workspace references must use core.workspace kind".to_owned(),
            ));
        }
        for reference in [source_workspace_ref, target_workspace_ref] {
            let found = self.workspace.workspace(reference.entity_id).map_err(|_| {
                D03Error::WorkspaceAdapter("workspace not found or invalid".to_owned())
            })?;
            if found.workspace_ref != *reference {
                return Err(D03Error::WorkspaceAdapter(
                    "workspace reference inconsistent with durable record".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Table-oriented derived View over one exact D03 result set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultTableView {
    /// Stable output column labels.
    pub columns: Vec<String>,
    /// Typed rows without changing source truth.
    pub rows: Vec<Vec<CellValue>>,
    /// Citation matrix aligned exactly with `rows` and `columns`.
    pub citations: Vec<Vec<CitationEvidence>>,
    /// Mechanical completeness inherited from the query result.
    pub complete: bool,
    /// Always false: visualization is a derived View.
    pub authoritative: bool,
}

/// Deterministic caller-requested export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// One deterministic JSON document.
    Json,
    /// One deterministic JSON value per line.
    JsonLines,
    /// UTF-8 comma-separated values with LF line endings.
    Csv,
}

/// Provenance-bound derived export bytes. This is deliberately not an A07 Artifact identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportBundle {
    /// Exact deterministic export bytes.
    pub bytes: Vec<u8>,
    /// Lowercase SHA-256 of `bytes`.
    pub sha256: String,
    /// Stable media type for the chosen format.
    pub media_type: String,
    /// Exact source revisions represented in the export.
    pub source_refs: Vec<KnowledgeSourceRevision>,
    /// Exact query-plan digest inherited from the result.
    pub query_plan_sha256: String,
    /// Always false: an export is a derived output.
    pub authoritative: bool,
}

/// Produce a table-oriented derived View without changing result/citation truth.
///
/// # Errors
/// Rejects authoritative or structurally inconsistent result sets.
pub fn visualize(result: &KnowledgeResultSet) -> Result<ResultTableView, D03Error> {
    validate_result_shape(result)?;
    Ok(ResultTableView {
        columns: result.columns.clone(),
        rows: result.rows.iter().map(|row| row.values.clone()).collect(),
        citations: result
            .rows
            .iter()
            .map(|row| row.citations.clone())
            .collect(),
        complete: result.complete,
        authoritative: false,
    })
}

/// Export one source-bound derived result deterministically.
///
/// # Errors
/// Rejects malformed result shape, unsupported cell encodings or outputs beyond `max_export_bytes`.
pub fn export(
    result: &KnowledgeResultSet,
    format: ExportFormat,
    limits: KnowledgeLimits,
) -> Result<ExportBundle, D03Error> {
    limits.validate()?;
    let view = visualize(result)?;
    let (bytes, media_type) = match format {
        ExportFormat::Json => (export_json(&view)?, "application/json"),
        ExportFormat::JsonLines => (export_json_lines(&view)?, "application/x-ndjson"),
        ExportFormat::Csv => (export_csv(&view)?, "text/csv; charset=utf-8"),
    };
    if bytes.len() > limits.max_export_bytes {
        return Err(D03Error::Export("export byte limit exceeded".to_owned()));
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(ExportBundle {
        bytes,
        sha256: format!("{:x}", hasher.finalize()),
        media_type: media_type.to_owned(),
        source_refs: result.source_refs.clone(),
        query_plan_sha256: result.query_plan_sha256.clone(),
        authoritative: false,
    })
}

fn validate_result_shape(result: &KnowledgeResultSet) -> Result<(), D03Error> {
    if result.authoritative {
        return Err(D03Error::Export(
            "derived result cannot be authoritative".to_owned(),
        ));
    }
    if result.columns.is_empty() {
        return Err(D03Error::Export("result has no columns".to_owned()));
    }
    if result.query_plan_sha256.len() != 64
        || !result
            .query_plan_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(D03Error::Export("invalid query-plan digest".to_owned()));
    }
    for row in &result.rows {
        if row.values.len() != result.columns.len() || row.citations.len() != result.columns.len() {
            return Err(D03Error::Export("result row shape mismatch".to_owned()));
        }
        if row.citations.iter().any(|citation| citation.authoritative) {
            return Err(D03Error::Export(
                "citation cannot be authoritative".to_owned(),
            ));
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct JsonExport<'a> {
    columns: &'a [String],
    rows: &'a [Vec<CellValue>],
}

fn export_json(view: &ResultTableView) -> Result<Vec<u8>, D03Error> {
    serde_json::to_vec(&JsonExport {
        columns: &view.columns,
        rows: &view.rows,
    })
    .map_err(|error| D03Error::Export(error.to_string()))
}

fn export_json_lines(view: &ResultTableView) -> Result<Vec<u8>, D03Error> {
    let mut output = Vec::new();
    for row in &view.rows {
        let encoded =
            serde_json::to_vec(row).map_err(|error| D03Error::Export(error.to_string()))?;
        output.extend_from_slice(&encoded);
        output.push(b'\n');
    }
    Ok(output)
}

fn export_csv(view: &ResultTableView) -> Result<Vec<u8>, D03Error> {
    let mut output = String::new();
    write_csv_row(&mut output, &view.columns);
    for row in &view.rows {
        let values = row
            .iter()
            .map(csv_cell)
            .collect::<Result<Vec<_>, D03Error>>()?;
        write_csv_row(&mut output, &values);
    }
    Ok(output.into_bytes())
}

fn write_csv_row(output: &mut String, values: &[String]) {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        if value.contains([',', '"', '\n', '\r']) {
            output.push('"');
            for character in value.chars() {
                if character == '"' {
                    output.push('"');
                }
                output.push(character);
            }
            output.push('"');
        } else {
            output.push_str(value);
        }
    }
    output.push('\n');
}

fn csv_cell(value: &CellValue) -> Result<String, D03Error> {
    match value {
        CellValue::Null => Ok(String::new()),
        CellValue::Boolean(value) => Ok(value.to_string()),
        CellValue::Integer(value) => Ok(value.to_string()),
        CellValue::Decimal(value) => {
            if value.contains([',', '"', '\n', '\r', '\0']) {
                return Err(D03Error::Export("invalid decimal export value".to_owned()));
            }
            Ok(value.clone())
        }
        CellValue::Text(value) => {
            if value.contains('\0') {
                return Err(D03Error::Export("text export contains NUL".to_owned()));
            }
            Ok(value.clone())
        }
        CellValue::BytesDigest { sha256, size } => Ok(format!("sha256:{sha256}:{size}")),
    }
}
