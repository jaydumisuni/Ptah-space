use crate::{CitationEvidence, D03Error, KnowledgeLimits, KnowledgeSourceRevision};
use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
