use crate::{D03Error, KnowledgeSourceRevision};
use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};

/// Exact source-local location supporting one D03 citation/result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnowledgeLocator {
    /// Exact half-open source byte range.
    ByteRange {
        /// First included byte offset.
        start: u64,
        /// First excluded byte offset.
        end_exclusive: u64,
    },
    /// Exact inclusive source line range.
    LineRange {
        /// First included one-based line.
        start: u64,
        /// Last included one-based line.
        end_inclusive: u64,
    },
    /// B03-style anchored document span.
    DocumentAnchor {
        /// Optional one-based page number.
        page: Option<u32>,
        /// Optional first included byte offset.
        byte_start: Option<u64>,
        /// Optional first excluded byte offset.
        byte_end_exclusive: Option<u64>,
    },
    /// Exact symbol name within one exact source revision.
    SourceSymbol {
        /// Exact source symbol text.
        symbol: String,
    },
    /// Firmware/package component identity.
    FirmwareComponent {
        /// Exact firmware component or manifest-entry name.
        component: String,
    },
    /// Exact partition byte range.
    PartitionRange {
        /// Optional exact partition name.
        name: Option<String>,
        /// First included partition byte offset.
        byte_start: u64,
        /// First excluded partition byte offset.
        byte_end_exclusive: u64,
    },
    /// Exact dataset cell.
    DatasetCell {
        /// Dataset table name.
        table: String,
        /// Zero-based snapshot row index.
        row: u64,
        /// Dataset column name.
        column: String,
    },
    /// Exact dataset row.
    DatasetRow {
        /// Dataset table name.
        table: String,
        /// Zero-based snapshot row index.
        row: u64,
    },
    /// Exact database cell in one captured snapshot.
    DatabaseCell {
        /// Database table name.
        table: String,
        /// Zero-based bounded result-row index.
        row: u64,
        /// Database result column name.
        column: String,
    },
    /// Exact database row in one captured snapshot.
    DatabaseRow {
        /// Database table name.
        table: String,
        /// Zero-based bounded result-row index.
        row: u64,
    },
}

/// Provenance-bound derived citation evidence. It is never source authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CitationEvidence {
    /// Exact source revision supporting this citation.
    pub source: KnowledgeSourceRevision,
    /// Exact source-local locator.
    pub locator: KnowledgeLocator,
    /// Mechanical extraction or query mechanism.
    pub mechanism: String,
    /// Optional additional evidence object or receipt.
    pub evidence_ref: Option<EntityRef>,
    /// Optional derived index revision.
    pub index_revision: Option<u64>,
    /// Optional deterministic derived-index digest.
    pub index_sha256: Option<String>,
    /// Optional query-run identity.
    pub query_run_ref: Option<EntityRef>,
    /// Always false; citation evidence is a derived View, not source authority.
    pub authoritative: bool,
}

impl CitationEvidence {
    /// Construct a mechanically valid, explicitly non-authoritative citation.
    ///
    /// # Errors
    /// Returns [`D03Error::InvalidCitationBinding`] for malformed mechanism/locator data.
    pub fn new(
        source: KnowledgeSourceRevision,
        locator: KnowledgeLocator,
        mechanism: &str,
        evidence_ref: Option<EntityRef>,
    ) -> Result<Self, D03Error> {
        require_text(mechanism, "mechanism")?;
        validate_locator(&locator)?;
        Ok(Self {
            source,
            locator,
            mechanism: mechanism.to_owned(),
            evidence_ref,
            index_revision: None,
            index_sha256: None,
            query_run_ref: None,
            authoritative: false,
        })
    }
}

fn validate_locator(locator: &KnowledgeLocator) -> Result<(), D03Error> {
    match locator {
        KnowledgeLocator::ByteRange {
            start,
            end_exclusive,
        } if end_exclusive <= start => Err(D03Error::InvalidCitationBinding("byte range")),
        KnowledgeLocator::LineRange {
            start,
            end_inclusive,
        } if *start == 0 || end_inclusive < start => {
            Err(D03Error::InvalidCitationBinding("line range"))
        }
        KnowledgeLocator::DocumentAnchor {
            page,
            byte_start,
            byte_end_exclusive,
        } => {
            if page.is_none() && byte_start.is_none() {
                return Err(D03Error::InvalidCitationBinding("document anchor"));
            }
            if let (Some(start), Some(end)) = (byte_start, byte_end_exclusive)
                && end <= start
            {
                return Err(D03Error::InvalidCitationBinding("document byte range"));
            }
            Ok(())
        }
        KnowledgeLocator::SourceSymbol { symbol } => require_text(symbol, "symbol"),
        KnowledgeLocator::FirmwareComponent { component } => require_text(component, "component"),
        KnowledgeLocator::PartitionRange {
            byte_start,
            byte_end_exclusive,
            ..
        } if byte_end_exclusive <= byte_start => {
            Err(D03Error::InvalidCitationBinding("partition range"))
        }
        KnowledgeLocator::DatasetCell { table, column, .. }
        | KnowledgeLocator::DatabaseCell { table, column, .. } => {
            require_text(table, "table")?;
            require_text(column, "column")
        }
        KnowledgeLocator::DatasetRow { table, .. }
        | KnowledgeLocator::DatabaseRow { table, .. } => require_text(table, "table"),
        _ => Ok(()),
    }
}

fn require_text(value: &str, field: &'static str) -> Result<(), D03Error> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(D03Error::InvalidCitationBinding(field));
    }
    Ok(())
}
