#![forbid(unsafe_code)]
//! D03 Knowledge, Data and Search v2 neutral derived-query substrate.

mod adapters;
mod error;
mod evidence;
mod index;
mod query;
mod source;

pub use error::D03Error;
pub use evidence::{CitationEvidence, KnowledgeLocator};
pub use index::{
    AnchoredTextInput, KnowledgeField, KnowledgeIndex, KnowledgeIndexRevision,
    KnowledgeSearchDocument,
};
pub use query::{
    KnowledgeResultRow, KnowledgeResultSet, KnowledgeSearchDomain, KnowledgeTextQuery,
    KnowledgeValue,
};
pub use source::{
    KnowledgeSourceClass, KnowledgeSourceRevision, KnowledgeSourceRevisionInput,
    require_knowledge_schema, validate_current_source,
};

/// Bounded D03 resource policy. Exceeding a bound fails closed rather than silently truncating input truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnowledgeLimits {
    /// Maximum source revisions admitted into one derived index.
    pub max_sources: usize,
    /// Maximum derived searchable fields per source.
    pub max_fields_per_source: usize,
    /// Maximum UTF-8 bytes in one copied field.
    pub max_field_bytes: usize,
    /// Maximum UTF-8 bytes in one textual query.
    pub max_query_bytes: usize,
    /// Maximum rows or hits returned by one query.
    pub max_results: usize,
    /// Maximum tables admitted into one structured snapshot.
    pub max_tables: usize,
    /// Maximum columns admitted per table.
    pub max_columns: usize,
    /// Maximum rows admitted or retained by one bounded operation.
    pub max_rows: usize,
    /// Maximum bytes retained inline for one cell value.
    pub max_cell_bytes: usize,
    /// Maximum source bytes accepted by one ingestion operation.
    pub max_input_bytes: usize,
    /// Maximum joins in one relational query plan.
    pub max_joins: usize,
    /// Maximum predicate nodes in one query plan.
    pub max_predicates: usize,
    /// Maximum projection items in one query.
    pub max_projection_items: usize,
    /// Maximum bytes in one derived export bundle.
    pub max_export_bytes: usize,
}

impl Default for KnowledgeLimits {
    fn default() -> Self {
        Self {
            max_sources: 100_000,
            max_fields_per_source: 4_096,
            max_field_bytes: 1024 * 1024,
            max_query_bytes: 8_192,
            max_results: 1_000,
            max_tables: 1_024,
            max_columns: 4_096,
            max_rows: 1_000_000,
            max_cell_bytes: 1024 * 1024,
            max_input_bytes: 256 * 1024 * 1024,
            max_joins: 16,
            max_predicates: 256,
            max_projection_items: 1_024,
            max_export_bytes: 512 * 1024 * 1024,
        }
    }
}

impl KnowledgeLimits {
    /// Validate that every configured bound is positive.
    ///
    /// # Errors
    /// Returns [`D03Error::InvalidLimits`] if any bound is zero.
    pub fn validate(self) -> Result<(), D03Error> {
        let values = [
            self.max_sources,
            self.max_fields_per_source,
            self.max_field_bytes,
            self.max_query_bytes,
            self.max_results,
            self.max_tables,
            self.max_columns,
            self.max_rows,
            self.max_cell_bytes,
            self.max_input_bytes,
            self.max_joins,
            self.max_predicates,
            self.max_projection_items,
            self.max_export_bytes,
        ];
        if values.contains(&0) {
            return Err(D03Error::InvalidLimits);
        }
        Ok(())
    }
}
