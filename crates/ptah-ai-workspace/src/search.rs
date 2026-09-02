//! D02-owned, non-authoritative façade over the current B07 derived search index.

use crate::{D02Error, WorkspaceReader};
use ptah_archive_decomposition::{
    AnchoredText, SearchDocument, SearchDocumentKind, SearchDomain, SearchError, SearchIndex,
    SearchLimits, SearchMetadata, SearchQuery, SearchSourceBinding, SourceAnchor,
    activity_search_document, artifact_search_document, document_text_search_document,
    filename_metadata_document, log_search_document, source_symbol_search_document,
};
use ptah_identifiers::EntityRef;

/// D02-owned mechanical failures from the derived search adapter.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceSearchFailure {
    /// Search resource/configuration bounds are invalid.
    #[error("D02 search configuration is invalid")]
    InvalidConfiguration,
    /// Canonical source or revision binding is invalid.
    #[error("D02 search source binding is invalid")]
    InvalidBinding,
    /// A copied search document is structurally invalid.
    #[error("D02 search document is invalid")]
    InvalidDocument,
    /// Query text or requested result bound is invalid.
    #[error("D02 search query is invalid")]
    InvalidQuery,
    /// A bounded search resource or revision limit was exceeded.
    #[error("D02 search capacity was exceeded")]
    CapacityExceeded,
    /// Derived index serialization failed.
    #[error("D02 search serialization failed")]
    Serialization,
}

/// D02-owned B07 resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceSearchLimits {
    /// Maximum documents retained by one rebuild.
    pub max_documents: usize,
    /// Maximum fields retained in one document.
    pub max_fields_per_document: usize,
    /// Maximum UTF-8 bytes retained in any field.
    pub max_field_bytes: usize,
    /// Maximum query bytes.
    pub max_query_bytes: usize,
    /// Maximum returned hits.
    pub max_results: usize,
}

impl Default for WorkspaceSearchLimits {
    fn default() -> Self {
        let limits = SearchLimits::default();
        Self {
            max_documents: limits.max_documents,
            max_fields_per_document: limits.max_fields_per_document,
            max_field_bytes: limits.max_field_bytes,
            max_query_bytes: limits.max_query_bytes,
            max_results: limits.max_results,
        }
    }
}

/// Exact source identity retained by every D02 search document and hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSearchSource {
    /// Workspace owning the canonical source.
    pub workspace_ref: EntityRef,
    /// Exact canonical source entity.
    pub source_ref: EntityRef,
    /// Exact canonical source record revision.
    pub source_record_revision: u64,
    /// Exact Object Revision where byte/content-derived.
    pub object_revision_ref: Option<EntityRef>,
}

/// D02-owned metadata field for filename/metadata indexing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSearchMetadata {
    /// Optional logical source path.
    pub path: Option<String>,
    /// Stable metadata key.
    pub key: String,
    /// Exact metadata value.
    pub value: String,
    /// Evidence source that supplied the value.
    pub source: String,
}

/// D02-owned anchored text span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSearchText {
    /// Exact extracted text.
    pub text: String,
    /// Inclusive byte start where known.
    pub byte_start: Option<u64>,
    /// Exclusive byte end where known.
    pub byte_end_exclusive: Option<u64>,
    /// One-based page where known.
    pub page: Option<u32>,
}

/// D02-owned source-bound search document input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceSearchDocument {
    /// Filename and metadata projection.
    FilenameMetadata {
        /// Exact canonical source binding.
        source: WorkspaceSearchSource,
        /// Optional filename.
        filename: Option<String>,
        /// Exact metadata fields.
        metadata: Vec<WorkspaceSearchMetadata>,
    },
    /// Exact Object-Revision-bound document text.
    DocumentText {
        /// Exact canonical source binding.
        source: WorkspaceSearchSource,
        /// Exact anchored spans.
        spans: Vec<WorkspaceSearchText>,
    },
    /// Exact-revision source symbols.
    SourceSymbols {
        /// Exact canonical source binding.
        source: WorkspaceSearchSource,
        /// Symbol values.
        values: Vec<String>,
    },
    /// Log values.
    Log {
        /// Exact canonical source binding.
        source: WorkspaceSearchSource,
        /// Log values.
        values: Vec<String>,
    },
    /// Activity values.
    Activity {
        /// Exact canonical source binding.
        source: WorkspaceSearchSource,
        /// Activity values.
        values: Vec<String>,
    },
    /// Artifact values.
    Artifact {
        /// Exact canonical source binding.
        source: WorkspaceSearchSource,
        /// Artifact values.
        values: Vec<String>,
    },
}

/// D02-owned query domain filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceSearchDomain {
    /// Filename.
    Filename,
    /// Metadata.
    Metadata,
    /// Document text.
    DocumentText,
    /// Source symbol.
    SourceSymbol,
    /// Log.
    Log,
    /// Activity.
    Activity,
    /// Artifact.
    Artifact,
}

/// Exact authority-gated D02 search request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSearchRequest {
    /// Caller identity.
    pub actor_ref: EntityRef,
    /// Workspace from which the caller is operating.
    pub source_workspace_ref: EntityRef,
    /// Workspace whose derived index may be searched.
    pub target_workspace_ref: EntityRef,
    /// Configured scope required at A06.
    pub required_scope: String,
    /// Optional exact Secure Grant.
    pub grant_ref: Option<EntityRef>,
    /// Exact caller query text.
    pub text: String,
    /// Optional mechanical domain filters.
    pub domains: Vec<WorkspaceSearchDomain>,
    /// Maximum hits requested.
    pub limit: usize,
}

/// D02-owned immutable identity for one derived index state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSearchIndexRevision {
    /// Monotonic derived B07 index revision.
    pub revision: u64,
    /// SHA-256 of canonicalized copied index content.
    pub content_sha256: String,
    /// Number of retained documents.
    pub document_count: usize,
}

/// D02-owned match field copied from one B07 hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSearchMatch {
    /// Mechanical search domain.
    pub domain: WorkspaceSearchDomain,
    /// Optional field key.
    pub key: Option<String>,
    /// Exact copied field value.
    pub value: String,
    /// Exact evidence-source label.
    pub evidence_source: String,
}

/// Source-bound D02 search hit. It is not an authority or truth decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSearchHit {
    /// Exact canonical source entity.
    pub source_ref: EntityRef,
    /// Exact canonical source record revision.
    pub source_record_revision: u64,
    /// Exact Object Revision where present.
    pub object_revision_ref: Option<EntityRef>,
    /// Mechanical projection class.
    pub document_kind: String,
    /// B07 mechanical match count.
    pub score: u32,
    /// Exact matching copied fields.
    pub matches: Vec<WorkspaceSearchMatch>,
}

/// D02 search response bound to one exact derived index revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSearchResponse {
    /// Exact derived index revision queried.
    pub index_revision: u64,
    /// Exact derived index content digest.
    pub index_sha256: String,
    /// Source-bound hits in B07 deterministic order.
    pub hits: Vec<WorkspaceSearchHit>,
    /// Always false: search ranking is not source authority.
    pub authoritative: bool,
}

/// D02-owned wrapper around B07. The underlying B07 type is not exposed publicly.
pub struct WorkspaceSearchIndex {
    inner: SearchIndex,
}

impl WorkspaceSearchIndex {
    /// Construct one bounded derived search index.
    ///
    /// # Errors
    /// Returns B07 limit validation errors.
    pub fn new(limits: WorkspaceSearchLimits) -> Result<Self, D02Error> {
        Ok(Self {
            inner: SearchIndex::new(SearchLimits {
                max_documents: limits.max_documents,
                max_fields_per_document: limits.max_fields_per_document,
                max_field_bytes: limits.max_field_bytes,
                max_query_bytes: limits.max_query_bytes,
                max_results: limits.max_results,
            })
            .map_err(|error| map_search_error(&error))?,
        })
    }

    /// Rebuild from exact source-bound D02 documents.
    ///
    /// # Errors
    /// Returns B07 validation/resource errors.
    pub fn rebuild(
        &mut self,
        documents: &[WorkspaceSearchDocument],
    ) -> Result<WorkspaceSearchIndexRevision, D02Error> {
        let mapped: Result<Vec<SearchDocument>, D02Error> =
            documents.iter().map(map_document).collect();
        let revision = self
            .inner
            .rebuild(&mapped?)
            .map_err(|error| map_search_error(&error))?;
        Ok(WorkspaceSearchIndexRevision {
            revision: revision.revision,
            content_sha256: revision.content_sha256,
            document_count: revision.document_count,
        })
    }
}

/// Search one exact Workspace after configured A06 access succeeds.
///
/// # Errors
/// Access denial occurs before B07 query execution; B07 query errors remain mechanical.
pub fn query_workspace_index(
    reader: &WorkspaceReader,
    index: &WorkspaceSearchIndex,
    request: &WorkspaceSearchRequest,
) -> Result<WorkspaceSearchResponse, D02Error> {
    reader.authorize_workspace_scope(
        &request.actor_ref,
        &request.source_workspace_ref,
        &request.target_workspace_ref,
        &request.required_scope,
        request.grant_ref.as_ref(),
    )?;
    let response = index
        .inner
        .query(&SearchQuery {
            workspace_ref: request.target_workspace_ref.clone(),
            text: request.text.clone(),
            domains: request.domains.iter().copied().map(map_domain).collect(),
            limit: request.limit,
        })
        .map_err(|error| map_search_error(&error))?;
    Ok(WorkspaceSearchResponse {
        index_revision: response.index.revision,
        index_sha256: response.index.content_sha256,
        hits: response
            .hits
            .into_iter()
            .map(|hit| WorkspaceSearchHit {
                source_ref: hit.source.source_ref,
                source_record_revision: hit.source.source_record_revision,
                object_revision_ref: hit.source.object_revision_ref,
                document_kind: document_kind(hit.kind).to_owned(),
                score: hit.score,
                matches: hit
                    .matches
                    .into_iter()
                    .map(|item| WorkspaceSearchMatch {
                        domain: unmap_domain(item.domain),
                        key: item.key,
                        value: item.value,
                        evidence_source: item.evidence_source,
                    })
                    .collect(),
            })
            .collect(),
        authoritative: false,
    })
}

fn map_source(source: &WorkspaceSearchSource) -> SearchSourceBinding {
    SearchSourceBinding {
        workspace_ref: source.workspace_ref.clone(),
        source_ref: source.source_ref.clone(),
        source_record_revision: source.source_record_revision,
        object_revision_ref: source.object_revision_ref.clone(),
    }
}

fn map_document(document: &WorkspaceSearchDocument) -> Result<SearchDocument, D02Error> {
    Ok(match document {
        WorkspaceSearchDocument::FilenameMetadata {
            source,
            filename,
            metadata,
        } => filename_metadata_document(
            map_source(source),
            filename.clone(),
            &metadata
                .iter()
                .map(|item| SearchMetadata {
                    path: item.path.clone(),
                    key: item.key.clone(),
                    value: item.value.clone(),
                    source: item.source.clone(),
                })
                .collect::<Vec<_>>(),
        )
        .map_err(|error| map_search_error(&error))?,
        WorkspaceSearchDocument::DocumentText { source, spans } => {
            let revision = source
                .object_revision_ref
                .clone()
                .ok_or(D02Error::RecordClassMismatch)?;
            document_text_search_document(
                map_source(source),
                &spans
                    .iter()
                    .map(|span| AnchoredText {
                        text: span.text.clone(),
                        anchor: SourceAnchor {
                            source_revision_ref: revision.clone(),
                            byte_start: span.byte_start,
                            byte_end_exclusive: span.byte_end_exclusive,
                            page: span.page,
                        },
                    })
                    .collect::<Vec<_>>(),
            )
            .map_err(|error| map_search_error(&error))?
        }
        WorkspaceSearchDocument::SourceSymbols { source, values } => {
            source_symbol_search_document(map_source(source), values)
                .map_err(|error| map_search_error(&error))?
        }
        WorkspaceSearchDocument::Log { source, values } => {
            log_search_document(map_source(source), values)
                .map_err(|error| map_search_error(&error))?
        }
        WorkspaceSearchDocument::Activity { source, values } => {
            activity_search_document(map_source(source), values)
                .map_err(|error| map_search_error(&error))?
        }
        WorkspaceSearchDocument::Artifact { source, values } => {
            artifact_search_document(map_source(source), values)
                .map_err(|error| map_search_error(&error))?
        }
    })
}

fn map_search_error(error: &SearchError) -> D02Error {
    let failure = match error {
        SearchError::InvalidLimits => WorkspaceSearchFailure::InvalidConfiguration,
        SearchError::InvalidWorkspaceRef
        | SearchError::InvalidObjectRevisionRef
        | SearchError::InvalidSourceRecordRevision
        | SearchError::MissingObjectRevisionBinding
        | SearchError::AnchorMismatch => WorkspaceSearchFailure::InvalidBinding,
        SearchError::InvalidText(_)
        | SearchError::FieldTooLarge
        | SearchError::InvalidDocumentDomain
        | SearchError::DuplicateDocument => WorkspaceSearchFailure::InvalidDocument,
        SearchError::InvalidQuery | SearchError::InvalidResultLimit => {
            WorkspaceSearchFailure::InvalidQuery
        }
        SearchError::TooManyFields
        | SearchError::TooManyDocuments
        | SearchError::RevisionOverflow => WorkspaceSearchFailure::CapacityExceeded,
        SearchError::Serialization(_) => WorkspaceSearchFailure::Serialization,
    };
    D02Error::Search(failure)
}

const fn map_domain(domain: WorkspaceSearchDomain) -> SearchDomain {
    match domain {
        WorkspaceSearchDomain::Filename => SearchDomain::Filename,
        WorkspaceSearchDomain::Metadata => SearchDomain::Metadata,
        WorkspaceSearchDomain::DocumentText => SearchDomain::DocumentText,
        WorkspaceSearchDomain::SourceSymbol => SearchDomain::SourceSymbol,
        WorkspaceSearchDomain::Log => SearchDomain::Log,
        WorkspaceSearchDomain::Activity => SearchDomain::Activity,
        WorkspaceSearchDomain::Artifact => SearchDomain::Artifact,
    }
}

const fn unmap_domain(domain: SearchDomain) -> WorkspaceSearchDomain {
    match domain {
        SearchDomain::Filename => WorkspaceSearchDomain::Filename,
        SearchDomain::Metadata => WorkspaceSearchDomain::Metadata,
        SearchDomain::DocumentText => WorkspaceSearchDomain::DocumentText,
        SearchDomain::SourceSymbol => WorkspaceSearchDomain::SourceSymbol,
        SearchDomain::Log => WorkspaceSearchDomain::Log,
        SearchDomain::Activity => WorkspaceSearchDomain::Activity,
        SearchDomain::Artifact => WorkspaceSearchDomain::Artifact,
    }
}

const fn document_kind(kind: SearchDocumentKind) -> &'static str {
    match kind {
        SearchDocumentKind::ObjectMetadata => "object_metadata",
        SearchDocumentKind::DocumentText => "document_text",
        SearchDocumentKind::SourceSymbols => "source_symbols",
        SearchDocumentKind::Log => "log",
        SearchDocumentKind::Activity => "activity",
        SearchDocumentKind::Artifact => "artifact",
    }
}
