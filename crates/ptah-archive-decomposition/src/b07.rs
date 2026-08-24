use crate::{AnchoredText, SearchMetadata};
use ptah_identifiers::EntityRef;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

/// Search domains delivered by B07 Search v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SearchDomain {
    /// User-facing filename or logical path.
    Filename,
    /// Evidence-derived metadata key/value material.
    Metadata,
    /// B03 anchored document text.
    DocumentText,
    /// Source-code symbol names.
    SourceSymbol,
    /// Log text.
    Log,
    /// Activity text/status/labels.
    Activity,
    /// Artifact type, purpose or labels.
    Artifact,
}

impl SearchDomain {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Filename => "filename",
            Self::Metadata => "metadata",
            Self::DocumentText => "document_text",
            Self::SourceSymbol => "source_symbol",
            Self::Log => "log",
            Self::Activity => "activity",
            Self::Artifact => "artifact",
        }
    }
}

/// Logical indexed-document class. One canonical source may contribute multiple classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SearchDocumentKind {
    /// Filename and B02 metadata projection.
    ObjectMetadata,
    /// Anchored document text projection.
    DocumentText,
    /// Source symbol projection.
    SourceSymbols,
    /// Log projection.
    Log,
    /// Activity projection.
    Activity,
    /// Artifact projection.
    Artifact,
}

impl SearchDocumentKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ObjectMetadata => "object_metadata",
            Self::DocumentText => "document_text",
            Self::SourceSymbols => "source_symbols",
            Self::Log => "log",
            Self::Activity => "activity",
            Self::Artifact => "artifact",
        }
    }
}

/// One searchable field copied from canonical or evidence-bound source truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchField {
    /// Search domain of this field.
    pub domain: SearchDomain,
    /// Optional stable key such as a metadata key, page or symbol class.
    pub key: Option<String>,
    /// Exact searchable value.
    pub value: String,
    /// Evidence/projection source that supplied this field.
    pub evidence_source: String,
}

/// Exact source binding retained by every indexed document and every search hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchSourceBinding {
    /// Workspace owning the canonical source.
    pub workspace_ref: EntityRef,
    /// Canonical source entity, such as Object, Activity, Artifact, View or log owner.
    pub source_ref: EntityRef,
    /// Exact canonical record revision of `source_ref` represented by this document.
    pub source_record_revision: u64,
    /// Exact Object Revision when the indexed material is byte/content derived.
    pub object_revision_ref: Option<EntityRef>,
}

/// One derived B07 index document. It is not canonical source truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchDocument {
    /// Exact source binding.
    pub source: SearchSourceBinding,
    /// Logical projection class.
    pub kind: SearchDocumentKind,
    /// Searchable copied fields.
    pub fields: Vec<SearchField>,
}

/// Resource and query limits for one B07 index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchLimits {
    /// Maximum documents retained by one rebuild.
    pub max_documents: usize,
    /// Maximum fields retained in one document.
    pub max_fields_per_document: usize,
    /// Maximum UTF-8 bytes retained in one field value.
    pub max_field_bytes: usize,
    /// Maximum UTF-8 bytes accepted in one query.
    pub max_query_bytes: usize,
    /// Maximum results returned by one query.
    pub max_results: usize,
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_documents: 100_000,
            max_fields_per_document: 4_096,
            max_field_bytes: 1024 * 1024,
            max_query_bytes: 8_192,
            max_results: 1_000,
        }
    }
}

/// Immutable identity of one derived index state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchIndexRevision {
    /// Monotonic local index revision. This is not a canonical Object Revision.
    pub revision: u64,
    /// Deterministic SHA-256 of canonicalized copied index content.
    pub content_sha256: String,
    /// Number of retained derived documents.
    pub document_count: usize,
}

/// Workspace-scoped B07 query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery {
    /// Workspace within which results may be returned.
    pub workspace_ref: EntityRef,
    /// Case-insensitive AND query text split on Unicode whitespace.
    pub text: String,
    /// Optional domain filter. Empty means all domains.
    pub domains: Vec<SearchDomain>,
    /// Maximum number of hits requested.
    pub limit: usize,
}

/// One exact field that matched a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchMatch {
    /// Matching search domain.
    pub domain: SearchDomain,
    /// Optional copied field key.
    pub key: Option<String>,
    /// Exact copied field value.
    pub value: String,
    /// Evidence/projection source retained from indexing.
    pub evidence_source: String,
}

/// Source-bound B07 result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    /// Exact source binding; callers never receive an index-local surrogate identity.
    pub source: SearchSourceBinding,
    /// Projection class that matched.
    pub kind: SearchDocumentKind,
    /// Number of matching fields in this document.
    pub score: u32,
    /// Exact matching copied fields.
    pub matches: Vec<SearchMatch>,
}

/// Search response bound to one exact derived index revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResponse {
    /// Exact index revision queried.
    pub index: SearchIndexRevision,
    /// Deterministically ordered source-bound hits.
    pub hits: Vec<SearchHit>,
}

/// B07 validation failures. Search/index state never upgrades canonical truth.
#[derive(Debug, Error)]
pub enum SearchError {
    /// At least one configured limit is zero.
    #[error("B07 search limits must all be greater than zero")]
    InvalidLimits,
    /// Workspace reference is not canonical `core.workspace`.
    #[error("B07 workspace reference must be core.workspace")]
    InvalidWorkspaceRef,
    /// Optional Object Revision binding is not canonical `object.revision`.
    #[error("B07 object revision binding must be object.revision")]
    InvalidObjectRevisionRef,
    /// Canonical source record revision must be positive.
    #[error("B07 source record revision must be positive")]
    InvalidSourceRecordRevision,
    /// A required copied field is empty or not canonical text.
    #[error("B07 required text is invalid: {0}")]
    InvalidText(&'static str),
    /// A copied field exceeds the configured bound.
    #[error("B07 copied field exceeds max_field_bytes")]
    FieldTooLarge,
    /// A document exceeds the configured field-count bound.
    #[error("B07 document exceeds max_fields_per_document")]
    TooManyFields,
    /// A rebuild exceeds the configured document bound.
    #[error("B07 rebuild exceeds max_documents")]
    TooManyDocuments,
    /// Two documents claim the same exact source binding and projection class.
    #[error("B07 duplicate indexed document identity")]
    DuplicateDocument,
    /// Query text is invalid or exceeds configured bounds.
    #[error("B07 query is invalid")]
    InvalidQuery,
    /// Query asks for an unsupported result count.
    #[error("B07 query limit exceeds max_results")]
    InvalidResultLimit,
    /// B03 text anchor does not bind the supplied exact Object Revision.
    #[error("B07 document text anchor does not match exact source Object Revision")]
    AnchorMismatch,
    /// Local index revision overflowed.
    #[error("B07 index revision overflow")]
    RevisionOverflow,
    /// Canonical reference serialization failed while deriving an index digest.
    #[error("B07 reference serialization failed: {0}")]
    Serialization(String),
}

/// Derived, rebuildable B07 search index. It owns no canonical Objects or ledger records.
pub struct SearchIndex {
    limits: SearchLimits,
    revision: u64,
    content_sha256: String,
    documents: Vec<SearchDocument>,
}

impl SearchIndex {
    /// Create an empty bounded search index.
    ///
    /// # Errors
    /// Returns [`SearchError::InvalidLimits`] when any bound is zero.
    pub fn new(limits: SearchLimits) -> Result<Self, SearchError> {
        validate_limits(limits)?;
        Ok(Self {
            limits,
            revision: 0,
            content_sha256: sha256_bytes(&[]),
            documents: Vec::new(),
        })
    }

    /// Return the current derived index identity.
    #[must_use]
    pub fn snapshot(&self) -> SearchIndexRevision {
        SearchIndexRevision {
            revision: self.revision,
            content_sha256: self.content_sha256.clone(),
            document_count: self.documents.len(),
        }
    }

    /// Replace all derived index content from exact source-bound documents.
    ///
    /// Input order is not index identity: fields/documents are canonicalized on private clones.
    /// Canonical callers remain unchanged.
    ///
    /// # Errors
    /// Fails closed for malformed bindings/fields, duplicate document identity, configured bounds,
    /// reference serialization failure or revision overflow.
    pub fn rebuild(
        &mut self,
        documents: &[SearchDocument],
    ) -> Result<SearchIndexRevision, SearchError> {
        if documents.len() > self.limits.max_documents {
            return Err(SearchError::TooManyDocuments);
        }
        let mut canonical = documents.to_vec();
        for document in &mut canonical {
            validate_document(document, self.limits)?;
            canonicalize_fields(&mut document.fields);
        }
        canonical.sort_by_key(document_key);
        if canonical
            .windows(2)
            .any(|window| document_key(&window[0]) == document_key(&window[1]))
        {
            return Err(SearchError::DuplicateDocument);
        }
        let digest = digest_documents(&canonical)?;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(SearchError::RevisionOverflow)?;
        self.documents = canonical;
        self.content_sha256 = digest;
        Ok(self.snapshot())
    }

    /// Delete all derived index content without touching any canonical source.
    ///
    /// # Errors
    /// Returns revision overflow if the local index generation cannot advance.
    pub fn clear(&mut self) -> Result<SearchIndexRevision, SearchError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(SearchError::RevisionOverflow)?;
        self.documents.clear();
        self.content_sha256 = sha256_bytes(&[]);
        Ok(self.snapshot())
    }

    /// Search one exact Workspace against one exact derived index revision.
    ///
    /// # Errors
    /// Fails closed for malformed Workspace/query/result limits.
    pub fn query(&self, query: &SearchQuery) -> Result<SearchResponse, SearchError> {
        validate_workspace(&query.workspace_ref)?;
        if query.limit == 0 || query.limit > self.limits.max_results {
            return Err(SearchError::InvalidResultLimit);
        }
        if query.text.trim().is_empty()
            || query.text != query.text.trim()
            || query.text.len() > self.limits.max_query_bytes
        {
            return Err(SearchError::InvalidQuery);
        }
        let terms: BTreeSet<String> = query
            .text
            .split_whitespace()
            .map(str::to_lowercase)
            .collect();
        if terms.is_empty() {
            return Err(SearchError::InvalidQuery);
        }
        let domains: BTreeSet<_> = query.domains.iter().copied().collect();
        let mut hits = Vec::new();
        for document in &self.documents {
            if document.source.workspace_ref != query.workspace_ref {
                continue;
            }
            let mut matches = Vec::new();
            for field in &document.fields {
                if !domains.is_empty() && !domains.contains(&field.domain) {
                    continue;
                }
                let haystack = match &field.key {
                    Some(key) => format!("{key} {}", field.value).to_lowercase(),
                    None => field.value.to_lowercase(),
                };
                if terms.iter().all(|term| haystack.contains(term)) {
                    matches.push(SearchMatch {
                        domain: field.domain,
                        key: field.key.clone(),
                        value: field.value.clone(),
                        evidence_source: field.evidence_source.clone(),
                    });
                }
            }
            if !matches.is_empty() {
                let score = u32::try_from(matches.len()).unwrap_or(u32::MAX);
                hits.push(SearchHit {
                    source: document.source.clone(),
                    kind: document.kind,
                    score,
                    matches,
                });
            }
        }
        hits.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| hit_key(left).cmp(&hit_key(right)))
        });
        hits.truncate(query.limit);
        Ok(SearchResponse {
            index: self.snapshot(),
            hits,
        })
    }
}

/// Build a filename/B02 metadata index document over one exact source record.
///
/// # Errors
/// Returns malformed-source/field errors. Final configured bounds are rechecked on rebuild.
pub fn filename_metadata_document(
    source: SearchSourceBinding,
    filename: Option<String>,
    metadata: &[SearchMetadata],
) -> Result<SearchDocument, SearchError> {
    validate_binding(&source)?;
    let mut fields = Vec::new();
    if let Some(filename) = filename {
        require_text(&filename, "filename")?;
        fields.push(SearchField {
            domain: SearchDomain::Filename,
            key: None,
            value: filename,
            evidence_source: "caller.filename".to_owned(),
        });
    }
    for item in metadata {
        require_text(&item.key, "metadata.key")?;
        require_text(&item.value, "metadata.value")?;
        require_text(&item.source, "metadata.source")?;
        let key = match &item.path {
            Some(path) => {
                require_text(path, "metadata.path")?;
                format!("{path}:{}", item.key)
            }
            None => item.key.clone(),
        };
        fields.push(SearchField {
            domain: SearchDomain::Metadata,
            key: Some(key),
            value: item.value.clone(),
            evidence_source: item.source.clone(),
        });
    }
    if fields.is_empty() {
        return Err(SearchError::InvalidText("filename/metadata"));
    }
    Ok(SearchDocument {
        source,
        kind: SearchDocumentKind::ObjectMetadata,
        fields,
    })
}

/// Build a B03 anchored-document-text search document.
///
/// # Errors
/// Fails if any text anchor is not bound to the exact supplied Object Revision.
pub fn document_text_search_document(
    source: SearchSourceBinding,
    spans: &[AnchoredText],
) -> Result<SearchDocument, SearchError> {
    validate_binding(&source)?;
    let expected = source
        .object_revision_ref
        .as_ref()
        .ok_or(SearchError::InvalidObjectRevisionRef)?;
    if spans.is_empty() {
        return Err(SearchError::InvalidText("document text"));
    }
    let mut fields = Vec::with_capacity(spans.len());
    for span in spans {
        if &span.anchor.source_revision_ref != expected {
            return Err(SearchError::AnchorMismatch);
        }
        require_text(&span.text, "document text")?;
        let key = span
            .anchor
            .page
            .map(|page| format!("page:{page}"))
            .or_else(|| span.anchor.byte_start.map(|start| format!("byte:{start}")));
        fields.push(SearchField {
            domain: SearchDomain::DocumentText,
            key,
            value: span.text.clone(),
            evidence_source: "b03.anchored_text".to_owned(),
        });
    }
    Ok(SearchDocument {
        source,
        kind: SearchDocumentKind::DocumentText,
        fields,
    })
}

/// Build an exact-revision source-symbol search document.
///
/// # Errors
/// Fails for malformed source binding or empty symbols.
pub fn source_symbol_search_document(
    source: SearchSourceBinding,
    symbols: &[String],
) -> Result<SearchDocument, SearchError> {
    multi_value_document(
        source,
        SearchDocumentKind::SourceSymbols,
        SearchDomain::SourceSymbol,
        "symbol",
        symbols,
        "source.symbol.adapter",
    )
}

/// Build a log search document.
///
/// # Errors
/// Fails for malformed source binding or empty log values.
pub fn log_search_document(
    source: SearchSourceBinding,
    values: &[String],
) -> Result<SearchDocument, SearchError> {
    multi_value_document(
        source,
        SearchDocumentKind::Log,
        SearchDomain::Log,
        "log",
        values,
        "log.adapter",
    )
}

/// Build an Activity search document.
///
/// # Errors
/// Fails for malformed source binding or empty Activity values.
pub fn activity_search_document(
    source: SearchSourceBinding,
    values: &[String],
) -> Result<SearchDocument, SearchError> {
    multi_value_document(
        source,
        SearchDocumentKind::Activity,
        SearchDomain::Activity,
        "activity",
        values,
        "activity.adapter",
    )
}

/// Build an Artifact search document.
///
/// # Errors
/// Fails for malformed source binding or empty Artifact values.
pub fn artifact_search_document(
    source: SearchSourceBinding,
    values: &[String],
) -> Result<SearchDocument, SearchError> {
    multi_value_document(
        source,
        SearchDocumentKind::Artifact,
        SearchDomain::Artifact,
        "artifact",
        values,
        "artifact.adapter",
    )
}

fn multi_value_document(
    source: SearchSourceBinding,
    kind: SearchDocumentKind,
    domain: SearchDomain,
    key: &str,
    values: &[String],
    evidence_source: &str,
) -> Result<SearchDocument, SearchError> {
    validate_binding(&source)?;
    if values.is_empty() {
        return Err(SearchError::InvalidText("search values"));
    }
    let mut fields = Vec::with_capacity(values.len());
    for value in values {
        require_text(value, "search value")?;
        fields.push(SearchField {
            domain,
            key: Some(key.to_owned()),
            value: value.clone(),
            evidence_source: evidence_source.to_owned(),
        });
    }
    Ok(SearchDocument {
        source,
        kind,
        fields,
    })
}

fn validate_limits(limits: SearchLimits) -> Result<(), SearchError> {
    if limits.max_documents == 0
        || limits.max_fields_per_document == 0
        || limits.max_field_bytes == 0
        || limits.max_query_bytes == 0
        || limits.max_results == 0
    {
        return Err(SearchError::InvalidLimits);
    }
    Ok(())
}

fn validate_document(document: &SearchDocument, limits: SearchLimits) -> Result<(), SearchError> {
    validate_binding(&document.source)?;
    if document.fields.is_empty() {
        return Err(SearchError::InvalidText("document fields"));
    }
    if document.fields.len() > limits.max_fields_per_document {
        return Err(SearchError::TooManyFields);
    }
    for field in &document.fields {
        if field.value.len() > limits.max_field_bytes {
            return Err(SearchError::FieldTooLarge);
        }
        require_text(&field.value, "field value")?;
        require_text(&field.evidence_source, "field evidence_source")?;
        if let Some(key) = &field.key {
            require_text(key, "field key")?;
        }
    }
    Ok(())
}

fn validate_binding(source: &SearchSourceBinding) -> Result<(), SearchError> {
    validate_workspace(&source.workspace_ref)?;
    if source.source_record_revision == 0 {
        return Err(SearchError::InvalidSourceRecordRevision);
    }
    if let Some(revision) = &source.object_revision_ref
        && revision.entity_kind.as_str() != "object.revision"
    {
        return Err(SearchError::InvalidObjectRevisionRef);
    }
    Ok(())
}

fn validate_workspace(workspace_ref: &EntityRef) -> Result<(), SearchError> {
    if workspace_ref.entity_kind.as_str() != "core.workspace" {
        return Err(SearchError::InvalidWorkspaceRef);
    }
    Ok(())
}

fn require_text(value: &str, field: &'static str) -> Result<(), SearchError> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(SearchError::InvalidText(field));
    }
    Ok(())
}

fn canonicalize_fields(fields: &mut [SearchField]) {
    fields.sort_by(|left, right| {
        left.domain
            .cmp(&right.domain)
            .then_with(|| left.key.cmp(&right.key))
            .then_with(|| left.value.cmp(&right.value))
            .then_with(|| left.evidence_source.cmp(&right.evidence_source))
    });
}

fn document_key(document: &SearchDocument) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        ref_key(&document.source.workspace_ref),
        ref_key(&document.source.source_ref),
        document.source.source_record_revision,
        document
            .source
            .object_revision_ref
            .as_ref()
            .map(ref_key)
            .unwrap_or_default(),
        document.kind.as_str()
    )
}

fn hit_key(hit: &SearchHit) -> String {
    format!(
        "{}|{}|{}|{}",
        ref_key(&hit.source.source_ref),
        hit.source.source_record_revision,
        hit.source
            .object_revision_ref
            .as_ref()
            .map(ref_key)
            .unwrap_or_default(),
        hit.kind.as_str()
    )
}

fn ref_key(reference: &EntityRef) -> String {
    serde_json::to_string(reference).unwrap_or_else(|_| "<invalid-ref>".to_owned())
}

fn digest_documents(documents: &[SearchDocument]) -> Result<String, SearchError> {
    let mut hasher = Sha256::new();
    hash_usize(&mut hasher, documents.len());
    for document in documents {
        hash_text(&mut hasher, &serialize_ref(&document.source.workspace_ref)?);
        hash_text(&mut hasher, &serialize_ref(&document.source.source_ref)?);
        hasher.update(document.source.source_record_revision.to_le_bytes());
        match &document.source.object_revision_ref {
            Some(reference) => {
                hasher.update([1]);
                hash_text(&mut hasher, &serialize_ref(reference)?);
            }
            None => hasher.update([0]),
        }
        hash_text(&mut hasher, document.kind.as_str());
        hash_usize(&mut hasher, document.fields.len());
        for field in &document.fields {
            hash_text(&mut hasher, field.domain.as_str());
            match &field.key {
                Some(key) => {
                    hasher.update([1]);
                    hash_text(&mut hasher, key);
                }
                None => hasher.update([0]),
            }
            hash_text(&mut hasher, &field.value);
            hash_text(&mut hasher, &field.evidence_source);
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn serialize_ref(reference: &EntityRef) -> Result<String, SearchError> {
    serde_json::to_string(reference).map_err(|error| SearchError::Serialization(error.to_string()))
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hash_usize(hasher, value.len());
    hasher.update(value.as_bytes());
}

fn hash_usize(hasher: &mut Sha256, value: usize) {
    hasher.update(u64::try_from(value).unwrap_or(u64::MAX).to_le_bytes());
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
