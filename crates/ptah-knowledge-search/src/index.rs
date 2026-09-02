use crate::adapters::b07::{B07Adapter, B07ProjectionKind};
use crate::{
    CitationEvidence, D03Error, KnowledgeLimits, KnowledgeLocator, KnowledgeResultRow,
    KnowledgeResultSet, KnowledgeSearchDomain, KnowledgeSourceRevision, KnowledgeTextQuery,
    KnowledgeValue,
};
use ptah_identifiers::EntityRef;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// One D03-owned searchable field copied from exact source/evidence truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeField {
    domain: KnowledgeSearchDomain,
    key: Option<String>,
    value: String,
    evidence_source: String,
    locator: KnowledgeLocator,
}

impl KnowledgeField {
    /// Create a metadata-style searchable field with a source-record metadata locator.
    ///
    /// # Errors
    /// Returns [`D03Error::InvalidIndexInput`] for empty/non-canonical text.
    pub fn new(
        domain: KnowledgeSearchDomain,
        key: Option<String>,
        value: &str,
        evidence_source: &str,
    ) -> Result<Self, D03Error> {
        Self::with_locator(
            domain,
            key.clone(),
            value,
            evidence_source,
            KnowledgeLocator::MetadataField { key },
        )
    }

    /// Create a searchable field with an exact caller-supplied mechanical source locator.
    ///
    /// # Errors
    /// Returns [`D03Error::InvalidIndexInput`] for empty/non-canonical text.
    pub fn with_locator(
        domain: KnowledgeSearchDomain,
        key: Option<String>,
        value: &str,
        evidence_source: &str,
        locator: KnowledgeLocator,
    ) -> Result<Self, D03Error> {
        require_text(value, "field value")?;
        require_text(evidence_source, "field evidence_source")?;
        if let Some(key) = &key {
            require_text(key, "field key")?;
        }
        Ok(Self {
            domain,
            key,
            value: value.to_owned(),
            evidence_source: evidence_source.to_owned(),
            locator,
        })
    }

    pub(crate) const fn domain(&self) -> KnowledgeSearchDomain {
        self.domain
    }
    pub(crate) fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }
    pub(crate) fn value(&self) -> &str {
        &self.value
    }
    pub(crate) fn evidence_source(&self) -> &str {
        &self.evidence_source
    }
    pub(crate) fn locator(&self) -> &KnowledgeLocator {
        &self.locator
    }
}

/// D03-owned B03 anchored text input. B03 implementation types remain private.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchoredTextInput {
    /// Exact extracted UTF-8 text.
    pub text: String,
    /// Exact source Object Revision.
    pub object_revision_ref: EntityRef,
    /// Optional one-based source page.
    pub page: Option<u32>,
    /// Optional inclusive source byte start.
    pub byte_start: Option<u64>,
    /// Optional exclusive source byte end.
    pub byte_end_exclusive: Option<u64>,
}

impl AnchoredTextInput {
    pub(crate) fn validate(&self) -> Result<(), D03Error> {
        require_text(&self.text, "anchored text")?;
        if self.object_revision_ref.entity_kind.as_str() != "object.revision" {
            return Err(D03Error::InvalidIndexInput("anchored object revision"));
        }
        if self.page.is_none() && self.byte_start.is_none() {
            return Err(D03Error::InvalidIndexInput("anchored locator"));
        }
        if let (Some(start), Some(end)) = (self.byte_start, self.byte_end_exclusive)
            && end <= start
        {
            return Err(D03Error::InvalidIndexInput("anchored byte range"));
        }
        Ok(())
    }

    fn locator(&self) -> KnowledgeLocator {
        KnowledgeLocator::DocumentAnchor {
            page: self.page,
            byte_start: self.byte_start,
            byte_end_exclusive: self.byte_end_exclusive,
        }
    }
}

/// D03-owned source-bound document admitted to the derived index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnowledgeSearchDocument {
    /// Filename and evidence-derived metadata projection.
    ObjectMetadata {
        /// Exact source revision.
        source: KnowledgeSourceRevision,
        /// Optional filename/logical path.
        filename: Option<String>,
        /// Searchable metadata fields.
        metadata: Vec<KnowledgeField>,
    },
    /// Exact B03-anchored document text.
    B03DocumentText {
        /// Exact source revision.
        source: KnowledgeSourceRevision,
        /// Anchored text spans.
        spans: Vec<AnchoredTextInput>,
    },
    /// Exact source-symbol names.
    SourceSymbols {
        /// Exact source revision.
        source: KnowledgeSourceRevision,
        /// Exact symbols.
        symbols: Vec<String>,
    },
    /// Programme-C firmware fields mapped privately to B07 metadata.
    FirmwareFields {
        /// Exact source revision.
        source: KnowledgeSourceRevision,
        /// Mechanically proven firmware fields.
        fields: Vec<KnowledgeField>,
    },
    /// Programme-C partition fields mapped privately to B07 metadata.
    PartitionFields {
        /// Exact source revision.
        source: KnowledgeSourceRevision,
        /// Mechanically proven partition fields.
        fields: Vec<KnowledgeField>,
    },
}

impl KnowledgeSearchDocument {
    pub(crate) fn source(&self) -> &KnowledgeSourceRevision {
        match self {
            Self::ObjectMetadata { source, .. }
            | Self::B03DocumentText { source, .. }
            | Self::SourceSymbols { source, .. }
            | Self::FirmwareFields { source, .. }
            | Self::PartitionFields { source, .. } => source,
        }
    }

    pub(crate) const fn projection_kind(&self) -> B07ProjectionKind {
        match self {
            Self::ObjectMetadata { .. } => B07ProjectionKind::ObjectMetadata,
            Self::B03DocumentText { .. } => B07ProjectionKind::DocumentText,
            Self::SourceSymbols { .. } => B07ProjectionKind::SourceSymbols,
            Self::FirmwareFields { .. } => B07ProjectionKind::Firmware,
            Self::PartitionFields { .. } => B07ProjectionKind::Partition,
        }
    }
}

/// Immutable identity of one derived D03 index state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeIndexRevision {
    /// Monotonic local derived-index revision.
    pub revision: u64,
    /// Deterministic digest of canonicalized copied index content.
    pub content_sha256: String,
    /// Number of exact unique source revisions represented.
    pub source_count: usize,
}

/// D03 derived source registry plus private B07 textual index.
pub struct KnowledgeIndex {
    limits: KnowledgeLimits,
    adapter: B07Adapter,
    documents: BTreeMap<String, KnowledgeSearchDocument>,
    sources: BTreeMap<String, KnowledgeSourceRevision>,
}

impl KnowledgeIndex {
    /// Create an empty bounded D03 index.
    ///
    /// # Errors
    /// Returns invalid-limit/private-adapter errors when construction cannot be bounded.
    pub fn new(limits: KnowledgeLimits) -> Result<Self, D03Error> {
        limits.validate()?;
        Ok(Self {
            limits,
            adapter: B07Adapter::new(limits)?,
            documents: BTreeMap::new(),
            sources: BTreeMap::new(),
        })
    }

    /// Replace derived index state from exact normalized source documents.
    ///
    /// # Errors
    /// Fails closed for malformed/duplicate source projections or B07 adapter rejection.
    pub fn rebuild(
        &mut self,
        docs: &[KnowledgeSearchDocument],
    ) -> Result<KnowledgeIndexRevision, D03Error> {
        if docs.len() > self.limits.max_sources.saturating_mul(5) {
            return Err(D03Error::InvalidIndexInput("document limit"));
        }
        let normalized = normalize_documents(docs, self.limits)?;
        let mut documents = BTreeMap::new();
        let mut sources = BTreeMap::new();
        for doc in normalized {
            validate_document(&doc, self.limits)?;
            let source_key = source_key(doc.source())?;
            match sources.get(&source_key) {
                Some(existing) if existing != doc.source() => {
                    return Err(D03Error::InvalidIndexInput("conflicting source binding"));
                }
                _ => {
                    sources.insert(source_key.clone(), doc.source().clone());
                }
            }
            let key = document_key(&doc)?;
            if documents.insert(key, doc).is_some() {
                return Err(D03Error::InvalidIndexInput("duplicate document"));
            }
        }
        let indexed = documents.values().cloned().collect::<Vec<_>>();
        let revision = self.adapter.rebuild(&indexed)?;
        self.documents = documents;
        self.sources = sources;
        Ok(KnowledgeIndexRevision {
            revision: revision.revision,
            content_sha256: revision.content_sha256,
            source_count: self.sources.len(),
        })
    }

    /// Search one Workspace against the current exact derived index revision.
    ///
    /// # Errors
    /// Returns mechanical query/index/citation failures and never promotes a hit to source truth.
    pub fn search(&self, request: &KnowledgeTextQuery) -> Result<KnowledgeResultSet, D03Error> {
        request.validate_limits(self.limits)?;
        let response = self.adapter.query(request)?;
        let mut rows = Vec::new();
        let mut source_refs = Vec::new();
        let mut seen_sources = BTreeSet::new();
        for hit in response.hits {
            let key = hit.document_key.clone();
            let document = self
                .documents
                .get(&key)
                .ok_or(D03Error::InvalidIndexInput("unmapped B07 hit"))?;
            if !projection_requested(document.projection_kind(), &request.domains) {
                continue;
            }
            let source = document.source().clone();
            let mut citations = Vec::new();
            let mut values = Vec::new();
            for matched in &hit.matches {
                if let Some(citation) =
                    citation_for_match(document, matched, &response.index, &request.domains)?
                {
                    values.push(KnowledgeValue::Text(matched.value.clone()));
                    citations.push(citation);
                }
            }
            if citations.is_empty() {
                continue;
            }
            rows.push(KnowledgeResultRow { values, citations });
            let source_key = source_key(&source)?;
            if seen_sources.insert(source_key) {
                source_refs.push(source);
            }
        }
        let digest = crate::query::query_digest(request, &response.index.content_sha256)?;
        Ok(KnowledgeResultSet {
            columns: vec!["match".to_owned()],
            complete: rows.len() < request.limit,
            rows,
            source_refs,
            query_plan_sha256: digest,
            authoritative: false,
        })
    }
}

fn normalize_documents(
    docs: &[KnowledgeSearchDocument],
    limits: KnowledgeLimits,
) -> Result<Vec<KnowledgeSearchDocument>, D03Error> {
    let mut merged = BTreeMap::<String, KnowledgeSearchDocument>::new();
    for doc in docs {
        validate_document(doc, limits)?;
        let key = match doc {
            KnowledgeSearchDocument::ObjectMetadata { .. }
            | KnowledgeSearchDocument::FirmwareFields { .. }
            | KnowledgeSearchDocument::PartitionFields { .. } => {
                format!("{}|object_metadata", source_key(doc.source())?)
            }
            _ => document_key(doc)?,
        };
        if matches!(
            doc,
            KnowledgeSearchDocument::ObjectMetadata { .. }
                | KnowledgeSearchDocument::FirmwareFields { .. }
                | KnowledgeSearchDocument::PartitionFields { .. }
        ) {
            merge_metadata_document(&mut merged, key, doc)?;
        } else if merged.insert(key, doc.clone()).is_some() {
            return Err(D03Error::InvalidIndexInput("duplicate document"));
        }
    }
    for doc in merged.values() {
        validate_document(doc, limits)?;
    }
    Ok(merged.into_values().collect())
}

fn merge_metadata_document(
    merged: &mut BTreeMap<String, KnowledgeSearchDocument>,
    key: String,
    incoming: &KnowledgeSearchDocument,
) -> Result<(), D03Error> {
    let source = incoming.source().clone();
    let entry = merged
        .entry(key)
        .or_insert_with(|| KnowledgeSearchDocument::ObjectMetadata {
            source: source.clone(),
            filename: None,
            metadata: Vec::new(),
        });
    let KnowledgeSearchDocument::ObjectMetadata {
        source: existing_source,
        filename,
        metadata,
    } = entry
    else {
        return Err(D03Error::InvalidIndexInput("metadata merge target"));
    };
    if existing_source != &source {
        return Err(D03Error::InvalidIndexInput("conflicting source binding"));
    }
    match incoming {
        KnowledgeSearchDocument::ObjectMetadata {
            filename: incoming_filename,
            metadata: fields,
            ..
        } => {
            if let Some(incoming_filename) = incoming_filename {
                if filename
                    .as_ref()
                    .is_some_and(|existing| existing != incoming_filename)
                {
                    return Err(D03Error::InvalidIndexInput("conflicting filename"));
                }
                *filename = Some(incoming_filename.clone());
            }
            metadata.extend(fields.iter().cloned());
        }
        KnowledgeSearchDocument::FirmwareFields { fields, .. }
        | KnowledgeSearchDocument::PartitionFields { fields, .. } => {
            metadata.extend(fields.iter().cloned());
        }
        KnowledgeSearchDocument::B03DocumentText { .. }
        | KnowledgeSearchDocument::SourceSymbols { .. } => {
            return Err(D03Error::InvalidIndexInput("non-metadata merge input"));
        }
    }
    Ok(())
}

fn validate_document(
    doc: &KnowledgeSearchDocument,
    limits: KnowledgeLimits,
) -> Result<(), D03Error> {
    let source = doc.source();
    if source.workspace_ref.entity_kind.as_str() != "core.workspace"
        || source.source_record_revision == 0
    {
        return Err(D03Error::InvalidIndexInput("source binding"));
    }
    match doc {
        KnowledgeSearchDocument::ObjectMetadata {
            filename, metadata, ..
        } => {
            if filename.is_none() && metadata.is_empty() {
                return Err(D03Error::InvalidIndexInput("empty metadata document"));
            }
            if let Some(name) = filename {
                require_bounded(name, "filename", limits.max_field_bytes)?;
            }
            validate_metadata_fields(metadata, limits)
        }
        KnowledgeSearchDocument::B03DocumentText { source, spans } => {
            let expected = source
                .object_revision_ref
                .as_ref()
                .ok_or(D03Error::InvalidIndexInput("document object revision"))?;
            if spans.is_empty() {
                return Err(D03Error::InvalidIndexInput("empty document spans"));
            }
            for span in spans {
                span.validate()?;
                if &span.object_revision_ref != expected {
                    return Err(D03Error::InvalidIndexInput("document anchor mismatch"));
                }
                require_bounded(&span.text, "document text", limits.max_field_bytes)?;
            }
            Ok(())
        }
        KnowledgeSearchDocument::SourceSymbols { symbols, .. } => {
            if symbols.is_empty() {
                return Err(D03Error::InvalidIndexInput("empty symbols"));
            }
            for symbol in symbols {
                require_bounded(symbol, "symbol", limits.max_field_bytes)?;
            }
            Ok(())
        }
        KnowledgeSearchDocument::FirmwareFields { fields, .. } => {
            validate_fields(fields, KnowledgeSearchDomain::Firmware, limits)
        }
        KnowledgeSearchDocument::PartitionFields { fields, .. } => {
            validate_fields(fields, KnowledgeSearchDomain::Partition, limits)
        }
    }
}

fn validate_metadata_fields(
    fields: &[KnowledgeField],
    limits: KnowledgeLimits,
) -> Result<(), D03Error> {
    if fields.len() > limits.max_fields_per_source {
        return Err(D03Error::InvalidIndexInput("field count"));
    }
    for field in fields {
        if !matches!(
            field.domain(),
            KnowledgeSearchDomain::Metadata
                | KnowledgeSearchDomain::Firmware
                | KnowledgeSearchDomain::Partition
        ) {
            return Err(D03Error::InvalidIndexInput("metadata field domain"));
        }
        require_bounded(field.value(), "field value", limits.max_field_bytes)?;
        require_bounded(
            field.evidence_source(),
            "evidence source",
            limits.max_field_bytes,
        )?;
        if let Some(key) = field.key() {
            require_bounded(key, "field key", limits.max_field_bytes)?;
        }
    }
    Ok(())
}

fn validate_fields(
    fields: &[KnowledgeField],
    expected: KnowledgeSearchDomain,
    limits: KnowledgeLimits,
) -> Result<(), D03Error> {
    if fields.is_empty() || fields.len() > limits.max_fields_per_source {
        return Err(D03Error::InvalidIndexInput("field count"));
    }
    for field in fields {
        if field.domain() != expected {
            return Err(D03Error::InvalidIndexInput("field domain"));
        }
        require_bounded(field.value(), "field value", limits.max_field_bytes)?;
        require_bounded(
            field.evidence_source(),
            "evidence source",
            limits.max_field_bytes,
        )?;
        if let Some(key) = field.key() {
            require_bounded(key, "field key", limits.max_field_bytes)?;
        }
    }
    Ok(())
}

fn projection_requested(kind: B07ProjectionKind, domains: &[KnowledgeSearchDomain]) -> bool {
    domains.iter().any(|domain| {
        matches!(
            (kind, domain),
            (
                B07ProjectionKind::ObjectMetadata,
                KnowledgeSearchDomain::Filename
                    | KnowledgeSearchDomain::Metadata
                    | KnowledgeSearchDomain::Firmware
                    | KnowledgeSearchDomain::Partition,
            ) | (
                B07ProjectionKind::DocumentText,
                KnowledgeSearchDomain::DocumentText
            ) | (
                B07ProjectionKind::SourceSymbols,
                KnowledgeSearchDomain::SourceSymbol
            ) | (B07ProjectionKind::Firmware, KnowledgeSearchDomain::Firmware)
                | (
                    B07ProjectionKind::Partition,
                    KnowledgeSearchDomain::Partition
                )
        )
    })
}

fn citation_for_match(
    document: &KnowledgeSearchDocument,
    matched: &crate::adapters::b07::B07Match,
    index: &crate::adapters::b07::B07IndexRevision,
    requested_domains: &[KnowledgeSearchDomain],
) -> Result<Option<CitationEvidence>, D03Error> {
    let locator = match document {
        KnowledgeSearchDocument::SourceSymbols { .. } => KnowledgeLocator::SourceSymbol {
            symbol: matched.value.clone(),
        },
        KnowledgeSearchDocument::B03DocumentText { spans, .. } => {
            let mut found = spans.iter().filter(|span| {
                span.text == matched.value && b03_key(span).as_deref() == matched.key.as_deref()
            });
            let first = found
                .next()
                .ok_or(D03Error::InvalidCitationBinding("document anchor missing"))?;
            if found.next().is_some() {
                return Err(D03Error::InvalidCitationBinding(
                    "document anchor ambiguous",
                ));
            }
            first.locator()
        }
        KnowledgeSearchDocument::ObjectMetadata {
            filename, metadata, ..
        } => {
            if matched.domain == KnowledgeSearchDomain::Filename {
                if !requested_domains.contains(&KnowledgeSearchDomain::Filename) {
                    return Ok(None);
                }
                if filename.as_deref() != Some(matched.value.as_str()) {
                    return Err(D03Error::InvalidCitationBinding("filename mismatch"));
                }
                KnowledgeLocator::MetadataField {
                    key: Some("filename".to_owned()),
                }
            } else {
                let Some(field) = matching_field(metadata, matched, requested_domains)? else {
                    return Ok(None);
                };
                field.locator().clone()
            }
        }
        KnowledgeSearchDocument::FirmwareFields { fields, .. }
        | KnowledgeSearchDocument::PartitionFields { fields, .. } => {
            let Some(field) = matching_field(fields, matched, requested_domains)? else {
                return Ok(None);
            };
            field.locator().clone()
        }
    };
    let mut citation = CitationEvidence::new(
        document.source().clone(),
        locator,
        &matched.evidence_source,
        None,
    )?;
    citation.index_revision = Some(index.revision);
    citation.index_sha256 = Some(index.content_sha256.clone());
    Ok(Some(citation))
}

fn matching_field<'a>(
    fields: &'a [KnowledgeField],
    matched: &crate::adapters::b07::B07Match,
    requested_domains: &[KnowledgeSearchDomain],
) -> Result<Option<&'a KnowledgeField>, D03Error> {
    let mut values = fields.iter().filter(|field| {
        requested_domains.contains(&field.domain())
            && field.value() == matched.value
            && field.key() == matched.key.as_deref()
            && field.evidence_source() == matched.evidence_source
    });
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(D03Error::InvalidCitationBinding("field locator ambiguous"));
    }
    Ok(Some(first))
}

fn b03_key(span: &AnchoredTextInput) -> Option<String> {
    span.page
        .map(|page| format!("page:{page}"))
        .or_else(|| span.byte_start.map(|start| format!("byte:{start}")))
}

fn source_key(source: &KnowledgeSourceRevision) -> Result<String, D03Error> {
    serde_json::to_string(&(
        &source.workspace_ref,
        &source.source_ref,
        source.source_record_revision,
        &source.object_revision_ref,
    ))
    .map_err(|error| D03Error::Serialization(error.to_string()))
}

fn document_key(doc: &KnowledgeSearchDocument) -> Result<String, D03Error> {
    Ok(format!(
        "{}|{}",
        source_key(doc.source())?,
        doc.projection_kind().as_str()
    ))
}

fn require_text(value: &str, field: &'static str) -> Result<(), D03Error> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(D03Error::InvalidIndexInput(field));
    }
    Ok(())
}

fn require_bounded(value: &str, field: &'static str, max: usize) -> Result<(), D03Error> {
    require_text(value, field)?;
    if value.len() > max {
        return Err(D03Error::InvalidIndexInput("field too large"));
    }
    Ok(())
}
