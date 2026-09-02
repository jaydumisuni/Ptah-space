use crate::{
    D03Error, KnowledgeLimits, KnowledgeSearchDocument, KnowledgeSearchDomain, KnowledgeTextQuery,
};
use ptah_archive_decomposition::{
    SearchDocument, SearchDocumentKind, SearchDomain, SearchIndex, SearchLimits, SearchMetadata,
    SearchQuery, SearchSourceBinding, document_text_search_document, filename_metadata_document,
    source_symbol_search_document,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum B07ProjectionKind {
    ObjectMetadata,
    DocumentText,
    SourceSymbols,
    Firmware,
    Partition,
}

impl B07ProjectionKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ObjectMetadata => "object_metadata",
            Self::DocumentText => "document_text",
            Self::SourceSymbols => "source_symbols",
            Self::Firmware => "firmware",
            Self::Partition => "partition",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct B07IndexRevision {
    pub(crate) revision: u64,
    pub(crate) content_sha256: String,
}

#[derive(Debug, Clone)]
pub(crate) struct B07Match {
    pub(crate) domain: KnowledgeSearchDomain,
    pub(crate) key: Option<String>,
    pub(crate) value: String,
    pub(crate) evidence_source: String,
}

#[derive(Debug, Clone)]
pub(crate) struct B07Hit {
    pub(crate) document_key: String,
    pub(crate) matches: Vec<B07Match>,
}

pub(crate) struct B07Response {
    pub(crate) index: B07IndexRevision,
    pub(crate) hits: Vec<B07Hit>,
}

pub(crate) struct B07Adapter {
    index: SearchIndex,
    projection_map: BTreeMap<String, B07ProjectionKind>,
}

impl B07Adapter {
    pub(crate) fn new(limits: KnowledgeLimits) -> Result<Self, D03Error> {
        let index = SearchIndex::new(SearchLimits {
            max_documents: limits.max_sources.saturating_mul(5),
            max_fields_per_document: limits.max_fields_per_source,
            max_field_bytes: limits.max_field_bytes,
            max_query_bytes: limits.max_query_bytes,
            max_results: limits.max_results,
        })
        .map_err(map_error)?;
        Ok(Self {
            index,
            projection_map: BTreeMap::new(),
        })
    }

    pub(crate) fn rebuild(
        &mut self,
        docs: &[KnowledgeSearchDocument],
    ) -> Result<B07IndexRevision, D03Error> {
        let mut converted = Vec::with_capacity(docs.len());
        let mut projection_map = BTreeMap::new();
        for doc in docs {
            let (document, projection) = convert_document(doc)?;
            let key = b07_document_key(document.source(), document.kind())?;
            if projection_map.insert(key, projection).is_some() {
                return Err(D03Error::InvalidIndexInput("B07 projection collision"));
            }
            converted.push(document);
        }
        let revision = self.index.rebuild(&converted).map_err(map_error)?;
        self.projection_map = projection_map;
        Ok(B07IndexRevision {
            revision: revision.revision,
            content_sha256: revision.content_sha256,
        })
    }

    pub(crate) fn query(&self, request: &KnowledgeTextQuery) -> Result<B07Response, D03Error> {
        let mut domains = request
            .domains
            .iter()
            .map(|domain| match domain {
                KnowledgeSearchDomain::Filename => SearchDomain::Filename,
                KnowledgeSearchDomain::Metadata
                | KnowledgeSearchDomain::Firmware
                | KnowledgeSearchDomain::Partition => SearchDomain::Metadata,
                KnowledgeSearchDomain::DocumentText => SearchDomain::DocumentText,
                KnowledgeSearchDomain::SourceSymbol => SearchDomain::SourceSymbol,
            })
            .collect::<Vec<_>>();
        domains.sort();
        domains.dedup();
        let response = self
            .index
            .query(&SearchQuery {
                workspace_ref: request.workspace_ref.clone(),
                text: request.text.clone(),
                domains,
                limit: request.limit,
            })
            .map_err(map_error)?;
        let index = B07IndexRevision {
            revision: response.index.revision,
            content_sha256: response.index.content_sha256,
        };
        let hits = response
            .hits
            .into_iter()
            .map(|hit| {
                let b07_key = b07_document_key(&hit.source, hit.kind)?;
                let projection = *self
                    .projection_map
                    .get(&b07_key)
                    .ok_or(D03Error::InvalidIndexInput("unmapped B07 projection"))?;
                let document_key = d03_document_key(&hit.source, projection)?;
                let matches = hit
                    .matches
                    .into_iter()
                    .map(|matched| B07Match {
                        domain: map_domain(matched.domain, projection),
                        key: matched.key,
                        value: matched.value,
                        evidence_source: matched.evidence_source,
                    })
                    .collect();
                Ok(B07Hit {
                    document_key,
                    matches,
                })
            })
            .collect::<Result<Vec<_>, D03Error>>()?;
        Ok(B07Response { index, hits })
    }
}

fn convert_document(
    doc: &KnowledgeSearchDocument,
) -> Result<(SearchDocument, B07ProjectionKind), D03Error> {
    let binding = binding(doc);
    match doc {
        KnowledgeSearchDocument::ObjectMetadata {
            filename, metadata, ..
        } => {
            let items = metadata
                .iter()
                .map(|field| SearchMetadata {
                    path: None,
                    key: field.key().unwrap_or("metadata").to_owned(),
                    value: field.value().to_owned(),
                    source: field.evidence_source().to_owned(),
                })
                .collect::<Vec<_>>();
            Ok((
                filename_metadata_document(binding, filename.clone(), &items).map_err(map_error)?,
                B07ProjectionKind::ObjectMetadata,
            ))
        }
        KnowledgeSearchDocument::B03DocumentText { spans, .. } => {
            let anchored = crate::adapters::b03::to_b03(spans)?;
            Ok((
                document_text_search_document(binding, &anchored).map_err(map_error)?,
                B07ProjectionKind::DocumentText,
            ))
        }
        KnowledgeSearchDocument::SourceSymbols { symbols, .. } => Ok((
            source_symbol_search_document(binding, symbols).map_err(map_error)?,
            B07ProjectionKind::SourceSymbols,
        )),
        KnowledgeSearchDocument::FirmwareFields { fields, .. } => {
            let items = fields_to_metadata(fields);
            Ok((
                filename_metadata_document(binding, None, &items).map_err(map_error)?,
                B07ProjectionKind::Firmware,
            ))
        }
        KnowledgeSearchDocument::PartitionFields { fields, .. } => {
            let items = fields_to_metadata(fields);
            Ok((
                filename_metadata_document(binding, None, &items).map_err(map_error)?,
                B07ProjectionKind::Partition,
            ))
        }
    }
}

fn fields_to_metadata(fields: &[crate::KnowledgeField]) -> Vec<SearchMetadata> {
    fields
        .iter()
        .map(|field| SearchMetadata {
            path: None,
            key: field.key().unwrap_or("field").to_owned(),
            value: field.value().to_owned(),
            source: field.evidence_source().to_owned(),
        })
        .collect()
}

fn binding(doc: &KnowledgeSearchDocument) -> SearchSourceBinding {
    let source = doc.source();
    SearchSourceBinding {
        workspace_ref: source.workspace_ref.clone(),
        source_ref: source.source_ref.clone(),
        source_record_revision: source.source_record_revision,
        object_revision_ref: source.object_revision_ref.clone(),
    }
}

fn map_domain(domain: SearchDomain, projection: B07ProjectionKind) -> KnowledgeSearchDomain {
    match domain {
        SearchDomain::Filename => KnowledgeSearchDomain::Filename,
        SearchDomain::DocumentText => KnowledgeSearchDomain::DocumentText,
        SearchDomain::SourceSymbol => KnowledgeSearchDomain::SourceSymbol,
        SearchDomain::Metadata if projection == B07ProjectionKind::Firmware => {
            KnowledgeSearchDomain::Firmware
        }
        SearchDomain::Metadata if projection == B07ProjectionKind::Partition => {
            KnowledgeSearchDomain::Partition
        }
        SearchDomain::Metadata
        | SearchDomain::Log
        | SearchDomain::Activity
        | SearchDomain::Artifact => KnowledgeSearchDomain::Metadata,
    }
}

fn b07_document_key(
    source: &SearchSourceBinding,
    kind: SearchDocumentKind,
) -> Result<String, D03Error> {
    let kind = match kind {
        SearchDocumentKind::ObjectMetadata => "object_metadata",
        SearchDocumentKind::DocumentText => "document_text",
        SearchDocumentKind::SourceSymbols => "source_symbols",
        SearchDocumentKind::Log => "log",
        SearchDocumentKind::Activity => "activity",
        SearchDocumentKind::Artifact => "artifact",
    };
    Ok(format!("{}|{kind}", source_key(source)?))
}

fn d03_document_key(
    source: &SearchSourceBinding,
    kind: B07ProjectionKind,
) -> Result<String, D03Error> {
    Ok(format!("{}|{}", source_key(source)?, kind.as_str()))
}

fn source_key(source: &SearchSourceBinding) -> Result<String, D03Error> {
    serde_json::to_string(&(
        &source.workspace_ref,
        &source.source_ref,
        source.source_record_revision,
        &source.object_revision_ref,
    ))
    .map_err(|error| D03Error::Serialization(error.to_string()))
}

fn map_error(error: impl std::fmt::Display) -> D03Error {
    D03Error::SearchAdapter(error.to_string())
}
