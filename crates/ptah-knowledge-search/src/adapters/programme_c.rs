use crate::{
    D03Error, KnowledgeField, KnowledgeLocator, KnowledgeSearchDocument, KnowledgeSearchDomain,
    KnowledgeSourceRevision,
};
#[cfg(test)]
use ptah_archive_decomposition::{
    AndroidReport, AppleFirmwareReport, DiskImageReport, MediatekReport, QualcommBundleReport,
    UnisocComponentRole, UnisocPacReport,
};
use serde::{Deserialize, Serialize};

/// D03-owned exact firmware component evidence. It carries no execution or device authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareComponentEvidence {
    /// Exact component/path/name retained by the source report.
    pub name: String,
    /// Exact component digest when the source report established one.
    pub sha256: Option<String>,
    /// Exact source byte range when mechanically available.
    pub byte_range: Option<(u64, u64)>,
    /// Exact manifest digest when this component binding came from a manifest.
    pub manifest_sha256: Option<String>,
    /// Mechanical evidence family such as `c03.component`.
    pub evidence_source: String,
}

impl FirmwareComponentEvidence {
    /// Construct bounded static firmware evidence.
    ///
    /// # Errors
    /// Returns [`D03Error::InvalidIndexInput`] for malformed name, digest, range or evidence source.
    pub fn new(
        name: &str,
        sha256: Option<String>,
        byte_range: Option<(u64, u64)>,
        evidence_source: &str,
    ) -> Result<Self, D03Error> {
        require_text(name, "firmware name")?;
        require_text(evidence_source, "firmware evidence source")?;
        if sha256.as_deref().is_some_and(|value| !valid_sha256(value)) {
            return Err(D03Error::InvalidIndexInput("firmware digest"));
        }
        if byte_range.is_some_and(|(start, end)| end <= start) {
            return Err(D03Error::InvalidIndexInput("firmware byte range"));
        }
        Ok(Self {
            name: name.to_owned(),
            sha256,
            byte_range,
            manifest_sha256: None,
            evidence_source: evidence_source.to_owned(),
        })
    }

    /// Bind this component to one exact manifest digest.
    ///
    /// # Errors
    /// Returns [`D03Error::InvalidIndexInput`] when `manifest_sha256` is malformed.
    pub fn with_manifest_sha256(mut self, manifest_sha256: &str) -> Result<Self, D03Error> {
        if !valid_sha256(manifest_sha256) {
            return Err(D03Error::InvalidIndexInput("firmware manifest digest"));
        }
        self.manifest_sha256 = Some(manifest_sha256.to_owned());
        Ok(self)
    }

    fn fields(&self) -> Result<Vec<KnowledgeField>, D03Error> {
        let locator = KnowledgeLocator::FirmwareComponent {
            component: self.name.clone(),
        };
        let mut fields = vec![KnowledgeField::with_locator(
            KnowledgeSearchDomain::Firmware,
            Some("component".to_owned()),
            &self.name,
            &self.evidence_source,
            locator.clone(),
        )?];
        if let Some(digest) = &self.sha256 {
            fields.push(KnowledgeField::with_locator(
                KnowledgeSearchDomain::Firmware,
                Some("sha256".to_owned()),
                digest,
                &self.evidence_source,
                locator.clone(),
            )?);
        }
        if let Some(manifest_sha256) = &self.manifest_sha256 {
            fields.push(KnowledgeField::with_locator(
                KnowledgeSearchDomain::Firmware,
                Some("manifest_sha256".to_owned()),
                manifest_sha256,
                &self.evidence_source,
                locator.clone(),
            )?);
        }
        if let Some((start, end)) = self.byte_range {
            fields.push(KnowledgeField::with_locator(
                KnowledgeSearchDomain::Firmware,
                Some("byte_range".to_owned()),
                &format!("{start}..{end}"),
                &self.evidence_source,
                locator,
            )?);
        }
        Ok(fields)
    }
}

/// Typed construction request for exact read-only partition evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionEvidenceInput {
    /// Exact partition label/name when available.
    pub name: Option<String>,
    /// Exact source-local partition index/token when available.
    pub index: Option<String>,
    /// Inclusive exact byte start.
    pub byte_start: u64,
    /// Exclusive exact byte end.
    pub byte_end_exclusive: u64,
    /// Optional first LBA/sector.
    pub first_lba: Option<u64>,
    /// Optional last inclusive LBA/sector.
    pub last_lba_inclusive: Option<u64>,
    /// Optional storage-family evidence.
    pub storage: Option<String>,
    /// Optional physical partition/LUN.
    pub physical_partition: Option<u32>,
    /// Mechanical evidence family such as `c01.partition`.
    pub evidence_source: String,
}

/// D03-owned exact partition/layout evidence. It deliberately omits write/download/programmer semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionEvidence {
    /// Exact partition label/name when available.
    pub name: Option<String>,
    /// Exact source-local partition index/token when available.
    pub index: Option<String>,
    /// Inclusive exact byte start.
    pub byte_start: u64,
    /// Exclusive exact byte end.
    pub byte_end_exclusive: u64,
    /// Optional first LBA/sector.
    pub first_lba: Option<u64>,
    /// Optional last inclusive LBA/sector.
    pub last_lba_inclusive: Option<u64>,
    /// Optional storage-family evidence.
    pub storage: Option<String>,
    /// Optional physical partition/LUN.
    pub physical_partition: Option<u32>,
    /// Mechanical evidence family such as `c01.partition`.
    pub evidence_source: String,
}

impl PartitionEvidence {
    /// Construct one exact read-only partition evidence record.
    ///
    /// # Errors
    /// Returns [`D03Error::InvalidIndexInput`] for malformed ranges/labels/evidence.
    pub fn new(input: PartitionEvidenceInput) -> Result<Self, D03Error> {
        if input.byte_end_exclusive <= input.byte_start {
            return Err(D03Error::InvalidIndexInput("partition byte range"));
        }
        validate_optional_text(input.name.as_deref(), "partition name")?;
        validate_optional_text(input.index.as_deref(), "partition index")?;
        validate_optional_text(input.storage.as_deref(), "partition storage")?;
        if let (Some(first), Some(last)) = (input.first_lba, input.last_lba_inclusive)
            && last < first
        {
            return Err(D03Error::InvalidIndexInput("partition lba range"));
        }
        require_text(&input.evidence_source, "partition evidence source")?;
        Ok(Self {
            name: input.name,
            index: input.index,
            byte_start: input.byte_start,
            byte_end_exclusive: input.byte_end_exclusive,
            first_lba: input.first_lba,
            last_lba_inclusive: input.last_lba_inclusive,
            storage: input.storage,
            physical_partition: input.physical_partition,
            evidence_source: input.evidence_source,
        })
    }

    fn fields(&self) -> Result<Vec<KnowledgeField>, D03Error> {
        let locator = KnowledgeLocator::PartitionRange {
            name: self.name.clone(),
            byte_start: self.byte_start,
            byte_end_exclusive: self.byte_end_exclusive,
        };
        let mut fields = Vec::new();
        if let Some(name) = &self.name {
            fields.push(self.field("name", name, locator.clone())?);
        }
        if let Some(index) = &self.index {
            fields.push(self.field("index", index, locator.clone())?);
        }
        fields.push(self.field(
            "byte_range",
            &format!("{}..{}", self.byte_start, self.byte_end_exclusive),
            locator.clone(),
        )?);
        if let (Some(first), Some(last)) = (self.first_lba, self.last_lba_inclusive) {
            fields.push(self.field("lba_range", &format!("{first}..={last}"), locator.clone())?);
        }
        if let Some(storage) = &self.storage {
            fields.push(self.field("storage", storage, locator.clone())?);
        }
        if let Some(lun) = self.physical_partition {
            fields.push(self.field("physical_partition", &lun.to_string(), locator)?);
        }
        Ok(fields)
    }

    fn field(
        &self,
        key: &str,
        value: &str,
        locator: KnowledgeLocator,
    ) -> Result<KnowledgeField, D03Error> {
        KnowledgeField::with_locator(
            KnowledgeSearchDomain::Partition,
            Some(key.to_owned()),
            value,
            &self.evidence_source,
            locator,
        )
    }
}

/// D03-owned normalized C01 partition projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct C01InputProjection {
    /// Exact immutable C01 source digest.
    pub source_sha256: String,
    /// Exact C01 partition ranges.
    pub partitions: Vec<PartitionEvidence>,
}

/// D03-owned normalized C03 Android projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct C03InputProjection {
    /// Exact immutable C03 source digest.
    pub source_sha256: String,
    /// Exact firmware/component/manifest evidence.
    pub firmware: Vec<FirmwareComponentEvidence>,
    /// Exact static logical/partition evidence when mechanically available.
    pub partitions: Vec<PartitionEvidence>,
}

/// D03-owned normalized C04 Apple firmware projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct C04InputProjection {
    /// Exact immutable C04 source digest.
    pub source_sha256: String,
    /// Exact archive/manifest/DER component evidence.
    pub firmware: Vec<FirmwareComponentEvidence>,
}

/// D03-owned normalized C05 `MediaTek` projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct C05InputProjection {
    /// Exact immutable C05 scatter digest.
    pub source_sha256: String,
    /// Exact static sibling component evidence.
    pub firmware: Vec<FirmwareComponentEvidence>,
    /// Exact static scatter partition evidence.
    pub partitions: Vec<PartitionEvidence>,
}

/// D03-owned normalized C06 Unisoc/Qualcomm projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct C06InputProjection {
    /// Exact immutable C06 primary-source digest.
    pub source_sha256: String,
    /// Exact static package/component evidence.
    pub firmware: Vec<FirmwareComponentEvidence>,
    /// Exact static partition/LUN plan evidence when mechanically available.
    pub partitions: Vec<PartitionEvidence>,
}

/// Build one source-bound firmware-search document from D03-owned evidence.
///
/// # Errors
/// Fails closed for empty or malformed evidence.
pub fn firmware_evidence_document(
    source: KnowledgeSourceRevision,
    evidence: &[FirmwareComponentEvidence],
) -> Result<KnowledgeSearchDocument, D03Error> {
    if evidence.is_empty() {
        return Err(D03Error::InvalidIndexInput("empty firmware evidence"));
    }
    let fields = evidence
        .iter()
        .map(FirmwareComponentEvidence::fields)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    Ok(KnowledgeSearchDocument::FirmwareFields { source, fields })
}

/// Build one source-bound partition-search document from D03-owned evidence.
///
/// # Errors
/// Fails closed for empty or malformed evidence.
pub fn partition_evidence_document(
    source: KnowledgeSourceRevision,
    evidence: &[PartitionEvidence],
) -> Result<KnowledgeSearchDocument, D03Error> {
    if evidence.is_empty() {
        return Err(D03Error::InvalidIndexInput("empty partition evidence"));
    }
    let fields = evidence
        .iter()
        .map(PartitionEvidence::fields)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    Ok(KnowledgeSearchDocument::PartitionFields { source, fields })
}

/// Normalize a D03-owned C01 projection into source-bound search documents.
///
/// # Errors
/// Rejects stale digest binding or empty/invalid partition evidence.
pub fn from_c01_partition_report(
    source: KnowledgeSourceRevision,
    report: &C01InputProjection,
) -> Result<Vec<KnowledgeSearchDocument>, D03Error> {
    validate_projection_source(&source, &report.source_sha256)?;
    Ok(vec![partition_evidence_document(
        source,
        &report.partitions,
    )?])
}

/// Normalize a D03-owned C03 projection into source-bound search documents.
///
/// # Errors
/// Rejects stale digest binding or empty/invalid evidence.
pub fn from_c03_android_report(
    source: KnowledgeSourceRevision,
    report: &C03InputProjection,
) -> Result<Vec<KnowledgeSearchDocument>, D03Error> {
    validate_projection_source(&source, &report.source_sha256)?;
    documents_from_evidence(source, &report.firmware, &report.partitions)
}

/// Normalize a D03-owned C04 projection into source-bound search documents.
///
/// # Errors
/// Rejects stale digest binding or empty/invalid firmware evidence.
pub fn from_c04_apple_report(
    source: KnowledgeSourceRevision,
    report: &C04InputProjection,
) -> Result<Vec<KnowledgeSearchDocument>, D03Error> {
    validate_projection_source(&source, &report.source_sha256)?;
    Ok(vec![firmware_evidence_document(source, &report.firmware)?])
}

/// Normalize a D03-owned C05 projection into source-bound search documents.
///
/// # Errors
/// Rejects stale digest binding or empty/invalid evidence.
pub fn from_c05_mediatek_report(
    source: KnowledgeSourceRevision,
    report: &C05InputProjection,
) -> Result<Vec<KnowledgeSearchDocument>, D03Error> {
    validate_projection_source(&source, &report.source_sha256)?;
    documents_from_evidence(source, &report.firmware, &report.partitions)
}

/// Normalize a D03-owned C06 projection into source-bound search documents.
///
/// # Errors
/// Rejects stale digest binding or empty/invalid evidence.
pub fn from_c06_firmware_report(
    source: KnowledgeSourceRevision,
    report: &C06InputProjection,
) -> Result<Vec<KnowledgeSearchDocument>, D03Error> {
    validate_projection_source(&source, &report.source_sha256)?;
    documents_from_evidence(source, &report.firmware, &report.partitions)
}

fn documents_from_evidence(
    source: KnowledgeSourceRevision,
    firmware: &[FirmwareComponentEvidence],
    partitions: &[PartitionEvidence],
) -> Result<Vec<KnowledgeSearchDocument>, D03Error> {
    let mut documents = Vec::new();
    if !firmware.is_empty() {
        documents.push(firmware_evidence_document(source.clone(), firmware)?);
    }
    if !partitions.is_empty() {
        documents.push(partition_evidence_document(source, partitions)?);
    }
    if documents.is_empty() {
        return Err(D03Error::InvalidIndexInput("empty Programme-C projection"));
    }
    Ok(documents)
}

fn validate_projection_source(
    source: &KnowledgeSourceRevision,
    source_sha256: &str,
) -> Result<(), D03Error> {
    if !valid_sha256(source_sha256) {
        return Err(D03Error::InvalidIndexInput("Programme-C source digest"));
    }
    if source.content_sha256 != source_sha256 {
        return Err(D03Error::SourceDigestMismatch);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn projection_from_c01_report(
    report: &DiskImageReport,
) -> Result<C01InputProjection, D03Error> {
    let partitions = report
        .partitions
        .iter()
        .map(|partition| {
            PartitionEvidence::new(PartitionEvidenceInput {
                name: partition.name.clone(),
                index: Some(partition.index.to_string()),
                byte_start: partition.byte_start,
                byte_end_exclusive: partition.byte_end_exclusive,
                first_lba: Some(partition.first_lba),
                last_lba_inclusive: Some(partition.last_lba_inclusive),
                storage: None,
                physical_partition: None,
                evidence_source: "c01.partition".to_owned(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(C01InputProjection {
        source_sha256: report.source_sha256.clone(),
        partitions,
    })
}

#[cfg(test)]
pub(crate) fn projection_from_c03_report(
    report: &AndroidReport,
) -> Result<C03InputProjection, D03Error> {
    let mut firmware = report
        .components
        .iter()
        .map(|component| {
            FirmwareComponentEvidence::new(
                &component.name,
                Some(component.sha256.clone()),
                Some((component.byte_start, component.byte_end_exclusive)),
                "c03.component",
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(manifest) = &report.ota_manifest {
        for partition in &manifest.partitions {
            firmware.push(
                FirmwareComponentEvidence::new(&partition.name, None, None, "c03.ota_manifest")?
                    .with_manifest_sha256(&manifest.manifest_sha256)?,
            );
        }
    }
    let partitions = report
        .dynamic_partitions
        .iter()
        .filter(|partition| partition.logical_size > 0)
        .map(|partition| {
            PartitionEvidence::new(PartitionEvidenceInput {
                name: Some(partition.name.clone()),
                index: Some(partition.metadata_slot.to_string()),
                byte_start: 0,
                byte_end_exclusive: partition.logical_size,
                first_lba: None,
                last_lba_inclusive: None,
                storage: None,
                physical_partition: None,
                evidence_source: "c03.dynamic_partition.logical_range".to_owned(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(C03InputProjection {
        source_sha256: report.source_sha256.clone(),
        firmware,
        partitions,
    })
}

#[cfg(test)]
pub(crate) fn projection_from_c04_report(
    report: &AppleFirmwareReport,
) -> Result<C04InputProjection, D03Error> {
    let mut firmware = report
        .archive_entries
        .iter()
        .map(|entry| {
            FirmwareComponentEvidence::new(
                &entry.path,
                Some(entry.sha256.clone()),
                None,
                "c04.archive_entry",
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    for component in &report.der_components {
        firmware.push(FirmwareComponentEvidence::new(
            &component.name,
            Some(component.sha256.clone()),
            Some((component.byte_start, component.byte_end_exclusive)),
            "c04.der_component",
        )?);
    }
    if let Some(manifest) = &report.manifest {
        for component in &manifest.components {
            firmware.push(
                FirmwareComponentEvidence::new(
                    &component.name,
                    Some(component.entry_sha256.clone()),
                    None,
                    "c04.manifest",
                )?
                .with_manifest_sha256(&manifest.manifest_sha256)?,
            );
        }
    }
    Ok(C04InputProjection {
        source_sha256: report.source_sha256.clone(),
        firmware,
    })
}

#[cfg(test)]
pub(crate) fn projection_from_c05_report(
    report: &MediatekReport,
) -> Result<C05InputProjection, D03Error> {
    let firmware = report
        .bundle_entries
        .iter()
        .map(|entry| {
            FirmwareComponentEvidence::new(
                &entry.path,
                Some(entry.sha256.clone()),
                None,
                "c05.bundle_component",
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let partitions = report
        .partitions
        .iter()
        .map(|partition| {
            PartitionEvidence::new(PartitionEvidenceInput {
                name: Some(partition.partition_name.clone()),
                index: Some(partition.partition_index.clone()),
                byte_start: partition.linear_range.start,
                byte_end_exclusive: partition.linear_range.end_exclusive,
                first_lba: None,
                last_lba_inclusive: None,
                storage: Some(partition.storage.clone()),
                physical_partition: None,
                evidence_source: "c05.scatter".to_owned(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(C05InputProjection {
        source_sha256: report.source_sha256.clone(),
        firmware,
        partitions,
    })
}

#[cfg(test)]
pub(crate) fn projection_from_unisoc_report(
    report: &UnisocPacReport,
) -> Result<C06InputProjection, D03Error> {
    let firmware = report
        .entries
        .iter()
        .map(|entry| {
            let source = if entry.role == UnisocComponentRole::PartitionImage {
                "c06.unisoc.partition_image"
            } else {
                "c06.unisoc.component"
            };
            FirmwareComponentEvidence::new(
                &entry.path,
                Some(entry.sha256.clone()),
                Some((entry.range.start, entry.range.end_exclusive)),
                source,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(C06InputProjection {
        source_sha256: report.source_sha256.clone(),
        firmware,
        partitions: Vec::new(),
    })
}

#[cfg(test)]
pub(crate) fn projection_from_qualcomm_report(
    report: &QualcommBundleReport,
) -> Result<C06InputProjection, D03Error> {
    let firmware = report
        .entries
        .iter()
        .map(|entry| {
            FirmwareComponentEvidence::new(
                &entry.path,
                Some(entry.sha256.clone()),
                None,
                "c06.qualcomm.component",
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let partitions = report
        .program_operations
        .iter()
        .filter(|operation| operation.byte_range.end_exclusive > operation.byte_range.start)
        .map(|operation| {
            PartitionEvidence::new(PartitionEvidenceInput {
                name: operation
                    .label
                    .clone()
                    .or_else(|| operation.filename.clone()),
                index: Some(operation.xml_path.clone()),
                byte_start: operation.byte_range.start,
                byte_end_exclusive: operation.byte_range.end_exclusive,
                first_lba: None,
                last_lba_inclusive: None,
                storage: None,
                physical_partition: Some(operation.physical_partition),
                evidence_source: "c06.qualcomm.rawprogram.static".to_owned(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(C06InputProjection {
        source_sha256: report.source_sha256.clone(),
        firmware,
        partitions,
    })
}

fn validate_optional_text(value: Option<&str>, field: &'static str) -> Result<(), D03Error> {
    if let Some(value) = value {
        require_text(value, field)?;
    }
    Ok(())
}

fn require_text(value: &str, field: &'static str) -> Result<(), D03Error> {
    if value.trim().is_empty() || value != value.trim() || value.contains('\0') {
        return Err(D03Error::InvalidIndexInput(field));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptah_archive_decomposition::{
        AndroidArtifactKind, AndroidContext, AndroidInspectRequest, AndroidLimits,
        AppleFirmwareContext, AppleFirmwareLimits, AppleInspectRequest, C06Context, C06Limits,
        DiskImageContext, DiskImageLimits, MediatekContext, MediatekLimits, OtaDynamicGroup,
        OtaManifestObservation, OtaManifestProvider, OtaOperationRange, OtaPartitionUpdate,
        QualcommBundleEntryObservation, QualcommBundleObservation, QualcommBundleProvider,
        QualcommComponentKind, QualcommProgramOperationObservation, UnisocComponentRole,
        UnisocPacEntryObservation, UnisocPacObservation, UnisocPacProvider,
        UnisocPacValidationObservation, inspect_android_artifact, inspect_apple_firmware,
        inspect_mediatek_package, inspect_partition_map, inspect_qualcomm_bundle,
        inspect_unisoc_pac, normalize_disk_image,
    };
    use ptah_identifiers::EntityRef;
    use ptah_object_store::ProductionEvidence;
    use sha2::{Digest, Sha256};

    fn reference(kind: &str) -> EntityRef {
        EntityRef::new(kind).expect("fixture reference")
    }

    fn production() -> ProductionEvidence {
        ProductionEvidence {
            activity_ref: reference("core.activity"),
            operation_ref: reference("core.operation"),
            attempt_ref: reference("core.attempt"),
            receipt_refs: vec![reference("proof.receipt")],
        }
    }

    fn sha256(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    #[test]
    fn c01_real_parser_projects_exact_partition_range() {
        let mut source = vec![0_u8; 16 * 512];
        source[510] = 0x55;
        source[511] = 0xaa;
        let offset = 446;
        source[offset + 4] = 0x83;
        source[offset + 8..offset + 12].copy_from_slice(&2_u32.to_le_bytes());
        source[offset + 12..offset + 16].copy_from_slice(&4_u32.to_le_bytes());
        let normalized =
            normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
        let context = DiskImageContext {
            workspace_ref: reference("core.workspace"),
            authority_ref: reference("core.authority"),
            source_revision_ref: reference("object.revision"),
            production: production(),
        };
        let report = inspect_partition_map(&normalized, &context, DiskImageLimits::default())
            .expect("partition report");
        let projection = projection_from_c01_report(&report).expect("projection");
        assert_eq!(projection.source_sha256, report.source_sha256);
        assert_eq!(projection.partitions.len(), 1);
        assert_eq!(projection.partitions[0].byte_start, 1024);
        assert_eq!(projection.partitions[0].byte_end_exclusive, 3072);
        assert_eq!(projection.partitions[0].first_lba, Some(2));
        assert_eq!(projection.partitions[0].last_lba_inclusive, Some(5));
    }

    #[derive(Clone)]
    struct OtaProvider;

    impl OtaManifestProvider for OtaProvider {
        fn provider_id(&self) -> &'static str {
            "d03.c03.fixture"
        }

        fn decode_manifest(
            &self,
            _manifest_bytes: &[u8],
            _major_version: u64,
            _limits: AndroidLimits,
        ) -> Result<OtaManifestObservation, String> {
            Ok(OtaManifestObservation {
                block_size: 4096,
                partitions: vec![OtaPartitionUpdate {
                    name: "system".to_owned(),
                    new_size: Some(8192),
                    operations: vec![OtaOperationRange {
                        data_offset: 0,
                        data_length: 8,
                    }],
                }],
                dynamic_groups: vec![OtaDynamicGroup {
                    name: "group_a".to_owned(),
                    maximum_size: Some(8192),
                    partition_names: vec!["system".to_owned()],
                }],
                partial_update: false,
                complete_claim: true,
                limitations: Vec::new(),
            })
        }
    }

    #[test]
    fn c03_real_ota_parser_preserves_component_and_manifest_digest() {
        let manifest_size = 16_usize;
        let signature_size = 8_usize;
        let data_size = 32_usize;
        let mut source = vec![0_u8; 24 + manifest_size + signature_size + data_size];
        source[..4].copy_from_slice(b"CrAU");
        source[4..12].copy_from_slice(&2_u64.to_be_bytes());
        source[12..20].copy_from_slice(&(manifest_size as u64).to_be_bytes());
        source[20..24].copy_from_slice(
            &u32::try_from(signature_size)
                .expect("fixture signature size")
                .to_be_bytes(),
        );
        source[24..24 + manifest_size].fill(0xb1);
        source[24 + manifest_size..24 + manifest_size + signature_size].fill(0xb2);
        source[24 + manifest_size + signature_size..].fill(0xb3);
        let context = AndroidContext {
            workspace_ref: reference("core.workspace"),
            authority_ref: reference("core.authority"),
            source_revision_ref: reference("object.revision"),
            production: production(),
        };
        let report = inspect_android_artifact(
            &source,
            &context,
            AndroidInspectRequest {
                declared_kind: Some(AndroidArtifactKind::OtaPayload),
            },
            AndroidLimits::default(),
            Some(&OtaProvider),
        )
        .expect("OTA report");
        let manifest_sha256 = report
            .ota_manifest
            .as_ref()
            .expect("manifest")
            .manifest_sha256
            .clone();
        let projection = projection_from_c03_report(&report).expect("projection");
        let system = projection
            .firmware
            .iter()
            .find(|component| component.name == "system")
            .expect("manifest partition");
        assert_eq!(
            system.manifest_sha256.as_deref(),
            Some(manifest_sha256.as_str())
        );
        assert_eq!(projection.source_sha256, report.source_sha256);
    }

    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        assert!(content.len() < 128);
        let mut bytes = vec![
            tag,
            u8::try_from(content.len()).expect("fixture DER length"),
        ];
        bytes.extend_from_slice(content);
        bytes
    }

    fn sequence(children: &[Vec<u8>]) -> Vec<u8> {
        let content = children.iter().flatten().copied().collect::<Vec<_>>();
        der_tlv(0x30, &content)
    }

    #[test]
    fn c04_real_im4p_parser_projects_exact_der_component() {
        let source = sequence(&[
            der_tlv(0x16, b"IM4P"),
            der_tlv(0x16, b"krnl"),
            der_tlv(0x16, b"KernelCache"),
            der_tlv(0x04, b"payload-exact"),
        ]);
        let context = AppleFirmwareContext {
            workspace_ref: reference("core.workspace"),
            authority_ref: reference("core.authority"),
            source_revision_ref: reference("object.revision"),
            production: production(),
        };
        let report = inspect_apple_firmware(
            &source,
            &context,
            AppleInspectRequest::default(),
            AppleFirmwareLimits::default(),
            None,
            None,
        )
        .expect("IM4P report");
        let projection = projection_from_c04_report(&report).expect("projection");
        assert!(projection.firmware.iter().any(|component| {
            component.name == "im4p.payload" && component.byte_range.is_some()
        }));
    }

    #[test]
    fn c05_real_scatter_parser_projects_static_partition_without_write_semantics() {
        let source = br"- general: MTK_PLATFORM_CFG
  info:
    - config_version: V1.1.2
      platform: MT6789
      storage: EMMC
- partition_index: SYS0
  partition_name: otp
  file_name: NONE
  is_download: true
  type: NORMAL_ROM
  linear_start_addr: 0x1000
  physical_start_addr: 0x1000
  partition_size: 0x2000
  region: EMMC_USER
  storage: HW_STORAGE_EMMC
";
        let context = MediatekContext {
            workspace_ref: reference("core.workspace"),
            authority_ref: reference("core.authority"),
            source_revision_ref: reference("object.revision"),
            production: production(),
        };
        let report =
            inspect_mediatek_package(source, &context, MediatekLimits::default(), None, None)
                .expect("scatter report");
        let projection = projection_from_c05_report(&report).expect("projection");
        assert_eq!(projection.partitions.len(), 1);
        assert_eq!(projection.partitions[0].byte_start, 0x1000);
        assert_eq!(projection.partitions[0].byte_end_exclusive, 0x3000);
        let json = serde_json::to_string(&projection).expect("serialize");
        assert!(!json.contains("is_download"));
        assert!(!json.contains("write"));
    }

    #[derive(Clone)]
    struct QualcommProvider;

    impl QualcommBundleProvider for QualcommProvider {
        fn provider_id(&self) -> &'static str {
            "d03.c06.qualcomm"
        }

        fn inspect_bundle(
            &self,
            _primary_source: &[u8],
            _limits: C06Limits,
        ) -> Result<QualcommBundleObservation, String> {
            Ok(QualcommBundleObservation {
                entries: vec![
                    QualcommBundleEntryObservation {
                        path: "boot.img".to_owned(),
                        recovered_bytes: b"BOOT".to_vec(),
                        expected_sha256: sha256(b"BOOT"),
                        kind: QualcommComponentKind::Other,
                    },
                    QualcommBundleEntryObservation {
                        path: "rawprogram0.xml".to_owned(),
                        recovered_bytes: b"<rawprogram/>".to_vec(),
                        expected_sha256: sha256(b"<rawprogram/>"),
                        kind: QualcommComponentKind::RawprogramXml,
                    },
                ],
                program_operations: vec![QualcommProgramOperationObservation {
                    xml_path: "rawprogram0.xml".to_owned(),
                    filename: Some("boot.img".to_owned()),
                    label: Some("boot".to_owned()),
                    start_sector: 64,
                    num_partition_sectors: 8,
                    sector_size: 4096,
                    physical_partition: 0,
                }],
                patch_operations: Vec::new(),
                programmer: None,
                complete_claim: true,
                limitations: Vec::new(),
            })
        }
    }

    #[test]
    fn c06_real_qualcomm_parser_projects_static_lun_range_only() {
        let source = b"qualcomm-index";
        let context = C06Context {
            workspace_ref: reference("core.workspace"),
            authority_ref: reference("core.authority"),
            source_revision_ref: reference("object.revision"),
            production: production(),
        };
        let report =
            inspect_qualcomm_bundle(source, &context, C06Limits::default(), &QualcommProvider)
                .expect("qualcomm report");
        let projection = projection_from_qualcomm_report(&report).expect("projection");
        assert_eq!(projection.partitions.len(), 1);
        assert_eq!(projection.partitions[0].name.as_deref(), Some("boot"));
        assert_eq!(projection.partitions[0].physical_partition, Some(0));
        let json = serde_json::to_string(&projection).expect("serialize");
        assert!(!json.contains("programmer"));
        assert!(!json.contains("flash"));
    }

    #[derive(Clone)]
    struct UnisocProvider {
        observation: UnisocPacObservation,
    }

    impl UnisocPacProvider for UnisocProvider {
        fn provider_id(&self) -> &'static str {
            "d03.c06.unisoc"
        }

        fn inspect_pac(
            &self,
            _source: &[u8],
            _limits: C06Limits,
        ) -> Result<UnisocPacObservation, String> {
            Ok(self.observation.clone())
        }
    }

    #[test]
    fn c06_real_unisoc_parser_keeps_fdl_as_static_component_evidence() {
        let source = b"PAC|FDL1|SYSTEM";
        let fdl_start = 4_u64;
        let system_start = 9_u64;
        let provider = UnisocProvider {
            observation: UnisocPacObservation {
                product_name: Some("fixture".to_owned()),
                product_version: Some("1".to_owned()),
                product_alias: None,
                validation: UnisocPacValidationObservation {
                    magic_validated: true,
                    header_crc_validated: true,
                    table_crc_validated: true,
                },
                entries: vec![
                    UnisocPacEntryObservation {
                        file_id: 1,
                        path: "fdl1.bin".to_owned(),
                        file_version: None,
                        data_offset: fdl_start,
                        byte_size: 4,
                        flags: 0,
                        check_flag: 0,
                        addresses: [Some(0x5000_0000), None, None, None, None],
                        role: UnisocComponentRole::Fdl1,
                        expected_sha256: sha256(b"FDL1"),
                    },
                    UnisocPacEntryObservation {
                        file_id: 2,
                        path: "system.img".to_owned(),
                        file_version: None,
                        data_offset: system_start,
                        byte_size: 6,
                        flags: 0,
                        check_flag: 0,
                        addresses: [None, None, None, None, None],
                        role: UnisocComponentRole::PartitionImage,
                        expected_sha256: sha256(b"SYSTEM"),
                    },
                ],
                complete_claim: true,
                limitations: Vec::new(),
            },
        };
        let context = C06Context {
            workspace_ref: reference("core.workspace"),
            authority_ref: reference("core.authority"),
            source_revision_ref: reference("object.revision"),
            production: production(),
        };
        let report = inspect_unisoc_pac(source, &context, C06Limits::default(), &provider)
            .expect("unisoc report");
        let projection = projection_from_unisoc_report(&report).expect("projection");
        assert_eq!(projection.firmware.len(), 2);
        assert!(projection.partitions.is_empty());
        assert!(
            projection
                .firmware
                .iter()
                .any(|component| component.name == "fdl1.bin")
        );
    }
}
