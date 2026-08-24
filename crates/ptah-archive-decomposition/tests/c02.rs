//! C02 filesystem Provider acceptance corpus.

use ptah_archive_decomposition::{
    C02Error, FilesystemAssessment, FilesystemContentState, FilesystemContext,
    FilesystemCoverageKind, FilesystemCoverageRange, FilesystemEntry, FilesystemEntryKind,
    FilesystemExtent, FilesystemKind, FilesystemLimits, FilesystemProvider,
    FilesystemProviderAlias, ProviderFilesystemObservation, detect_filesystem, inspect_filesystem,
    materialize_filesystem_file,
};
use ptah_identifiers::EntityRef;
use ptah_object_store::{ProductionEvidence, Registration};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid fixture reference")
}

fn context(source_revision_ref: EntityRef) -> FilesystemContext {
    FilesystemContext {
        workspace_ref: reference("core.workspace"),
        authority_ref: reference("core.authority"),
        source_revision_ref,
        production: ProductionEvidence {
            activity_ref: reference("core.activity"),
            operation_ref: reference("core.operation"),
            attempt_ref: reference("core.attempt"),
            receipt_refs: vec![reference("proof.receipt")],
        },
    }
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn source_for(kind: FilesystemKind) -> Vec<u8> {
    let mut bytes = vec![0_u8; 40_000];
    match kind {
        FilesystemKind::Ext4 => bytes[1080..1082].copy_from_slice(&0xef53_u16.to_le_bytes()),
        FilesystemKind::Erofs => {
            bytes[1024..1028].copy_from_slice(&0xe0f5_e1e2_u32.to_le_bytes());
        }
        FilesystemKind::F2fs => {
            bytes[1024..1028].copy_from_slice(&0xf2f5_2010_u32.to_le_bytes());
        }
        FilesystemKind::SquashFs => bytes[0..4].copy_from_slice(b"hsqs"),
        FilesystemKind::Ubi => bytes[0..4].copy_from_slice(b"UBI#"),
        FilesystemKind::Ubifs => bytes[0..4].copy_from_slice(&[0x31, 0x18, 0x10, 0x06]),
        FilesystemKind::Fat => {
            bytes[11..13].copy_from_slice(&512_u16.to_le_bytes());
            bytes[13] = 1;
            bytes[14..16].copy_from_slice(&1_u16.to_le_bytes());
            bytes[16] = 1;
            bytes[17..19].copy_from_slice(&16_u16.to_le_bytes());
            bytes[19..21].copy_from_slice(&78_u16.to_le_bytes());
            bytes[21] = 0xf8;
            bytes[22..24].copy_from_slice(&1_u16.to_le_bytes());
            bytes[510] = 0x55;
            bytes[511] = 0xaa;
        }
        FilesystemKind::Ntfs => {
            bytes[3..11].copy_from_slice(b"NTFS    ");
            bytes[510] = 0x55;
            bytes[511] = 0xaa;
        }
        FilesystemKind::Iso9660 => {
            bytes[32_768] = 1;
            bytes[32_769..32_774].copy_from_slice(b"CD001");
        }
        FilesystemKind::Unknown => {}
    }
    bytes
}

fn exact_file(path: &str, source: &[u8], start: usize, end: usize) -> FilesystemEntry {
    FilesystemEntry {
        path: path.to_owned(),
        kind: FilesystemEntryKind::File,
        size: u64::try_from(end - start).expect("fixture size"),
        content_state: FilesystemContentState::Exact,
        extents: vec![FilesystemExtent::Data {
            source_start: u64::try_from(start).expect("start"),
            source_end_exclusive: u64::try_from(end).expect("end"),
        }],
        content_sha256: Some(sha256(&source[start..end])),
        metadata: BTreeMap::new(),
        limitations: Vec::new(),
    }
}

fn complete_observation(kind: FilesystemKind, source: &[u8]) -> ProviderFilesystemObservation {
    ProviderFilesystemObservation {
        filesystem_kind: kind,
        complete_claim: true,
        entries: vec![exact_file("etc/config", source, 2048, 2064)],
        coverage: vec![FilesystemCoverageRange {
            byte_start: 0,
            byte_end_exclusive: u64::try_from(source.len()).expect("source size"),
            kind: FilesystemCoverageKind::Read,
        }],
        metadata: BTreeMap::from([("label".to_owned(), "fixture".to_owned())]),
        limitations: Vec::new(),
    }
}

#[derive(Clone)]
struct FixtureProvider {
    alias: FilesystemProviderAlias,
    supported: Vec<FilesystemKind>,
    result: Result<ProviderFilesystemObservation, String>,
}

impl FixtureProvider {
    fn new(kind: FilesystemKind, observation: ProviderFilesystemObservation) -> Self {
        Self {
            alias: FilesystemProviderAlias {
                provider_id: format!("fixture-{}", kind.as_str()),
                provider_revision: "fixture-v1".to_owned(),
                generation: 1,
                mount_id: Some("readonly-session-1".to_owned()),
            },
            supported: vec![kind],
            result: Ok(observation),
        }
    }
}

impl FilesystemProvider for FixtureProvider {
    fn alias(&self) -> FilesystemProviderAlias {
        self.alias.clone()
    }

    fn supports(&self, kind: FilesystemKind) -> bool {
        self.supported.contains(&kind)
    }

    fn inspect(
        &self,
        _source: &[u8],
        _kind: FilesystemKind,
        _limits: FilesystemLimits,
    ) -> Result<ProviderFilesystemObservation, String> {
        self.result.clone()
    }
}

#[test]
fn required_filesystem_signatures_are_mechanically_detected() {
    let kinds = [
        FilesystemKind::Ext4,
        FilesystemKind::Erofs,
        FilesystemKind::F2fs,
        FilesystemKind::SquashFs,
        FilesystemKind::Ubi,
        FilesystemKind::Ubifs,
        FilesystemKind::Fat,
        FilesystemKind::Ntfs,
        FilesystemKind::Iso9660,
    ];
    for kind in kinds {
        let source = source_for(kind);
        let detection = detect_filesystem(&source);
        assert_eq!(detection.kind, kind);
        assert!(!detection.evidence.is_empty());
    }
    let mut fat_without_type_label = source_for(FilesystemKind::Fat);
    fat_without_type_label[54..62].copy_from_slice(b"NOTFAT!!");
    let fat = detect_filesystem(&fat_without_type_label);
    assert_eq!(fat.kind, FilesystemKind::Fat);
    assert!(fat.evidence[0].contains("FAT12"));
}

#[test]
fn no_provider_is_inconclusive_and_retains_unknown_coverage() {
    let source = source_for(FilesystemKind::Ext4);
    let ctx = context(reference("object.revision"));
    let report = inspect_filesystem(&source, &ctx, FilesystemLimits::default(), None)
        .expect("detection-only report");
    assert_eq!(report.assessment, FilesystemAssessment::Inconclusive);
    assert!(report.provider_alias.is_none());
    assert_eq!(report.coverage.len(), 1);
    assert_eq!(report.coverage[0].kind, FilesystemCoverageKind::Unknown);
    assert!(!report.limitations.is_empty());
}

#[test]
fn complete_provider_evidence_is_source_bound_and_alias_only() {
    let source = source_for(FilesystemKind::Ext4);
    let provider = FixtureProvider::new(
        FilesystemKind::Ext4,
        complete_observation(FilesystemKind::Ext4, &source),
    );
    let ctx = context(reference("object.revision"));
    let report = inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider))
        .expect("complete report");
    assert_eq!(report.assessment, FilesystemAssessment::Complete);
    assert_eq!(report.source_revision_ref, ctx.source_revision_ref);
    let alias = report.provider_alias.expect("provider alias");
    assert_eq!(alias.provider_id, "fixture-ext4");
    assert_eq!(alias.mount_id.as_deref(), Some("readonly-session-1"));
}

#[test]
fn provider_kind_disagreement_fails_closed() {
    let source = source_for(FilesystemKind::Ext4);
    let mut observation = complete_observation(FilesystemKind::Ext4, &source);
    observation.filesystem_kind = FilesystemKind::Fat;
    let provider = FixtureProvider::new(FilesystemKind::Ext4, observation);
    let ctx = context(reference("object.revision"));
    assert!(matches!(
        inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider)),
        Err(C02Error::ProviderKindMismatch)
    ));
}

#[test]
fn false_complete_claim_with_gap_is_rejected() {
    let source = source_for(FilesystemKind::Ext4);
    let mut observation = complete_observation(FilesystemKind::Ext4, &source);
    observation.coverage[0].byte_start = 1024;
    let provider = FixtureProvider::new(FilesystemKind::Ext4, observation);
    let ctx = context(reference("object.revision"));
    assert!(matches!(
        inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider)),
        Err(C02Error::FalseCompletenessClaim)
    ));
}

#[test]
fn false_complete_claim_with_unsupported_region_is_rejected() {
    let source = source_for(FilesystemKind::Ext4);
    let mut observation = complete_observation(FilesystemKind::Ext4, &source);
    observation.coverage = vec![
        FilesystemCoverageRange {
            byte_start: 0,
            byte_end_exclusive: 10_000,
            kind: FilesystemCoverageKind::Read,
        },
        FilesystemCoverageRange {
            byte_start: 10_000,
            byte_end_exclusive: u64::try_from(source.len()).expect("size"),
            kind: FilesystemCoverageKind::Unsupported,
        },
    ];
    let provider = FixtureProvider::new(FilesystemKind::Ext4, observation);
    let ctx = context(reference("object.revision"));
    assert!(matches!(
        inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider)),
        Err(C02Error::FalseCompletenessClaim)
    ));
    let mut entry_limited = complete_observation(FilesystemKind::Ext4, &source);
    entry_limited.entries[0]
        .limitations
        .push("extended attribute feature not interpreted".to_owned());
    let provider = FixtureProvider::new(FilesystemKind::Ext4, entry_limited);
    assert!(matches!(
        inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider)),
        Err(C02Error::FalseCompletenessClaim)
    ));
}

#[test]
fn partial_provider_gaps_become_explicit_unknown_coverage() {
    let source = source_for(FilesystemKind::Ext4);
    let mut observation = complete_observation(FilesystemKind::Ext4, &source);
    observation.complete_claim = false;
    observation.coverage = vec![FilesystemCoverageRange {
        byte_start: 0,
        byte_end_exclusive: 4096,
        kind: FilesystemCoverageKind::Read,
    }];
    observation.entries.clear();
    let provider = FixtureProvider::new(FilesystemKind::Ext4, observation);
    let ctx = context(reference("object.revision"));
    let report = inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider))
        .expect("partial report");
    assert_eq!(report.assessment, FilesystemAssessment::Partial);
    assert_eq!(report.coverage.len(), 2);
    assert_eq!(report.coverage[1].kind, FilesystemCoverageKind::Unknown);
    assert!(!report.limitations.is_empty());
}

#[test]
fn traversal_entry_path_is_rejected() {
    let source = source_for(FilesystemKind::Ext4);
    let mut observation = complete_observation(FilesystemKind::Ext4, &source);
    observation.entries[0].path = "../escape".to_owned();
    let provider = FixtureProvider::new(FilesystemKind::Ext4, observation);
    let ctx = context(reference("object.revision"));
    assert!(matches!(
        inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider)),
        Err(C02Error::UnsafePath)
    ));
}

#[test]
fn windows_drive_and_backslash_paths_are_rejected() {
    let source = source_for(FilesystemKind::Ext4);
    let ctx = context(reference("object.revision"));
    for unsafe_path in ["C:/escape", "dir\\escape"] {
        let mut observation = complete_observation(FilesystemKind::Ext4, &source);
        observation.entries[0].path = unsafe_path.to_owned();
        let provider = FixtureProvider::new(FilesystemKind::Ext4, observation);
        assert!(matches!(
            inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider)),
            Err(C02Error::UnsafePath)
        ));
    }
}

#[test]
fn duplicate_inventory_paths_are_rejected() {
    let source = source_for(FilesystemKind::Ext4);
    let mut observation = complete_observation(FilesystemKind::Ext4, &source);
    observation.entries.push(observation.entries[0].clone());
    let provider = FixtureProvider::new(FilesystemKind::Ext4, observation);
    let ctx = context(reference("object.revision"));
    assert!(matches!(
        inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider)),
        Err(C02Error::DuplicatePath)
    ));
}

#[test]
fn out_of_bounds_exact_extent_is_rejected() {
    let source = source_for(FilesystemKind::Ext4);
    let mut observation = complete_observation(FilesystemKind::Ext4, &source);
    observation.entries[0].extents = vec![FilesystemExtent::Data {
        source_start: 39_999,
        source_end_exclusive: 40_001,
    }];
    observation.entries[0].size = 2;
    let provider = FixtureProvider::new(FilesystemKind::Ext4, observation);
    let ctx = context(reference("object.revision"));
    assert!(matches!(
        inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider)),
        Err(C02Error::InvalidExtent)
    ));
}

#[test]
fn exact_extent_must_be_backed_by_read_coverage() {
    let source = source_for(FilesystemKind::Ext4);
    let mut observation = complete_observation(FilesystemKind::Ext4, &source);
    observation.complete_claim = false;
    observation.coverage = vec![
        FilesystemCoverageRange {
            byte_start: 0,
            byte_end_exclusive: 2048,
            kind: FilesystemCoverageKind::Read,
        },
        FilesystemCoverageRange {
            byte_start: 2048,
            byte_end_exclusive: 2064,
            kind: FilesystemCoverageKind::Unknown,
        },
    ];
    let provider = FixtureProvider::new(FilesystemKind::Ext4, observation);
    let ctx = context(reference("object.revision"));
    assert!(matches!(
        inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider)),
        Err(C02Error::ExtentNotReadable)
    ));
}

#[test]
fn unsupported_regular_file_requires_explicit_limitation() {
    let source = source_for(FilesystemKind::Ext4);
    let mut observation = complete_observation(FilesystemKind::Ext4, &source);
    let entry = &mut observation.entries[0];
    entry.content_state = FilesystemContentState::Unsupported;
    entry.extents.clear();
    entry.content_sha256 = None;
    entry.limitations.clear();
    observation.complete_claim = false;
    let provider = FixtureProvider::new(FilesystemKind::Ext4, observation);
    let ctx = context(reference("object.revision"));
    assert!(matches!(
        inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider)),
        Err(C02Error::ExactFileMismatch)
    ));
}

#[test]
fn exact_file_materialization_is_read_only_and_digest_bound() {
    let mut source = source_for(FilesystemKind::Ext4);
    source[2048..2064].copy_from_slice(b"0123456789abcdef");
    let before = source.clone();
    let provider = FixtureProvider::new(
        FilesystemKind::Ext4,
        complete_observation(FilesystemKind::Ext4, &source),
    );
    let ctx = context(reference("object.revision"));
    let report = inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider))
        .expect("report");
    let file = materialize_filesystem_file(
        &source,
        &report,
        "etc/config",
        &ctx,
        FilesystemLimits::default(),
    )
    .expect("materialize");
    assert_eq!(file.bytes(), b"0123456789abcdef");
    assert_eq!(source, before);
    assert_eq!(file.sha256, sha256(file.bytes()));
}

#[test]
fn report_mutation_cannot_authorize_materialization() {
    let source = source_for(FilesystemKind::Ext4);
    let provider = FixtureProvider::new(
        FilesystemKind::Ext4,
        complete_observation(FilesystemKind::Ext4, &source),
    );
    let ctx = context(reference("object.revision"));
    let report = inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider))
        .expect("report");
    let mut forged = report.clone();
    forged.entries[0].path = "forged".to_owned();
    assert!(matches!(
        materialize_filesystem_file(
            &source,
            &forged,
            "forged",
            &ctx,
            FilesystemLimits::default()
        ),
        Err(C02Error::ReportIntegrityMismatch)
    ));
}

#[test]
fn source_mutation_invalidates_materialization_binding() {
    let source = source_for(FilesystemKind::Ext4);
    let provider = FixtureProvider::new(
        FilesystemKind::Ext4,
        complete_observation(FilesystemKind::Ext4, &source),
    );
    let ctx = context(reference("object.revision"));
    let report = inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider))
        .expect("report");
    let mut changed = source.clone();
    changed[3000] ^= 0xff;
    assert!(matches!(
        materialize_filesystem_file(
            &changed,
            &report,
            "etc/config",
            &ctx,
            FilesystemLimits::default()
        ),
        Err(C02Error::SourceBindingMismatch)
    ));
}

#[test]
fn exact_file_builds_a07_registration_and_relationship_plans() {
    let source = source_for(FilesystemKind::Ext4);
    let provider = FixtureProvider::new(
        FilesystemKind::Ext4,
        complete_observation(FilesystemKind::Ext4, &source),
    );
    let ctx = context(reference("object.revision"));
    let report = inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider))
        .expect("report");
    let file = materialize_filesystem_file(
        &source,
        &report,
        "etc/config",
        &ctx,
        FilesystemLimits::default(),
    )
    .expect("file");
    let spec = file.registration_spec(&ctx).expect("registration plan");
    assert_eq!(spec.object_class, "filesystem.file");
    assert_eq!(spec.source_refs, vec![ctx.source_revision_ref.clone()]);
    let registration = Registration {
        content_ref: reference("object.content"),
        object_ref: reference("object.object"),
        revision_ref: reference("object.revision"),
        location_ref: reference("storage.location"),
        sha256: file.sha256.clone(),
        byte_size: u64::try_from(file.bytes().len()).expect("size"),
        cas_object_key: file.sha256.clone(),
        content_deduplicated: false,
    };
    let relationship = file
        .relationship_spec(&ctx, &registration)
        .expect("relationship");
    assert_eq!(relationship.relationship_type, "contains.filesystem_file");
    assert_eq!(
        relationship.subject_refs,
        vec![ctx.source_revision_ref.clone()]
    );
}

#[test]
fn view_plans_are_exact_source_bound() {
    let source = source_for(FilesystemKind::Ext4);
    let provider = FixtureProvider::new(
        FilesystemKind::Ext4,
        complete_observation(FilesystemKind::Ext4, &source),
    );
    let ctx = context(reference("object.revision"));
    let report = inspect_filesystem(&source, &ctx, FilesystemLimits::default(), Some(&provider))
        .expect("report");
    let views = report.view_specs(&ctx).expect("views");
    assert_eq!(views.len(), 2);
    assert!(
        views
            .iter()
            .all(|view| view.source_revision_refs == vec![ctx.source_revision_ref.clone()])
    );
    let other = context(reference("object.revision"));
    assert!(matches!(
        report.view_specs(&other),
        Err(C02Error::SourceBindingMismatch)
    ));
}

#[test]
fn configured_inventory_and_metadata_bounds_fail_closed() {
    let source = source_for(FilesystemKind::Ext4);
    let observation = complete_observation(FilesystemKind::Ext4, &source);
    let provider = FixtureProvider::new(FilesystemKind::Ext4, observation.clone());
    let ctx = context(reference("object.revision"));
    let limits = FilesystemLimits {
        max_entries: 1,
        ..FilesystemLimits::default()
    };
    let mut too_many = observation.clone();
    too_many.entries.push(FilesystemEntry {
        path: "second".to_owned(),
        kind: FilesystemEntryKind::Directory,
        size: 0,
        content_state: FilesystemContentState::MetadataOnly,
        extents: Vec::new(),
        content_sha256: None,
        metadata: BTreeMap::new(),
        limitations: Vec::new(),
    });
    let provider_many = FixtureProvider::new(FilesystemKind::Ext4, too_many);
    assert!(matches!(
        inspect_filesystem(&source, &ctx, limits, Some(&provider_many)),
        Err(C02Error::TooManyEntries)
    ));

    let tiny = FilesystemLimits {
        max_string_bytes: 3,
        ..FilesystemLimits::default()
    };
    assert!(matches!(
        inspect_filesystem(&source, &ctx, tiny, Some(&provider)),
        Err(C02Error::InvalidProviderAlias | C02Error::MetadataTooLarge)
    ));
}

#[test]
fn provider_failure_and_unknown_signature_never_manufacture_completeness() {
    let source = source_for(FilesystemKind::Ext4);
    let mut provider = FixtureProvider::new(
        FilesystemKind::Ext4,
        complete_observation(FilesystemKind::Ext4, &source),
    );
    provider.result = Err("engine unavailable".to_owned());
    let ctx = context(reference("object.revision"));
    assert!(matches!(
        inspect_filesystem(
            &source,
            &ctx,
            FilesystemLimits::default(),
            Some(&provider)
        ),
        Err(C02Error::Provider(message)) if message == "engine unavailable"
    ));

    let unknown = vec![0_u8; 4096];
    let report = inspect_filesystem(&unknown, &ctx, FilesystemLimits::default(), Some(&provider))
        .expect("unknown report");
    assert_eq!(report.detection.kind, FilesystemKind::Unknown);
    assert_eq!(report.assessment, FilesystemAssessment::Inconclusive);
    assert!(report.provider_alias.is_none());
}
