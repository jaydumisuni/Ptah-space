//! C06 Unisoc PAC and Qualcomm MBN/ELF/Firehose/XML static acceptance corpus.

use ptah_archive_decomposition::{
    C06Assessment, C06ComparisonLevel, C06Context, C06Error, C06Limits, C06StaticProofLevel,
    C06TrustAssessment, QualcommBundleEntryObservation, QualcommBundleObservation,
    QualcommBundleProvider, QualcommComponentKind, QualcommPatchOperationObservation,
    QualcommProgramOperationObservation, QualcommProgrammerObservation, UnisocComponentRole,
    UnisocPacEntryObservation, UnisocPacObservation, UnisocPacProvider,
    UnisocPacValidationObservation, compare_qualcomm_bundles, compare_unisoc_packages,
    inspect_qualcomm_bundle, inspect_unisoc_pac, materialize_qualcomm_component,
    materialize_unisoc_component,
};
use ptah_identifiers::EntityRef;
use ptah_object_store::{ProductionEvidence, Registration};
use sha2::{Digest, Sha256};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid fixture reference")
}

fn context() -> C06Context {
    C06Context {
        workspace_ref: reference("core.workspace"),
        authority_ref: reference("core.authority"),
        source_revision_ref: reference("object.revision"),
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

fn pac_source() -> Vec<u8> {
    b"PAC-HEADER|FDL1-EXACT|FDL2-EXACT|SYSTEM-EXACT|PAC-TAIL".to_vec()
}

fn source_slice(source: &[u8], needle: &[u8]) -> (u64, u64) {
    let start = source
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("fixture slice");
    (
        u64::try_from(start).expect("fixture offset"),
        u64::try_from(needle.len()).expect("fixture size"),
    )
}

fn pac_entry(
    source: &[u8],
    file_id: u32,
    path: &str,
    bytes: &[u8],
    role: UnisocComponentRole,
    base: Option<u64>,
) -> UnisocPacEntryObservation {
    let (data_offset, byte_size) = source_slice(source, bytes);
    UnisocPacEntryObservation {
        file_id,
        path: path.to_owned(),
        file_version: Some("1.0".to_owned()),
        data_offset,
        byte_size,
        flags: 1,
        check_flag: 1,
        addresses: [base, None, None, None, None],
        role,
        expected_sha256: sha256(bytes),
    }
}

#[derive(Clone)]
struct FixturePacProvider {
    observation: UnisocPacObservation,
    fail: Option<String>,
}

impl UnisocPacProvider for FixturePacProvider {
    fn provider_id(&self) -> &'static str {
        "fixture.unisoc.pac"
    }

    fn inspect_pac(
        &self,
        _source: &[u8],
        _limits: C06Limits,
    ) -> Result<UnisocPacObservation, String> {
        if let Some(error) = &self.fail {
            Err(error.clone())
        } else {
            Ok(self.observation.clone())
        }
    }
}

fn good_pac_provider(source: &[u8]) -> FixturePacProvider {
    FixturePacProvider {
        observation: UnisocPacObservation {
            product_name: Some("T606 fixture".to_owned()),
            product_version: Some("1.0".to_owned()),
            product_alias: Some("C06".to_owned()),
            validation: UnisocPacValidationObservation {
                magic_validated: true,
                header_crc_validated: true,
                table_crc_validated: true,
            },
            entries: vec![
                pac_entry(
                    source,
                    1,
                    "fdl1.bin",
                    b"FDL1-EXACT",
                    UnisocComponentRole::Fdl1,
                    Some(0x5000_0000),
                ),
                pac_entry(
                    source,
                    2,
                    "fdl2.bin",
                    b"FDL2-EXACT",
                    UnisocComponentRole::Fdl2,
                    Some(0x9eff_fe00),
                ),
                pac_entry(
                    source,
                    3,
                    "system.img",
                    b"SYSTEM-EXACT",
                    UnisocComponentRole::PartitionImage,
                    None,
                ),
            ],
            complete_claim: true,
            limitations: Vec::new(),
        },
        fail: None,
    }
}

fn q_entry(
    path: &str,
    bytes: &[u8],
    kind: QualcommComponentKind,
) -> QualcommBundleEntryObservation {
    QualcommBundleEntryObservation {
        path: path.to_owned(),
        recovered_bytes: bytes.to_vec(),
        expected_sha256: sha256(bytes),
        kind,
    }
}

#[derive(Clone)]
struct FixtureQualcommProvider {
    observation: QualcommBundleObservation,
    fail: Option<String>,
}

impl QualcommBundleProvider for FixtureQualcommProvider {
    fn provider_id(&self) -> &'static str {
        "fixture.qualcomm.bundle"
    }

    fn inspect_bundle(
        &self,
        _primary_source: &[u8],
        _limits: C06Limits,
    ) -> Result<QualcommBundleObservation, String> {
        if let Some(error) = &self.fail {
            Err(error.clone())
        } else {
            Ok(self.observation.clone())
        }
    }
}

fn good_qualcomm_provider() -> FixtureQualcommProvider {
    FixtureQualcommProvider {
        observation: QualcommBundleObservation {
            entries: vec![
                q_entry(
                    "prog_firehose_ddr.elf",
                    b"ELF-PROGRAMMER",
                    QualcommComponentKind::FirehoseProgrammer,
                ),
                q_entry("xbl.elf", b"XBL-ELF", QualcommComponentKind::Elf),
                q_entry("boot.img", b"BOOT-IMAGE", QualcommComponentKind::Other),
                q_entry(
                    "rawprogram0.xml",
                    b"<rawprogram/>",
                    QualcommComponentKind::RawprogramXml,
                ),
                q_entry("patch0.xml", b"<patch/>", QualcommComponentKind::PatchXml),
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
            patch_operations: vec![QualcommPatchOperationObservation {
                xml_path: "patch0.xml".to_owned(),
                start_sector: 1,
                byte_offset: 8,
                size_bytes: 4,
                sector_size: 4096,
                physical_partition: 0,
            }],
            programmer: Some(QualcommProgrammerObservation {
                component_path: "prog_firehose_ddr.elf".to_owned(),
                target_claim: Some("SM7250".to_owned()),
                hwid_claim: Some("fixture-hwid".to_owned()),
                pkhash_claim: Some("fixture-pkhash".to_owned()),
                signature_observed: true,
            }),
            complete_claim: true,
            limitations: Vec::new(),
        },
        fail: None,
    }
}

fn inspect_pac(
    source: &[u8],
    provider: &dyn UnisocPacProvider,
) -> Result<ptah_archive_decomposition::UnisocPacReport, C06Error> {
    inspect_unisoc_pac(source, &context(), C06Limits::default(), provider)
}

fn inspect_q(
    primary: &[u8],
    provider: &dyn QualcommBundleProvider,
) -> Result<ptah_archive_decomposition::QualcommBundleReport, C06Error> {
    inspect_qualcomm_bundle(primary, &context(), C06Limits::default(), provider)
}

/* 1 */
#[test]
fn unisoc_valid_pac_inventory_exact_ranges_and_loader_evidence() {
    let source = pac_source();
    let provider = good_pac_provider(&source);
    let report = inspect_pac(&source, &provider).expect("valid PAC");
    assert_eq!(report.assessment, C06Assessment::Complete);
    assert_eq!(
        report.proof_level,
        Some(C06StaticProofLevel::StructureChecked)
    );
    assert_eq!(report.entries.len(), 3);
    assert_eq!(report.loaders.len(), 2);
    assert!(
        report
            .loaders
            .iter()
            .all(|loader| loader.compatibility == C06TrustAssessment::NotEstablished)
    );
    assert_eq!(report.trust, C06TrustAssessment::NotEstablished);
}

/* 2 */
#[test]
fn unisoc_out_of_range_and_overlapping_entries_fail_closed() {
    let source = pac_source();
    let mut out_of_range = good_pac_provider(&source);
    out_of_range.observation.entries[0].data_offset =
        u64::try_from(source.len()).expect("fixture size");
    assert_eq!(
        inspect_pac(&source, &out_of_range).expect_err("outside source"),
        C06Error::RangeOutsideSource
    );

    let mut overlap = good_pac_provider(&source);
    overlap.observation.entries[1].data_offset = overlap.observation.entries[0].data_offset;
    overlap.observation.entries[1].byte_size = overlap.observation.entries[0].byte_size;
    overlap.observation.entries[1].expected_sha256 =
        overlap.observation.entries[0].expected_sha256.clone();
    assert_eq!(
        inspect_pac(&source, &overlap).expect_err("overlap"),
        C06Error::OverlappingRanges
    );
}

/* 3 */
#[test]
fn unisoc_duplicate_ids_paths_and_unsafe_paths_are_rejected() {
    let source = pac_source();
    let mut duplicate_id = good_pac_provider(&source);
    duplicate_id.observation.entries[1].file_id = 1;
    assert_eq!(
        inspect_pac(&source, &duplicate_id).expect_err("duplicate id"),
        C06Error::DuplicateEntry
    );

    let mut duplicate_path = good_pac_provider(&source);
    duplicate_path.observation.entries[1].path = "fdl1.bin".to_owned();
    assert_eq!(
        inspect_pac(&source, &duplicate_path).expect_err("duplicate path"),
        C06Error::DuplicateEntry
    );

    for path in [
        "../escape.bin",
        "/absolute.bin",
        "dir\\file.bin",
        "C:/drive.bin",
    ] {
        let mut unsafe_provider = good_pac_provider(&source);
        unsafe_provider.observation.entries[0].path = path.to_owned();
        assert_eq!(
            inspect_pac(&source, &unsafe_provider).expect_err("unsafe path"),
            C06Error::InvalidPath
        );
    }
}

/* 4 */
#[test]
fn unisoc_source_slice_digest_lie_is_rejected() {
    let source = pac_source();
    let mut provider = good_pac_provider(&source);
    provider.observation.entries[0].expected_sha256 = "0".repeat(64);
    assert_eq!(
        inspect_pac(&source, &provider).expect_err("digest mismatch"),
        C06Error::DigestMismatch
    );
}

/* 5 */
#[test]
fn unisoc_missing_magic_or_crc_validation_reduces_truth_not_loader_trust() {
    let source = pac_source();
    let mut provider = good_pac_provider(&source);
    provider.observation.validation.table_crc_validated = false;
    let report = inspect_pac(&source, &provider).expect("partial PAC remains reportable");
    assert_eq!(report.assessment, C06Assessment::Partial);
    assert_eq!(report.proof_level, Some(C06StaticProofLevel::InventoryOnly));
    assert_eq!(report.trust, C06TrustAssessment::NotEstablished);
    assert!(
        report
            .limitations
            .iter()
            .any(|value| value.contains("file-table CRC"))
    );
}

/* 6 */
#[test]
fn unisoc_fdl_roles_and_base_addresses_are_evidence_only() {
    let source = pac_source();
    let provider = good_pac_provider(&source);
    let report = inspect_pac(&source, &provider).expect("valid PAC");
    let fdl1 = report
        .loaders
        .iter()
        .find(|loader| loader.role == UnisocComponentRole::Fdl1)
        .expect("FDL1");
    assert_eq!(fdl1.base_address, Some(0x5000_0000));
    assert_eq!(fdl1.compatibility, C06TrustAssessment::NotEstablished);
    assert_eq!(report.trust, C06TrustAssessment::NotEstablished);
}

/* 7 */
#[test]
fn unisoc_bounds_and_provider_failure_are_explicit() {
    let source = pac_source();
    let provider = good_pac_provider(&source);
    let limits = C06Limits {
        max_entries: 1,
        ..C06Limits::default()
    };
    assert_eq!(
        inspect_unisoc_pac(&source, &context(), limits, &provider).expect_err("entry bound"),
        C06Error::TooManyEntries
    );

    let failed = FixturePacProvider {
        observation: provider.observation,
        fail: Some("mechanical parser failed".to_owned()),
    };
    assert!(matches!(
        inspect_pac(&source, &failed).expect_err("provider failure"),
        C06Error::UnisocProvider(_)
    ));
}

/* 8 */
#[test]
fn unisoc_report_mutation_and_changed_source_fail_reuse() {
    let source = pac_source();
    let provider = good_pac_provider(&source);
    let ctx = context();
    let mut report =
        inspect_unisoc_pac(&source, &ctx, C06Limits::default(), &provider).expect("report");
    report.assessment = C06Assessment::Inconclusive;
    assert_eq!(
        report.view_specs(&ctx).expect_err("mutated report"),
        C06Error::ReportIntegrityMismatch
    );

    let report =
        inspect_unisoc_pac(&source, &ctx, C06Limits::default(), &provider).expect("fresh report");
    let mut changed = source.clone();
    changed.push(b'!');
    assert_eq!(
        materialize_unisoc_component(&changed, &report, "fdl1.bin", &ctx, C06Limits::default())
            .expect_err("changed source"),
        C06Error::SourceBindingMismatch
    );
}

/* 9 */
#[test]
fn unisoc_materialization_registration_relationship_and_views_are_source_bound() {
    let source = pac_source();
    let provider = good_pac_provider(&source);
    let ctx = context();
    let report =
        inspect_unisoc_pac(&source, &ctx, C06Limits::default(), &provider).expect("report");
    let child =
        materialize_unisoc_component(&source, &report, "fdl1.bin", &ctx, C06Limits::default())
            .expect("component");
    assert_eq!(child.bytes(), b"FDL1-EXACT");
    let spec = child.registration_spec(&ctx).expect("registration");
    assert_eq!(spec.source_refs, vec![ctx.source_revision_ref.clone()]);
    assert_eq!(spec.expected_sha256, Some(child.sha256.clone()));

    let registration = Registration {
        content_ref: reference("object.content"),
        object_ref: reference("object.object"),
        revision_ref: reference("object.revision"),
        location_ref: reference("storage.location"),
        sha256: child.sha256.clone(),
        byte_size: u64::try_from(child.bytes().len()).expect("size"),
        cas_object_key: "sha256/c06-unisoc".to_owned(),
        content_deduplicated: false,
    };
    let relationship = child
        .relationship_spec(&ctx, &registration)
        .expect("relationship");
    assert_eq!(
        relationship.relationship_type,
        "contains.unisoc_pac_component"
    );
    assert_eq!(
        relationship.subject_refs,
        vec![ctx.source_revision_ref.clone()]
    );
    assert_eq!(report.view_specs(&ctx).expect("views").len(), 3);
}

/* 10 */
#[test]
fn unisoc_comparison_distinguishes_structure_components_and_primary_bytes() {
    let source = pac_source();
    let provider = good_pac_provider(&source);
    let left = inspect_pac(&source, &provider).expect("left");
    let exact = inspect_pac(&source, &provider).expect("exact");
    assert_eq!(
        compare_unisoc_packages(&left, &exact).level,
        C06ComparisonLevel::ByteExact
    );

    let mut appended = source.clone();
    appended.push(b'!');
    let appended_provider = good_pac_provider(&appended);
    let component_exact = inspect_pac(&appended, &appended_provider).expect("component exact");
    assert_eq!(
        compare_unisoc_packages(&left, &component_exact).level,
        C06ComparisonLevel::ComponentExact
    );

    let changed = b"PAC-HEADER|FDL1-ALTER|FDL2-EXACT|SYSTEM-EXACT|PAC-TAIL".to_vec();
    let changed_provider = FixturePacProvider {
        observation: UnisocPacObservation {
            entries: vec![
                pac_entry(
                    &changed,
                    1,
                    "fdl1.bin",
                    b"FDL1-ALTER",
                    UnisocComponentRole::Fdl1,
                    Some(0x5000_0000),
                ),
                pac_entry(
                    &changed,
                    2,
                    "fdl2.bin",
                    b"FDL2-EXACT",
                    UnisocComponentRole::Fdl2,
                    Some(0x9eff_fe00),
                ),
                pac_entry(
                    &changed,
                    3,
                    "system.img",
                    b"SYSTEM-EXACT",
                    UnisocComponentRole::PartitionImage,
                    None,
                ),
            ],
            ..good_pac_provider(&source).observation
        },
        fail: None,
    };
    let structural = inspect_pac(&changed, &changed_provider).expect("structural");
    assert_eq!(
        compare_unisoc_packages(&left, &structural).level,
        C06ComparisonLevel::Structural
    );

    let mut different_provider = good_pac_provider(&source);
    different_provider.observation.entries[2].flags = 7;
    let different = inspect_pac(&source, &different_provider).expect("different");
    assert_eq!(
        compare_unisoc_packages(&left, &different).level,
        C06ComparisonLevel::Different
    );
}

/* 11 */
#[test]
fn qualcomm_valid_bundle_links_program_plan_patch_and_programmer_evidence() {
    let primary = b"QUALCOMM-INDEX".to_vec();
    let provider = good_qualcomm_provider();
    let report = inspect_q(&primary, &provider).expect("valid Qualcomm bundle");
    assert_eq!(report.assessment, C06Assessment::Complete);
    assert_eq!(report.proof_level, Some(C06StaticProofLevel::PlanLinked));
    assert_eq!(report.program_operations.len(), 1);
    assert_eq!(report.patch_operations.len(), 1);
    assert!(report.program_operations[0].component_resolved);
    let programmer = report.programmer.expect("programmer evidence");
    assert_eq!(programmer.compatibility, C06TrustAssessment::NotEstablished);
    assert_eq!(report.trust, C06TrustAssessment::NotEstablished);
}

/* 12 */
#[test]
fn qualcomm_bundle_paths_duplicates_and_digest_lies_are_rejected() {
    let primary = b"QUALCOMM-INDEX".to_vec();
    for path in ["../escape", "/absolute", "dir\\child", "C:/drive"] {
        let mut provider = good_qualcomm_provider();
        provider.observation.entries[0].path = path.to_owned();
        assert_eq!(
            inspect_q(&primary, &provider).expect_err("unsafe path"),
            C06Error::InvalidPath
        );
    }

    let mut duplicate = good_qualcomm_provider();
    duplicate.observation.entries[1].path = duplicate.observation.entries[0].path.clone();
    assert_eq!(
        inspect_q(&primary, &duplicate).expect_err("duplicate path"),
        C06Error::DuplicateEntry
    );

    let mut digest = good_qualcomm_provider();
    digest.observation.entries[0].expected_sha256 = "f".repeat(64);
    assert_eq!(
        inspect_q(&primary, &digest).expect_err("digest mismatch"),
        C06Error::DigestMismatch
    );
}

/* 13 */
#[test]
fn qualcomm_missing_rawprogram_component_reference_reduces_truth() {
    let primary = b"QUALCOMM-INDEX".to_vec();
    let mut provider = good_qualcomm_provider();
    provider.observation.program_operations[0].filename = Some("missing.img".to_owned());
    let report = inspect_q(&primary, &provider).expect("partial plan remains reportable");
    assert_eq!(report.assessment, C06Assessment::Partial);
    assert_eq!(
        report.proof_level,
        Some(C06StaticProofLevel::ComponentsLinked)
    );
    assert!(!report.program_operations[0].component_resolved);
    assert!(
        report
            .limitations
            .iter()
            .any(|value| value.contains("unresolved"))
    );
}

/* 14 */
#[test]
fn qualcomm_sector_zero_overflow_and_invalid_patch_ranges_fail_closed() {
    let primary = b"QUALCOMM-INDEX".to_vec();
    let mut zero = good_qualcomm_provider();
    zero.observation.program_operations[0].sector_size = 0;
    assert_eq!(
        inspect_q(&primary, &zero).expect_err("zero sector"),
        C06Error::InvalidSectorSize
    );

    let mut overflow = good_qualcomm_provider();
    overflow.observation.program_operations[0].start_sector = u64::MAX;
    overflow.observation.program_operations[0].sector_size = 4096;
    assert_eq!(
        inspect_q(&primary, &overflow).expect_err("range overflow"),
        C06Error::RangeOverflow
    );

    let mut patch = good_qualcomm_provider();
    patch.observation.patch_operations[0].byte_offset = 4096;
    assert_eq!(
        inspect_q(&primary, &patch).expect_err("patch range"),
        C06Error::InvalidPatchRange
    );
}

/* 15 */
#[test]
fn qualcomm_xml_source_kind_and_missing_source_fail_closed() {
    let primary = b"QUALCOMM-INDEX".to_vec();
    let mut wrong_kind = good_qualcomm_provider();
    let raw = wrong_kind
        .observation
        .entries
        .iter_mut()
        .find(|entry| entry.path == "rawprogram0.xml")
        .expect("rawprogram");
    raw.kind = QualcommComponentKind::Other;
    assert_eq!(
        inspect_q(&primary, &wrong_kind).expect_err("wrong XML kind"),
        C06Error::InvalidPlanSourceKind
    );

    let mut missing = good_qualcomm_provider();
    missing
        .observation
        .entries
        .retain(|entry| entry.path != "patch0.xml");
    assert_eq!(
        inspect_q(&primary, &missing).expect_err("missing patch source"),
        C06Error::PlanSourceNotFound
    );
}

/* 16 */
#[test]
fn qualcomm_programmer_metadata_never_establishes_device_compatibility() {
    let primary = b"QUALCOMM-INDEX".to_vec();
    let provider = good_qualcomm_provider();
    let report = inspect_q(&primary, &provider).expect("bundle");
    let programmer = report.programmer.expect("programmer");
    assert_eq!(programmer.target_claim.as_deref(), Some("SM7250"));
    assert_eq!(programmer.hwid_claim.as_deref(), Some("fixture-hwid"));
    assert_eq!(programmer.pkhash_claim.as_deref(), Some("fixture-pkhash"));
    assert!(programmer.signature_observed);
    assert_eq!(programmer.compatibility, C06TrustAssessment::NotEstablished);
    assert_eq!(report.trust, C06TrustAssessment::NotEstablished);
}

/* 17 */
#[test]
fn qualcomm_provider_limitations_and_bounds_reduce_or_reject_truth() {
    let primary = b"QUALCOMM-INDEX".to_vec();
    let mut partial = good_qualcomm_provider();
    partial.observation.limitations = vec!["fixture unsupported XML attribute".to_owned()];
    let report = inspect_q(&primary, &partial).expect("partial report");
    assert_eq!(report.assessment, C06Assessment::Partial);

    let provider = good_qualcomm_provider();
    let limits = C06Limits {
        max_operations: 1,
        ..C06Limits::default()
    };
    assert_eq!(
        inspect_qualcomm_bundle(&primary, &context(), limits, &provider)
            .expect_err("operation bound"),
        C06Error::TooManyOperations
    );

    let limits = C06Limits {
        max_recovered_bytes: 4,
        ..C06Limits::default()
    };
    assert_eq!(
        inspect_qualcomm_bundle(&primary, &context(), limits, &provider).expect_err("byte bound"),
        C06Error::TooManyRecoveredBytes
    );
}

/* 18 */
#[test]
fn qualcomm_report_mutation_primary_source_mismatch_and_provider_failure_are_explicit() {
    let primary = b"QUALCOMM-INDEX".to_vec();
    let provider = good_qualcomm_provider();
    let ctx = context();
    let mut report =
        inspect_qualcomm_bundle(&primary, &ctx, C06Limits::default(), &provider).expect("report");
    report.assessment = C06Assessment::Inconclusive;
    assert_eq!(
        report.view_specs(&ctx).expect_err("mutated report"),
        C06Error::ReportIntegrityMismatch
    );

    let report =
        inspect_qualcomm_bundle(&primary, &ctx, C06Limits::default(), &provider).expect("fresh");
    let mut changed = primary.clone();
    changed.push(b'!');
    assert_eq!(
        materialize_qualcomm_component(&changed, &report, "boot.img", &ctx, C06Limits::default())
            .expect_err("changed source"),
        C06Error::SourceBindingMismatch
    );

    let failed = FixtureQualcommProvider {
        observation: provider.observation,
        fail: Some("mechanical bundle parser failed".to_owned()),
    };
    assert!(matches!(
        inspect_q(&primary, &failed).expect_err("provider failure"),
        C06Error::QualcommProvider(_)
    ));
}

/* 19 */
#[test]
fn qualcomm_materialization_registration_relationship_and_views_are_source_bound() {
    let primary = b"QUALCOMM-INDEX".to_vec();
    let provider = good_qualcomm_provider();
    let ctx = context();
    let report =
        inspect_qualcomm_bundle(&primary, &ctx, C06Limits::default(), &provider).expect("report");
    let child =
        materialize_qualcomm_component(&primary, &report, "boot.img", &ctx, C06Limits::default())
            .expect("component");
    assert_eq!(child.bytes(), b"BOOT-IMAGE");
    let spec = child.registration_spec(&ctx).expect("registration");
    assert_eq!(spec.source_refs, vec![ctx.source_revision_ref.clone()]);
    assert_eq!(spec.expected_sha256, Some(child.sha256.clone()));

    let registration = Registration {
        content_ref: reference("object.content"),
        object_ref: reference("object.object"),
        revision_ref: reference("object.revision"),
        location_ref: reference("storage.location"),
        sha256: child.sha256.clone(),
        byte_size: u64::try_from(child.bytes().len()).expect("size"),
        cas_object_key: "sha256/c06-qualcomm".to_owned(),
        content_deduplicated: false,
    };
    let relationship = child
        .relationship_spec(&ctx, &registration)
        .expect("relationship");
    assert_eq!(
        relationship.relationship_type,
        "references.qualcomm_firmware_component"
    );
    assert_eq!(
        relationship.subject_refs,
        vec![ctx.source_revision_ref.clone()]
    );
    assert_eq!(report.view_specs(&ctx).expect("views").len(), 4);
}

/* 20 */
#[test]
fn qualcomm_comparison_distinguishes_structure_components_and_primary_bytes() {
    let primary = b"QUALCOMM-INDEX".to_vec();
    let provider = good_qualcomm_provider();
    let left = inspect_q(&primary, &provider).expect("left");
    let exact = inspect_q(&primary, &provider).expect("exact");
    assert_eq!(
        compare_qualcomm_bundles(&left, &exact).level,
        C06ComparisonLevel::ByteExact
    );

    let mut primary_changed = primary.clone();
    primary_changed.push(b'!');
    let component_exact = inspect_q(&primary_changed, &provider).expect("component exact");
    assert_eq!(
        compare_qualcomm_bundles(&left, &component_exact).level,
        C06ComparisonLevel::ComponentExact
    );

    let mut bytes_changed = good_qualcomm_provider();
    let boot = bytes_changed
        .observation
        .entries
        .iter_mut()
        .find(|entry| entry.path == "boot.img")
        .expect("boot");
    boot.recovered_bytes = b"BOOT-ALTER".to_vec();
    boot.expected_sha256 = sha256(&boot.recovered_bytes);
    let structural = inspect_q(&primary, &bytes_changed).expect("structural");
    assert_eq!(
        compare_qualcomm_bundles(&left, &structural).level,
        C06ComparisonLevel::Structural
    );

    let mut structure_changed = good_qualcomm_provider();
    structure_changed.observation.program_operations[0].start_sector = 65;
    let different = inspect_q(&primary, &structure_changed).expect("different");
    assert_eq!(
        compare_qualcomm_bundles(&left, &different).level,
        C06ComparisonLevel::Different
    );
}
