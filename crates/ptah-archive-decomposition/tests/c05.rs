//! C05 `MediaTek` scatter/bundle/read-only evidence acceptance corpus.

use ptah_archive_decomposition::{
    C05Error, MediatekAssessment, MediatekBundleEntryObservation, MediatekBundleObservation,
    MediatekBundleProvider, MediatekComparisonLevel, MediatekContext, MediatekEvidenceLevel,
    MediatekEvidenceObservation, MediatekEvidenceProvider, MediatekLimits, MediatekMode,
    MediatekStaticProofLevel, MediatekTrustAssessment, compare_mediatek_packages,
    inspect_mediatek_package, materialize_mediatek_component,
};
use ptah_identifiers::EntityRef;
use ptah_object_store::{ProductionEvidence, Registration};
use sha2::{Digest, Sha256};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid fixture reference")
}

fn context() -> MediatekContext {
    MediatekContext {
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

fn scatter() -> Vec<u8> {
    br"############################################################################################################
- general: MTK_PLATFORM_CFG
  info:
    - config_version: V1.1.2
      platform: MT6789
      project: c05_fixture
      storage: EMMC
      boot_channel: MSDC_0
      block_size: 0x20000
- partition_index: SYS0
  partition_name: preloader
  file_name: preloader.bin
  is_download: true
  type: SV5_BL_BIN
  linear_start_addr: 0x0
  physical_start_addr: 0x0
  partition_size: 0x1000
  region: EMMC_BOOT_1
  storage: HW_STORAGE_EMMC
- partition_index: SYS1
  partition_name: boot
  file_name: boot.img
  is_download: true
  type: NORMAL_ROM
  linear_start_addr: 0x1000
  physical_start_addr: 0x1000
  partition_size: 0x2000
  region: EMMC_USER
  storage: HW_STORAGE_EMMC
"
    .to_vec()
}

fn no_component_scatter() -> Vec<u8> {
    br"- general: MTK_PLATFORM_CFG
  info:
    - config_version: V1.1.2
      platform: MT6789
      storage: EMMC
- partition_index: SYS0
  partition_name: otp
  file_name: NONE
  is_download: true
  type: NORMAL_ROM
  linear_start_addr: 0x0
  physical_start_addr: 0x0
  partition_size: 0x100
  region: EMMC_USER
  storage: HW_STORAGE_EMMC
"
    .to_vec()
}

fn bundle_entry(path: &str, bytes: &[u8]) -> MediatekBundleEntryObservation {
    MediatekBundleEntryObservation {
        path: path.to_owned(),
        recovered_bytes: bytes.to_vec(),
        expected_sha256: sha256(bytes),
    }
}

#[derive(Clone)]
struct FixtureBundleProvider {
    observation: MediatekBundleObservation,
    fail: Option<String>,
}

impl FixtureBundleProvider {
    fn complete(entries: Vec<MediatekBundleEntryObservation>) -> Self {
        Self {
            observation: MediatekBundleObservation {
                entries,
                complete_claim: true,
                limitations: Vec::new(),
            },
            fail: None,
        }
    }
}

impl MediatekBundleProvider for FixtureBundleProvider {
    fn provider_id(&self) -> &'static str {
        "fixture.mediatek.bundle"
    }

    fn inspect_bundle(
        &self,
        _scatter_source: &[u8],
        _limits: MediatekLimits,
    ) -> Result<MediatekBundleObservation, String> {
        if let Some(error) = &self.fail {
            Err(error.clone())
        } else {
            Ok(self.observation.clone())
        }
    }
}

#[derive(Clone)]
struct FixtureEvidenceProvider {
    observation: MediatekEvidenceObservation,
    fail: Option<String>,
}

impl MediatekEvidenceProvider for FixtureEvidenceProvider {
    fn provider_id(&self) -> &'static str {
        "fixture.mediatek.evidence"
    }

    fn inspect_evidence(
        &self,
        _scatter_source: &[u8],
        _limits: MediatekLimits,
    ) -> Result<MediatekEvidenceObservation, String> {
        if let Some(error) = &self.fail {
            Err(error.clone())
        } else {
            Ok(self.observation.clone())
        }
    }
}

fn good_bundle() -> FixtureBundleProvider {
    FixtureBundleProvider::complete(vec![
        bundle_entry("preloader.bin", b"preloader-exact"),
        bundle_entry("boot.img", b"boot-exact"),
    ])
}

fn exact_evidence() -> FixtureEvidenceProvider {
    FixtureEvidenceProvider {
        observation: MediatekEvidenceObservation {
            mode: MediatekMode::Meta,
            usb_vid: Some(0x0e8d),
            usb_pid: Some(0x2007),
            platform: Some("MT6789".to_owned()),
            storage: Some("EMMC".to_owned()),
            partition_names: vec!["preloader".to_owned(), "boot".to_owned()],
            service_session_established: true,
            layout_inventoried: true,
            complete_claim: true,
            limitations: Vec::new(),
        },
        fail: None,
    }
}

fn inspect(
    source: &[u8],
    bundle: Option<&dyn MediatekBundleProvider>,
    evidence: Option<&dyn MediatekEvidenceProvider>,
) -> Result<ptah_archive_decomposition::MediatekReport, C05Error> {
    inspect_mediatek_package(
        source,
        &context(),
        MediatekLimits::default(),
        bundle,
        evidence,
    )
}

#[test]
fn valid_scatter_and_complete_bundle_link_exact_components() {
    let source = scatter();
    let bundle = good_bundle();
    let report = inspect(&source, Some(&bundle), None).expect("valid MediaTek bundle");
    assert_eq!(report.assessment, MediatekAssessment::Complete);
    assert_eq!(
        report.proof_level,
        Some(MediatekStaticProofLevel::BundleLinked)
    );
    assert_eq!(report.platform, "MT6789");
    assert_eq!(report.storage, "EMMC");
    assert_eq!(report.partitions.len(), 2);
    assert!(
        report
            .partitions
            .iter()
            .all(|partition| partition.linked_component_sha256.is_some())
    );
}

#[test]
fn static_scatter_without_bundle_is_device_independent_and_partial() {
    let source = scatter();
    let report = inspect(&source, None, None).expect("scatter-only inspection");
    assert_eq!(report.assessment, MediatekAssessment::Partial);
    assert_eq!(
        report.proof_level,
        Some(MediatekStaticProofLevel::StructureChecked)
    );
    assert!(report.evidence.is_none());
    assert!(report.bundle_entries.is_empty());
}

#[test]
fn traversal_absolute_backslash_and_drive_bundle_paths_are_rejected() {
    let source = scatter();
    for path in ["../escape", "/absolute", "dir\\child", "C:/drive/file"] {
        let bundle = FixtureBundleProvider::complete(vec![bundle_entry(path, b"x")]);
        assert_eq!(
            inspect(&source, Some(&bundle), None).expect_err("unsafe path must fail"),
            C05Error::InvalidBundlePath
        );
    }
}

#[test]
fn duplicate_bundle_paths_are_rejected() {
    let source = scatter();
    let bundle = FixtureBundleProvider::complete(vec![
        bundle_entry("boot.img", b"one"),
        bundle_entry("boot.img", b"two"),
    ]);
    assert_eq!(
        inspect(&source, Some(&bundle), None).expect_err("duplicate bundle path"),
        C05Error::DuplicateBundlePath
    );
}

#[test]
fn recovered_bundle_digest_mismatch_is_rejected() {
    let source = scatter();
    let mut entry = bundle_entry("boot.img", b"exact");
    entry.expected_sha256 = "0".repeat(64);
    let bundle = FixtureBundleProvider::complete(vec![entry]);
    assert_eq!(
        inspect(&source, Some(&bundle), None).expect_err("digest lie must fail"),
        C05Error::DigestMismatch
    );
}

#[test]
fn entry_byte_string_and_line_limits_fail_closed() {
    let source = scatter();
    let bundle = good_bundle();
    let ctx = context();
    let limits = MediatekLimits {
        max_bundle_entries: 1,
        ..MediatekLimits::default()
    };
    assert_eq!(
        inspect_mediatek_package(&source, &ctx, limits, Some(&bundle), None)
            .expect_err("entry bound"),
        C05Error::TooManyEntries
    );

    let limits = MediatekLimits {
        max_recovered_bytes: 8,
        ..MediatekLimits::default()
    };
    assert_eq!(
        inspect_mediatek_package(&source, &ctx, limits, Some(&bundle), None)
            .expect_err("recovered byte bound"),
        C05Error::TooManyRecoveredBytes
    );

    let limits = MediatekLimits {
        max_string_bytes: 4,
        ..MediatekLimits::default()
    };
    assert_eq!(
        inspect_mediatek_package(&source, &ctx, limits, None, None).expect_err("string bound"),
        C05Error::InvalidString
    );

    let limits = MediatekLimits {
        max_lines: 2,
        ..MediatekLimits::default()
    };
    assert_eq!(
        inspect_mediatek_package(&source, &ctx, limits, None, None).expect_err("line bound"),
        C05Error::TooManyLines
    );
}

#[test]
fn malformed_utf8_scatter_is_rejected() {
    let source = vec![0xff, 0xfe, 0xfd];
    assert_eq!(
        inspect(&source, None, None).expect_err("UTF-8 required"),
        C05Error::InvalidUtf8
    );
}

#[test]
fn missing_required_partition_field_is_rejected() {
    let text = String::from_utf8(scatter()).expect("fixture UTF-8");
    let source = text.replacen("  region: EMMC_BOOT_1\n", "", 1).into_bytes();
    assert_eq!(
        inspect(&source, None, None).expect_err("required region missing"),
        C05Error::InvalidScatter
    );
}

#[test]
fn invalid_or_negative_numeric_fields_are_rejected() {
    let text = String::from_utf8(scatter()).expect("fixture UTF-8");
    for bad in ["-1", "0xGG"] {
        let source = text
            .replacen(
                "linear_start_addr: 0x0",
                &format!("linear_start_addr: {bad}"),
                1,
            )
            .into_bytes();
        assert_eq!(
            inspect(&source, None, None).expect_err("invalid numeric field"),
            C05Error::InvalidNumber
        );
    }
}

#[test]
fn partition_range_overflow_is_rejected() {
    let text = String::from_utf8(scatter()).expect("fixture UTF-8");
    let source = text
        .replacen(
            "linear_start_addr: 0x0",
            "linear_start_addr: 0xfffffffffffffff0",
            1,
        )
        .replacen("partition_size: 0x1000", "partition_size: 0x100", 1)
        .into_bytes();
    assert_eq!(
        inspect(&source, None, None).expect_err("range overflow"),
        C05Error::PartitionRangeOverflow
    );
}

#[test]
fn duplicate_partition_index_or_name_is_rejected() {
    let text = String::from_utf8(scatter()).expect("fixture UTF-8");
    let duplicate_index = text.replacen("partition_index: SYS1", "partition_index: SYS0", 1);
    assert_eq!(
        inspect(duplicate_index.as_bytes(), None, None).expect_err("duplicate index"),
        C05Error::DuplicatePartition
    );
    let duplicate_name = text.replacen("partition_name: boot", "partition_name: preloader", 1);
    assert_eq!(
        inspect(duplicate_name.as_bytes(), None, None).expect_err("duplicate name"),
        C05Error::DuplicatePartition
    );
}

#[test]
fn missing_scatter_referenced_component_reduces_truth() {
    let source = scatter();
    let bundle =
        FixtureBundleProvider::complete(vec![bundle_entry("preloader.bin", b"preloader-exact")]);
    let report =
        inspect(&source, Some(&bundle), None).expect("missing component remains reportable");
    assert_eq!(report.assessment, MediatekAssessment::Partial);
    assert_eq!(
        report.proof_level,
        Some(MediatekStaticProofLevel::StructureChecked)
    );
    assert!(
        report
            .limitations
            .iter()
            .any(|value| value.contains("unresolved"))
    );
}

#[test]
fn incomplete_bundle_provider_claim_remains_partial() {
    let source = scatter();
    let mut bundle = good_bundle();
    bundle.observation.complete_claim = false;
    let report =
        inspect(&source, Some(&bundle), None).expect("incomplete claim remains reportable");
    assert_eq!(report.assessment, MediatekAssessment::Partial);
    assert_eq!(
        report.proof_level,
        Some(MediatekStaticProofLevel::StructureChecked)
    );
    assert!(
        report
            .limitations
            .iter()
            .any(|value| value.contains("did not claim complete"))
    );
    let mut limited_bundle = good_bundle();
    limited_bundle.observation.limitations = vec!["fixture partial bundle semantics".to_owned()];
    let limited_report = inspect(&source, Some(&limited_bundle), None)
        .expect("provider limitation remains reportable");
    assert_eq!(limited_report.assessment, MediatekAssessment::Partial);
    assert_eq!(
        limited_report.proof_level,
        Some(MediatekStaticProofLevel::StructureChecked)
    );
}

#[test]
fn lawful_read_only_layout_evidence_can_be_correlated_exactly() {
    let source = scatter();
    let bundle = good_bundle();
    let evidence = exact_evidence();
    let report =
        inspect(&source, Some(&bundle), Some(&evidence)).expect("exact evidence correlation");
    assert_eq!(report.assessment, MediatekAssessment::Complete);
    assert_eq!(
        report.proof_level,
        Some(MediatekStaticProofLevel::EvidenceCorrelated)
    );
    assert_eq!(
        report.evidence.expect("evidence").level,
        MediatekEvidenceLevel::LayoutEvidence
    );
    let correlation = report.evidence_correlation.expect("correlation");
    assert_eq!(correlation.platform_matches, Some(true));
    assert_eq!(correlation.storage_matches, Some(true));
    assert_eq!(correlation.partition_names_match, Some(true));
}

#[test]
fn meta_pid_2007_transport_does_not_establish_service_session() {
    let source = scatter();
    let bundle = good_bundle();
    let mut evidence = exact_evidence();
    evidence.observation.service_session_established = false;
    evidence.observation.layout_inventoried = false;
    evidence.observation.partition_names.clear();
    let report = inspect(&source, Some(&bundle), Some(&evidence)).expect("transport/mode evidence");
    let evidence = report.evidence.expect("evidence");
    assert_eq!(evidence.usb_vid, Some(0x0e8d));
    assert_eq!(evidence.usb_pid, Some(0x2007));
    assert_eq!(evidence.mode, MediatekMode::Meta);
    assert_eq!(evidence.level, MediatekEvidenceLevel::ModePresence);
    assert!(!evidence.service_session_established);
    assert_eq!(
        report.proof_level,
        Some(MediatekStaticProofLevel::BundleLinked)
    );
}

#[test]
fn contradictory_platform_storage_or_layout_evidence_reduces_truth() {
    let source = scatter();
    let bundle = good_bundle();
    let mut evidence = exact_evidence();
    evidence.observation.platform = Some("MT9999".to_owned());
    evidence.observation.storage = Some("UFS".to_owned());
    evidence.observation.partition_names = vec!["boot".to_owned()];
    let report =
        inspect(&source, Some(&bundle), Some(&evidence)).expect("mismatch remains reportable");
    assert_eq!(report.assessment, MediatekAssessment::Partial);
    assert_eq!(
        report.proof_level,
        Some(MediatekStaticProofLevel::BundleLinked)
    );
    let correlation = report.evidence_correlation.expect("correlation");
    assert_eq!(correlation.platform_matches, Some(false));
    assert_eq!(correlation.storage_matches, Some(false));
    assert_eq!(correlation.partition_names_match, Some(false));
    let mut limited_evidence = exact_evidence();
    limited_evidence.observation.limitations =
        vec!["fixture partial evidence semantics".to_owned()];
    let limited_report = inspect(&source, Some(&bundle), Some(&limited_evidence))
        .expect("evidence limitation remains reportable");
    assert_eq!(limited_report.assessment, MediatekAssessment::Partial);
    assert_eq!(
        limited_report.proof_level,
        Some(MediatekStaticProofLevel::BundleLinked)
    );
}

#[test]
fn scatter_is_download_metadata_never_establishes_write_trust() {
    let source = no_component_scatter();
    let report = inspect(&source, None, None).expect("static scatter");
    assert!(report.partitions[0].is_download);
    assert_eq!(report.assessment, MediatekAssessment::Complete);
    assert_eq!(report.trust, MediatekTrustAssessment::NotEstablished);
    assert_eq!(
        report.proof_level,
        Some(MediatekStaticProofLevel::StructureChecked)
    );
}

#[test]
fn report_mutation_and_source_mismatch_fail_before_reuse() {
    let source = scatter();
    let bundle = good_bundle();
    let ctx = context();
    let mut report = inspect_mediatek_package(
        &source,
        &ctx,
        MediatekLimits::default(),
        Some(&bundle),
        None,
    )
    .expect("valid report");
    report.assessment = MediatekAssessment::Inconclusive;
    assert_eq!(
        report
            .view_specs(&ctx)
            .expect_err("mutated report cannot produce views"),
        C05Error::ReportIntegrityMismatch
    );

    let report = inspect_mediatek_package(
        &source,
        &ctx,
        MediatekLimits::default(),
        Some(&bundle),
        None,
    )
    .expect("fresh valid report");
    let mut changed_source = source.clone();
    changed_source.push(b'\n');
    assert_eq!(
        materialize_mediatek_component(
            &changed_source,
            &report,
            "boot.img",
            &ctx,
            MediatekLimits::default(),
        )
        .expect_err("changed source must fail"),
        C05Error::SourceBindingMismatch
    );
}

#[test]
fn registration_relationship_and_view_plans_retain_exact_evidence() {
    let source = scatter();
    let bundle = good_bundle();
    let ctx = context();
    let report = inspect_mediatek_package(
        &source,
        &ctx,
        MediatekLimits::default(),
        Some(&bundle),
        None,
    )
    .expect("valid report");
    let child = materialize_mediatek_component(
        &source,
        &report,
        "boot.img",
        &ctx,
        MediatekLimits::default(),
    )
    .expect("exact component");
    assert_eq!(child.bytes(), b"boot-exact");
    let registration_spec = child.registration_spec(&ctx).expect("registration plan");
    assert_eq!(
        registration_spec.source_refs,
        vec![ctx.source_revision_ref.clone()]
    );
    assert_eq!(
        registration_spec.production.attempt_ref,
        ctx.production.attempt_ref
    );
    assert_eq!(
        registration_spec.expected_sha256,
        Some(child.sha256.clone())
    );

    let registration = Registration {
        content_ref: reference("object.content"),
        object_ref: reference("object.object"),
        revision_ref: reference("object.revision"),
        location_ref: reference("storage.location"),
        sha256: child.sha256.clone(),
        byte_size: u64::try_from(child.bytes().len()).expect("fixture byte size"),
        cas_object_key: "sha256/c05".to_owned(),
        content_deduplicated: false,
    };
    let relationship = child
        .relationship_spec(&ctx, &registration)
        .expect("relationship plan");
    assert_eq!(
        relationship.subject_refs,
        vec![ctx.source_revision_ref.clone()]
    );
    assert_eq!(
        relationship.production.attempt_ref,
        ctx.production.attempt_ref
    );
    assert_eq!(
        relationship.relationship_type,
        "references.mediatek_firmware_component"
    );

    let views = report.view_specs(&ctx).expect("view plans");
    assert_eq!(views.len(), 4);
    assert!(views.iter().all(|view| {
        view.source_revision_refs == vec![ctx.source_revision_ref.clone()]
            && view.production.attempt_ref == ctx.production.attempt_ref
    }));
}

#[test]
fn comparison_levels_distinguish_structure_components_and_exact_scatter_bytes() {
    let bundle_a = good_bundle();
    let source_a = scatter();
    let left = inspect(&source_a, Some(&bundle_a), None).expect("left");

    let byte_exact = inspect(&source_a, Some(&bundle_a), None).expect("byte exact");
    assert_eq!(
        compare_mediatek_packages(&left, &byte_exact).level,
        MediatekComparisonLevel::ByteExact
    );

    let mut source_component_exact = source_a.clone();
    source_component_exact.extend_from_slice(b"# ignored-tail\n");
    let component_exact =
        inspect(&source_component_exact, Some(&bundle_a), None).expect("component exact");
    assert_eq!(
        compare_mediatek_packages(&left, &component_exact).level,
        MediatekComparisonLevel::ComponentExact
    );

    let bundle_changed = FixtureBundleProvider::complete(vec![
        bundle_entry("preloader.bin", b"preloader-changed"),
        bundle_entry("boot.img", b"boot-changed"),
    ]);
    let structural = inspect(&source_a, Some(&bundle_changed), None).expect("structural");
    assert_eq!(
        compare_mediatek_packages(&left, &structural).level,
        MediatekComparisonLevel::Structural
    );

    let different_source = String::from_utf8(source_a.clone())
        .expect("fixture UTF-8")
        .replacen("partition_size: 0x2000", "partition_size: 0x3000", 1)
        .into_bytes();
    let different = inspect(&different_source, Some(&bundle_a), None).expect("different");
    assert_eq!(
        compare_mediatek_packages(&left, &different).level,
        MediatekComparisonLevel::Different
    );
}
