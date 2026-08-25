//! C04 Apple IPSW, OTA and IMG4 acceptance corpus.

use ptah_archive_decomposition::{
    AppleArchiveEntryObservation, AppleArchiveObservation, AppleArchiveProvider, AppleArchiveRole,
    AppleAssessment, AppleComparisonLevel, AppleFirmwareArtifactKind, AppleFirmwareContext,
    AppleFirmwareLimits, AppleInspectRequest, AppleManifestComponentObservation,
    AppleManifestObservation, AppleManifestProvider, AppleStaticProofLevel, AppleTrustAssessment,
    C04Error, assess_apple_rebuild, compare_apple_firmware, inspect_apple_firmware,
    materialize_apple_archive_entry, materialize_apple_der_component,
};
use ptah_identifiers::EntityRef;
use ptah_object_store::{ProductionEvidence, Registration};
use sha2::{Digest, Sha256};

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid fixture reference")
}

fn context() -> AppleFirmwareContext {
    AppleFirmwareContext {
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

fn zip_source() -> Vec<u8> {
    b"PK\x03\x04C04-archive-fixture".to_vec()
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn archive_entry(path: &str, bytes: &[u8]) -> AppleArchiveEntryObservation {
    AppleArchiveEntryObservation {
        path: path.to_owned(),
        recovered_bytes: bytes.to_vec(),
        expected_sha256: sha256(bytes),
    }
}

#[derive(Clone)]
struct FixtureArchiveProvider {
    observation: AppleArchiveObservation,
    fail: Option<String>,
}

impl FixtureArchiveProvider {
    fn complete(entries: Vec<AppleArchiveEntryObservation>) -> Self {
        Self {
            observation: AppleArchiveObservation {
                entries,
                complete_claim: true,
                limitations: Vec::new(),
            },
            fail: None,
        }
    }
}

impl AppleArchiveProvider for FixtureArchiveProvider {
    fn provider_id(&self) -> &str {
        "fixture.apple.archive"
    }

    fn inspect_archive(
        &self,
        _source: &[u8],
        _role: AppleArchiveRole,
        _limits: AppleFirmwareLimits,
    ) -> Result<AppleArchiveObservation, String> {
        if let Some(error) = &self.fail {
            Err(error.clone())
        } else {
            Ok(self.observation.clone())
        }
    }
}

#[derive(Clone)]
struct FixtureManifestProvider {
    observation: AppleManifestObservation,
    fail: Option<String>,
}

impl FixtureManifestProvider {
    fn linked(path: &str) -> Self {
        Self {
            observation: AppleManifestObservation {
                build_id: Some("22A400".to_owned()),
                product_version: Some("18.0".to_owned()),
                components: vec![AppleManifestComponentObservation {
                    name: "KernelCache".to_owned(),
                    path: path.to_owned(),
                }],
                complete_claim: true,
                limitations: Vec::new(),
            },
            fail: None,
        }
    }
}

impl AppleManifestProvider for FixtureManifestProvider {
    fn provider_id(&self) -> &str {
        "fixture.apple.manifest"
    }

    fn inspect_manifest(
        &self,
        _manifest_bytes: &[u8],
        _role: AppleArchiveRole,
        _limits: AppleFirmwareLimits,
    ) -> Result<AppleManifestObservation, String> {
        if let Some(error) = &self.fail {
            Err(error.clone())
        } else {
            Ok(self.observation.clone())
        }
    }
}

fn good_archive_provider() -> FixtureArchiveProvider {
    FixtureArchiveProvider::complete(vec![
        archive_entry("BuildManifest.plist", b"fixture-build-manifest"),
        archive_entry("Firmware/kernelcache.im4p", b"kernelcache-exact"),
    ])
}

fn archive_request(role: AppleArchiveRole) -> AppleInspectRequest {
    AppleInspectRequest {
        archive_role: Some(role),
    }
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 128 {
        return vec![u8::try_from(length).expect("short DER length")];
    }
    let raw = length.to_be_bytes();
    let first_nonzero = raw
        .iter()
        .position(|byte| *byte != 0)
        .expect("non-zero long DER length");
    let significant = &raw[first_nonzero..];
    let width = u8::try_from(significant.len()).expect("DER length width fits u8");
    let mut encoded = vec![0x80 | width];
    encoded.extend_from_slice(significant);
    encoded
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&der_length(content.len()));
    bytes.extend_from_slice(content);
    bytes
}

fn ia5(value: &str) -> Vec<u8> {
    der_tlv(0x16, value.as_bytes())
}

fn octets(value: &[u8]) -> Vec<u8> {
    der_tlv(0x04, value)
}

fn sequence(children: &[Vec<u8>]) -> Vec<u8> {
    let content: Vec<u8> = children.iter().flatten().copied().collect();
    der_tlv(0x30, &content)
}

fn context_wrapper(tag: u8, child: &[u8]) -> Vec<u8> {
    der_tlv(tag, child)
}

fn im4p(payload: &[u8]) -> Vec<u8> {
    sequence(&[
        ia5("IM4P"),
        ia5("krnl"),
        ia5("KernelCache"),
        octets(payload),
    ])
}

fn im4p_with_tail(payload: &[u8], tail: &[u8]) -> Vec<u8> {
    sequence(&[
        ia5("IM4P"),
        ia5("krnl"),
        ia5("KernelCache"),
        octets(payload),
        octets(tail),
    ])
}

fn im4m() -> Vec<u8> {
    sequence(&[
        ia5("IM4M"),
        octets(b"signature-material"),
        octets(b"certificate-material"),
    ])
}

fn im4r() -> Vec<u8> {
    sequence(&[ia5("IM4R"), octets(b"restore-properties")])
}

fn img4() -> Vec<u8> {
    let payload = im4p(b"payload-exact");
    let manifest = context_wrapper(0xa0, &im4m());
    let restore = context_wrapper(0xa1, &im4r());
    sequence(&[ia5("IMG4"), payload, manifest, restore])
}

fn inspect_archive(
    role: AppleArchiveRole,
    archive_provider: Option<&dyn AppleArchiveProvider>,
    manifest_provider: Option<&dyn AppleManifestProvider>,
) -> Result<ptah_archive_decomposition::AppleFirmwareReport, C04Error> {
    inspect_apple_firmware(
        &zip_source(),
        &context(),
        archive_request(role),
        AppleFirmwareLimits::default(),
        archive_provider,
        manifest_provider,
    )
}

#[test]
fn ipsw_inventory_with_buildmanifest_linkage() {
    let archive = good_archive_provider();
    let manifest = FixtureManifestProvider::linked("Firmware/kernelcache.im4p");
    let report = inspect_archive(AppleArchiveRole::Ipsw, Some(&archive), Some(&manifest))
        .expect("valid linked IPSW");
    assert_eq!(report.kind, AppleFirmwareArtifactKind::IpswArchive);
    assert_eq!(report.assessment, AppleAssessment::Complete);
    assert_eq!(report.proof_level, Some(AppleStaticProofLevel::ManifestLinked));
    assert_eq!(report.trust, AppleTrustAssessment::NotEstablished);
    let linked = report.manifest.expect("manifest projection");
    assert_eq!(linked.components.len(), 1);
    assert_eq!(linked.components[0].path, "Firmware/kernelcache.im4p");
    assert!(linked.unresolved_paths.is_empty());
}

#[test]
fn apple_ota_inventory_requires_and_retains_explicit_role() {
    let archive = FixtureArchiveProvider::complete(vec![archive_entry(
        "AssetData/payload.bin",
        b"ota-payload",
    )]);
    let report = inspect_archive(AppleArchiveRole::Ota, Some(&archive), None)
        .expect("valid explicit OTA inventory");
    assert_eq!(report.kind, AppleFirmwareArtifactKind::OtaArchive);
    assert_eq!(report.assessment, AppleAssessment::Partial);
    assert_eq!(report.proof_level, Some(AppleStaticProofLevel::StructureChecked));
    assert_eq!(report.archive_entries[0].path, "AssetData/payload.bin");
}

#[test]
fn zip_framing_without_archive_role_fails_closed() {
    let error = inspect_apple_firmware(
        &zip_source(),
        &context(),
        AppleInspectRequest::default(),
        AppleFirmwareLimits::default(),
        None,
        None,
    )
    .expect_err("ZIP role must be explicit");
    assert_eq!(error, C04Error::ArchiveRoleRequired);
}

#[test]
fn traversal_absolute_and_backslash_archive_paths_are_rejected() {
    for path in ["../escape", "/absolute", "dir\\child", "C:/drive/file"] {
        let archive = FixtureArchiveProvider::complete(vec![archive_entry(path, b"x")]);
        let error = inspect_archive(AppleArchiveRole::Ipsw, Some(&archive), None)
            .expect_err("unsafe path must fail");
        assert_eq!(error, C04Error::InvalidArchivePath);
    }
}

#[test]
fn duplicate_archive_paths_are_rejected() {
    let archive = FixtureArchiveProvider::complete(vec![
        archive_entry("Firmware/a", b"one"),
        archive_entry("Firmware/a", b"two"),
    ]);
    let error = inspect_archive(AppleArchiveRole::Ipsw, Some(&archive), None)
        .expect_err("duplicate path must fail");
    assert_eq!(error, C04Error::DuplicateArchivePath);
}

#[test]
fn recovered_entry_digest_mismatch_is_rejected() {
    let mut bad = archive_entry("Firmware/a", b"exact");
    bad.expected_sha256 = "0".repeat(64);
    let archive = FixtureArchiveProvider::complete(vec![bad]);
    let error = inspect_archive(AppleArchiveRole::Ipsw, Some(&archive), None)
        .expect_err("digest mismatch must fail");
    assert_eq!(error, C04Error::DigestMismatch);
}

#[test]
fn archive_count_byte_and_string_limits_fail_closed() {
    let archive = FixtureArchiveProvider::complete(vec![
        archive_entry("a", b"one"),
        archive_entry("b", b"two"),
    ]);
    let source = zip_source();
    let ctx = context();
    let mut limits = AppleFirmwareLimits::default();
    limits.max_archive_entries = 1;
    assert_eq!(
        inspect_apple_firmware(
            &source,
            &ctx,
            archive_request(AppleArchiveRole::Ipsw),
            limits,
            Some(&archive),
            None,
        )
        .expect_err("entry bound"),
        C04Error::TooManyEntries
    );

    let mut limits = AppleFirmwareLimits::default();
    limits.max_recovered_bytes = 5;
    assert_eq!(
        inspect_apple_firmware(
            &source,
            &ctx,
            archive_request(AppleArchiveRole::Ipsw),
            limits,
            Some(&archive),
            None,
        )
        .expect_err("byte bound"),
        C04Error::TooManyRecoveredBytes
    );

    let long_path = FixtureArchiveProvider::complete(vec![archive_entry("long-name", b"x")]);
    let mut limits = AppleFirmwareLimits::default();
    limits.max_string_bytes = 4;
    assert_eq!(
        inspect_apple_firmware(
            &source,
            &ctx,
            archive_request(AppleArchiveRole::Ipsw),
            limits,
            Some(&long_path),
            None,
        )
        .expect_err("string bound"),
        C04Error::InvalidString
    );
}

#[test]
fn missing_archive_provider_remains_inconclusive() {
    let report = inspect_archive(AppleArchiveRole::Ipsw, None, None)
        .expect("missing Provider is a truthful inconclusive report");
    assert_eq!(report.assessment, AppleAssessment::Inconclusive);
    assert_eq!(report.proof_level, None);
    assert!(report.archive_entries.is_empty());
    assert!(!report.limitations.is_empty());
}

#[test]
fn unresolved_manifest_component_reduces_truth() {
    let archive = good_archive_provider();
    let manifest = FixtureManifestProvider::linked("Firmware/missing.im4p");
    let report = inspect_archive(AppleArchiveRole::Ipsw, Some(&archive), Some(&manifest))
        .expect("unresolved linkage remains reportable");
    assert_eq!(report.assessment, AppleAssessment::Partial);
    assert_eq!(report.proof_level, Some(AppleStaticProofLevel::StructureChecked));
    let manifest = report.manifest.expect("manifest projection");
    assert_eq!(manifest.unresolved_paths, vec!["Firmware/missing.im4p"]);
}

#[test]
fn incomplete_manifest_provider_claim_remains_partial() {
    let archive = good_archive_provider();
    let mut manifest = FixtureManifestProvider::linked("Firmware/kernelcache.im4p");
    manifest.observation.complete_claim = false;
    manifest.observation.limitations.clear();
    let report = inspect_archive(AppleArchiveRole::Ipsw, Some(&archive), Some(&manifest))
        .expect("incomplete claim remains reportable");
    assert_eq!(report.assessment, AppleAssessment::Partial);
    assert_ne!(report.proof_level, Some(AppleStaticProofLevel::ManifestLinked));
    assert!(
        report
            .manifest
            .expect("manifest projection")
            .limitations
            .iter()
            .any(|value| value.contains("did not claim complete"))
    );
}

#[test]
fn valid_img4_yields_exact_im4p_im4m_and_im4r_inventory() {
    let source = img4();
    let report = inspect_apple_firmware(
        &source,
        &context(),
        AppleInspectRequest::default(),
        AppleFirmwareLimits::default(),
        None,
        None,
    )
    .expect("valid IMG4");
    assert_eq!(report.kind, AppleFirmwareArtifactKind::Img4);
    assert_eq!(report.assessment, AppleAssessment::Complete);
    for name in [
        "img4.im4p",
        "img4.im4p.payload",
        "img4.im4m",
        "img4.im4m.signing.0",
        "img4.im4r",
        "img4.im4r.payload",
    ] {
        assert!(report.der_components.iter().any(|component| component.name == name));
    }
}

#[test]
fn standalone_im4p_exposes_exact_payload_range() {
    let source = im4p(b"exact-payload");
    let report = inspect_apple_firmware(
        &source,
        &context(),
        AppleInspectRequest::default(),
        AppleFirmwareLimits::default(),
        None,
        None,
    )
    .expect("valid IM4P");
    assert_eq!(report.kind, AppleFirmwareArtifactKind::Im4p);
    let materialized = materialize_apple_der_component(
        &source,
        &report,
        "im4p.payload",
        &context(),
        AppleFirmwareLimits::default(),
    )
    .expect("payload materialization");
    assert_eq!(materialized.bytes(), b"exact-payload");
}

#[test]
fn standalone_im4m_observes_signing_material_without_trust() {
    let source = im4m();
    let report = inspect_apple_firmware(
        &source,
        &context(),
        AppleInspectRequest::default(),
        AppleFirmwareLimits::default(),
        None,
        None,
    )
    .expect("valid IM4M");
    assert_eq!(report.kind, AppleFirmwareArtifactKind::Im4m);
    assert_eq!(report.trust, AppleTrustAssessment::NotEstablished);
    assert_eq!(report.proof_level, Some(AppleStaticProofLevel::StructureChecked));
    assert_eq!(
        report
            .der_components
            .iter()
            .filter(|component| component.name.starts_with("im4m.signing."))
            .count(),
        2
    );
}

#[test]
fn malformed_or_truncated_der_fails_closed() {
    let mut truncated = im4p(b"payload");
    truncated.pop();
    assert!(matches!(
        inspect_apple_firmware(
            &truncated,
            &context(),
            AppleInspectRequest::default(),
            AppleFirmwareLimits::default(),
            None,
            None,
        ),
        Err(C04Error::MalformedDer(_))
    ));
    let unsupported = b"not-der".to_vec();
    assert_eq!(
        inspect_apple_firmware(
            &unsupported,
            &context(),
            AppleInspectRequest::default(),
            AppleFirmwareLimits::default(),
            None,
            None,
        )
        .expect_err("unsupported framing"),
        C04Error::UnsupportedArtifact
    );
}

#[test]
fn indefinite_and_nonminimal_der_lengths_fail_closed() {
    let indefinite = vec![0x30, 0x80, 0x16, 0x04, b'I', b'M', b'4', b'P', 0x00, 0x00];
    assert!(matches!(
        inspect_apple_firmware(
            &indefinite,
            &context(),
            AppleInspectRequest::default(),
            AppleFirmwareLimits::default(),
            None,
            None,
        ),
        Err(C04Error::MalformedDer(_))
    ));
    let nonminimal = vec![0x30, 0x81, 0x01, 0x00];
    assert!(matches!(
        inspect_apple_firmware(
            &nonminimal,
            &context(),
            AppleInspectRequest::default(),
            AppleFirmwareLimits::default(),
            None,
            None,
        ),
        Err(C04Error::MalformedDer(_))
    ));
}

#[test]
fn wrong_marker_and_malformed_context_wrapper_fail_closed() {
    let wrong_marker = sequence(&[ia5("NOPE"), octets(b"x")]);
    assert!(matches!(
        inspect_apple_firmware(
            &wrong_marker,
            &context(),
            AppleInspectRequest::default(),
            AppleFirmwareLimits::default(),
            None,
            None,
        ),
        Err(C04Error::MalformedDer(_))
    ));
    let malformed_wrapper = sequence(&[
        ia5("IMG4"),
        im4p(b"payload"),
        context_wrapper(0xa0, &im4r()),
    ]);
    assert!(matches!(
        inspect_apple_firmware(
            &malformed_wrapper,
            &context(),
            AppleInspectRequest::default(),
            AppleFirmwareLimits::default(),
            None,
            None,
        ),
        Err(C04Error::MalformedDer(_))
    ));
}

#[test]
fn exact_child_and_archive_materialization_are_source_bound() {
    let archive = good_archive_provider();
    let source = zip_source();
    let report = inspect_archive(AppleArchiveRole::Ipsw, Some(&archive), None)
        .expect("archive report");
    let entry = materialize_apple_archive_entry(
        &source,
        &report,
        "Firmware/kernelcache.im4p",
        &context(),
        AppleFirmwareLimits::default(),
    )
    .expect("archive entry materialization");
    assert_eq!(entry.bytes(), b"kernelcache-exact");
    let mut changed_source = source.clone();
    changed_source.push(0);
    assert_eq!(
        materialize_apple_archive_entry(
            &changed_source,
            &report,
            "Firmware/kernelcache.im4p",
            &context(),
            AppleFirmwareLimits::default(),
        )
        .expect_err("source mutation must fail"),
        C04Error::SourceBindingMismatch
    );

    let source = img4();
    let report = inspect_apple_firmware(
        &source,
        &context(),
        AppleInspectRequest::default(),
        AppleFirmwareLimits::default(),
        None,
        None,
    )
    .expect("IMG4 report");
    let child = materialize_apple_der_component(
        &source,
        &report,
        "img4.im4p",
        &context(),
        AppleFirmwareLimits::default(),
    )
    .expect("exact IM4P child");
    assert_eq!(child.bytes(), im4p(b"payload-exact"));
}

#[test]
fn report_mutation_cannot_authorize_materialization_or_views() {
    let source = zip_source();
    let mut report = inspect_archive(AppleArchiveRole::Ipsw, None, None)
        .expect("truthful inconclusive report");
    report.assessment = AppleAssessment::Complete;
    assert_eq!(
        materialize_apple_archive_entry(
            &source,
            &report,
            "anything",
            &context(),
            AppleFirmwareLimits::default(),
        )
        .expect_err("mutated report must fail first"),
        C04Error::ReportIntegrityMismatch
    );
    assert_eq!(
        report
            .view_specs(&context())
            .expect_err("mutated report cannot produce views"),
        C04Error::ReportIntegrityMismatch
    );
}

#[test]
fn registration_relationship_and_view_plans_retain_exact_evidence() {
    let source = im4p(b"registration-payload");
    let ctx = context();
    let report = inspect_apple_firmware(
        &source,
        &ctx,
        AppleInspectRequest::default(),
        AppleFirmwareLimits::default(),
        None,
        None,
    )
    .expect("valid IM4P report");
    let child = materialize_apple_der_component(
        &source,
        &report,
        "im4p.payload",
        &ctx,
        AppleFirmwareLimits::default(),
    )
    .expect("exact child");
    let registration_spec = child.registration_spec(&ctx).expect("registration plan");
    assert_eq!(registration_spec.source_refs, vec![ctx.source_revision_ref.clone()]);
    assert_eq!(registration_spec.production.attempt_ref, ctx.production.attempt_ref);
    assert_eq!(registration_spec.expected_sha256, Some(child.sha256.clone()));

    let registration = Registration {
        content_ref: reference("object.content"),
        object_ref: reference("object.object"),
        revision_ref: reference("object.revision"),
        location_ref: reference("storage.location"),
        sha256: child.sha256.clone(),
        byte_size: u64::try_from(child.bytes().len()).expect("fixture byte size"),
        cas_object_key: "sha256/c04".to_owned(),
        content_deduplicated: false,
    };
    let relationship = child
        .relationship_spec(&ctx, &registration)
        .expect("relationship plan");
    assert_eq!(relationship.subject_refs, vec![ctx.source_revision_ref.clone()]);
    assert_eq!(relationship.production.attempt_ref, ctx.production.attempt_ref);
    assert_eq!(relationship.relationship_type, "contains.apple_firmware_child");

    let views = report.view_specs(&ctx).expect("view plans");
    assert_eq!(views.len(), 3);
    assert!(views.iter().all(|view| {
        view.source_revision_refs == vec![ctx.source_revision_ref.clone()]
            && view.production.attempt_ref == ctx.production.attempt_ref
    }));
}

#[test]
fn comparison_and_proof_levels_do_not_manufacture_signing_or_restore_truth() {
    let ctx = context();
    let original_source = im4p_with_tail(b"payload", b"tail-a");
    let original = inspect_apple_firmware(
        &original_source,
        &ctx,
        AppleInspectRequest::default(),
        AppleFirmwareLimits::default(),
        None,
        None,
    )
    .expect("original IM4P");

    let structural_source = im4p_with_tail(b"payloae", b"tail-a");
    let structural = inspect_apple_firmware(
        &structural_source,
        &ctx,
        AppleInspectRequest::default(),
        AppleFirmwareLimits::default(),
        None,
        None,
    )
    .expect("structurally equivalent IM4P");
    assert_eq!(
        compare_apple_firmware(&original, &structural).level,
        AppleComparisonLevel::Structural
    );

    let component_source = im4p_with_tail(b"payload", b"tail-b");
    let component = inspect_apple_firmware(
        &component_source,
        &ctx,
        AppleInspectRequest::default(),
        AppleFirmwareLimits::default(),
        None,
        None,
    )
    .expect("component-exact IM4P");
    assert_eq!(
        compare_apple_firmware(&original, &component).level,
        AppleComparisonLevel::ComponentExact
    );
    assert_eq!(
        assess_apple_rebuild(&original, &component),
        Some(AppleStaticProofLevel::ComponentExact)
    );
    assert_eq!(
        compare_apple_firmware(&original, &original).level,
        AppleComparisonLevel::ByteExact
    );
    assert_eq!(original.trust, AppleTrustAssessment::NotEstablished);

    let different_source = im4m();
    let different = inspect_apple_firmware(
        &different_source,
        &ctx,
        AppleInspectRequest::default(),
        AppleFirmwareLimits::default(),
        None,
        None,
    )
    .expect("different family");
    assert_eq!(
        compare_apple_firmware(&original, &different).level,
        AppleComparisonLevel::Different
    );
    assert_eq!(assess_apple_rebuild(&original, &different), None);
}
