//! C03 Generic Android image and OTA acceptance corpus.

use ptah_archive_decomposition::{
    AndroidArtifactKind, AndroidAssessment, AndroidComparisonLevel, AndroidContext,
    AndroidInspectRequest, AndroidIntegrityAssessment, AndroidLimits, AndroidRebuildProofLevel,
    AndroidTrustAssessment, C03Error, OtaDynamicGroup, OtaManifestObservation, OtaManifestProvider,
    OtaOperationRange, OtaPartitionUpdate, assess_android_rebuild, compare_android_artifacts,
    inspect_android_artifact, materialize_android_component, materialize_dynamic_partition,
};
use ptah_identifiers::EntityRef;
use ptah_object_store::{ProductionEvidence, Registration};
use sha2::{Digest, Sha256};

const SECTOR: usize = 512;

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid fixture reference")
}

fn context() -> AndroidContext {
    AndroidContext {
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

fn request(kind: AndroidArtifactKind) -> AndroidInspectRequest {
    AndroidInspectRequest {
        declared_kind: Some(kind),
    }
}

fn align_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

fn boot_legacy(version: u32) -> Vec<u8> {
    let page = 2048_usize;
    let kernel_size = 64_usize;
    let ramdisk_size = 48_usize;
    let second_size = 32_usize;
    let kernel_start = page;
    let ramdisk_start = align_up(kernel_start + kernel_size, page);
    let second_start = align_up(ramdisk_start + ramdisk_size, page);
    let mut end = align_up(second_start + second_size, page);
    let recovery_size = if version >= 1 { 40_usize } else { 0 };
    let recovery_offset = end;
    if recovery_size > 0 {
        end = align_up(recovery_offset + recovery_size, page);
    }
    let dtb_size = if version == 2 { 50_usize } else { 0 };
    let dtb_start = end;
    if dtb_size > 0 {
        end = dtb_start + dtb_size;
    }
    let mut bytes = vec![0_u8; end.max(page)];
    bytes[..8].copy_from_slice(b"ANDROID!");
    bytes[8..12].copy_from_slice(&(kernel_size as u32).to_le_bytes());
    bytes[16..20].copy_from_slice(&(ramdisk_size as u32).to_le_bytes());
    bytes[24..28].copy_from_slice(&(second_size as u32).to_le_bytes());
    bytes[36..40].copy_from_slice(&(page as u32).to_le_bytes());
    bytes[40..44].copy_from_slice(&version.to_le_bytes());
    bytes[kernel_start..kernel_start + kernel_size].fill(0x11);
    bytes[ramdisk_start..ramdisk_start + ramdisk_size].fill(0x22);
    bytes[second_start..second_start + second_size].fill(0x33);
    if version >= 1 {
        bytes[1632..1636].copy_from_slice(&(recovery_size as u32).to_le_bytes());
        bytes[1636..1644].copy_from_slice(&(recovery_offset as u64).to_le_bytes());
        bytes[1644..1648].copy_from_slice(&1648_u32.to_le_bytes());
        bytes[recovery_offset..recovery_offset + recovery_size].fill(0x44);
    }
    if version == 2 {
        bytes[1648..1652].copy_from_slice(&(dtb_size as u32).to_le_bytes());
        bytes[1652..1660].copy_from_slice(&0x8000_0000_u64.to_le_bytes());
        bytes[dtb_start..dtb_start + dtb_size].fill(0x55);
    }
    bytes
}

fn boot_modern(version: u32, init_boot: bool) -> Vec<u8> {
    let page = 4096_usize;
    let kernel_size = if init_boot { 0_usize } else { 64 };
    let ramdisk_size = if init_boot { 64_usize } else { 32 };
    let signature_size = if version == 4 && !init_boot { 16_usize } else { 0 };
    let mut cursor = page;
    let kernel_start = cursor;
    if kernel_size > 0 {
        cursor = align_up(cursor + kernel_size, page);
    }
    let ramdisk_start = cursor;
    if ramdisk_size > 0 {
        cursor = align_up(cursor + ramdisk_size, page);
    }
    let signature_start = cursor;
    let end = signature_start + signature_size;
    let mut bytes = vec![0_u8; end.max(ramdisk_start + ramdisk_size).max(page)];
    bytes[..8].copy_from_slice(b"ANDROID!");
    bytes[8..12].copy_from_slice(&(kernel_size as u32).to_le_bytes());
    bytes[12..16].copy_from_slice(&(ramdisk_size as u32).to_le_bytes());
    let header_size = if version == 3 { 1580_u32 } else { 1584_u32 };
    bytes[20..24].copy_from_slice(&header_size.to_le_bytes());
    bytes[40..44].copy_from_slice(&version.to_le_bytes());
    if version == 4 {
        bytes[1580..1584].copy_from_slice(&(signature_size as u32).to_le_bytes());
    }
    if kernel_size > 0 {
        bytes[kernel_start..kernel_start + kernel_size].fill(0x61);
    }
    bytes[ramdisk_start..ramdisk_start + ramdisk_size].fill(0x62);
    if signature_size > 0 {
        bytes[signature_start..signature_start + signature_size].fill(0x63);
    }
    bytes
}

fn vendor_boot(version: u32) -> Vec<u8> {
    let page = 4096_usize;
    let ramdisk_size = 256_usize;
    let dtb_size = 128_usize;
    let header_size = if version == 3 { 2112_usize } else { 2128 };
    let ramdisk_start = align_up(header_size, page);
    let dtb_start = align_up(ramdisk_start + ramdisk_size, page);
    let mut cursor = align_up(dtb_start + dtb_size, page);
    let table_size = if version == 4 { 108_usize } else { 0 };
    let table_start = cursor;
    if table_size > 0 {
        cursor = align_up(table_start + table_size, page);
    }
    let bootconfig_size = if version == 4 { 32_usize } else { 0 };
    let bootconfig_start = cursor;
    let end = (bootconfig_start + bootconfig_size)
        .max(dtb_start + dtb_size)
        .max(ramdisk_start + ramdisk_size);
    let mut bytes = vec![0_u8; end];
    bytes[..8].copy_from_slice(b"VNDRBOOT");
    bytes[8..12].copy_from_slice(&version.to_le_bytes());
    bytes[12..16].copy_from_slice(&(page as u32).to_le_bytes());
    bytes[24..28].copy_from_slice(&(ramdisk_size as u32).to_le_bytes());
    bytes[2096..2100].copy_from_slice(&(header_size as u32).to_le_bytes());
    bytes[2100..2104].copy_from_slice(&(dtb_size as u32).to_le_bytes());
    bytes[ramdisk_start..ramdisk_start + ramdisk_size].fill(0x71);
    bytes[dtb_start..dtb_start + dtb_size].fill(0x72);
    if version == 4 {
        bytes[2112..2116].copy_from_slice(&(table_size as u32).to_le_bytes());
        bytes[2116..2120].copy_from_slice(&1_u32.to_le_bytes());
        bytes[2120..2124].copy_from_slice(&108_u32.to_le_bytes());
        bytes[2124..2128].copy_from_slice(&(bootconfig_size as u32).to_le_bytes());
        bytes[table_start..table_start + 4].copy_from_slice(&128_u32.to_le_bytes());
        bytes[table_start + 4..table_start + 8].copy_from_slice(&0_u32.to_le_bytes());
        bytes[table_start + 8..table_start + 12].copy_from_slice(&1_u32.to_le_bytes());
        bytes[table_start + 12..table_start + 20].copy_from_slice(b"platform");
        bytes[bootconfig_start..bootconfig_start + bootconfig_size].fill(0x73);
    }
    bytes
}

fn dtbo(version: u32) -> Vec<u8> {
    let entry_size = if version == 2 { 64_usize } else { 32 };
    let entries_offset = 32_usize;
    let payload_offset = entries_offset + entry_size;
    let payload_size = 16_usize;
    let total = payload_offset + payload_size;
    let mut bytes = vec![0_u8; total];
    for (offset, value) in [
        (0, 0xd7b7_ab1e_u32),
        (4, total as u32),
        (8, 32_u32),
        (12, entry_size as u32),
        (16, 1_u32),
        (20, entries_offset as u32),
        (24, 4096_u32),
        (28, version),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    bytes[entries_offset..entries_offset + 4].copy_from_slice(&(payload_size as u32).to_be_bytes());
    bytes[entries_offset + 4..entries_offset + 8]
        .copy_from_slice(&(payload_offset as u32).to_be_bytes());
    bytes[payload_offset..payload_offset + payload_size].fill(0x81);
    bytes
}

fn vbmeta() -> Vec<u8> {
    let auth_size = 32_usize;
    let aux_size = 64_usize;
    let mut bytes = vec![0_u8; 256 + auth_size + aux_size];
    bytes[..4].copy_from_slice(b"AVB0");
    bytes[4..8].copy_from_slice(&1_u32.to_be_bytes());
    bytes[8..12].copy_from_slice(&0_u32.to_be_bytes());
    bytes[12..20].copy_from_slice(&(auth_size as u64).to_be_bytes());
    bytes[20..28].copy_from_slice(&(aux_size as u64).to_be_bytes());
    bytes[96..104].copy_from_slice(&16_u64.to_be_bytes());
    bytes[104..112].copy_from_slice(&16_u64.to_be_bytes());
    bytes[256..256 + auth_size].fill(0x91);
    bytes[256 + auth_size..].fill(0x92);
    bytes
}

fn sha256_raw(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn lp_geometry(metadata_max_size: u32, slots: u32) -> [u8; 52] {
    let mut bytes = [0_u8; 52];
    bytes[0..4].copy_from_slice(&0x616c_4467_u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&52_u32.to_le_bytes());
    bytes[40..44].copy_from_slice(&metadata_max_size.to_le_bytes());
    bytes[44..48].copy_from_slice(&slots.to_le_bytes());
    bytes[48..52].copy_from_slice(&4096_u32.to_le_bytes());
    let checksum = sha256_raw(&bytes);
    bytes[8..40].copy_from_slice(&checksum);
    bytes
}

fn lp_metadata(partition_name: &str) -> Vec<u8> {
    let partition_size = 52_usize;
    let extent_size = 48_usize;
    let group_size = 48_usize;
    let block_size = 64_usize;
    let tables_size = partition_size + extent_size + group_size + block_size;
    let mut tables = vec![0_u8; tables_size];

    tables[..partition_name.len()].copy_from_slice(partition_name.as_bytes());
    tables[40..44].copy_from_slice(&0_u32.to_le_bytes());
    tables[44..48].copy_from_slice(&2_u32.to_le_bytes());
    tables[48..52].copy_from_slice(&0_u32.to_le_bytes());

    let extent0 = partition_size;
    tables[extent0..extent0 + 8].copy_from_slice(&4_u64.to_le_bytes());
    tables[extent0 + 8..extent0 + 12].copy_from_slice(&0_u32.to_le_bytes());
    tables[extent0 + 12..extent0 + 20].copy_from_slice(&48_u64.to_le_bytes());
    tables[extent0 + 20..extent0 + 24].copy_from_slice(&0_u32.to_le_bytes());
    let extent1 = extent0 + 24;
    tables[extent1..extent1 + 8].copy_from_slice(&2_u64.to_le_bytes());
    tables[extent1 + 8..extent1 + 12].copy_from_slice(&1_u32.to_le_bytes());

    let group = partition_size + extent_size;
    tables[group..group + 7].copy_from_slice(b"default");

    let block = group + group_size;
    tables[block..block + 8].copy_from_slice(&40_u64.to_le_bytes());
    tables[block + 8..block + 12].copy_from_slice(&4096_u32.to_le_bytes());
    tables[block + 16..block + 24].copy_from_slice(&(128_u64 * 512).to_le_bytes());
    tables[block + 24..block + 29].copy_from_slice(b"super");

    let mut header = vec![0_u8; 128];
    header[0..4].copy_from_slice(&0x414c_5030_u32.to_le_bytes());
    header[4..6].copy_from_slice(&10_u16.to_le_bytes());
    header[6..8].copy_from_slice(&0_u16.to_le_bytes());
    header[8..12].copy_from_slice(&128_u32.to_le_bytes());
    header[44..48].copy_from_slice(&(tables_size as u32).to_le_bytes());
    header[48..80].copy_from_slice(&sha256_raw(&tables));

    for (offset, table_offset, count, entry_size) in [
        (80, 0_u32, 1_u32, 52_u32),
        (92, 52_u32, 2_u32, 24_u32),
        (104, 100_u32, 1_u32, 48_u32),
        (116, 148_u32, 1_u32, 64_u32),
    ] {
        header[offset..offset + 4].copy_from_slice(&table_offset.to_le_bytes());
        header[offset + 4..offset + 8].copy_from_slice(&count.to_le_bytes());
        header[offset + 8..offset + 12].copy_from_slice(&entry_size.to_le_bytes());
    }
    let mut checked = header.clone();
    checked[12..44].fill(0);
    header[12..44].copy_from_slice(&sha256_raw(&checked));
    header.extend_from_slice(&tables);
    header
}

fn super_image(backup_partition_name: &str) -> Vec<u8> {
    let metadata_max = 4096_usize;
    let mut bytes = vec![0_u8; 128 * SECTOR];
    let geometry = lp_geometry(metadata_max as u32, 1);
    bytes[4096..4096 + 52].copy_from_slice(&geometry);
    bytes[8192..8192 + 52].copy_from_slice(&geometry);
    let primary = lp_metadata("system");
    let backup = lp_metadata(backup_partition_name);
    bytes[12288..12288 + primary.len()].copy_from_slice(&primary);
    bytes[16384..16384 + backup.len()].copy_from_slice(&backup);
    bytes[48 * SECTOR..52 * SECTOR].fill(0xa5);
    bytes
}

fn ota_payload(manifest_size: usize, signature_size: usize, data_size: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; 24 + manifest_size + signature_size + data_size];
    bytes[..4].copy_from_slice(b"CrAU");
    bytes[4..12].copy_from_slice(&2_u64.to_be_bytes());
    bytes[12..20].copy_from_slice(&(manifest_size as u64).to_be_bytes());
    bytes[20..24].copy_from_slice(&(signature_size as u32).to_be_bytes());
    bytes[24..24 + manifest_size].fill(0xb1);
    bytes[24 + manifest_size..24 + manifest_size + signature_size].fill(0xb2);
    bytes[24 + manifest_size + signature_size..].fill(0xb3);
    bytes
}

#[derive(Debug, Clone)]
struct FixtureOtaProvider {
    id: String,
    observation: OtaManifestObservation,
    fail: bool,
}

impl OtaManifestProvider for FixtureOtaProvider {
    fn provider_id(&self) -> &str {
        &self.id
    }

    fn decode_manifest(
        &self,
        _manifest_bytes: &[u8],
        _major_version: u64,
        _limits: AndroidLimits,
    ) -> Result<OtaManifestObservation, String> {
        if self.fail {
            Err("fixture failure".to_owned())
        } else {
            Ok(self.observation.clone())
        }
    }
}

fn ota_observation() -> OtaManifestObservation {
    OtaManifestObservation {
        block_size: 4096,
        partitions: vec![OtaPartitionUpdate {
            name: "system".to_owned(),
            new_size: Some(8192),
            operations: vec![OtaOperationRange {
                data_offset: 4,
                data_length: 16,
            }],
        }],
        dynamic_groups: vec![OtaDynamicGroup {
            name: "group_a".to_owned(),
            maximum_size: Some(16_384),
            partition_names: vec!["system".to_owned()],
        }],
        partial_update: false,
        complete_claim: true,
        limitations: Vec::new(),
    }
}

#[test]
fn boot_v0_v1_v2_boundaries_are_exact_and_source_is_immutable() {
    for version in 0..=2 {
        let source = boot_legacy(version);
        let before = source.clone();
        let report = inspect_android_artifact(
            &source,
            &context(),
            request(AndroidArtifactKind::Boot),
            AndroidLimits::default(),
            None,
        )
        .expect("legacy boot inspection");
        assert_eq!(source, before);
        assert_eq!(report.kind, AndroidArtifactKind::Boot);
        assert_eq!(report.assessment, AndroidAssessment::Complete);
        assert!(report.components.iter().any(|component| component.name == "boot.kernel"));
        assert!(report.components.iter().any(|component| component.name == "boot.ramdisk"));
        if version >= 1 {
            assert!(report.components.iter().any(|component| component.name == "boot.recovery_dtbo"));
        }
        if version == 2 {
            assert!(report.components.iter().any(|component| component.name == "boot.dtb"));
        }
    }
}

#[test]
fn boot_v3_v4_use_exact_4096_alignment_and_v4_signature_range() {
    let v3 = boot_modern(3, false);
    let report = inspect_android_artifact(
        &v3,
        &context(),
        request(AndroidArtifactKind::Boot),
        AndroidLimits::default(),
        None,
    )
    .expect("v3");
    assert_eq!(report.components.iter().find(|c| c.name == "boot.kernel").unwrap().byte_start, 4096);
    assert_eq!(report.components.iter().find(|c| c.name == "boot.ramdisk").unwrap().byte_start, 8192);

    let v4 = boot_modern(4, false);
    let report = inspect_android_artifact(
        &v4,
        &context(),
        request(AndroidArtifactKind::Boot),
        AndroidLimits::default(),
        None,
    )
    .expect("v4");
    assert!(report.components.iter().any(|c| c.name == "boot.signature"));
    assert_eq!(report.trust, AndroidTrustAssessment::NotEstablished);
}

#[test]
fn android_magic_requires_explicit_boot_or_init_boot_role() {
    let source = boot_modern(4, false);
    assert!(matches!(
        inspect_android_artifact(
            &source,
            &context(),
            AndroidInspectRequest::default(),
            AndroidLimits::default(),
            None,
        ),
        Err(C03Error::BootRoleRequired)
    ));
    assert!(matches!(
        inspect_android_artifact(
            &source,
            &context(),
            request(AndroidArtifactKind::VendorBoot),
            AndroidLimits::default(),
            None,
        ),
        Err(C03Error::DeclaredKindMismatch)
    ));
}

#[test]
fn init_boot_requires_v4_ramdisk_only_framing() {
    let init = boot_modern(4, true);
    let report = inspect_android_artifact(
        &init,
        &context(),
        request(AndroidArtifactKind::InitBoot),
        AndroidLimits::default(),
        None,
    )
    .expect("init_boot");
    assert_eq!(report.kind, AndroidArtifactKind::InitBoot);
    assert!(report.components.iter().any(|c| c.name == "init_boot.ramdisk"));
    let v3 = boot_modern(3, false);
    assert!(inspect_android_artifact(
        &v3,
        &context(),
        request(AndroidArtifactKind::InitBoot),
        AndroidLimits::default(),
        None,
    )
    .is_err());
}

#[test]
fn vendor_boot_v3_boundaries_are_exact() {
    let source = vendor_boot(3);
    let report = inspect_android_artifact(
        &source,
        &context(),
        request(AndroidArtifactKind::VendorBoot),
        AndroidLimits::default(),
        None,
    )
    .expect("vendor boot v3");
    assert_eq!(report.assessment, AndroidAssessment::Complete);
    assert!(report.components.iter().any(|c| c.name == "vendor_boot.ramdisk_section"));
    assert!(report.components.iter().any(|c| c.name == "vendor_boot.dtb"));
}

#[test]
fn vendor_boot_v4_validates_ramdisk_table_fragments_and_bootconfig() {
    let source = vendor_boot(4);
    let report = inspect_android_artifact(
        &source,
        &context(),
        request(AndroidArtifactKind::VendorBoot),
        AndroidLimits::default(),
        None,
    )
    .expect("vendor boot v4");
    assert!(report.components.iter().any(|c| c.name == "vendor_boot.ramdisk_table"));
    assert!(report.components.iter().any(|c| c.name == "vendor_boot.ramdisk_fragment.0"));
    assert!(report.components.iter().any(|c| c.name == "vendor_boot.bootconfig"));
}

#[test]
fn dtbo_v0_v1_and_v2_entries_are_bounded() {
    for version in 0..=2 {
        let source = dtbo(version);
        let report = inspect_android_artifact(
            &source,
            &context(),
            request(AndroidArtifactKind::Dtbo),
            AndroidLimits::default(),
            None,
        )
        .expect("dtbo");
        assert_eq!(report.kind, AndroidArtifactKind::Dtbo);
        assert!(report.components.iter().any(|c| c.name == "dtbo.entry.0"));
    }
}

#[test]
fn malformed_or_truncated_dtbo_fails_closed() {
    let mut source = dtbo(1);
    source[4..8].copy_from_slice(&10_000_u32.to_be_bytes());
    assert!(inspect_android_artifact(
        &source,
        &context(),
        request(AndroidArtifactKind::Dtbo),
        AndroidLimits::default(),
        None,
    )
    .is_err());
    assert!(inspect_android_artifact(
        &dtbo(1)[..20],
        &context(),
        request(AndroidArtifactKind::Dtbo),
        AndroidLimits::default(),
        None,
    )
    .is_err());
}

#[test]
fn vbmeta_ranges_are_exact_but_trust_is_not_established() {
    let source = vbmeta();
    let report = inspect_android_artifact(
        &source,
        &context(),
        request(AndroidArtifactKind::Vbmeta),
        AndroidLimits::default(),
        None,
    )
    .expect("vbmeta");
    assert_eq!(report.assessment, AndroidAssessment::Partial);
    assert_eq!(report.trust, AndroidTrustAssessment::NotEstablished);
    assert!(report.components.iter().any(|c| c.name == "vbmeta.authentication"));
    assert!(report.components.iter().any(|c| c.name == "vbmeta.descriptors"));
    assert!(report.limitations.iter().any(|l| l.contains("known-good key")));
}

#[test]
fn malformed_vbmeta_auxiliary_or_descriptor_bounds_fail_closed() {
    let mut source = vbmeta();
    source[104..112].copy_from_slice(&1000_u64.to_be_bytes());
    assert!(inspect_android_artifact(
        &source,
        &context(),
        request(AndroidArtifactKind::Vbmeta),
        AndroidLimits::default(),
        None,
    )
    .is_err());
}

#[test]
fn valid_super_checksums_and_dynamic_partition_inventory_are_exact() {
    let source = super_image("system");
    let report = inspect_android_artifact(
        &source,
        &context(),
        request(AndroidArtifactKind::Super),
        AndroidLimits::default(),
        None,
    )
    .expect("super");
    assert_eq!(report.integrity, AndroidIntegrityAssessment::ChecksumsVerified);
    assert_eq!(report.assessment, AndroidAssessment::Complete);
    assert_eq!(report.dynamic_partitions.len(), 1);
    assert_eq!(report.dynamic_partitions[0].name, "system");
    assert_eq!(report.dynamic_partitions[0].logical_size, 6 * 512);
    assert_eq!(report.dynamic_groups[0].name, "default");
    assert_eq!(report.block_devices[0].name, "super");
}

#[test]
fn super_checksum_table_and_extent_corruption_fail_or_reduce_truth() {
    let mut one_bad_copy = super_image("system");
    one_bad_copy[12288 + 12] ^= 1;
    let report = inspect_android_artifact(
        &one_bad_copy,
        &context(),
        request(AndroidArtifactKind::Super),
        AndroidLimits::default(),
        None,
    )
    .expect("backup survives");
    assert_eq!(report.assessment, AndroidAssessment::Partial);
    assert!(report.limitations.iter().any(|l| l.contains("primary copy is invalid")));

    let mut both_bad = super_image("system");
    both_bad[12288 + 12] ^= 1;
    both_bad[16384 + 12] ^= 1;
    assert!(inspect_android_artifact(
        &both_bad,
        &context(),
        request(AndroidArtifactKind::Super),
        AndroidLimits::default(),
        None,
    )
    .is_err());
}

#[test]
fn dynamic_partition_linear_and_zero_extents_materialize_exactly() {
    let source = super_image("system");
    let ctx = context();
    let report = inspect_android_artifact(
        &source,
        &ctx,
        request(AndroidArtifactKind::Super),
        AndroidLimits::default(),
        None,
    )
    .expect("super");
    let materialized = materialize_dynamic_partition(
        &source,
        &report,
        0,
        "system",
        &ctx,
        AndroidLimits::default(),
    )
    .expect("partition bytes");
    assert_eq!(materialized.bytes().len(), 6 * 512);
    assert!(materialized.bytes()[..4 * 512].iter().all(|byte| *byte == 0xa5));
    assert!(materialized.bytes()[4 * 512..].iter().all(|byte| *byte == 0));
}

#[test]
fn super_primary_backup_metadata_disagreement_remains_explicit() {
    let source = super_image("vendor");
    let report = inspect_android_artifact(
        &source,
        &context(),
        request(AndroidArtifactKind::Super),
        AndroidLimits::default(),
        None,
    )
    .expect("super disagreement");
    assert_eq!(report.assessment, AndroidAssessment::Partial);
    assert_eq!(report.dynamic_partitions[0].name, "system");
    assert!(report.limitations.iter().any(|l| l.contains("copies disagree")));
}

#[test]
fn ota_v2_envelope_has_exact_manifest_signature_and_data_ranges() {
    let source = ota_payload(16, 8, 64);
    let report = inspect_android_artifact(
        &source,
        &context(),
        request(AndroidArtifactKind::OtaPayload),
        AndroidLimits::default(),
        None,
    )
    .expect("OTA envelope");
    assert_eq!(report.assessment, AndroidAssessment::Partial);
    let manifest = report.components.iter().find(|c| c.name == "ota.manifest").unwrap();
    assert_eq!((manifest.byte_start, manifest.byte_end_exclusive), (24, 40));
    let signature = report.components.iter().find(|c| c.name == "ota.metadata_signature").unwrap();
    assert_eq!((signature.byte_start, signature.byte_end_exclusive), (40, 48));
    let data = report.components.iter().find(|c| c.name == "ota.payload_data").unwrap();
    assert_eq!(data.byte_start, 48);
}

#[test]
fn malformed_or_oversized_ota_metadata_fails_before_provider() {
    let mut source = ota_payload(16, 8, 64);
    source[12..20].copy_from_slice(&10_000_u64.to_be_bytes());
    assert!(inspect_android_artifact(
        &source,
        &context(),
        request(AndroidArtifactKind::OtaPayload),
        AndroidLimits::default(),
        None,
    )
    .is_err());

    let source = ota_payload(16, 8, 64);
    let limits = AndroidLimits {
        max_manifest_bytes: 8,
        ..AndroidLimits::default()
    };
    assert!(matches!(
        inspect_android_artifact(
            &source,
            &context(),
            request(AndroidArtifactKind::OtaPayload),
            limits,
            None,
        ),
        Err(C03Error::ManifestTooLarge)
    ));
}

#[test]
fn ota_provider_partition_group_and_data_relationships_are_validated() {
    let source = ota_payload(16, 8, 64);
    let provider = FixtureOtaProvider {
        id: "aosp-update-metadata".to_owned(),
        observation: ota_observation(),
        fail: false,
    };
    let report = inspect_android_artifact(
        &source,
        &context(),
        request(AndroidArtifactKind::OtaPayload),
        AndroidLimits::default(),
        Some(&provider),
    )
    .expect("OTA manifest");
    assert_eq!(report.assessment, AndroidAssessment::Complete);
    let manifest = report.ota_manifest.expect("manifest");
    assert_eq!(manifest.provider_alias, "aosp-update-metadata");
    assert_eq!(manifest.partitions[0].name, "system");
    assert_eq!(manifest.dynamic_groups[0].partition_names, vec!["system"]);
}

#[test]
fn ota_provider_failure_or_out_of_bounds_operations_fail_closed() {
    let source = ota_payload(16, 8, 64);
    let failed = FixtureOtaProvider {
        id: "fixture".to_owned(),
        observation: ota_observation(),
        fail: true,
    };
    assert!(matches!(
        inspect_android_artifact(
            &source,
            &context(),
            request(AndroidArtifactKind::OtaPayload),
            AndroidLimits::default(),
            Some(&failed),
        ),
        Err(C03Error::OtaProvider(_))
    ));
    let mut observation = ota_observation();
    observation.partitions[0].operations[0].data_offset = 1000;
    let invalid = FixtureOtaProvider {
        id: "fixture".to_owned(),
        observation,
        fail: false,
    };
    assert!(matches!(
        inspect_android_artifact(
            &source,
            &context(),
            request(AndroidArtifactKind::OtaPayload),
            AndroidLimits::default(),
            Some(&invalid),
        ),
        Err(C03Error::InvalidOtaObservation)
    ));
}

#[test]
fn a07_component_partition_relationship_views_and_integrity_are_source_bound() {
    let source = boot_modern(4, false);
    let ctx = context();
    let report = inspect_android_artifact(
        &source,
        &ctx,
        request(AndroidArtifactKind::Boot),
        AndroidLimits::default(),
        None,
    )
    .expect("boot");
    let child = materialize_android_component(
        &source,
        &report,
        "boot.kernel",
        &ctx,
        AndroidLimits::default(),
    )
    .expect("kernel");
    let registration_spec = child.registration_spec(&ctx).expect("registration");
    assert_eq!(registration_spec.object_class, "android.image.component");
    assert_eq!(registration_spec.source_refs, vec![ctx.source_revision_ref.clone()]);
    let registration = Registration {
        content_ref: reference("object.content"),
        object_ref: reference("object.object"),
        revision_ref: reference("object.revision"),
        location_ref: reference("storage.location"),
        sha256: child.sha256.clone(),
        byte_size: child.bytes().len() as u64,
        cas_object_key: child.sha256.clone(),
        content_deduplicated: false,
    };
    let relationship = child.relationship_spec(&ctx, &registration).expect("relationship");
    assert_eq!(relationship.relationship_type, "contains.android_child");
    assert_eq!(report.view_specs(&ctx).expect("views").len(), 3);

    let mut mutated = report.clone();
    mutated.components[0].byte_end_exclusive += 1;
    assert!(matches!(
        mutated.view_specs(&ctx),
        Err(C03Error::ReportIntegrityMismatch)
    ));
    assert!(matches!(
        materialize_android_component(
            &source,
            &mutated,
            "boot.kernel",
            &ctx,
            AndroidLimits::default(),
        ),
        Err(C03Error::ReportIntegrityMismatch)
    ));
}

#[test]
fn comparison_and_rebuild_levels_do_not_overclaim_trust_or_bootability() {
    let original_source = boot_modern(4, false);
    let ctx = context();
    let original = inspect_android_artifact(
        &original_source,
        &ctx,
        request(AndroidArtifactKind::Boot),
        AndroidLimits::default(),
        None,
    )
    .expect("original");
    let exact = inspect_android_artifact(
        &original_source,
        &context(),
        request(AndroidArtifactKind::Boot),
        AndroidLimits::default(),
        None,
    )
    .expect("exact");
    assert_eq!(compare_android_artifacts(&original, &exact).level, AndroidComparisonLevel::ByteExact);
    assert_eq!(assess_android_rebuild(&original, &exact), AndroidRebuildProofLevel::ByteExact);

    let mut padding_changed = original_source.clone();
    padding_changed[2000] ^= 1;
    let component_exact = inspect_android_artifact(
        &padding_changed,
        &context(),
        request(AndroidArtifactKind::Boot),
        AndroidLimits::default(),
        None,
    )
    .expect("padding change");
    assert_eq!(
        compare_android_artifacts(&original, &component_exact).level,
        AndroidComparisonLevel::ComponentExact
    );

    let mut kernel_changed = original_source.clone();
    kernel_changed[4096] ^= 1;
    let structural = inspect_android_artifact(
        &kernel_changed,
        &context(),
        request(AndroidArtifactKind::Boot),
        AndroidLimits::default(),
        None,
    )
    .expect("kernel change");
    assert_eq!(
        compare_android_artifacts(&original, &structural).level,
        AndroidComparisonLevel::Structural
    );
    assert_eq!(structural.trust, AndroidTrustAssessment::NotEstablished);
}
