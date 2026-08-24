use ptah_archive_decomposition::{
    C01Error, DiskImageContext, DiskImageFormat, DiskImageLimits, PartitionLayoutKind,
    PartitionMapAssessment, PartitionTableKind, SourceCoverageKind, compare_disk_images,
    encode_android_sparse, inspect_partition_map, materialize_partition, normalize_disk_image,
};
use ptah_identifiers::EntityRef;
use ptah_object_store::{ProductionEvidence, Registration};

const SECTOR: usize = 512;

fn reference(kind: &str) -> EntityRef {
    EntityRef::new(kind).expect("valid fixture reference")
}

fn context(source_revision_ref: EntityRef) -> DiskImageContext {
    DiskImageContext {
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

fn mbr_image(total_sectors: usize, entries: &[(usize, u8, u8, u32, u32)]) -> Vec<u8> {
    let mut image = vec![0_u8; total_sectors * SECTOR];
    image[510] = 0x55;
    image[511] = 0xaa;
    for (slot, status, partition_type, first_lba, sectors) in entries {
        let offset = 446 + slot * 16;
        image[offset] = *status;
        image[offset + 4] = *partition_type;
        image[offset + 8..offset + 12].copy_from_slice(&first_lba.to_le_bytes());
        image[offset + 12..offset + 16].copy_from_slice(&sectors.to_le_bytes());
    }
    image
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn gpt_image(first_lba: u64, last_lba: u64, hybrid_mbr: bool) -> Vec<u8> {
    let total_sectors = 128_usize;
    let mut image = mbr_image(total_sectors, &[(0, 0, 0xee, 1, 127)]);
    if hybrid_mbr {
        let offset = 446 + 16;
        image[offset + 4] = 0x83;
        image[offset + 8..offset + 12].copy_from_slice(&60_u32.to_le_bytes());
        image[offset + 12..offset + 16].copy_from_slice(&10_u32.to_le_bytes());
    }

    let entries_start = 2 * SECTOR;
    let entries_len = 4 * 128;
    let entry = &mut image[entries_start..entries_start + 128];
    entry[0..16].copy_from_slice(&[
        0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26,
        0x99, 0xc7,
    ]);
    entry[16..32].copy_from_slice(&[
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
        0xdc, 0xfe,
    ]);
    entry[32..40].copy_from_slice(&first_lba.to_le_bytes());
    entry[40..48].copy_from_slice(&last_lba.to_le_bytes());
    for (index, word) in "system".encode_utf16().enumerate() {
        let offset = 56 + index * 2;
        entry[offset..offset + 2].copy_from_slice(&word.to_le_bytes());
    }

    let entries_crc = crc32(&image[entries_start..entries_start + entries_len]);
    let header = &mut image[SECTOR..2 * SECTOR];
    header[0..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes());
    header[12..16].copy_from_slice(&92_u32.to_le_bytes());
    header[16..20].fill(0);
    header[24..32].copy_from_slice(&1_u64.to_le_bytes());
    header[32..40].copy_from_slice(&127_u64.to_le_bytes());
    header[40..48].copy_from_slice(&34_u64.to_le_bytes());
    header[48..56].copy_from_slice(&126_u64.to_le_bytes());
    header[56..72].copy_from_slice(&[
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ]);
    header[72..80].copy_from_slice(&2_u64.to_le_bytes());
    header[80..84].copy_from_slice(&4_u32.to_le_bytes());
    header[84..88].copy_from_slice(&128_u32.to_le_bytes());
    header[88..92].copy_from_slice(&entries_crc.to_le_bytes());
    let header_crc = crc32(&header[..92]);
    header[16..20].copy_from_slice(&header_crc.to_le_bytes());
    image
}

fn sparse_with_mbr_dontcare() -> Vec<u8> {
    let first = mbr_image(1, &[(0, 0, 0x83, 1, 1)]);
    let mut sparse = Vec::new();
    sparse.extend_from_slice(&0xed26_ff3a_u32.to_le_bytes());
    sparse.extend_from_slice(&1_u16.to_le_bytes());
    sparse.extend_from_slice(&0_u16.to_le_bytes());
    sparse.extend_from_slice(&28_u16.to_le_bytes());
    sparse.extend_from_slice(&12_u16.to_le_bytes());
    sparse.extend_from_slice(&512_u32.to_le_bytes());
    sparse.extend_from_slice(&3_u32.to_le_bytes());
    sparse.extend_from_slice(&3_u32.to_le_bytes());
    sparse.extend_from_slice(&0_u32.to_le_bytes());

    sparse.extend_from_slice(&0xcac1_u16.to_le_bytes());
    sparse.extend_from_slice(&0_u16.to_le_bytes());
    sparse.extend_from_slice(&1_u32.to_le_bytes());
    sparse.extend_from_slice(&(12_u32 + 512).to_le_bytes());
    sparse.extend_from_slice(&first);

    sparse.extend_from_slice(&0xcac3_u16.to_le_bytes());
    sparse.extend_from_slice(&0_u16.to_le_bytes());
    sparse.extend_from_slice(&1_u32.to_le_bytes());
    sparse.extend_from_slice(&12_u32.to_le_bytes());

    sparse.extend_from_slice(&0xcac2_u16.to_le_bytes());
    sparse.extend_from_slice(&0_u16.to_le_bytes());
    sparse.extend_from_slice(&1_u32.to_le_bytes());
    sparse.extend_from_slice(&16_u32.to_le_bytes());
    sparse.extend_from_slice(&0x1122_3344_u32.to_le_bytes());
    sparse
}

#[test]
fn raw_normalization_is_identity_and_source_immutable() {
    let source = mbr_image(16, &[(0, 0x80, 0x83, 2, 4)]);
    let before = source.clone();
    let normalized = normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
    assert_eq!(source, before);
    assert_eq!(normalized.source_format(), DiskImageFormat::Raw);
    assert_eq!(normalized.bytes(), source.as_slice());
    assert_eq!(normalized.source_coverage().len(), 1);
    assert_eq!(normalized.source_coverage()[0].kind, SourceCoverageKind::Defined);
}

#[test]
fn raw_to_sparse_roundtrip_preserves_bytes_and_coverage() {
    let source = vec![0x5a_u8; 4 * SECTOR];
    let raw = normalize_disk_image(&source, DiskImageLimits::default()).expect("raw");
    let sparse =
        encode_android_sparse(&raw, 512, DiskImageLimits::default()).expect("encode sparse");
    let roundtrip =
        normalize_disk_image(&sparse, DiskImageLimits::default()).expect("decode sparse");
    assert_eq!(roundtrip.bytes(), source.as_slice());
    assert_eq!(roundtrip.source_coverage(), raw.source_coverage());
    assert_eq!(roundtrip.source_format(), DiskImageFormat::AndroidSparse);
}

#[test]
fn sparse_raw_fill_and_dontcare_preserve_exact_coverage() {
    let sparse = sparse_with_mbr_dontcare();
    let normalized =
        normalize_disk_image(&sparse, DiskImageLimits::default()).expect("normalize sparse");
    assert_eq!(normalized.bytes().len(), 3 * SECTOR);
    assert_eq!(normalized.source_coverage().len(), 3);
    assert_eq!(normalized.source_coverage()[0].byte_end_exclusive, 512);
    assert_eq!(normalized.source_coverage()[1].kind, SourceCoverageKind::Unspecified);
    assert_eq!(normalized.source_coverage()[1].byte_start, 512);
    assert_eq!(normalized.source_coverage()[1].byte_end_exclusive, 1024);
    assert_eq!(
        &normalized.bytes()[1024..1028],
        &0x1122_3344_u32.to_le_bytes()
    );
}

#[test]
fn malformed_and_crc_bad_sparse_fail_closed() {
    let mut malformed = vec![0_u8; 28];
    malformed[0..4].copy_from_slice(&0xed26_ff3a_u32.to_le_bytes());
    malformed[4..6].copy_from_slice(&2_u16.to_le_bytes());
    assert!(matches!(
        normalize_disk_image(&malformed, DiskImageLimits::default()),
        Err(C01Error::MalformedSparse(_))
    ));

    let source = vec![0x11_u8; SECTOR];
    let raw = normalize_disk_image(&source, DiskImageLimits::default()).expect("raw");
    let mut sparse =
        encode_android_sparse(&raw, 512, DiskImageLimits::default()).expect("sparse");
    sparse[24..28].copy_from_slice(&0xdead_beef_u32.to_le_bytes());
    assert!(matches!(
        normalize_disk_image(&sparse, DiskImageLimits::default()),
        Err(C01Error::SparseCrcMismatch)
    ));
}

#[test]
fn mbr_partition_boundaries_and_layout_are_exact() {
    let source = mbr_image(16, &[(0, 0x80, 0x83, 2, 4)]);
    let normalized = normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
    let ctx = context(reference("object.revision"));
    let report =
        inspect_partition_map(&normalized, &ctx, DiskImageLimits::default()).expect("inspect");
    assert_eq!(report.partition_table, PartitionTableKind::Mbr);
    assert_eq!(report.assessment, PartitionMapAssessment::Complete);
    assert_eq!(report.partitions.len(), 1);
    let partition = &report.partitions[0];
    assert_eq!(partition.first_lba, 2);
    assert_eq!(partition.last_lba_inclusive, 5);
    assert_eq!(partition.byte_start, 1024);
    assert_eq!(partition.byte_end_exclusive, 3072);
    assert!(partition.bootable);
    assert_eq!(report.layout_coverage[0].kind, PartitionLayoutKind::Unallocated);
    assert_eq!(report.layout_coverage[1].kind, PartitionLayoutKind::Partition);
    assert_eq!(report.layout_coverage[2].kind, PartitionLayoutKind::Unallocated);
}

#[test]
fn corrupt_mbr_extent_is_inconclusive_not_complete() {
    let source = mbr_image(8, &[(0, 0, 0x83, 7, 8)]);
    let normalized = normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
    let report = inspect_partition_map(
        &normalized,
        &context(reference("object.revision")),
        DiskImageLimits::default(),
    )
    .expect("inspect");
    assert_eq!(report.assessment, PartitionMapAssessment::Inconclusive);
    assert!(report.partitions.is_empty());
    assert!(report
        .layout_coverage
        .iter()
        .all(|range| range.kind == PartitionLayoutKind::Unknown));
}

#[test]
fn extended_mbr_is_explicit_partial() {
    let source = mbr_image(32, &[(0, 0, 0x0f, 2, 20)]);
    let normalized = normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
    let report = inspect_partition_map(
        &normalized,
        &context(reference("object.revision")),
        DiskImageLimits::default(),
    )
    .expect("inspect");
    assert_eq!(report.assessment, PartitionMapAssessment::Partial);
    assert!(report.partitions[0].container);
    assert!(report
        .limitations
        .iter()
        .any(|value| value.contains("EBR recursion")));
}

#[test]
fn overlapping_mbr_layout_becomes_unknown() {
    let source = mbr_image(32, &[(0, 0, 0x83, 2, 10), (1, 0, 0x07, 8, 8)]);
    let normalized = normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
    let report = inspect_partition_map(
        &normalized,
        &context(reference("object.revision")),
        DiskImageLimits::default(),
    )
    .expect("inspect");
    assert_eq!(report.assessment, PartitionMapAssessment::Partial);
    assert_eq!(report.layout_coverage.len(), 1);
    assert_eq!(report.layout_coverage[0].kind, PartitionLayoutKind::Unknown);
}

#[test]
fn gpt_partition_and_crcs_produce_complete_map() {
    let source = gpt_image(40, 49, false);
    let normalized = normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
    let report = inspect_partition_map(
        &normalized,
        &context(reference("object.revision")),
        DiskImageLimits::default(),
    )
    .expect("inspect");
    assert_eq!(report.partition_table, PartitionTableKind::Gpt);
    assert_eq!(report.assessment, PartitionMapAssessment::Complete);
    assert_eq!(report.partitions.len(), 1);
    assert_eq!(report.partitions[0].name.as_deref(), Some("system"));
    assert_eq!(report.partitions[0].first_lba, 40);
    assert_eq!(report.partitions[0].last_lba_inclusive, 49);
    assert_eq!(report.partition_table_ranges.len(), 3);
}

#[test]
fn corrupt_gpt_header_crc_is_inconclusive() {
    let mut source = gpt_image(40, 49, false);
    source[SECTOR + 20] ^= 0x01;
    let normalized = normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
    let report = inspect_partition_map(
        &normalized,
        &context(reference("object.revision")),
        DiskImageLimits::default(),
    )
    .expect("inspect");
    assert_eq!(report.assessment, PartitionMapAssessment::Inconclusive);
    assert!(report.partitions.is_empty());
    assert!(report
        .limitations
        .iter()
        .any(|value| value.contains("header CRC32")));
}

#[test]
fn corrupt_gpt_entry_crc_is_inconclusive() {
    let mut source = gpt_image(40, 49, false);
    source[2 * SECTOR] ^= 0x01;
    let normalized = normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
    let report = inspect_partition_map(
        &normalized,
        &context(reference("object.revision")),
        DiskImageLimits::default(),
    )
    .expect("inspect");
    assert_eq!(report.assessment, PartitionMapAssessment::Inconclusive);
    assert!(report.partitions.is_empty());
    assert!(report
        .limitations
        .iter()
        .any(|value| value.contains("entry array CRC32")));
}

#[test]
fn invalid_gpt_partition_extent_is_inconclusive() {
    let source = gpt_image(120, 140, false);
    let normalized = normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
    let report = inspect_partition_map(
        &normalized,
        &context(reference("object.revision")),
        DiskImageLimits::default(),
    )
    .expect("inspect");
    assert_eq!(report.assessment, PartitionMapAssessment::Inconclusive);
    assert!(report.partitions.is_empty());
    assert!(report
        .warnings
        .iter()
        .any(|value| value.contains("invalid identity or usable-LBA extent")));
}

#[test]
fn hybrid_mbr_is_partial_even_with_valid_gpt() {
    let source = gpt_image(40, 49, true);
    let normalized = normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
    let report = inspect_partition_map(
        &normalized,
        &context(reference("object.revision")),
        DiskImageLimits::default(),
    )
    .expect("inspect");
    assert_eq!(report.partition_table, PartitionTableKind::Gpt);
    assert_eq!(report.assessment, PartitionMapAssessment::Partial);
    assert!(report
        .limitations
        .iter()
        .any(|value| value.contains("hybrid MBR")));
}

#[test]
fn dontcare_partition_materialization_fails_closed() {
    let sparse = sparse_with_mbr_dontcare();
    let normalized =
        normalize_disk_image(&sparse, DiskImageLimits::default()).expect("normalize sparse");
    let ctx = context(reference("object.revision"));
    let report =
        inspect_partition_map(&normalized, &ctx, DiskImageLimits::default()).expect("inspect");
    assert_eq!(report.partitions[0].byte_start, 512);
    assert!(matches!(
        materialize_partition(&normalized, &report, 1, &ctx),
        Err(C01Error::UnspecifiedPartitionBytes)
    ));
}

#[test]
fn materialization_is_exact_and_builds_a07_registration() {
    let mut source = mbr_image(16, &[(0, 0, 0x83, 2, 2)]);
    source[2 * SECTOR..4 * SECTOR].fill(0x7a);
    let normalized = normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
    let ctx = context(reference("object.revision"));
    let report =
        inspect_partition_map(&normalized, &ctx, DiskImageLimits::default()).expect("inspect");
    let materialized =
        materialize_partition(&normalized, &report, 1, &ctx).expect("materialize partition");
    assert_eq!(materialized.bytes(), &source[2 * SECTOR..4 * SECTOR]);
    let spec = materialized.registration_spec(&ctx);
    assert_eq!(spec.object_class, "disk.partition");
    assert_eq!(spec.source_refs, vec![ctx.source_revision_ref.clone()]);
    assert_eq!(
        spec.expected_sha256.as_deref(),
        Some(materialized.sha256.as_str())
    );
}

#[test]
fn relationship_requires_exact_registered_partition_bytes() {
    let source = mbr_image(16, &[(0, 0, 0x83, 2, 2)]);
    let normalized = normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
    let ctx = context(reference("object.revision"));
    let report =
        inspect_partition_map(&normalized, &ctx, DiskImageLimits::default()).expect("inspect");
    let materialized =
        materialize_partition(&normalized, &report, 1, &ctx).expect("materialize");
    let good = Registration {
        content_ref: reference("object.content"),
        object_ref: reference("object.object"),
        revision_ref: reference("object.revision"),
        location_ref: reference("storage.location"),
        sha256: materialized.sha256.clone(),
        byte_size: u64::try_from(materialized.bytes().len()).expect("size"),
        cas_object_key: materialized.sha256.clone(),
        content_deduplicated: false,
    };
    let relationship = materialized
        .relationship_spec(&ctx, &good)
        .expect("relationship");
    assert_eq!(relationship.relationship_type, "contains.partition");

    let mut bad = good;
    bad.sha256 = "0".repeat(64);
    assert!(matches!(
        materialized.relationship_spec(&ctx, &bad),
        Err(C01Error::PartitionRegistrationMismatch)
    ));
}

#[test]
fn view_plans_are_exact_source_bound() {
    let source = mbr_image(16, &[(0, 0, 0x83, 2, 2)]);
    let normalized = normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
    let ctx = context(reference("object.revision"));
    let report =
        inspect_partition_map(&normalized, &ctx, DiskImageLimits::default()).expect("inspect");
    let views = report.view_specs(&ctx).expect("views");
    assert_eq!(views.len(), 2);
    assert!(views
        .iter()
        .all(|view| view.source_revision_refs == vec![ctx.source_revision_ref.clone()]));

    let other = context(reference("object.revision"));
    assert!(matches!(
        report.view_specs(&other),
        Err(C01Error::SourceBindingMismatch)
    ));
}

#[test]
fn structural_comparison_retains_both_source_revisions() {
    let left_source = mbr_image(16, &[(0, 0, 0x83, 2, 2)]);
    let right_source = mbr_image(16, &[(0, 0, 0x83, 2, 3)]);
    let left_image =
        normalize_disk_image(&left_source, DiskImageLimits::default()).expect("left normalize");
    let right_image =
        normalize_disk_image(&right_source, DiskImageLimits::default()).expect("right normalize");
    let left_ctx = context(reference("object.revision"));
    let right_ctx = context(reference("object.revision"));
    let left = inspect_partition_map(&left_image, &left_ctx, DiskImageLimits::default())
        .expect("left inspect");
    let right = inspect_partition_map(&right_image, &right_ctx, DiskImageLimits::default())
        .expect("right inspect");
    let comparison = compare_disk_images(&left, &right);
    assert_eq!(
        comparison.left_source_revision_ref,
        left_ctx.source_revision_ref
    );
    assert_eq!(
        comparison.right_source_revision_ref,
        right_ctx.source_revision_ref
    );
    assert!(!comparison.identical_layout);
    assert!(comparison
        .differences
        .iter()
        .any(|difference| difference.contains("partition_slot_changed:1")));
}

#[test]
fn limits_fail_closed() {
    let source = vec![0_u8; 2 * SECTOR];
    let tiny = DiskImageLimits {
        max_output_bytes: 512,
        max_sparse_chunks: 1,
        max_partition_entries: 1,
    };
    assert!(matches!(
        normalize_disk_image(&source, tiny),
        Err(C01Error::OutputTooLarge)
    ));

    let gpt = gpt_image(40, 49, false);
    let normalized = normalize_disk_image(&gpt, DiskImageLimits::default()).expect("normalize");
    assert!(matches!(
        inspect_partition_map(
            &normalized,
            &context(reference("object.revision")),
            DiskImageLimits {
                max_output_bytes: 1024 * 1024,
                max_sparse_chunks: 10,
                max_partition_entries: 1,
            }
        ),
        Err(C01Error::TooManyPartitionEntries)
    ));
}

#[test]
fn unrecognized_partition_map_remains_inconclusive() {
    let source = vec![0_u8; 8 * SECTOR];
    let normalized = normalize_disk_image(&source, DiskImageLimits::default()).expect("normalize");
    let report = inspect_partition_map(
        &normalized,
        &context(reference("object.revision")),
        DiskImageLimits::default(),
    )
    .expect("inspect");
    assert_eq!(report.partition_table, PartitionTableKind::None);
    assert_eq!(report.assessment, PartitionMapAssessment::Inconclusive);
    assert!(report.partitions.is_empty());
}
