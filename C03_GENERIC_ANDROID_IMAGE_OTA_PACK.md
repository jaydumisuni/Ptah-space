# C03 — Generic Android image and OTA pack

Status: BUILD / REVIEW candidate

Accepted base: `2d07a514dcff6fb740d2c5a81b073a46620cb3fd` (C02 merge)

Authority: Ptah Implementation Roadmap 1.1.0, Programme C / C03.

## Scope

C03 is a read-first Generic Android firmware pack layered on the exact C01 disk/partition and C02 filesystem foundations. It owns mechanical Android container framing, exact component/partition provenance, bounded Provider observations, structural comparison and explicit rebuild proof levels. It does not own flashing, boot execution, device compatibility, signing authority or Verified Boot trust decisions.

Delivered candidate surface:

- Android boot image v0-v4 structural inspection;
- explicit `boot` versus `init_boot` role binding when both use `ANDROID!` framing;
- Android `vendor_boot` v3/v4 inspection including vendor ramdisk/table/bootconfig ranges;
- DTBO table v0-v2 header/entry inspection with big-endian bounds checks;
- AVB vbmeta framing, authentication/auxiliary/descriptor ranges and explicit untrusted state;
- dynamic-partition `super.img` primary/backup geometry verification;
- liblp metadata header/table SHA-256 verification;
- logical partition, group, block-device and LINEAR/ZERO extent inventory;
- Android OTA `payload.bin` (`CrAU`) header/manifest/signature/data framing;
- replaceable bounded `OtaManifestProvider` for protobuf manifest semantics;
- OTA partition update and dynamic-group relationships from validated Provider observations;
- source-bound component and logical-partition materialization where exact bytes are mechanically available;
- A07 registration, source-child Relationship and inventory/manifest/proof View plans;
- structural comparison levels and rebuild proof levels: none, structural, component-exact and byte-exact;
- resource bounds for source size, components, metadata tables, partitions, extents, manifest bytes, operations and strings;
- integrity-sealed reports before materialization or canonical planning.

## Evidence-derived format boundaries

- Boot images use `ANDROID!`; legacy v0-v2 are page-aligned and v3/v4 use fixed 4096-byte alignment. `init_boot` is Android 13+ header v4 and carries the generic ramdisk.
- `vendor_boot` uses `VNDRBOOT`; v3 contains vendor ramdisk + DTB, while v4 additionally carries a vendor ramdisk table and bootconfig.
- DTBO table metadata is big-endian, headed by magic `0xd7b7ab1e`; v0/v1 entries are 32 bytes and v2 entries are 64 bytes.
- vbmeta uses magic `AVB0` and network-byte-order fields. Parsing is not trust: AVB data must be verified with the AVB verifier and a known-good public key before it can establish Verified Boot trust.
- liblp `super` metadata uses 512-byte sectors, a 4096-byte reserved prefix, primary/backup geometry blocks, SHA-256 geometry/header/table checksums, and versioned partition/extent/group/block-device tables.
- OTA payloads use `CrAU`, big-endian major-version/manifest-size framing and, for major version 2, a 4-byte metadata-signature-size field before the protobuf manifest.

## Truth boundaries

- Source bytes are immutable and exact source SHA-256 is retained.
- `ANDROID!` alone cannot distinguish `boot` from `init_boot`; the caller must provide the partition role, and `init_boot` is accepted only with header v4.
- Component ranges must be exact, non-overflowing and inside immutable source bytes.
- Parse success does not establish bootability, runtime success, OTA applicability or device compatibility.
- vbmeta structure is retained separately from AVB trust. C03 never upgrades parsed vbmeta to trusted/signed without independent known-key verification evidence.
- OTA manifest protobuf semantics come from a replaceable Provider and are validated by C03 against the exact manifest bytes and payload data bounds.
- Provider IDs remain Aliases/evidence rather than canonical identity.
- Dynamic-partition logical extents are exact. ZERO extents produce defined zero bytes; LINEAR extents can be materialized only when their target block device is the exact source image and their physical range is in bounds.
- Metadata copies that disagree remain visible and cannot silently become one complete truth.
- Unsupported metadata versions, target types, descriptors, compression modes or manifest semantics reduce truth to partial/inconclusive rather than being ignored.
- A rebuilt artifact earns `ByteExact` only when its whole-source digest matches; `ComponentExact` only when exact retained component identities match; `Structural` is explicitly weaker and makes no boot/signature claim.
- Comparison/rebuild proof never implies Verified Boot trust, flashing safety or semantic equivalence.
- Materialization and A07 plans validate the report integrity seal and exact source Revision again.

## Acceptance corpus

The exact candidate must pass a fixed 20-case positive/adversarial C03 corpus covering:

1. boot v0-v2 component boundaries and immutable source;
2. boot v3/v4 exact 4096 alignment and v4 boot-signature range;
3. `ANDROID!` boot/init ambiguity fails without declared role;
4. `init_boot` rejects non-v4 and accepts v4 ramdisk-only framing;
5. vendor_boot v3 boundaries;
6. vendor_boot v4 ramdisk table and bootconfig bounds;
7. DTBO v0/v1 entries and v2 entry-size/version rules;
8. malformed/truncated DTBO fails closed;
9. vbmeta authentication/auxiliary/descriptor bounds plus explicit untrusted state;
10. malformed vbmeta cannot claim a valid structure;
11. valid liblp geometry/header/table checksums and logical partition inventory;
12. super metadata checksum/table/extent corruption remains partial/inconclusive;
13. LINEAR/ZERO logical-partition materialization is exact and bounded;
14. metadata copy disagreement remains explicit;
15. OTA v2 envelope exact manifest/signature/data boundaries;
16. malformed/oversized OTA metadata fails before Provider decoding;
17. validated OTA manifest Provider partition/group/data-range relationships;
18. Provider disagreement/out-of-bounds OTA operations fail closed;
19. source-bound A07 component/partition registration, Relationship and View plans plus integrity-mutation rejection;
20. comparison and rebuild levels distinguish structural, component-exact and byte-exact truth without trust/boot claims.

Review corrections strengthen these 20 cases rather than increasing the count without new semantic coverage.

## Exact-head proof

The permanent workflow must be read-only and prove on one exact six-file candidate head:

1. exact accepted C02 merge base and six-file C03 scope;
2. clean diff and pinned Rust 1.97.1;
3. formatting and 20/20 C03 acceptance;
4. strict Clippy with `-D warnings`;
5. inherited C01 disk foundations;
6. inherited C02 filesystem Providers;
7. inherited B05 Android package/static semantics;
8. inherited B02/B07 Object World semantics;
9. full locked workspace;
10. exact clean tree after proof;
11. retained exact-head proof manifest/artifact.

## Permanent C03 surface

Exactly six files may differ from the accepted C02 merge:

- `C03_GENERIC_ANDROID_IMAGE_OTA_PACK.md`
- `crates/ptah-archive-decomposition/Cargo.toml`
- `crates/ptah-archive-decomposition/src/lib.rs`
- `crates/ptah-archive-decomposition/src/c03.rs`
- `crates/ptah-archive-decomposition/tests/c03.rs`
- `.github/workflows/c03-generic-android-image-ota-pack.yml`

## Exit gate

C03 is complete only after Review is clean, the exact six-file head is Frozen, the permanent read-only workflow proves all gates and retains its artifact, all Review findings are resolved against that exact source, and the PR merges with expected-head protection.
