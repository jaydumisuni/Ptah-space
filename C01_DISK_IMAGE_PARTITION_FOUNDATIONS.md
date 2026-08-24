# C01 — Disk image and partition foundations

Status: BUILD / REVIEW candidate

Accepted base: `d6c0663a7a9c46c2d12dc9a4ce3bd404b5ffc710` (B07 / Object World Beta merge)

Authority: Ptah Implementation Roadmap 1.1.0, Programme C / C01.

## Scope

C01 is the first Firmware and Device Beta foundation. It remains read-first and source-immutable.

Delivered candidate surface:

- raw disk-image normalization;
- Android sparse v1 parsing and raw/sparse conversion;
- exact source-defined versus sparse `DONT_CARE` byte coverage;
- MBR primary partition parsing;
- GPT primary-header and partition-entry parsing with CRC32 verification;
- exact partition byte/LBA boundaries;
- partition-table metadata ranges;
- explicit complete / partial / inconclusive partition-map truth;
- explicit unknown/unallocated/partition layout coverage;
- MBR extended-container and hybrid-MBR limitation truth;
- exact read-only partition materialization;
- A07 partition Object registration plans;
- A07 source-to-partition Relationship plans;
- A07 partition-map and block-coverage View plans;
- structural, source-bound disk-image comparison foundations;
- bounded expanded-image, sparse-chunk and partition-entry resources.

Filesystem interpretation and filesystem mounting are intentionally outside C01; those begin at C02.

## Truth boundaries

- Source disk-image bytes are immutable inputs and are never rewritten in place.
- Normalized bytes are derived projection bytes, not a replacement canonical Revision.
- Android sparse `DONT_CARE` output positions are retained as `Unspecified`; zero-filled positional normalization does not upgrade those bytes into source truth.
- Partition materialization fails if any requested partition byte overlaps `Unspecified` source coverage.
- Corrupt MBR/GPT state cannot become a complete partition-map claim.
- GPT primary-header and partition-entry CRC32 checks are mechanical evidence gates.
- Invalid partition extents are excluded and reduce the map to partial/inconclusive.
- Extended MBR containers are retained but EBR recursion is not claimed by C01.
- Hybrid MBR + GPT is explicit partial coverage because C01 projects GPT only.
- Partition layout overlap becomes unknown coverage rather than contradictory overlapping truth.
- Partition Objects remain A07 registrations derived from exact source Revision bytes.
- View and Relationship plans bind the exact source Revision and A04 production evidence.
- Comparison is structural only; it does not claim filesystem or application semantic equality.

## Acceptance corpus

The exact candidate must pass all 20 C01 cases covering:

1. raw normalization identity and source immutability;
2. raw-to-sparse round-trip semantics;
3. sparse RAW/FILL/DONT_CARE exact coverage;
4. malformed and CRC-bad sparse fail-closed behavior;
5. exact MBR partition and layout boundaries;
6. out-of-bounds MBR inconclusive behavior;
7. explicit extended-MBR partial state;
8. overlapping MBR layout becoming unknown;
9. valid GPT CRC/boundary parsing;
10. corrupt GPT header CRC inconclusive behavior;
11. corrupt GPT entry-array CRC inconclusive behavior;
12. invalid GPT partition extent rejection;
13. hybrid MBR/GPT explicit partial state;
14. sparse DONT_CARE partition materialization rejection;
15. exact partition materialization and A07 registration plan;
16. exact A07 Relationship byte binding;
17. exact source-bound A07 View plans;
18. structural source-bound comparison;
19. resource bounds;
20. unrecognized partition-map inconclusive behavior.

## Exact-head proof gate

Promotion requires one exact PR head that passes:

- accepted B07 merge base and bounded six-file C01 scope lock;
- pinned Rust/Cargo 1.97.1;
- `cargo fmt --all -- --check`;
- C01 acceptance: 20/20;
- strict `ptah-archive-decomposition` Clippy with `-D warnings`;
- inherited B02 general-type/progressive-decomposition reproof;
- inherited B05 executable/application-package reproof;
- inherited B07 Search v1 reproof;
- full locked workspace regression;
- exact clean working tree;
- immutable exact-head proof manifest and retained artifact.

Any source movement invalidates Freeze and requires affected Review → Freeze → Prove again.

## Exit

C01 is COMPLETE only when the exact reviewed and proven candidate is merged to `main`.

Next dependency after C01: C02 — Filesystem Providers.
