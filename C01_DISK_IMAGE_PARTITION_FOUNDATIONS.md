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
- pre-expansion sparse chunk range/budget validation before allocation;
- MBR primary partition parsing;
- GPT primary-header and partition-entry parsing with CRC32 verification;
- GPT primary/current/backup/usable-LBA and entry-array bound validation;
- exact partition byte/LBA boundaries;
- partition-table metadata ranges;
- explicit complete / partial / inconclusive partition-map truth;
- explicit unknown/unallocated/partition layout coverage;
- MBR extended-container and hybrid-MBR limitation truth;
- exact read-only partition materialization;
- integrity-sealed parser reports before materialization or canonical View planning;
- A07 partition Object registration plans with exact source-Revision revalidation;
- A07 source-to-partition Relationship plans;
- A07 partition-map and block-coverage View plans;
- structural, source-bound disk-image comparison foundations including uncertainty/layout changes;
- bounded expanded-image, sparse-chunk and partition-entry resources.

Filesystem interpretation and filesystem mounting are intentionally outside C01; those begin at C02.

## Truth boundaries

- Source disk-image bytes are immutable inputs and are never rewritten in place.
- Normalized bytes are derived projection bytes, not a replacement canonical Revision.
- Android sparse `DONT_CARE` output positions are retained as `Unspecified`; zero-filled positional normalization does not upgrade those bytes into source truth.
- Sparse chunk cumulative byte ranges are rejected before RAW/FILL/DONT_CARE expansion when they exceed declared image or configured limits.
- Partition materialization fails if any requested partition byte overlaps `Unspecified` source coverage.
- Corrupt MBR/GPT state cannot become a complete partition-map claim.
- GPT primary-header and partition-entry CRC32 checks are mechanical evidence gates.
- GPT current/backup/usable LBA bounds and entry-array placement are validated before a complete claim.
- GPT entries outside usable LBAs, including partition-table metadata overlap, are excluded.
- Invalid partition extents or missing GPT partition identity are excluded and reduce the map to partial/inconclusive.
- Extended MBR containers are retained but EBR recursion is not claimed by C01.
- Hybrid MBR + GPT is explicit partial coverage because C01 projects GPT only.
- Partition layout overlap becomes unknown coverage rather than contradictory overlapping truth.
- Parser reports are integrity-sealed over exact source identity, partition projection and source coverage; post-parse mutation cannot authorize materialization.
- Partition Objects remain A07 registrations derived from exact source Revision bytes.
- Registration, View and Relationship plans re-bind the exact source Revision and A04 production evidence.
- Structural comparison treats assessment and layout-coverage changes as differences; uncertainty cannot compare equal to a complete layout.
- Comparison is structural only; it does not claim filesystem or application semantic equality.

## Acceptance corpus

The exact candidate must pass all 20 C01 cases covering:

1. raw normalization identity and source immutability;
2. raw-to-sparse round-trip semantics;
3. sparse RAW/FILL/DONT_CARE exact coverage;
4. malformed/CRC-bad sparse plus pre-expansion oversized-chunk rejection;
5. exact MBR partition and layout boundaries;
6. out-of-bounds MBR inconclusive behavior;
7. explicit extended-MBR partial state;
8. overlapping MBR layout becoming unknown;
9. valid GPT CRC/boundary parsing;
10. corrupt GPT header CRC inconclusive behavior;
11. corrupt GPT entry-array CRC inconclusive behavior;
12. invalid/out-of-usable-range GPT partition rejection including metadata overlap;
13. hybrid MBR/GPT explicit partial state;
14. sparse DONT_CARE partition materialization rejection plus report-integrity mutation rejection;
15. exact partition materialization and source-checked A07 registration plan;
16. exact A07 Relationship byte binding;
17. exact source-bound A07 View plans;
18. structural source-bound comparison including complete/partial layout uncertainty;
19. resource bounds;
20. unrecognized partition-map inconclusive behavior.

## Review findings bound into this candidate

- P1: sparse chunks must be range/budget validated before allocation or expansion.
- P1: GPT entries must stay within exact usable-LBA boundaries and outside GPT metadata.
- P2: materialization must reject post-parse mutation of the partition projection.
- P2: structural comparison must include assessment and layout coverage, not partition entries alone.

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
