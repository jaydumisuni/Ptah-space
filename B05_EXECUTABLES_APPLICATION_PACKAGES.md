# B05 — Executables and application packages

Status: BUILD / REVIEW candidate

Accepted base: `a6bd1fcd4e8d16dfe4eb36da1c72e683b37cb384` (B04 merge)

Authority: Ptah Implementation Roadmap 1.1.0, Programme B / B05.

## Scope

B05 extends the existing B02–B04 interpretation authority; it does not create a parallel Object world and it does not execute analyzed code.

Delivered candidate surface:

- B02-agreed type selection for PE, ELF, Mach-O, APK, AAB and DEX families;
- replaceable passive static-analysis Provider boundary;
- explicit denial of code execution, Provider-originated network access and external-resource loading;
- bounded technical/package metadata;
- section/segment, import, export and signature observations with canonical A07 View plans;
- APK/AAB/DEX embedded-child recovery with safe logical-path policy;
- exact child SHA-256 identity, recovered-Revision registration plan and parent/child Relationship plan;
- exact source Revision provenance frozen into every recovered child;
- explicit source-byte coverage, packed/unknown regions, retention gaps, warnings and limitations;
- static execution truth fixed to `NotExecuted`;
- no loader, installer, emulator, launcher or runtime-success surface.

## Truth boundaries

- B02 detector agreement remains type authority. B05 does not invent a winner for unknown/disputed type evidence.
- Provider IDs and observations remain mechanical evidence, not canonical Ptah identity.
- Signature verification is a static observation only; it is not a trust grant, approval or execution result.
- A recovered embedded child is a new A07 Object/Revision candidate with `RecoveredEmbeddedSource` provenance from the exact parent Revision.
- Relationship creation occurs only after the recovered child has an exact registered Object Revision.
- Missing Provider support, partial source inspection, packed regions and retention limits cannot silently become complete coverage.
- B05 never claims execution success because no source is executed.

## Acceptance corpus

The exact candidate must pass all 15 B05 cases covering:

1. PE metadata/import/export/section/signature Views and source immutability;
2. ELF and Mach-O class selection from B02 agreed type truth;
3. unknown and disputed B02 type truth;
4. unsupported type and missing-Provider coverage plans;
5. ambiguous and unsafe Provider rejection;
6. source/section extent overclaim rejection;
7. packed/unknown section coverage downgrade;
8. APK recovered-child Revision provenance;
9. AAB parent/child Relationship provenance;
10. child traversal/drive/backslash and duplicate-path rejection;
11. child retention-limit evidence;
12. bounded import-list evidence;
13. partial source/explicit unknown-region truth;
14. signature observation separated from execution/trust;
15. invalid child Relationship target rejection.

## Exact-head proof gate

Promotion requires one exact PR head that passes:

- accepted B04 base and bounded B05 scope lock;
- pinned Rust/Cargo 1.97.1;
- `cargo fmt --all -- --check`;
- B05 acceptance: 15/15;
- strict B05 Clippy with `-D warnings`;
- inherited B04 core + review regressions;
- inherited B03 core + review regressions;
- inherited B02 and A12 semantics;
- full locked workspace regression;
- clean working tree;
- immutable exact-head proof manifest and retained artifact.

Any source movement invalidates Freeze and requires affected Review → Freeze → Prove again.

## Exit

B05 is COMPLETE only when the exact proven candidate is merged to `main`. A proved canonical B05 candidate must not remain parked in an open PR.
