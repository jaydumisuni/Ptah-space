# B02 — General type detection and progressive decomposition

## Authority

Roadmap package: Programme B / B02.

Accepted base: `7adbc64d45687dddee3627303a2ec9e3022c4158` (B01 merge).

Dependencies consumed:

- A12 archive decomposition and recursive resource policy;
- A07 immutable Object/Revision semantics through A12;
- B01 accepted transfer/storage state;
- frozen Ptah authority model: mechanical evidence never becomes caller/reviewer authority.

## Delivered

- independent detector evidence aggregation;
- caller-declared type versus agreed observed type comparison;
- detector disagreement and detector failure retention;
- progressive L0/L1/L2/L3 execution;
- A12-backed bounded archive inventory/decomposition selection only after non-conflicting type evidence;
- generic child relationship projection over A12 inventory evidence;
- searchable root/child metadata derived from retained evidence;
- explicit unsupported regions when type is unknown, disputed, unsupported or a decomposer is unavailable;
- explicit recursion-boundary limitation when a decomposable child reaches the caller resource limit;
- immutable borrowed source bytes and source digest binding.

## Level contract

- **L0** — source identity and declared metadata only; no detector/decomposer call.
- **L1** — aggregate detector evidence and compare declared versus agreed observed type.
- **L2** — bounded root structural inventory using an existing matching decomposer; no recursive progression.
- **L3** — bounded recursive decomposition, child type projection and explicit recursion-limit evidence.

A requested level is a ceiling, not a success claim. `achieved_level` remains at the highest level that can be supported by actual evidence.

## Truth boundaries

- conflicting positive detector signals remain `Disputed`; Ptah does not choose a winner;
- detector failures do not erase independent positive evidence;
- a declared filename/type hint does not replace observed detector evidence;
- unsupported/unknown regions remain explicit;
- B02 does not create new canonical Object identities; the child graph is a projection over A12/A07 evidence;
- A12 remains the archive-specific parser/policy authority;
- original source Content remains immutable;
- no detector or decomposition result authorizes a follow-up action.

## Acceptance proof

The exact candidate must prove:

1. L0 invokes neither detectors nor archive backend;
2. detector disagreement is retained and blocks decomposer selection;
3. declared/observed mismatch remains explicit;
4. bounded detector failure is retained without erasing independent positive evidence;
5. L2 inventories root children without recursive decomposition;
6. L3 builds parent/child relationships and searchable metadata;
7. recursion limit leaves an explicit unsupported/limitation record;
8. a larger recursion budget reaches deeper children;
9. unsupported agreed types remain explicit and do not call the archive backend;
10. duplicate detector identities fail closed;
11. original source bytes remain unchanged;
12. inherited A12 acceptance remains green;
13. strict Clippy and the complete Rust workspace remain green;
14. the exact proven head remains clean and is retained with a digest-bound proof bundle.

## Promotion rule

Ship only the exact PR head that passes the B02 exact-head workflow and has no unresolved Review finding. Any source change after proof invalidates the proof and requires a complete rerun.
