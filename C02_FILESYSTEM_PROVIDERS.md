# C02 — Filesystem Providers

Status: BUILD / REVIEW candidate

Accepted base: `4db6f2d55edfa01b4367029bce1f3a4d11723fc3` (C01 merge)

Authority: Ptah Implementation Roadmap 1.1.0, Programme C / C02.

## Scope

C02 defines the source-bound Ptah contract around replaceable filesystem engines. Mature filesystem implementations remain Providers; Ptah owns validation, coverage truth, provenance, safe paths/materialization, bounded resources, and canonical A07 plans.

Required provider families, in roadmap order:

- ext4;
- EROFS;
- F2FS;
- SquashFS;
- UBI/UBIFS;
- FAT;
- NTFS;
- ISO-9660.

APFS/HFS remain later compatible-Node work and are not claimed by this package.

Delivered candidate surface:

- mechanical signature evidence for all required C02 families;
- replaceable `FilesystemProvider` inspection contract;
- Provider/mount identifiers retained only as scoped aliases/evidence;
- exact source Object Revision and SHA-256 binding;
- explicit `Complete`, `Partial`, and `Inconclusive` assessment;
- exact `Read`, `Unallocated`, `Unknown`, and `Unsupported` byte coverage;
- deterministic unknown-gap insertion for incomplete provider coverage;
- fail-closed rejection of provider false-completeness claims;
- canonical relative filesystem paths with traversal, absolute-path, Windows-drive, backslash, NUL, empty-component, `.` and `..` rejection;
- duplicate-path rejection;
- bounded filesystem/entry metadata and limitations;
- bounded inventory, coverage, per-file extents and materialization size;
- exact regular-file reconstruction from validated source extents and filesystem-defined zero extents;
- exact file digest verification before materialization succeeds;
- directories, symlinks and special entries retained only as non-materialized inventory truth;
- report integrity seal before View planning or file materialization;
- A07 recovered-file registration and source-to-file Relationship plans;
- A07 filesystem inventory and read-coverage View plans.

## Truth boundaries

- C01/C02 source bytes are immutable inputs and are never rewritten in place.
- A recognized filesystem signature is detection evidence only; it cannot establish inventory or completeness by itself.
- FAT detection derives family evidence from validated BPB geometry and data-cluster count; the informational filesystem-type label is not authoritative.
- Provider output is untrusted mechanical evidence and is validated before entering a C02 report.
- Provider IDs, mount IDs and backend-local handles are Aliases/evidence, never canonical Ptah identity.
- Gaps in provider coverage become `Unknown`; they are never inferred as free space or readable data.
- `Complete` is permitted only when the complete provider claim survives C02 validation, all source bytes are covered by `Read` or `Unallocated`, no unsupported file content remains, and no limitations remain.
- Unsupported features or unknown ranges cannot claim completeness.
- A complete claim also requires every retained entry to have no entry-specific limitations.
- Exact regular-file data extents must lie within exact `Read` coverage and source bounds.
- Sparse/hole file bytes may be reconstructed as filesystem-defined zeros only when the Provider explicitly supplied a zero extent.
- C02 never follows symlinks and never materializes directory or special-file semantics.
- Unsafe paths fail closed before inventory retention or materialization.
- Materialization uses exact source bytes and validated extents, not Provider mount paths.
- Post-inspection report mutation cannot authorize materialization or canonical Views.
- Registration, Relationship and View plans re-bind the exact source Object Revision and A04 production evidence.
- Filesystem Providers are read-first in C02; filesystem mutation/rebuild authority is not claimed.

## Acceptance corpus

The exact candidate must pass 20 positive/adversarial C02 tests covering:

1. all required filesystem signatures are mechanically detected;
2. detection without a Provider remains inconclusive with unknown coverage;
3. complete provider evidence remains source-bound and aliases stay non-canonical;
4. Provider/detection family disagreement fails closed;
5. false complete claim with coverage gaps fails closed;
6. unknown coverage gaps are inserted explicitly for partial observations;
7. unsupported coverage prevents completeness;
8. Provider invocation failure remains a failure;
9. unsupported Provider family fails closed;
10. traversal, absolute, Windows and backslash paths fail closed;
11. duplicate canonical paths fail closed;
12. malformed/out-of-source extents fail closed;
13. exact extents require exact `Read` coverage;
14. metadata-only and unsupported files cannot smuggle exact extents;
15. directory/symlink/special entries remain non-materializable inventory;
16. exact file materialization verifies source bytes/digest and configured bounds;
17. post-inspection report mutation fails the integrity seal;
18. A07 registration/Relationship/View plans remain exact-source bound;
19. Provider alias and metadata/resource limits fail closed;
20. unknown filesystem families remain explicit and cannot be upgraded by an arbitrary Provider.

The test count is intentionally fixed at 20 for this review package. Review corrections strengthen these cases rather than inflating the count without new semantic coverage.

## Exact-head proof

The permanent C02 workflow must be read-only and prove on one exact six-file candidate head:

1. exact accepted C01 merge base and six-file C02 scope;
2. clean diff and formatting;
3. 20/20 C02 acceptance;
4. strict Clippy with `-D warnings`;
5. inherited C01 acceptance;
6. inherited B02 decomposition semantics;
7. inherited B05 executable/package semantics;
8. inherited B07 Object World search semantics;
9. full locked workspace tests;
10. exact clean Git tree after proof;
11. retained proof manifest/artifact bound to the exact head.

## Permanent C02 surface

Exactly six files may differ from the accepted C01 merge:

- `C02_FILESYSTEM_PROVIDERS.md`
- `crates/ptah-archive-decomposition/Cargo.toml`
- `crates/ptah-archive-decomposition/src/lib.rs`
- `crates/ptah-archive-decomposition/src/c02.rs`
- `crates/ptah-archive-decomposition/tests/c02.rs`
- `.github/workflows/c02-filesystem-providers.yml`

## Exit gate

C02 is complete only after source review is clean, the exact six-file head is Frozen, the permanent read-only workflow proves all required gates and retains its artifact, all Review findings are resolved against that exact source, and the PR merges with expected-head protection.
