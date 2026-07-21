# Third-party NOTICE review

Status: reviewed

Reviewed: 2026-07-21

## Scope

This review covers the public `jaydumisuni/Ptah-space` repository at the Apache-2.0 owner-acceptance checkpoint.

The repository currently contains Ptah-owned source, generated metadata, contracts, policy and proof tooling, plus dependency and artifact identity records. It references or downloads third-party components behind replaceable boundaries, but does not copy their source into the public Work merely by recording names, versions, checksums, signatures or package metadata.

## Root NOTICE conclusion

No root NOTICE attribution entries are required at this Phase 0C acceptance checkpoint beyond the Ptah project and accepted owner notice.

This conclusion is limited to the current repository contents. It does not declare that third-party dependencies have no licence or NOTICE obligations in their own distributions.

## Third-party material remains separate

The following classes retain their upstream licences and notices:

- Rust crates and their registry metadata;
- Node.js and npm dependencies;
- Playwright and Chromium distributions;
- Ubuntu packages and APT artifacts;
- containerd, runc, Git, libarchive and SQLite;
- any later copied, adapted or redistributed upstream material.

Dependency and artifact lock records do not relicense those works.

## Re-review triggers

The root NOTICE and this review must be updated before merging any change that:

- copies or adapts third-party source into the repository;
- distributes a third-party binary or bundled asset from the repository;
- introduces an upstream NOTICE propagation requirement;
- changes a dependency licence or distribution model;
- adds third-party artwork, fonts, media, datasets or documentation;
- imports donor code rather than studying or wrapping it.

## Boundary

Runtime implementation remains unauthorized. This notice review does not accept the physical host, installed-package boundary, ADR-0033 or any runtime behavior.
