# Phase 0C pinned-host proof runbook

This runbook produces the remaining host and installed-package evidence required by ADR-0033. It does **not** authorize the Ptah runtime.

## Required candidate host

The proof host must report all of the following:

- Ubuntu Server `24.04.4 LTS`;
- `ID=ubuntu` and base `VERSION_ID=24.04` in `/etc/os-release`;
- `x86_64` architecture;
- kernel `6.8.0-136-generic`;
- every required capability in `host/capability-profile.json`;
- an exact installed `dpkg` package/version/architecture inventory;
- exact SHA-256 binary-package artifact metadata for every installed package;
- the exact clean `Ptah-space` commit selected for the Phase 0C closure review.

A generic GitHub Actions runner, another Ubuntu point release, an Azure kernel, a dirty repository, an incomplete APT cache or a package without exact artifact metadata may collect diagnostic evidence but cannot become proof-eligible.

## Preparation

1. Install the frozen Ubuntu Server image and boot the required kernel.
2. Apply only the reviewed package set intended for the first Ptah proof Node.
3. Ensure the local APT package lists still contain the exact installed versions. The proof runner does not run `apt update` or download packages.
4. Clone `jaydumisuni/Ptah-space` and check out the exact candidate commit.
5. Confirm the repository is clean:

```bash
git status --porcelain
```

6. Remove any previous candidate output. The runner fails closed when the selected output directory already contains files.
7. Do not run the collector from an unreviewed local modification.

## Collection

From the repository root:

```bash
python3 tools/run_pinned_host_proof.py \
  --repo-root . \
  --output evidence/phase0c/pinned-host-candidate
```

The runner invokes exactly these accepted collectors:

```text
host/scripts/collect_capabilities.py
tools/collect_apt_package_artifacts.py
```

The command intentionally exits non-zero after collecting diagnostics when the host identity, repository state, required capability result or package-artifact digest result does not match the frozen proof target.

## Installed-package artifact evidence

`installed-packages.json` is the exact `dpkg` package/version/architecture inventory. For each record, the package-artifact collector queries the existing local APT cache for that exact version and architecture and requires a complete `Filename`, `Size` and `SHA256` record.

The collector also hashes the local files under `/var/lib/apt/lists` that supplied the cached package metadata. It does not modify APT state, contact a package mirror or download `.deb` files. Its retained SHA-256 values are the binary-package artifact digests published in the local APT package metadata, not a claim that the original `.deb` remains cached on disk.

If one installed package lacks exact SHA-256 metadata, if conflicting SHA-256 records exist, or if the APT index inventory is absent, `package-artifacts.json` remains incomplete and the bundle cannot become proof-eligible.

## Repository cleanliness

The prescribed output path is inside the clean checkout. Generated files under that exact output directory are therefore excluded from the final untracked-file check; otherwise the proof command would invalidate itself merely by writing its own bundle.

The runner still fails eligibility when:

- tracked files differ before or after collection;
- the index contains staged changes;
- any untracked file exists outside the selected output directory;
- `HEAD` changes during collection;
- the selected output directory was not empty before collection.

Both pre-collection and post-collection repository states, plus the before/after commit identities, are retained in `bundle-manifest.json`.

## Proof-integrity gate

A bundle can report `proof_eligible: true` only when all four independent gates pass:

1. the runner's exact Ubuntu point-release, architecture and kernel check;
2. the existing host-capability report itself records `required_capabilities_passed: true`, `pinned_host_match.all_match: true` and `proof_eligible: true`;
3. every installed package has one exact APT binary-artifact SHA-256 record and the local APT index inventory is present;
4. the repository is clean at one unchanged exact commit before and after collection.

Capability failures are copied into `bundle-manifest.json` under `capability_failures`. Package-artifact failures are copied under `package_artifact_failures`. The combined fail-closed reasons are recorded under `eligibility_failures`. A host-identity match alone is insufficient.

## Privacy-preserving identity

The retained bundle does not store the raw hostname, `/etc/machine-id` value or boot ID. It stores SHA-256 representations of those values. The exact OS release, architecture and kernel remain visible because they are required proof facts.

## Produced records

- `host-identity.json` — OS, kernel, architecture, hashed machine/boot/host identity, secure-boot observation and exact match result;
- `host-capabilities.json` — sanitized output of the accepted fail-closed Ptah collector;
- `installed-packages.json` — exact installed `dpkg` package/version/architecture inventory and aggregate digest;
- `package-artifacts.json` — exact version/architecture APT binary-artifact SHA-256 records, missing records and hashed local APT index inventory;
- `apt-sources.json` — active APT source configuration and aggregate digest;
- `bundle-manifest.json` — exact implementation commit, repository state, file hashes, bundle digest, capability validation, package-artifact validation and proof eligibility.

Every record retains:

```json
"runtime_implementation_authorized": false
```

## Independent durable retention preparation

Do not commit the raw candidate directory directly. First independently verify every source byte and cross-record proof condition, then create a durable candidate package:

```bash
python3 tools/prepare_durable_pinned_host_evidence.py \
  --bundle-dir evidence/phase0c/pinned-host-candidate \
  --output-dir evidence/phase0c/pinned-host-durable-candidate
```

The retention tool requires the exact six-file source bundle and independently checks:

- every source file size and SHA-256 against `bundle-manifest.json`;
- the aggregate source bundle digest;
- one clean unchanged exact Git commit before and after collection;
- exact Ubuntu point release, architecture and kernel identity;
- hashed host, machine and boot identity with no raw hostname;
- the capability report's own proof-eligible state and zero required failures;
- the installed-package aggregate digest and unique installed identities;
- one exact package-artifact SHA-256 record per installed identity;
- the package-artifact aggregate digest and local APT release/package index inventory;
- APT source and index aggregate digests;
- explicit non-authorization boundaries on every source record.

It writes:

- `durable-pinned-host-bundle.json` — exact base64-encoded source bytes, individual digests, aggregate retained-file digest and source bundle bindings;
- `pinned-host-review-record.json` — a separate review record beginning with `review_status: pending` and every acceptance field set to `false`;
- `README.md` — the implementation commit and durable/source digest summary.

The durable candidate may be committed for retention after this independent verification. It does not become accepted host proof merely because it is retained. The review record must remain pending until the owner and Phase 0C closure review explicitly accept the host identity, installed-package boundary, package-artifact boundary and durable retention.

## Acceptance conditions

The pinned-host evidence may close the host blocker only when:

1. `proof_eligible` is `true` in the bundle manifest;
2. `eligibility_failures`, `host_identity_failures`, `capability_failures` and `package_artifact_failures` are empty;
3. every host-capability requirement passes in `host-capabilities.json`;
4. `package-artifacts.json` records `complete: true`, equal package/artifact counts, zero missing records and a present APT index inventory;
5. the implementation commit is the exact reviewed Phase 0C candidate and did not change during collection;
6. the repository was clean before and after collection, excluding only the generated bundle directory;
7. the installed-package and package-artifact manifests are reviewed against the selected package boundary;
8. the exact source bytes pass the independent durable-retention verifier;
9. the durable candidate and review record are committed to a durable evidence Location;
10. the review record explicitly accepts physical host identity, installed packages, package artifacts and durable retention;
11. a roadmap evidence record cites the source bundle, durable bundle and exact implementation commit digests;
12. the Phase 0C closure review confirms that no frozen contract or WP14 proof burden was weakened.

## Non-claims

This package does not:

- install or configure the Ptah runtime;
- deploy a Node, Workspace or Provider;
- accept a retained candidate without review;
- accept the public licence decision;
- execute WP14 runtime proofs;
- change ADR-0033 to accepted;
- change `Runtime implementation` to `AUTHORIZED`.
