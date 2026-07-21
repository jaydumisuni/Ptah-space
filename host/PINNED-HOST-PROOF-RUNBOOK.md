# Phase 0C pinned-host proof runbook

This runbook produces the remaining host and installed-package evidence required by ADR-0033. It does **not** authorize the Ptah runtime.

## Required candidate host

The proof host must report all of the following:

- Ubuntu Server `24.04.4 LTS`;
- `ID=ubuntu` and base `VERSION_ID=24.04` in `/etc/os-release`;
- `x86_64` architecture;
- kernel `6.8.0-136-generic`;
- every required capability in `host/capability-profile.json`;
- the exact clean `Ptah-space` commit selected for the Phase 0C closure review.

A generic GitHub Actions runner, another Ubuntu point release, an Azure kernel, or a dirty repository may collect diagnostic evidence but cannot become proof-eligible.

## Preparation

1. Install the frozen Ubuntu Server image and boot the required kernel.
2. Apply only the reviewed package set intended for the first Ptah proof Node.
3. Clone `jaydumisuni/Ptah-space` and check out the exact candidate commit.
4. Confirm the repository is clean:

```bash
git status --porcelain
```

5. Do not run the collector from an unreviewed local modification.

## Collection

From the repository root:

```bash
python3 tools/run_pinned_host_proof.py \
  --repo-root . \
  --output evidence/phase0c/pinned-host-candidate
```

The runner invokes the accepted collector at:

```text
host/scripts/collect_capabilities.py
```

The command intentionally exits non-zero after collecting diagnostics when the host identity, repository state or required capability result does not match the frozen proof target.

## Proof-integrity gate

A bundle can report `proof_eligible: true` only when all three independent gates pass:

1. the runner's exact Ubuntu point-release, architecture and kernel check;
2. the existing host-capability report itself records `required_capabilities_passed: true`, `pinned_host_match.all_match: true` and `proof_eligible: true`;
3. the repository is clean at the exact recorded commit.

Capability failures are copied into `bundle-manifest.json` under `capability_failures` and the combined fail-closed reasons are recorded under `eligibility_failures`. A host-identity match alone is insufficient.

## Produced records

- `host-identity.json` — OS, kernel, architecture, privacy-preserving machine identity, boot identity and exact match result;
- `host-capabilities.json` — output of the accepted fail-closed Ptah collector;
- `installed-packages.json` — exact installed `dpkg` package/version/architecture inventory and aggregate digest;
- `apt-sources.json` — active APT source configuration and aggregate digest;
- `bundle-manifest.json` — exact implementation commit, file hashes, bundle digest, capability validation and proof eligibility.

Every record retains:

```json
"runtime_implementation_authorized": false
```

## Acceptance conditions

The pinned-host evidence may close the host blocker only when:

1. `proof_eligible` is `true` in the bundle manifest;
2. `eligibility_failures`, `host_identity_failures` and `capability_failures` are empty;
3. every host-capability requirement passes in `host-capabilities.json`;
4. the implementation commit is the exact reviewed Phase 0C candidate;
5. the repository was clean during collection;
6. the installed-package manifest is reviewed against the selected package boundary;
7. the bundle and each contained file are retained in a durable evidence Location;
8. a roadmap evidence record cites the bundle digest and exact commit;
9. the Phase 0C closure review confirms that no frozen contract or WP14 proof burden was weakened.

## Non-claims

This package does not:

- install or configure the Ptah runtime;
- deploy a Node, Workspace or Provider;
- accept the public licence decision;
- execute WP14 runtime proofs;
- change ADR-0033 to accepted;
- change `Runtime implementation` to `AUTHORIZED`.
