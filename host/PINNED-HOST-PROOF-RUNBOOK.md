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

The command intentionally exits non-zero after collecting diagnostics when the host identity or repository state does not match the frozen proof target.

## Produced records

- `host-identity.json` — OS, kernel, architecture, privacy-preserving machine identity, boot identity and exact match result;
- `host-capabilities.json` — output of the existing fail-closed Ptah host-capability collector;
- `installed-packages.json` — exact installed `dpkg` package/version/architecture inventory and aggregate digest;
- `apt-sources.json` — active APT source configuration and aggregate digest;
- `bundle-manifest.json` — exact implementation commit, file hashes, bundle digest and proof eligibility.

Every record retains:

```json
"runtime_implementation_authorized": false
```

## Acceptance conditions

The pinned-host evidence may close the host blocker only when:

1. `proof_eligible` is `true` in the bundle manifest;
2. every host-capability requirement passes;
3. the implementation commit is the exact reviewed Phase 0C candidate;
4. the repository was clean during collection;
5. the installed-package manifest is reviewed against the selected package boundary;
6. the bundle and each contained file are retained in a durable evidence Location;
7. a roadmap evidence record cites the bundle digest and exact commit;
8. the Phase 0C closure review confirms that no frozen contract or WP14 proof burden was weakened.

## Non-claims

This package does not:

- install or configure the Ptah runtime;
- deploy a Node, Workspace or Provider;
- accept the public licence decision;
- execute WP14 runtime proofs;
- change ADR-0033 to accepted;
- change `Runtime implementation` to `AUTHORIZED`.
