# Apache-2.0 public/private boundary candidate

Status: candidate — owner acceptance required

This file is an engineering and governance proposal for the public `Ptah-space` repository. It is not legal advice, is not an operative licence grant, and does not accept ADR-0033 or authorize runtime implementation.

## Proposed public licence

Use the Apache License, Version 2.0 (`Apache-2.0`) for repository-owned public Ptah source after owner acceptance.

The exact candidate licence is:

```text
legal/candidates/LICENSE.apache-2.0.txt
```

It must match the unchanged official Apache text:

```text
Source:  https://www.apache.org/licenses/LICENSE-2.0.txt
Size:    11358 bytes
SHA-256: cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30
```

No root `LICENSE`, `NOTICE` or `CONTRIBUTING.md` is created by this candidate package. Those files become operative only through one reviewed owner-acceptance change.

## Proposed public default scope

After acceptance, Apache-2.0 would apply by default to repository-owned material intentionally published in `Ptah-space`, including:

- Ptah-owned source and test code;
- schemas, lifecycle definitions and generated metadata bindings;
- public architecture, operator and conformance documentation;
- CI definitions and policy checks;
- host, package, proof and durable-retention tooling;
- public non-sensitive evidence manifests and reproducibility metadata;
- repository-owned configuration and lock records.

A file or subtree with a separate compatible licence or notice keeps that specific boundary.

## Third-party boundary

Apache-2.0 must not be used to relicense third-party material merely because Ptah references, verifies, downloads, executes or describes it.

For each third-party component, retain as applicable:

- canonical upstream identity;
- exact version, release or commit;
- upstream licence;
- copyright and attribution notices;
- required NOTICE content;
- artifact or source digest;
- modification notice when Ptah changes a copied file.

Dependency metadata, generated SBOMs and proof records describe third-party works; they do not replace the upstream licence.

Unlicensed donor source must not enter the public repository.

## Private material excluded from the public repository

The following material is not part of the proposed public Apache-2.0 Work and must not be committed to `Ptah-space`:

- customer or client personal data;
- IMEI, serial, account, device or customer-case evidence;
- credentials, tokens, private keys, production secrets or private configuration;
- Hunter private memory, prompts, knowledge stores, model data or internal lessons;
- private THETECHGUY Domain Packs;
- restricted repair, recovery, unlock, bypass or credential-handling adapters;
- payment-provider secrets, transaction records or internal finance data;
- technician-only procedures, private incident records or forensic evidence;
- production deployment state, infrastructure inventory or access details;
- proprietary third-party code, firmware, media, datasets or documentation without distribution rights.

Private repositories and private data remain unlicensed unless their own explicit file-level or repository-level licence says otherwise.

## THETECHGUY internal systems outside the public default grant

The public Ptah licence would not automatically license private implementations or operational data from:

- Hunter AI and private Hunter services;
- TechGuy Tool, TechGuy DM, TechGuy IMEI, TechGuy ADB, TechGuy Redirect, TechGuy Repair and TechGuy Installer;
- TTG Device Manager, TTG Enabler and private device-management policy packages;
- MTK META, Qualcomm DIAG, SPD/Unisoc, MTP, Fastboot, USB/serial and recovery adapters;
- Pay Gateway, customer operations, sales, repair, event, logistics and employee-operating-system data;
- private Software Builder assets, signing keys, deployment configuration or commercial workflows.

Those systems may later expose public adapters or Domain Pack interfaces through a separately reviewed licence boundary.

## Trademark and brand boundary

Apache-2.0 section 6 does not grant permission to use trade names, trademarks, service marks or product names except for reasonable descriptive attribution.

The proposed code licence therefore does not grant a brand licence for:

- THETECHGUY;
- THETECHGUY DIGITAL SOLUTIONS;
- Ptah;
- Hunter;
- associated logos, icons, product artwork, slogans or visual identity.

No brand asset is included in the candidate public licence scope unless a separate asset notice explicitly says so.

This trademark boundary must not be used to restrict truthful statements that identify the origin of the Work or reproduce required NOTICE content.

## Evidence boundary

Public Phase 0C evidence may contain facts, hashes, package names, versions, workflow IDs and exact command output required for reproducibility.

Before public retention, evidence must remain privacy-preserving and must not contain:

- raw hostnames when a digest is sufficient;
- raw machine or boot identifiers;
- credentials, tokens, private URLs or internal network details;
- customer, device or employee records;
- private repository contents;
- third-party material that Ptah lacks permission to redistribute.

Publishing an evidence record does not relicense the third-party facts or artifacts it describes.

## Contribution boundary

The proposed initial contribution rule follows Apache-2.0 section 5:

- intentional contributions accepted for inclusion in the public Work are submitted under Apache-2.0 unless conspicuously marked `Not a Contribution`;
- a contributor must own the contribution or have authority to submit it;
- no private THETECHGUY material, customer/device data, secret or restricted adapter may be submitted;
- copied third-party material must retain its source, licence and required notices;
- modified copied files must carry a prominent modification notice;
- security reports must use the private reporting path rather than a public issue.

The candidate does not require a CLA or DCO initially. Adding either later requires a reviewed governance decision.

## NOTICE boundary

The proposed root `NOTICE` must be informational only. It may contain:

- the Ptah product name;
- the accepted copyright-owner wording;
- required third-party attribution notices that apply to distributed copied material.

It must not contain:

- additional licence restrictions;
- confidentiality requirements;
- a trademark licence;
- support or warranty promises;
- private operational information;
- notices for dependencies that are merely referenced and do not require NOTICE propagation.

The third-party notice inventory must be reviewed before the root NOTICE becomes operative.

## Security boundary

The accepted public repository needs a root `SECURITY.md` that:

- routes vulnerability reports privately;
- forbids public disclosure of secrets, customer/device data or exploitable operational details;
- identifies the public repository scope;
- makes no promise that the non-claiming Phase 0C scaffold is a production runtime;
- keeps private THETECHGUY systems outside the public issue tracker unless a maintainer explicitly requests a public report.

A candidate is provided in `legal/candidates/SECURITY.candidate.md`.

## Copyright-owner decision still required

Because THETECHGUY DIGITAL SOLUTIONS is registered as a Zambia business name rather than a limited company, the owner must confirm the exact copyright notice before the licence becomes operative.

Candidate A — recommended for clarity, subject to owner/legal confirmation:

```text
Copyright 2026 John Dumisuni trading as THETECHGUY DIGITAL SOLUTIONS
```

Candidate B — use only if the business name itself is confirmed as the proper rights holder:

```text
Copyright 2026 THETECHGUY DIGITAL SOLUTIONS
```

No candidate file silently chooses between these forms.

## Acceptance change required

One reviewed owner-acceptance change must:

1. record the accepted copyright-owner wording;
2. change `apache_2_0_accepted` to `true` in the machine-readable boundary;
3. copy the exact candidate licence bytes to root `LICENSE`;
4. create the reviewed root `NOTICE`;
5. create the reviewed root `CONTRIBUTING.md`;
6. create or replace the reviewed root `SECURITY.md`;
7. add `SPDX-License-Identifier: Apache-2.0` to repository-owned source where the file format permits it;
8. retain or create third-party licence and notice records;
9. verify no private or restricted material is included;
10. update the roadmap with the owner decision and exact file digests.

The licence acceptance change must not accept ADR-0033 or authorize runtime unless every independent Phase 0C blocker also passes in the same reviewed closure.

## Explicit non-claims

This candidate does not:

- grant an operative licence;
- confirm the legal copyright owner;
- licence private THETECHGUY repositories or data;
- grant trademark rights;
- relicense third-party dependencies or donor source;
- accept ADR-0033;
- authorize Ptah runtime implementation.
