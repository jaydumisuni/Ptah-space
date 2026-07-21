# Contributing to Ptah

Status: candidate — not operative until owner acceptance

Thank you for helping improve Ptah. The public repository is governed by strict source, privacy, evidence and no-build boundaries.

## Proposed contribution licence

Unless you explicitly and conspicuously mark a submission `Not a Contribution`, an intentional contribution accepted for inclusion in the public Ptah Work is proposed to be submitted under the Apache License, Version 2.0, consistent with section 5 of that licence.

Do not submit material unless you own it or have authority to submit it under compatible terms.

No Contributor Licence Agreement or Developer Certificate of Origin is proposed for the initial public repository. Either may be added later only through a reviewed governance decision.

## Never submit

Do not place any of the following in a public issue, pull request, discussion, commit, test fixture or evidence bundle:

- credentials, access tokens, passwords, signing keys or private keys;
- customer, employee or supplier personal data;
- IMEI, serial, account or device-case records;
- production configuration, internal network details or private URLs;
- Hunter private memory, prompts, knowledge stores or model data;
- THETECHGUY private Domain Packs or technician-only procedures;
- restricted recovery, unlock, bypass or credential-handling adapters;
- payment records or finance data;
- proprietary firmware, media, datasets or documentation without redistribution rights;
- copied donor source without an accepted licence and extraction record.

Use the private security-reporting path for vulnerabilities or accidental secret exposure.

## Third-party material

When a contribution includes copied or adapted third-party material, provide:

- canonical upstream source;
- exact version, release or commit;
- applicable licence;
- required copyright and attribution notices;
- modification notice where required;
- artifact or source digest where applicable.

Third-party material keeps its own licence. A Ptah pull request does not relicense it.

## Phase 0C no-build boundary

Until ADR-0033 is accepted and `CURRENT_STATE.md` explicitly says `Runtime implementation: AUTHORIZED`, contributions may improve only the approved Phase 0C lanes, including:

- contracts and generated metadata bindings;
- conformance and policy checks;
- dependency, artifact, signer and host locks;
- proof, package and durable-retention tooling;
- documentation and governance candidates;
- non-claiming repository scaffold maintenance.

Do not disguise runtime features as scaffolding, tests, examples or proof tooling.

## Pull request requirements

A proposed change should:

1. explain its purpose and claim boundary;
2. identify the exact files and frozen contracts affected;
3. include positive, negative and adversarial tests where behavior changes;
4. preserve immutable dependency and workflow pins;
5. retain exact-head evidence;
6. avoid private or restricted information;
7. record third-party licence and notice obligations;
8. state explicitly whether runtime implementation remains unauthorized.

All required workflows must pass at the exact reviewed head. A green workflow does not replace human review or owner acceptance.

## Source identification

After licence acceptance, repository-owned source files should carry:

```text
SPDX-License-Identifier: Apache-2.0
```

where the file format permits comments. Existing third-party files keep their original headers and licence identifiers.

## Security reports

Do not open a public issue for a vulnerability that includes exploit details, secrets, private endpoints, customer/device evidence or operational access.

Use the private reporting route defined in the accepted root `SECURITY.md`.

## Conduct and review

Be precise, respectful and evidence-based. Maintainers may reject contributions that weaken frozen contracts, blur public/private boundaries, add unsupported claims, introduce unreviewed dependencies or create unacceptable maintenance and security burden.

## Non-claims

This candidate does not grant an operative licence, accept contributions, accept ADR-0033 or authorize runtime implementation. It becomes operative only when copied to root `CONTRIBUTING.md` in the reviewed owner-acceptance change.
