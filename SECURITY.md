# Security Policy

Status: operative

## Reporting a vulnerability

Report security issues privately by email to:

```text
support@thetechguyds.com
```

Use the subject prefix:

```text
[PTAH SECURITY]
```

Include only the minimum information needed to reproduce and assess the issue. Do not send credentials, customer/device records, production secrets or large private evidence bundles unless a maintainer provides an approved secure transfer route.

Do not open a public issue when a report includes:

- exploit details that create immediate risk;
- credentials, tokens, keys or private endpoints;
- customer, employee or device data;
- internal infrastructure or deployment information;
- restricted recovery or credential-handling behavior;
- private THETECHGUY repository content.

## Public repository scope

The public security boundary covers repository-owned source, tests, contracts, generated metadata bindings, CI definitions, proof tooling, documentation and other material intentionally published in `Ptah-space`.

It does not automatically cover private THETECHGUY systems, customer operations, private Domain Packs, Hunter knowledge, production deployments or restricted device-service adapters.

## Current implementation status

Phase 0C contains a non-claiming implementation scaffold, frozen contracts, dependency and artifact locks, proof collectors and retention tooling. It is not an authorized or deployed Ptah runtime. Runtime implementation remains unauthorized until the independent ADR-0033 closure gates pass and the canonical roadmap explicitly authorizes it.

A report must not interpret the presence of a schema, tool, provider boundary or proof plan as evidence that the corresponding runtime capability exists.

## What to include

A useful report contains:

- affected path, commit and version;
- clear impact and threat model;
- minimal reproduction steps;
- expected and observed behavior;
- whether the issue crosses the public/private boundary;
- relevant logs with secrets and personal data removed;
- proposed mitigation when known.

## Coordinated handling

Maintainers will validate scope, preserve evidence and decide whether the issue belongs in the public repository or a private THETECHGUY lane. Public disclosure timing must be coordinated when disclosure could expose users, systems or unresolved vulnerabilities.

This policy does not promise a response deadline, bounty, support level or production remediation service.

## Supported versions

No production Ptah runtime version is supported during Phase 0C because runtime implementation remains unauthorized. Security fixes to the public scaffold and proof tooling may still be reviewed and merged under the Phase 0C boundary.
