# Public Web Search provider admission — 15 October 2026

**Status:** Ptah source-level integration, separate executable provider, KRATOS physical qualification. Production Node/Control registration or activation is **not** asserted.

## Scope and proof

- Standalone engine: independently delivered `ttg-internet-search==0.7.0a2` from TTG Internet Search, SHA-256 of installed wheel: `eaecd49153225e1b9c2972fa89d24edde69975e6dd15a7b05230c302fd7d65c4`.
- Ptah-side source: `public-web-search-provider/`, a dependency-free Node JSON-lines provider plus bounded CLI adapter and exact-wheel offline installer.
- Data plane: local FTS search, public indexed discovery with free-provider quotas, direct HTTPS HTML reading; no Chromium or personal browser profile access.
- Source trust: `canonical_evidence=false` always; external search hits are **not** B07/D03 canonical Workspace evidence. Partial documents retain explicit source warnings. Readable page text remains untrusted source material.
- Budget: ZMW 0. The Ptah wrapper does not pass paid API switches or credential variables, and Search itself rejects paid Brave access.
- Ownership: Ptah Browser Provider, canonical Provider schemas, B07, D03, D04, E01/E02/E05 admission paths, and existing runtimes remain unchanged.
- Runtime state: Ptah's existing Node/Control services are **not restarted**, and no D04 service, Grant, policy, lease, credential, or public URL is created.
- Browser fallback remains a separate, explicit operation subject to existing Ptah authorization.

## Source and tests

Within `public-web-search-provider/`:

```bash
npm run check
npm test
```

The tests verify read-only bounded operations, JSON framing and per-request isolation, source non-authority, version fencing, zero-cash operation, rejection of unknown commands/fields, and prevention of accidental shell execution.

For physical qualification, the Search wheel was installed offline into a private virtualenv and invoked from the Ptah worktree. Results:

| Test | Physical evidence |
| --- | --- |
| Health | Search 0.7.0a2 verified, READY |
| Local search | SQLite SELECT reference returned LOCAL_MATCH with partial-source truth; no network |
| Fresh general search | Python unittest documentation returned 3 documented index hits from You.com in ~1.1 seconds; discovered/not verified |
| HTTPS reader | `https://example.com/` READABLE |
| Cost | No paid keys, charges or paid fallback |
| Browser | A11 provider unmodified and not started |
| Node/Control runtime | Not modified, reconfigured or restarted |

**Availability caveat:** free sources have their own limits and may return quota errors, restricted status, or low-relevance results; this provider must report those conditions. Locally indexed searches are unmetered against the *finite* corpus, not unlimited fresh whole-Web coverage.

## Admission boundary

The descriptor `public-web-search-provider/integration/provider-descriptor.json` is a **non-authoritative candidate**. Production registration and execution must be admitted under existing Ptah Node enrollment, current lease/fence, D04 descriptor and Grant checks. Do not infer those authorities from a working sidecar or an HTTP 200.

This integration may be submitted and reviewed independently of unrelated E07 issues. Its physical provider qualification does not claim production Ptah service registration.
