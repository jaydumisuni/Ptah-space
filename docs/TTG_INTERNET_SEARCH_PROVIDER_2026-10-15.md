# Ptah — TTG Internet Search read-only Provider integration

**Date:** 2026-10-15
**Owner authorization:** User explicitly approved adding standalone TTG Internet Search to Ptah.
**Budget policy:** **ZMW 0**—no paid API keys, paid fallback, payment-card trials or new paid infrastructure.

## What is integrated

- New Ptah-owned `adapters/internet-search/bridge.py` accepts bounded, one-line JSON protocol and invokes **exact** pinned TTG Internet Search v0.7.0a2 wheel. Search remains a separately maintained product; no copied source/corpus goes into public Ptah.
- New `tools/ptah_internet_search.py` provides an optional terminal search/read/doctor entry.
- The existing A05 Native Process Provider can launch the bridge with `ProcessMode::Pty`, bind it to the current Provider generation, accept input under its authorized Control Lease, and independently observe successful process completion.
- Existing A11 Browser Provider remains byte-for-byte unchanged. B07/D03 internal Workspace knowledge search remains unchanged.
- No control-plane route, autonomous caller authorization, deployed provider-instance registration or automatic Hunter reasoning/tool routing is implied.

## Mechanically qualified boundary

Exact wheel SHA-256: `eaecd49153225e1b9c2972fa89d24edde69975e6dd15a7b05230c302fd7d65c4`.

Input: `{"operation":"search","query":"Python unittest documentation","limit":5,"request_id":"...","expected_provider_generation":7}` framed as UTF-8 line on Ptah A05 PTY.

Output: `ptah.ttg-internet-search.readonly.v1`, structured result URLs/titles/snippets, provider provenance, `DISCOVERED_NOT_PAGE_VERIFIED` truth, request ID, generation, `completed`, non-authoritative Ptah source status and zero paid calls.

A05 holds canonical identity, Node binding and Activity/Attempt/Lease authority. The bridge performs *additional mechanical generation checks* but cannot authorize itself. Provider acknowledgement does not constitute independently verified Web content.

### Safety controls

1. Open the external pinned wheel without following symlinks, copy and SHA-256 verify it into a Linux anonymous memfd, apply immutable write/grow/shrink seals, then execute the child by inherited descriptor. Mutating/replacing the original after verification cannot alter imported bytes.
2. Never invoke shell interpolation or accept arbitrary Search flags, mutations, installs or source indexing from Ptah API requests.
3. Bound request body to 8 KiB, query 250 characters, top results 10, stdout 160 KiB, stderr 8 KiB and runtime 30 seconds. Drain child pipes incrementally; terminate on overflow rather than buffering unbounded output.
4. Run Python in isolated mode, preserve the existing shared per-user XDG provider-quota state; do not create a separate resettable free-provider allowance.
5. Limit operations to `search`, `read` over HTTPS and `doctor`. Disabled paid Search adapter cannot be enabled through this protocol.
6. Preserve `LOCAL_INDEXED`, `DISCOVERED`, `READABLE`, `UNAVAILABLE` and partial-source truth distinctions. Search snippets never become canonical Ptah source evidence or factual assertions.
7. Ptah Browser, filesystem, caller authority, Provider registration and control-plane behavior are untouched.

### KRATOS qualification receipts

- Actual bridge-to-wheel **live Web search** returned official Python unittest documentation (5 results, about 1.4 s); paid calls 0.
- Actual bridge-to-wheel **direct HTML read** returned `READABLE` at example.com (about 1.0 s); paid calls 0.
- Operator CLI search/read/doctor all returned valid response; paid calls 0.
- **31/31 Python tests** when external wheel is present (offline-only CI may skip 2 physical cases).
- **A05 physical Native Process Provider test PASS:** correct Provider generation, current A05 PTY Input Lease, successful observed exit, qualified pinned external wheel. Run with approved `PTAH_TTG_SEARCH_WHEEL`. The bridge is always derived from this checkout's Cargo manifest directory; an optional `PTAH_TTG_SEARCH_BRIDGE` hint is rejected if it identifies a different file.
- Native-process crate unit and regression acceptance PASS; `cargo fmt --all -- --check` PASS.
- Browser Provider sources not modified; no Ptah production service started or restarted.

## Additional production adoption gates

The repository integration is qualified for an **authorized Ptah native-process execution path**, not installed as a default Provider for all users. Production activation—if separately desired—requires existing Ptah Controller/Node enrollment, caller authority, placement and lease proof, Provider Revision/Instance evidence, privacy-approved logs, and an exact reviewed branch/commit before deployment.

Search remains free-tier limited for fresh discovery. The local FTS5 index allows arbitrarily many queries against a finite, rights-cleared corpus, but global fresh-Web availability is not guaranteed.

**No Ptah canonical schema, provider-kind vocabulary, frozen contract, lockfile, Browser Provider, Node service, or Control Server implementation was modified.**
