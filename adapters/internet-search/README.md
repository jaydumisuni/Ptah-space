# Ptah Internet Search Provider — read-only integration candidate

**Scope:** Ptah A05 existing Native Process Provider can execute the independent **TTG Internet Search 0.7.0a2** through a pinned-wheel adapter. It is **not** the existing A11 Browser Provider, and it does not replace B07/D03 workspace-internal search. **ZMW 0**: no payment API, card, licensed overflow, account enrollment, or traffic-limit evasion.

## Accepted external package

- Product: TTG Internet Search v0.7.0a2 (standalone Python, no third-party Python dependencies).
- SHA-256 of exact wheel: `eaecd49153225e1b9c2972fa89d24edde69975e6dd15a7b05230c302fd7d65c4`.
- The wheel stays **outside the public Ptah repository**, under its own ownership/release. No TTG private indexed documents or query histories are copied into Ptah.
- A hash mismatch, missing wheel, malformed request, stale generation, unsupported operation or provider timeout fails closed.
- A replacement Search version requires updating the reviewed pin and running admission again.

## Process boundary (Ptah A05)

The canonical Ptah Provider Revision, Instance, Node binding, Activity Attempt, Lease, and caller authorization **remain owned by Ptah**. The adapter does not self-enroll as a canonical provider.

A05 uses the existing Process Provider's PTY mode and *current* Input Lease to send one UTF-8 newline-terminated JSON request. The provider must pass its current generation with `--provider-generation N`; the JSON `expected_provider_generation` must match.

Process command (argument vector; **never a shell command**):

```text
/usr/bin/python3 -I -B /path/to/Ptah-space/adapters/internet-search/bridge.py \
  --wheel /path/to/ttg_internet_search-0.7.0a2-py3-none-any.whl \
  --provider-generation N
```

Input on the authorized A05 PTY:

```json
{"operation":"search","query":"Python unittest documentation","limit":5,"request_id":"ptah-search-001","expected_provider_generation":7}
```

The PTY echoes input in ordinary terminal transcript semantics. **Do not send secrets, PII, tokens, or confidential searches through this lane without Ptah's normal sensitive-session controls.**

Supported commands:

- `search`: query 1–250 characters, limit 1–10, optional `require_fresh`, optional `offline` with an explicitly configured `--index-db`. Only published keyless/free providers. Experimental HTML scraping is off.
- `read`: ordinary public HTTPS URL, vetted by Search's DNS/SSRF/redirect checks.
- `doctor`: provider health and payment-control readout.

No import, delete, curate, merge, filesystem write, provider enrollment, elevated browser action or paid-API operation is exposed.

Output schema: `ptah.ttg-internet-search.readonly.v1`, request ID, observed generation, pinned provider version, `completed`, `has_results`, non-authoritative source URLs/snippets, explicit `result_truth`, and zero paid requests. No Search hit automatically becomes an A07 Object Revision or a D03 citation. `DISCOVERED_NOT_PAGE_VERIFIED` is not factual truth. Direct HTML `READABLE` is not verified factual correctness.

The Search engine's **shared existing XDG state** handles provider cooldown and daily courtesy quotas across callers. The adapter does not create independent provider allowance ledgers. If free providers are exhausted or fail, the result indicates unavailability; it never purchases overflow.

## Ptah operator entry point

For a manual read-only check from within Ptah:

```bash
python3 tools/ptah_internet_search.py \
  --wheel /path/to/ttg_internet_search-0.7.0a2-py3-none-any.whl \
  --provider-generation 7 search "Python unittest documentation"
python3 tools/ptah_internet_search.py --wheel /path/to/release.whl read https://example.com/
```

The operator CLI is a *terminal convenience only*. It is not itself a substitute for Ptah's canonical A05 authorization.

## KRATOS qualification

```bash
python3 -B -m unittest discover -s adapters/internet-search/test -q

PTAH_TTG_SEARCH_WHEEL=/path/to/ttg_internet_search-0.7.0a2-py3-none-any.whl \
PTAH_TTG_SEARCH_BRIDGE=/path/to/Ptah-space/adapters/internet-search/bridge.py \
cargo test --offline -p native-process --test a05_ttgs_search_integration
```

A05 physical qualification uses the actual Process Provider, provider-generation bound Input Lease, and independent exit observation. GitHub CI without KRATOS's external wheel skips the physical-only case; Python unit cases exercise contract and fail-closed behavior.

**Admission boundary:** repository integration and local A05 qualification do not by themselves claim production Provider enrollment or automatically route arbitrary Hunter/agent requests. Deployment still requires the ordinary Ptah authority/placement/lease path. Browser Provider remains unmodified, and no Control-plane endpoint is introduced.

## Agent-neutral reuse (no duplicate Search implementation)

The existing public-web discovery feature is a shared optional Ptah capability,
not a Hunter-specific tool. A read-only machine-readable descriptor is available
at adapters/internet-search/agent-capability.json and through the command:
  python3 tools/ptah_internet_search.py describe

The descriptor advertises the existing A05 Process Provider and pinned TTG Search
adapter. Describe only reads local metadata; it does not launch Search, issue a
Ptah lease, authenticate an agent, enroll a provider or imply production readiness.

Hunter, ChatGPT and other authorized agents use the same
ptah.ttg-internet-search.readonly.v1 JSON protocol, independently of agent brand.
The trusted Ptah caller, Workspace, Grant, Activity/Attempt, Provider generation
and current A05 Input Lease must be established upstream. A caller-chosen name
or supplied owner_ref is never treated as authorization. A one-line JSON request
is sent through the active authorized A05 PTY, not to an unauthenticated HTTP
listener or another search daemon.

Example payload on an authorized A05 PTY with its observed generation:
  {"operation":"search","query":"Godfrey Mountain full video","limit":5,
   "request_id":"agent-001","expected_provider_generation":7}

Search snippets remain DISCOVERED_NOT_PAGE_VERIFIED. An authorized caller can
separately invoke the existing A11 Browser Provider to verify promising pages
and playback evidence. Search neither selects nor launches Browser itself.
Local-only tasks make zero public-web calls. All callers share courtesy
quotas; no paid-provider overflow is enabled.

Current boundary: the shared protocol, pinned provider, operator entry, and
physical A05 process/lease proof are verified. Real production multi-agent
owner enrollment, individual Grant checks, automatic A05 dispatch and fallback
are not qualified by this descriptor. Reuse Ptah's existing authority services;
never grant production access based on JSON fields, a terminal process or a
tool manifest.
