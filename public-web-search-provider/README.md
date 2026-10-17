# Ptah Public Web Search — read-only provider

This Ptah-owned provider bridges **external public Internet discovery** into a
bounded JSON-lines command surface. It reuses the independently built
`ttg-internet-search==0.7.0a2` engine rather than copying or relicensing its
implementation into this public Ptah repository.

## Authority boundary

- Existing A11 Browser Provider is unchanged. Public-Web Search uses indexed
  providers without starting Chromium; JavaScript/challenge pages remain
  Browser-required and **no browser bypass** is implemented.
- B07/D03 canonical Workspace search is not touched. Public-Web hits are always
  `external_discovery_noncanonical`, not source-bound Ptah facts or verified
  Object Revisions. `read` returns untrusted public HTML text and metadata.
- No Ptah Node enrollment, lease, fence, A04 attempt, D04 Provider registration,
  production deployment, or automatic scheduled crawling is performed.
- **ZMW 0** hard budget. Paid Brave API, commercial access or billing/setup,
  proxy rotation, challenge bypass, and copy of unlicensed content are excluded.
- The shipped wheel and local corpus are deliberately **not committed** to Ptah.
  An optional licensed SQLite/Wikipedia index is Search-owned, with source rights
  and attribution retained in local results. No canonical Ptah evidence change.

## Reproducible installation from an approved wheel

Use an authorized locally held Search wheel; no network or dependency downloads:

```bash
python3 public-web-search-provider/scripts/install.py \
  --wheel /path/to/ttg_internet_search-0.7.0a2-py3-none-any.whl \
  --destination /path/to/search-isolated-venv
```

The installer checks the **exact SHA-256**:
`eaecd49153225e1b9c2972fa89d24edde69975e6dd15a7b05230c302fd7d65c4`.
Changing engine releases requires a reviewed adapter and digest update.

Point the provider to the isolated engine. All paths are absolute:

```bash
export PTAH_PUBLIC_WEB_PYTHON=/path/to/search-isolated-venv/bin/python
export PTAH_PUBLIC_WEB_HOME=/path/to/ptah-search-workspace
export PTAH_PUBLIC_WEB_STATE_DIR=/path/to/search-owned-state
export PTAH_PUBLIC_WEB_INDEX_DB=/path/to/authorized-owned-index.sqlite  # optional

node public-web-search-provider/bin/ptah-web-search.mjs health
node public-web-search-provider/bin/ptah-web-search.mjs search "SQLite FTS5"
node public-web-search-provider/bin/ptah-web-search.mjs search "SQLite SELECT" --offline
node public-web-search-provider/bin/ptah-web-search.mjs search "latest Zambia updates" --fresh
node public-web-search-provider/bin/ptah-web-search.mjs search "playwright" --scope github
node public-web-search-provider/bin/ptah-web-search.mjs read https://example.com/
```

## JSON-lines provider (same mechanical hosting pattern as A11)

Start `node public-web-search-provider/src/server.mjs`. Send one bounded JSON
object per line and receive exactly one result envelope per line:

```json
{"id":"q1","operation":"search","query":"SQLite FTS5","limit":5,"offline":true}
```

Envelope: `{"id":"q1","ok":true,"result":{...}}`. Failures use typed
error codes, not raw upstream errors or the user's query. Other operations:

```json
{"id":"q2","operation":"read","url":"https://example.com/"}
{"id":"q3","operation":"health"}
```

The optional `offline` flag forbids network search, and `require_fresh`
forces independent live discovery. Default provider ordering and persistent
rate caps are delegated to Search 0.7.0a2. The provider limits results to 10,
queries to 250 characters, page URLs to bounded HTTPS, processes to 20 seconds,
and stdout to 1.5 MB. It does not set any `BRAVE_SEARCH_API_KEY` or API token.

## Acceptance and deployment status

`cd public-web-search-provider && npm run check && npm test` uses only Node
built-ins. Physical acceptance also calls the **wheel-installed** Python engine
to prove health, no-network owned-index search, and direct HTTPS page reading.

The descriptor in `integration/provider-descriptor.json` is **non-authoritative
metadata**, not a canonical Ptah Provider identity or D04 Service registration.
Activation through Ptah Node/Control must follow existing enrollment,
placement, lease, Grant and precondition authority rather than silently widening
permissions. Runtime qualification is separate from the source integration.
