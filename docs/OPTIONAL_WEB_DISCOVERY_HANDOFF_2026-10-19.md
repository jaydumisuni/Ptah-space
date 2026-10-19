# Optional Internet Search — agent-selected on-demand qualification, 2026-10-19

## Scope and authoritative separation

TTG Internet Search is **already implemented** in Ptah by merged PR #121
(`5699561`). The native Hunter D02 workspace bridge is **already implemented**
by merged Ptah PR #133 (`e03feb7`). This follow-up does not duplicate either
provider or alter A05/A11/D02/E02 authority.

Ptah is the **workspace**, never a transport or a semantic decision authority.
Oracle is the authorized transport to KRATOS/ATHENA. Hunter, ChatGPT or another
authorized caller selects the task's required evidence. Ptah only supplies
requested available operations and evidence, without second admission. The optional Internet Search process
is not installed as an always-on service.

## Current KRATOS acceptance (2026-10-19)

Base: `origin/main` at `e03feb7`. Run from a separate clean Git worktree,
not the busy reverse-engineering checkout.

- Existing pinned, externally owned TTG Internet Search wheel:
  `ttg_internet_search-0.7.0a2-py3-none-any.whl`.
  SHA-256 `eaecd49153225e1b9c2972fa89d24edde69975e6dd15a7b05230c302fd7d65c4`
  matches Ptah's approved pin; no external wheel source was copied into Ptah.
- `python3 -B -m unittest discover -s adapters/internet-search/test -q`
  with `PTAH_TTG_SEARCH_WHEEL` set to that pinned wheel: **31/31 passed**.
- `cargo test --offline -p native-process --test a05_ttgs_search_integration`
  with the pinned wheel configured: **1/1 physical A05 process/PTY/lease/independent-exit acceptance passed**.
- `cargo test --manifest-path adapters/ptah-hunter-workspace/Cargo.toml --locked --offline`:
  **4/4 existing D02 native and binary-entry tests passed**. This is isolated fixture proof, not evidence of a Knights admission system.
- Exact wheel operator diagnostic returned version `0.7.0a2`, zero enabled
  paid providers and `payment_budget_zmw = 0`.
- One **agent-selected** live lookup for
  `Others Summon Dragons I Summon Legendary Knights Godfrey Mountain 50 episodes complete video`
  returned **8 candidates**, including FlickReels and YouTube. The bridge
  explicitly returned `DISCOVERED_NOT_PAGE_VERIFIED`, `provider_requests_paid=0`.
  The operator CLI is a convenience and needs no additional Ptah admission.
- The agent then used **Ptah-owned A11**, not an Oracle/browser profile shortcut,
  to open `https://www.flickreels.net/episodes-list/others-summon-dragons-i-summon-legendary-knights-10910`.
  HTTP **200** and verified DOM-load evidence identified a **52-episode catalogue** and
  the Godfrey Daniels/Golden Holy Order synopsis. Playback of 52 episodes was
  **not** independently verified.

This demonstrates **one on-demand search-to-browser choice by ChatGPT** and the
existing provider mechanics. It does not prove autonomous Hunter selection,
sustained availability, semantic correctness, rights, or complete video playback.

## Authority correction: Knights first, Ptah never re-authorizes

Knights is the dedicated, external security and cybersecurity department.
The workspace is presently open during tool development. Do not invent Ptah
owner logins, AI-by-AI enrollment, per-tool Grants, or separate browser/search
permissions while Knights is being built. When Knights admits a request,
the caller can select any available Ptah capability without another approval.
Oracle only transports machine commands. Ptah never ranks tasks, chooses
which tool is appropriate, or decides which admitted human/AI deserves access.

A05 Provider generation and Input Lease prevent old/misdirected process input;
they are *mechanics*, not a second security officer. Provider crashes,
missing dependencies and shared rate/resource limits produce precise execution
results rather than policy denials. The search provider is read-only by its
actual implemented interface and does not invent unavailable capabilities.

## Engineering still needed (not Ptah owner-access blockers)

1. **Caller selected invocation:** Hunter, ChatGPT or any admitted agent
   can decide when to invoke available search or A11 Browser. Neither choice
   requires an internal approval or semantic policy engine.
2. **Real tool integration:** validate normal invocation across the public
   descriptor, direct terminal CLI and native A05 process/PTY route.
3. **Execution evidence:** verify generation-stale/restart isolation,
   malformed input handling, download/citation truth, quota accounting,
   outage reporting and no paid-provider overflow. A known process lease
   proves whose process input is being used; it is not a new Grant.
4. **Knights ingress implementation:** belongs to the separate security
   department. Ptah must not implement a temporary second login while it
   is unfinished. Future security admission is upstream and reusable by
   every workspace tool without repeating authentication.

## Known pre-existing D02 deviation (separate implementation lane)

The merged native D02 Hunter bridge still takes owner_ref, requires
authority_ref/policy_ref during provisioning and checks recorded_owner
against the supplied owner during inspection
(adapters/ptah-hunter-workspace/src/main.rs). Those are pre-existing
Ptah-side owner/authorization semantics, not created by this Search PR.
They require their own migration so Knights-provided ingress identity can
supply workspace context without asking an admitted caller to re-prove
approval. Do not remove record-integrity checks, misroute another user's
workspace data, or claim existing D02 code has already been migrated.

The architectural correction applies to ALL Ptah capabilities, not
only Search or Browser. A Search descriptor fix cannot prove that every
legacy service follows the same boundary today.

## Disposition

**Existing Search and A11 local reuse have physical supporting evidence.**
**This PR describes reusable access, not Knights integration or all-tool
production acceptance.** No login, owner enrollment or per-tool Grants are
introduced. Do not fabricate playback verification, production readiness
or successful execution when the provider returns a technical failure.
