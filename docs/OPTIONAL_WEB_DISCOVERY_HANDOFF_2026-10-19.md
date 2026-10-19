# Optional Internet Search — agent-selected on-demand qualification, 2026-10-19

## Scope and authoritative separation

TTG Internet Search is **already implemented** in Ptah by merged PR #121
(`5699561`). The native Hunter D02 workspace bridge is **already implemented**
by merged Ptah PR #133 (`e03feb7`). This follow-up does not duplicate either
provider or alter A05/A11/D02/E02 authority.

Ptah is the **workspace**, never a transport or a semantic decision authority.
Oracle is the authorized transport to KRATOS/ATHENA. Hunter, ChatGPT or another
authorized caller selects the task's required evidence. Ptah only supplies
eligible governed operations and evidence. The optional Internet Search process
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
  **4/4 existing D02 native and binary-entry tests passed**. This is isolated
  fixture proof, not evidence that a real owner is enrolled.
- Exact wheel operator diagnostic returned version `0.7.0a2`, zero enabled
  paid providers and `payment_budget_zmw = 0`.
- One **agent-selected** live lookup for
  `Others Summon Dragons I Summon Legendary Knights Godfrey Mountain 50 episodes complete video`
  returned **8 candidates**, including FlickReels and YouTube. The bridge
  explicitly returned `DISCOVERED_NOT_PAGE_VERIFIED`, `provider_requests_paid=0`.
  The operator CLI is a convenience, **not canonical Ptah A05 admission**.
- The agent then used **Ptah-owned A11**, not an Oracle/browser profile shortcut,
  to open `https://www.flickreels.net/episodes-list/others-summon-dragons-i-summon-legendary-knights-10910`.
  HTTP **200** and verified DOM-load evidence identified a **52-episode catalogue** and
  the Godfrey Daniels/Golden Holy Order synopsis. Playback of 52 episodes was
  **not** independently verified.

This demonstrates **one on-demand search-to-browser choice by ChatGPT** and the
existing provider mechanics. It does not prove autonomous Hunter selection,
sustained availability, semantic correctness, rights, or complete video playback.

## What remains before autonomous production routing can be called qualified

1. **Caller decision boundary:** Hunter / another approved agent needs to
   request optional public-web discovery only for tasks genuinely needing it;
   no unconditional execution or Ptah-owned natural-language decision maker.
2. **Real enrollment:** verify existing signed-in owner's canonical identity,
   mapped Ptah Principal/Workspace and Grants. D02 fixture provisioning and an
   Oracle-connected machine do not automatically establish it.
3. **Runtime authority:** dispatch through current Ptah A05 process Provider
   with canonical Activity/Attempt, active Provider Revision/Instance generation,
   actual A05 input-control lease and verified completion. The operator CLI
   must not be substituted for this production path.
4. **Fallback under explicit policy:** use A11 only when the agent requires
   page evidence or the indexed provider is inadequate and browser access is
   authorized. Search snippets are not automatically promoted to truth.
5. **Independent production acceptance:** verify positive web task, negative
   local/offline task (zero web calls), disabled/revoked/stale owner/grant cases,
   provider failure/cooldown, shared quota, no paid overflow, replay/restart,
   and privacy-approved redacted evidence. Review separately from current
   Hunter specialist and E07 production work.

## Disposition

**Search provider and local on-demand workspace investigation: qualified.**
**Unattended Hunter/agent production tool selection: not yet qualified.**
Do not toggle defaults, create owner identities, launch persistent providers,
change Supervisor/Ptah authority or claim the entire armour complete from this
record. No repository code or frozen contract changed by this documentation.
