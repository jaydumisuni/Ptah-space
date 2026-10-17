# A11 post-baseline maintenance admission — 2026-10-17

**This is a new, independently evidenced maintenance lane.** It is not a replacement,
retroactive success, waiver, or rewrite of the original A11 single-commit A08-successor
proof. The historical A11 CI continues to fail on unrelated, later commits because
that historical predecessor requirement is immutable and remains authentic.

## Two distinct gates

1. **Universal exact-head scope** (`exact-head-current-pr`): validates the PR's
   immutable checked-out head against its exact base, denies any unrelated phase
   change, and for A11 changes invokes a fail-closed `check_a11_maintenance_admission.py`.
   The allowed A11 surface is explicit; original A11 workflow, Rust canonical API,
   Cargo locks, unrelated modules, paid Search, and self-editing scope checker are
   all outside it.
2. **Independent A11 physical browser proof** (`a11-maintenance`): always triggered
   for PRs to main. Non-A11 PRs report NOT_APPLICABLE; A11 maintenance PRs MUST
   pass the exact-head scope, pinned Node 24.18.0, Playwright 1.60.0, project-owned
   Chromium revision 1223 and physical multi-agent/browser behavior.
   The GitHub main-branch required-status checks MUST include
   `a11-maintenance` in addition to existing universal/other checks.

3. **Base-branch immutable governance integrity** (`a11-governance-integrity`):
   a separate required `pull_request_target` job runs exclusively the accepted
   base-branch workflow, fetches the proposed PR head only as Git **data** and
   rejects changes to A11 maintenance policy, either universal governance
   checker/workflow, or this integrity workflow. It never checks out or executes
   PR-head code. The initial adoption is a one-time governance bootstrap;
   subsequently any attempt to rewrite these gates through a normal PR fails
   closed. This job must ALSO be required by branch protection.

Neither a green unit suite nor a green universal scope alone grants A11 production
enrollment. The required `a11-maintenance` physical check and
the base-owned `a11-governance-integrity` check are independent
unskippable branch protection conditions for merging browser maintenance.
The original A11 proof body and trigger remain byte-for-byte unchanged. Its
historical failure on PR #128 stays visible and is not renamed as a pass.

## Default browser routing scope

Ptah's Browser Provider is Playwright/Chromium owned by the Ptah workspace,
with independently allocated ephemeral agent browser sessions. Its persistent
profiles still require canonical exclusive leases and the user or another
agent must not be silently evicted. Oracle's shared browser-control session
is a different transport and is not Ptah's A11 execution backend.

An operator/agent workspace command can default to the dedicated Ptah A11
browser, but the command is not a production Ptah Node-enrolled provider or
a default path for every automatically scheduled AI task. Production dispatch
requires independently qualifying canonical provider enrollment and routing.

## Search

Existing A05 zero-cash TTG Internet Search remains separately admitted,
pinned and read-only. A browser is used for sites where the lightweight
reader cannot reliably retrieve content, but `READABLE`, `DISCOVERED`
and `RENDERED_PAGE_NOT_FACT_VERIFIED` are distinct evidence states.
No paid browser/search service, credential transfer, or human-control
takeover is authorized.

## Verification

```bash
python3 -B -m unittest tools/test_check_current_pr_admission.py -q
python3 -B -m unittest tools/test_check_a11_maintenance_admission.py -q
# On A11 candidate PR (not on governance PR):
python3 tools/check_a11_maintenance_admission.py --base HEAD_BASE_SHA --head EXACT_HEAD_SHA
```

The governance PR must be independently accepted and merged under existing
required checks before the A11 implementation PR can rebase against it.
Do not combine governance rule introduction and product changes into one PR.
