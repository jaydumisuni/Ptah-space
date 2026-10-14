# E07 current physical admission — two-host, non-claiming checkpoint

**Observed:** 2026-10-14. **Review base:** Ptah gateway PR #112, `0a6f597a7ef1121ee633a5042cebae96f8a31bef`.

## What has been observed on the physical machines

- **KRATOS:** direct Phase-0C host collector completed, with required capability probes passing. Actual Ubuntu 26.04.1 LTS / kernel `7.0.0-34-generic` does **not** match the currently pinned Ubuntu 24.04.4 LTS / `6.8.0-136-generic` image; `proof_eligible=false`. This is host-baseline drift; do not change the accepted pin merely to turn the test green.
- **ATHENA:** Oracle PowerShell execution is restored and Windows 11 is observed. The `D:\projects\Ptah-space` folder currently contains a `.workspace` folder but **not** a checked-out `.git` repository; no installed Ptah Control/Node service or matching process was observed. Oracle transport identity is not Ptah E01 TLS enrollment.
- **Gateway PR #112, KRATOS fixture-backed tests:** E01 TLS 2/2, signed independent effect witness 3/3, Node gateway 14/14 active tests PASS; one TTG-Simulation integration test is intentionally ignored absent a physical fixture. These are development tests, not deployment-owned certificates, an installed resident service, or a hard reboot.

## Actual no-go barriers

| Requested gate | Evidence currently present | Required before closing |
| --- | --- | --- |
| E01 authenticated session | Fixture E01 TLS test, ATHENA Oracle access recovered | Approved production Node enrollment and current mTLS Control/Node sessions, both physical hosts |
| E05 Node admission | KRATOS capabilities present, pinned image mismatch | Current host-role/platform acceptance, A02 node identity, capability evidence and approval |
| E02 Reservation/Lease/Fence | Control-owned journal and issuer tested | Control-issued live exact-Attempt grant over authenticated E01, verified Node-side |
| Real Control → Node → Creative dispatch | A05 resident specialist and gateway components proven independently | End-to-end authenticated physical deployment and receipt |
| Durable crash recovery | SQLite journals and restart tests | External signed observer, hard-crash/reboot, uncertain outcomes reconciled or left unresolved without replay |
| Native Service/Recipe admission | D04 local in-memory lookup | Production-approved service key, capability mapping and admitted Recipe/Provider/placement |
| E07 acceptance | Technical component tests, current two-host preflight | Two independent enrolled Nodes, bounded soak, independent review and owner go/no-go |

## New verification asset

`conformance/e07/physical_acceptance_preflight.py` takes the unmodified native Linux capability collector report and a read-only Windows host-presence observation, checks schema and freshness, and emits a **NO_GO** result without accepting caller-provided Boolean claims as production authority. Its negative suite proves that forged `production_lease_authorized` flags, process names, unqualified host/image changes and stale observations cannot mark E01/E02/E05/E07 admitted.

Run locally:

```bash
python3 -B -m unittest discover -s conformance/e07 -p 'test_physical_acceptance_preflight.py' -v
python3 -B conformance/e07/physical_acceptance_preflight.py \
  --linux <current-KRATOS-collector.json> \
  --windows <current-ATHENA-observation.json> \
  --output <private-local-evidence-dir>/preflight.json
```

The physical input JSON and machine-specific full collector remain in private, ignored workspace evidence, **not** in Git. CI runs only the synthetic adversarial tests. **Passing CI is not an admission event.**

## Authority and ownership

- Existing Ptah E07 acceptance issue [#110](https://github.com/jaydumisuni/Ptah-space/issues/110) stays open and no runtime services are installed or activated.
- This branch is a stacked conformance/evidence proof on Ptah's existing E07 gateway candidate PR #112; do not merge it before that candidate is admitted.
- E06-02 journal sequence-gap freeze and E07 owner go/no-go remain additional programme gates; neither is claimed closed.
- Creative Studio remains a specialist caller of Ptah, not a substitute controller or a second scheduler.


## New real Creative Studio E02/A05 consumption test — 2026-10-14

`services/ptah-node/tests/supervisor_gateway_boundary.rs` now includes the explicitly opted-in
`e02_fixture_grant_dispatches_real_creative_studio_and_preserves_node_receipt` physical test.

With `TTG_PTAH_CREATIVE_REPO` explicitly pointing to the Creative Studio checkout, it uses the
existing Ptah **test Fixture** to issue Control-owned E02 Reservation/Lease/Fence; the Node validates
the grant, durably stages the exact Attempt, launches Creative Studio's existing Python headless
worker as an actual Ptah A05 process and independently verifies the resulting editable project,
PNG and portable ZIP. It stores the observed stdout hash and reopens the Node journal to verify
completed status and that the same Attempt cannot be dispatched again.

On KRATOS the opt-in test **1/1 PASS**. The existing Node gateway suite **14/14 active PASS**,
E01 TLS **2/2 PASS**, independent witness **3/3 PASS**. No Hunter is needed.

Run explicitly on a qualified Linux development host:

```bash
TTG_PTAH_CREATIVE_REPO=/home/kratos/projects/TTG-Creative-Studio \
TTG_PTAH_CREATIVE_PYTHON=/usr/bin/python3 \
cargo test --offline --locked -p ptah-node --test supervisor_gateway_boundary \
 e02_fixture_grant_dispatches_real_creative_studio -- --ignored --nocapture
```

This advances **fixture-authority Control E02 → Node A05 → real specialist → durable Node receipt**
but is **NOT** deployed E01 mTLS, production E05 host admission, E07 production scheduling,
external signed witness service or physical hard-crash proof. The test is ignored in generic CI
because it requires an explicitly opted-in physical Creative Studio checkout; this prevents
misrepresenting CI fixtures as production enrollment.

## ATHENA Oracle execution restored — physical recheck, 2026-10-14 16:04 CAT

New direct workstation RPC execution on ATHENA independently completed:

- `cmd.exe /d /c echo ATHENA_E07_EXECUTION_OK`: exit 0
- Windows PowerShell + WMI operating-system identification: exit 0; Windows 11 Home
- Cross-machine challenge test: KRATOS generated a random nonce and expected
  SHA-256; ATHENA computed its digest in native Windows PowerShell and returned
  the matching value through the authenticated Oracle transport

This **closes the previous ATHENA `NO_QUALIFIED_NODE` execution-transport
blocker**, but that is a different authority from Ptah E01 enrollment.

A fresh ATHENA read-only PowerShell observation, with UTC timestamp
`2026-10-14T14:04:10Z`, confirmed no Ptah Node/Control process or service,
no Git checkout at `D:\\projects\\Ptah-space`, no installed WSL
distribution, and no Rust toolchain. ATHENA's two available host interfaces
are on different IPv4 /24 networks from KRATOS's observed active interface;
a direct Ptah Control-to-Node route has not been demonstrated. Do not assume
a reachable service based on Oracle relay.

KRATOS's canonical Linux collector completed at
`2026-10-14T14:04:14Z`. Required capabilities PASS, but the pinned
image remains unqualified: running Ubuntu 26.04.1 / kernel
`7.0.0-34-generic` versus accepted Ubuntu 24.04.4 /
`6.8.0-136-generic`. No host baseline was silently relaxed.

The E07 combined preflight rerun, grounded in the fresh private inputs,
remains **NO_GO** for E01, E02, E05, actual dispatch, crash recovery,
Service/Recipe admission and E07. Host execution is now displayed separately
from production Node enrollment; the new hostile test asserts that a true
`oracle_terminal_execution_passed` flag cannot grant E07 status.

Private, untracked evidence paths in this worktree:
- `.workspace/scratch/e07-physical-20261014/athena-host-observation-current.json`
- `.workspace/scratch/e07-physical-20261014/kratos-current-capabilities.json`
- `.workspace/scratch/e07-physical-20261014/combined-gate-current.json`

The focused fail-closed preflight suite passed **5/5** on KRATOS.
No production certificates, authority grants, service installation, device
writes, firewall changes or Supervisor rerouting occurred.

**Next production blockers:** native supported ATHENA Ptah Node runtime and
installation, authenticated physical E01 enrollment, E05 role/image admission
on both hosts, a qualified network route, and independent reboot/crash
recovery with a deployed witness. Those require actual deployment evidence;
this host-readiness correction alone cannot close issue #110.


### Windows compilation and direct TCP verification (2026-10-14)

The native Windows-hosted exact-head `cargo check --locked -p ptah-node
-p ptah-control` passed on GitHub Actions run
[38579213250](https://github.com/jaydumisuni/Ptah-space/actions/runs/38579213250).
This qualifies native Windows **source compilation only**; the Node's
current executable still requires the reviewed resident runtime and
deployment-owned E01 credentials before any actual Node can be admitted.
A separate native Windows **library test** step is now required by the
E07 physical qualification workflow.

ATHENA attempted read-only TCP handshakes to KRATOS's physical host:
port 22 failed (no SSH listener was observed), and port 7070 failed
even though KRATOS reported an active wildcard listener there.
ATHENA used a different IPv4 subnet/gateway from KRATOS. Thus a
working direct Ptah Control/Node network path is **not qualified**.
Do not open inbound firewall ports or provision tunnels merely to make
the test pass; the owner-approved service/network design must identify
the allowed mTLS endpoint, trust roots, routing, and revocation.
