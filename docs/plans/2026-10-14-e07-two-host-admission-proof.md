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
