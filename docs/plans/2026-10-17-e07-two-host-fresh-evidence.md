# E07 two-host preflight — fresh physical recheck, 17 October 2026

**Status: NO-GO · review evidence only · not admission · no Supervisor cutover**

## Direct observations

- KRATOS (fresh canonical Phase-0C collector): Ubuntu 26.04.1 LTS, kernel `7.0.0-34-generic`; all required capability probes PASS. The frozen E05 profile still expects Ubuntu 24.04.4 LTS / `6.8.0-136-generic`, so `proof_eligible=false`. The frozen profile was not modified.
- ATHENA (native PowerShell via Oracle): Windows 11 Home, build 26200; tool execution PASS. TCP from ATHENA to KRATOS `192.168.1.101:7070` PASS, but listener identity **not verified as Ptah**.
- Both native Windows executable candidates actually ran unprovisioned and exited **2**; this is a pass for the *fail-closed startup* contract, not resident Node enrollment.
- ATHENA's public certificate has subject `CN=ptah-athena-e07-staging`, issuer `CN=Ptah E07 Physical Staging Root 20261017`, and expires 16 November 2026. The certificate file has **no associated private key** and no running Ptah Node or Control service was found. No staging certificate was treated as production-approved identity.
- ATHENA's isolated Windows ZIP matches known SHA-256 `af0c443cfe37ee387bfe916585445e1220de47386e16f4b43b442f5ee301e6b5`.
- KRATOS storage: root currently has ~47 GiB free at 95% used. No cache or source deletion was authorized or performed.
- Conformance: `python3 -B -m unittest discover -s conformance/e07 -p test_physical_acceptance_preflight.py -v` **9/9 PASS**.
- Combined preflight emitted `status=NO_GO`, `may_close_e07=false`, `may_run_production_dispatch=false` at `2026-10-17T10:25:48Z`.

## Private, integrity-bound receipts

These machine-specific inputs remain under `/home/kratos/.local/state/ptah-e07-physical-check-20261017/` with no secret material in Git:

| Receipt | SHA-256 |
|---|---|
| `kratos-20261017T1219-host.json` | `92d9a0507f26680fc3c9fb787d04e1d5cb35d9ac53d3749fc42a72680d6416af` |
| `athena-20261017T1025-native.json` | `489098789987d4dff5da0411721e3397fcbea6f04ca29315e1d887043a261eeb` |
| `two-host-current-gate.json` | `87405e72fe0cc2136f0f147998e3329a766b4c7dae9b4158aa1babfad8391e3c` |

The old ATHENA report from 00:33 UTC was rejected by the preflight as stale; it was **not** refreshed by changing its timestamp. Fresh native PowerShell probes produced the replacement.

## Remaining mandatory gates

1. **Production E01:** independently approved deployment CA/Node IDs, certificate custody and revocation, valid ATHENA private-key association and current mutual-TLS session receipts on both hosts.
2. **Resident E02:** a real persistent Control/Node process, Control-owned fresh A02/E05 admission and E02 lease/fence, exact Attempt journal ownership and independently read back A05 effect receipt.
3. **Current KRATOS E05:** independent owner/platform acceptance of the actual Ubuntu 26.04.1 host or deployment of the frozen image; neither host identity nor accepted pin may be silently altered.
4. **Physical crash recovery:** an independent live signed witness surviving a deliberately controlled full reboot, with no repeated uncertain external effect.
5. **Two-machine final E07:** dual admitted Nodes, bounded soak, independent current-head review, owner go/no-go, then reversible one-project Supervisor opt-in.

Also keep storage PR #131 review, cache disposal qualification, and E07 authority entirely separate. An ordinary TCP listener or staging certificate cannot pass any of the above gates.

**No production Ptah process, credential, firewall, kernel profile, Supervisor route or unqualified cache was changed during this physical recheck.**
