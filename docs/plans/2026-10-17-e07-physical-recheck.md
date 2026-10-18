# E07 physical recheck — 17 October 2026

**Status:** PARTIAL physical progress; E07 PRODUCTION NO-GO.

## Latest direct two-host observations (00:34 UTC)

- ATHENA is again an Oracle-qualified native execution target, running Windows 11 Home (build 26200). Its active Wi-Fi is TTG HOME 115, IPv4 `192.168.1.103`.
- KRATOS is reachable from ATHENA at `192.168.1.101`: three ICMP responses (3 ms each) and TCP connections to 7070, 8088, 8788 and 4100 succeeded. This **closes the previously reported network-layer separation** for ATHENA-originated traffic.
- KRATOS to ATHENA ICMP received no replies, although KRATOS neighbor discovery resolved ATHENA's MAC; this does **not** establish reverse-direction inbound reachability. E01 can be designed around the verified outbound ATHENA → KRATOS direction if service identities qualify.
- **None of those listeners is a verified Ptah mTLS listener.** Port 7070 must not be treated as Ptah based on TCP reachability alone.

## Verified Windows build on ATHENA

- Recovered GitHub Actions artifact `e07-windows-unprovisioned-executables` from run `38585928701`.
- Archive SHA-256 verified against GitHub metadata: `af0c443cfe37ee387bfe916585445e1220de47386e16f4b43b442f5ee301e6b5`.
- Extracted to isolated, **non-installed** local workspace `D:\\projects\\Ptah-space\\.workspace\\e07-qualification-20261017`.
- `ptah-node.exe` and `ptah-enrollment-gateway.exe` both executed natively and exited **2** with the expected fail-closed unprovisioned condition.
- The Windows Node binary remains an **E01 deployment configuration stub**, not a resident authenticated Node. There is no Ptah Windows service, no production enrollment, and no signed installable production release established by this artifact.

## Current KRATOS host admission

- Fresh canonical host collector: required capabilities PASS; `proof_eligible=false`.
- Observed Ubuntu **26.04.1 LTS**, kernel `7.0.0-34-generic`; frozen E05 host pin remains Ubuntu **24.04.4 LTS**, kernel `6.8.0-136-generic`.
- KRATOS root disk is **99% used** (17 GiB reported available). Capacity should be addressed before extensive Rust builds, 24-hour soak tests, additional VMs or release deployment. No files were removed by this inspection.

## Fresh fail-closed E07 preflight

Private evidence (intentionally excluded from Git):
`.workspace/scratch/e07-physical-20261017/`

- `kratos-current-capabilities.json`: freshly collected canonical Linux host facts.
- `athena-host-observation-current.json`: fresh Windows OS, native artifact, service and TCP facts from direct Oracle execution.
- `combined-gate-current.json`: E07 physical preflight `NO_GO` at 2026-10-17T00:34:09Z.

The preflight reports:

| Area | Current evidence | E07 qualification |
| --- | --- | --- |
| Native ATHENA execution | PASS | Host execution only |
| ATHENA → KRATOS TCP | PASS | Transport only; identity unverified |
| Native Windows build startup | Expected exit 2 | Not a persistent Node |
| Production E01 enrollment | Absent | NOT PROVEN |
| KRATOS E05 platform pin | Mismatch | NOT PROVEN |
| Control E02 resident dispatch | Absent | NOT PROVEN |
| Independently witnessed hard-crash recovery | Absent | NOT PROVEN |
| Two-Node soak and final review | Not run | NOT PROVEN |

The physical preflight's **seven negative/security tests passed**. Passing a TCP probe or Oracle command does not authorize E01/E02/E05 or close E07.

## Required implementation and acceptance

1. Implement and independently qualify a **native, resident Windows Ptah Node agent**, replacing the current unprovisioned binary stub with a deployment-gated TLS E01 client, protected credential handling, reconnect and Node Generation/Epoch control.
2. Establish **deployment-owned certificate issuance, storage, revocation and E01 enrollment** on both hosts. No test fixture key may be promoted to production approval.
3. Independently qualify KRATOS's actual OS/kernel for E05, or deploy in a separate appropriately qualified host environment. Do not silently relax the frozen host identity.
4. Connect current Control-owned E02 grants, resident Node A05, two-sided durable receipts and independently witnessed hard-crash/restart reconciliation. No uncertain Attempt may be replayed.
5. Only after these gates and an approved 2-Node sustained soak, independent review and owner go/no-go may Cookpit opt into a reversible Ptah execution route. Keep Supervisor's current scheduler operational until then.

**No Ptah production services, certificates, firewall rules, Supervisor routing or platform pins were changed in this checkpoint.**
