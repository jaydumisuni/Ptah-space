# E07 — Oracle-first machine transport (2026-10-21)

## Physical E01 → E02 → A05 native acceptance — 21 October 2026

**PASS: Oracle-carried native cross-host execution, caller-mediated.**

The first physical Oracle-carried attempt established E01 and reached
E02, but its reservation expired. Root cause: Control calculated TTL
at initial TCP acceptance rather than **after** slow TLS negotiation.
The source now derives issue time after successful E01. Bounded direct
LAN TTL remains 90s reservation / 75s lease; Oracle carrier uses
240s reservation / 210s lease. Tests include delayed TLS and overflow.

Physical test used disposable TLS and SQLite journals and two
loopback-only carriers, with packet batches transported by existing
authenticated Oracle terminal RPC. ATHENA ran the newly built Windows
Node from GitHub Actions workflow 39588365324 (Windows job PASS).
KRATOS ran a new Ptah branch Control binary. No direct KRATOS-ATHENA
TCP, internet-exposed port, Railway, firewall or Knights changes.

- Real E01 TLS established; Control transmitted E02 Reservation,
  Lease and Dispatch and received A05 liveness acknowledgment.
- ATHENA executed a real caller-selected A05 process with
  cmd.exe /C echo PTAH_E07_ORACLE_NATIVE_20261021; exit code 0.
- Both independent physical SQLite journal integrity checks: ok.
- Exact matching dispatch ID:
  01a15e28-646a-7023-a574-c5b28b885826.
- Exact matching attempt ID:
  01a15e28-646a-7023-a574-c58a6570bc53.
- ATHENA journal: one phase=completed A05 entry, stdout SHA-256
  sha256:2344e34e044bc52acc3bc4f659ad04a8a8437db66e42b1913d7cb246b639bb6e.
  An independent execution of the same Windows echo yielded exactly
  the recorded hash (including CRLF).
- KRATOS Control journal: one phase=sent_unconfirmed dispatch, zero
  independently signed/witnessed effect receipts. Acknowledgment
  is not the same as an independently verified effect witness.
- The existing ATHENA permanent Scheduled Task was left untouched.

**Exact claim:** live native E01/E02/A05 over the existing Oracle
transport PASSED on two physical machines. The Oracle terminal tool
API is RPC rather than a supported unattended TCP tunnel. This run
requires an active upstream tool invoker to exchange packet batches;
it does not yet prove always-on autonomous cross-network forwarding
without that invoker. This limitation affects unattended E07 roaming,
NOT general Ptah workspace tool availability. No additional user
approval or external provider account is required.

---


Oracle Live already reaches KRATOS and ATHENA through independent machine
connections. This is the existing upstream transport. Do not introduce a
Railway account, public relay or new Ptah login to connect the workspace.

## Native architecture

The Ptah-owned tools/e07_oracle_stream.py bridges **opaque TLS bytes** between
the existing E07 Control and Node processes through caller-mediated Oracle
terminal RPC invocations. Both native endpoints use loopback ONLY. Neither
computer has to accept an inbound connection on its real network address.
No new provider subscription or user-role decision is made by Ptah.

The carrier is not an Oracle client. A caller or orchestration agent already
able to invoke the existing Oracle terminal tool calls exchange on each
machine and forwards its packets to the other machine, preserving sequence.
It cannot decrypt E01, issue an E02 task or select the locally configured
A05 process. Bounds: 32KB packet, 32 packet batch, 8MiB per direction,
five-minute local process lifetime, replay-checked SQLite spool.

Control's --oracle-loopback-carrier and Node's oracle_loopback=true settings
allow the slower tool-mediated stream to complete within a three-minute
transport window. These are not new permissions: existing TLS 1.3,
enrollment, E02 fence/generation/expiry and durable A05 requirements still
apply. Direct LAN uses the original shorter deadlines unchanged.

## Grounded physical evidence

2026-10-21: the existing Oracle tool transported a 34-byte opaque request
from ATHENA to KRATOS and a 45-byte reply back. The two machines checked
identical content and no direct host-to-host IP connection was used.
The original native worker's five/ten-second E01 timeout was also tested:
ATHENA's 225-byte TLS ClientHello entered the KRATOS carrier, but the native
Control exited with E01 TLS timeout. No E02/A05 occurred in that test.
Do NOT report that timed-out native attempt as a successful dispatch.

The extended deadlines and fresh post-E01 lease expiry passed local
tests and strict Rust linting. Native cross-host E02/A05 completion
subsequently PASSED as detailed above; the older failed attempt is
retained only as the historical diagnostic. The included GitHub workflow builds
an isolated Windows Node binary with one-day artifact retention.

## Execution and limitations

Create disposable state separately on both machines with prepare. Launch
the carrier in dial mode beside the KRATOS Control loopback listener and
accept mode beside the ATHENA Node loopback client. The caller repeats
exchange --state STATE --after LAST --packets JSON on both computers,
passing each host's output packets to the other on its next call.
Advance LAST from latest. Verify E02 Control and A05 Node journals
independently. No job selection or secret key crosses the carrier.

Oracle terminal.exec is an authenticated RPC, not an always-on raw socket
forwarding API. This adapter requires an external Oracle tool invoker during
the requested session. It does NOT yet constitute an unattended permanent
cross-network E07 service. Permanent autonomous operation requires a
continuously running supported caller-side Oracle tool integration, not an
assumed undocumented Oracle socket/tunnel interface.

No production ATHENA config, scheduled task, Knights system, firewall,
router, or Oracle configuration changed in this work. Unavailable transport
only affects the E07 operation attempted; ordinary Ptah capabilities stay
available. Prime OS integration LAST.

## Pre-pump socket setup failure custody — 28 October 2026

Source-only E07 preparation now closes the accepted/dialed native socket
and any listener if socket timeout configuration fails after readiness
was published but before either byte-pump thread starts. The existing
exclusive claim remains in place; a private failed ended.json marker
records the unsuccessful lifetime without impersonating a successful
E01/E02/A05 exchange. Two adversarial regression cases reproduced the
previous leaked-socket condition before the correction. This does not
qualify unattended roaming or Windows-native acceptance.
