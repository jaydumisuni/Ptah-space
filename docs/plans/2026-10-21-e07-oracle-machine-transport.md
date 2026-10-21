# E07 — Oracle-first machine transport (2026-10-21)

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

The new extended deadlines passed local unit tests and strict Rust linting
but must be built for Windows and physically accepted to establish native
E07 completion through this carrier. The included GitHub workflow builds
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
