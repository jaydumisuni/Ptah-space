# E07 physical native E02/A05 follow-up — 20 October 2026

Scope: Ptah only. Knights untouched. Oracle transports engineering commands.

Native Control executable now accepts E01 mutual TLS, issues Node-bound E02
Reservation, Lease/Fence and DispatchRequest frames, stages an immutable
Control journal Attempt before transmit and retains sent_unconfirmed instead
of mistaking a Node transport acknowledgement for an effect witness.

Native Node worker uses existing Rust receive_one E02 guard, existing
NativeProcessProvider A05 and durable GatewayJournal. Node identity advances
in SQLite WAL/FULL across restart. Program and arguments are configured
locally by the caller; no executable commands arrive over E02 wire.

Real KRATOS separate-process test passed TLS, E02 dispatch, actual A05 exit 0,
Node journal completed and Control journal sent_unconfirmed, with SQLite
integrity OK. A test harness independently exercised E01 TLS, E02 guards
and A05 process execution with durable journal recovery.

Windows-native build is attempted in a SHA-pinned GitHub Actions workflow.

Limits: currently single caller-triggered E02 dispatch path, not the full
autonomous E02 placement scorer/E05 resource admission. Acknowledgement is
not an independent witnessed external-effect proof. Persistent ATHENA
Windows service and two-host native A05 execution are not yet claimed.
No startup or firewall changes and no Ptah user permission layer added.
Prime OS integration remains last.


## Persistent native remote Node — October 20 2026

The Node --serve-config option keeps the native A05 capability alive
across caller-initiated Control dispatches. The caller chooses each task.
Technical disconnects retry with bounded backoff (16 to 120 seconds),
without disabling unrelated Ptah workspace tools. Stored Node identity,
session generation and E02 fences continue to be validated. No
second Ptah login, Grant or user authorization is added.

A Windows user-owned Scheduled Task can start this native executable
at login without installing Rust or replacing Oracle transport.
Control currently dispatches one caller-selected action per invocation;
persistent Node availability does NOT autonomously dispatch tasks.


## 2026-10-20 physical installed worker / dynamic endpoint evidence

The native Windows Node worker is installed under the existing Ptah NativeE07
workspace on ATHENA and runs through scheduled task Ptah-E07-Native-Node.
The existing task restarted the worker automatically after a deliberate
worker termination; on 20 October 2026 at ~14:50 it was PID 30756,
created at 13:36:48 local time. The worker retained its existing
SQLite Node identity and A05 completion journal (integrity=ok).

The real KRATOS Control journal contains six E02 dispatches; the matching
ATHENA journal contains six A05 completed records, all exit_code=0 with
stdout SHA-256. Dispatch #6 is UUIDv7 timestamp 13:28 local -- BEFORE
the unattended 13:36:48 restart. Consequently the specific NEW dispatch
after the automatic restart has not yet been demonstrated.

At ~14:50 ATHENA had moved to Wi-Fi 192.168.1.155/24, while KRATOS's
existing Control endpoint remained 192.168.238.52:47821. The real
post-restart Control attempt listened and timed out without Node joining;
ATHENA explicitly failed TCP reachability to that endpoint. This is a
real changed network route, not Ptah authentication or resource admission.
Neither machine's Wi-Fi, gateways, Knights, Oracle, nor unrelated services
were changed. Control will use a four-minute bounded listener to encompass
the persistent Node retry interval (up to two minutes) when a route exists.

Current E07 capability evidence: original LAN native mTLS E02/A05
execution PASS; automatic ATHENA worker restart PASS independently;
post-restart end-to-end dispatch over the NOW DISJOINT NETWORK NOT TESTED.
Do not manufacture a completed A05 claim or stop unrelated Ptah tools
because this optional endpoint is temporarily unreachable. A real new
ATHENA completion entry with matching Control dispatch/fence is needed
to claim end-to-end post-restart acceptance.
