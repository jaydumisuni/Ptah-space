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
