# E07 physical two-computer E01 link — 20 October 2026

## Actual execution

- **Control:** KRATOS Linux, actual `ptah-enrollment-gateway` binary from protected Ptah `main` (`aa413dc` when tested), bound to one explicit private LAN interface and temporary high port, constrained by a 120-second TTL.
- **Node client:** ATHENA Windows 11, Python 3.10, new dependency-free `clients/python/ptah_e07_node_link.py` speaking the *existing Ptah E01 wire protocol* (TLS 1.3 and u32 big-endian length-prefixed tagged JSON frames).
- **Trust:** repo-supplied E01 **test-only certificate fixtures**, temporary files and canonical fixture Node enrollment. Not installation credentials; no Knights data touched, no Ptah user login or Grants, no production enrollment.
- **Observed:** ATHENA made a successful E01 mutual-TLS connection to KRATOS, received the exact `hello_ack` for its test Node, sent three strictly increasing heartbeats, then a `close`; a second connection with the same valid Node completed two heartbeats and clean close.
- **Negative cases:** changed-but-still-canonical Node ID caused the actual Rust gateway to terminate without a `hello_ack`; a TLS 1.3 client omitting its certificate was rejected with `TLSV13_ALERT_CERTIFICATE_REQUIRED`.
- No installation of Rust, WSL, new Windows software, OS/firewall changes, persistent daemon or production Node dispatch was performed. Oracle merely transported setup and test commands.
- The Ptah `ptah-node` executable currently has a connection-configuration placeholder; the test instead used a real Python E01 wire client. **This proves the actual two-host E01 enrollment/heartbeat transport, not E02 reservation/lease/fence dispatch, remote A05 process execution, production deployment, release enrollment or live effects.** Such optional capabilities are distinct engineering scopes, never conditions for ordinary shared workspace access.

## Reproduction

Build on KRATOS with the existing shared Cargo target:

```sh
cargo build -p ptah-control --bin ptah-enrollment-gateway --locked --offline
python3 -m unittest discover -s clients/python -p test_ptah_e07_node_link.py
```

For a two-host test, generate a disposable test-only TLS identity and matching canonical Node enrollment, run the Rust `ptah-enrollment-gateway` on a bounded private port, and launch `ptah_e07_node_link.py` from ATHENA with the test CA, client identity and NodeHello JSON. Never persist the test private keys as runtime credentials and never treat the fixture as an authorization system for workspace tools. This proof intentionally did not start remote process dispatch.

**Disposition:** E07's previously missing physical cross-host **E01 native-gateway transport demonstration is satisfied** with above scope. A real two-host production *execution and deployment* remains a separately unproved claim; it does not block Ptah or Prime OS integration.
