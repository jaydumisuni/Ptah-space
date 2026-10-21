# E07 roaming — different networks

ATHENA travels. Ptah must work when ATHENA and KRATOS are behind different
NAT routers. This is a transport requirement, never a Ptah user approval gate.

## Topology

KRATOS Control --> outbound TCP --> public Ptah opaque relay <-- outbound TCP <-- ATHENA Node

E01 mutual TLS 1.3 runs end-to-end between KRATOS and ATHENA. The relay
only copies ciphertext and pairs two endpoints by a random 256-bit
hexadecimal route identifier. It cannot grant a Ptah permission, choose
a program, forge an E02 lease/fence or write an A05 completion receipt.
The relay identifier is NOT a credential; E01 retains peer authentication.

## Configuration

An existing public TCP-reachable server must host the tiny Ptah binary:

    ptah-e07-relay --listen 0.0.0.0:4433

This publicly reachable TCP endpoint is a real network dependency,
not a new user/account access gate inside Ptah. Unlike a private
KRATOS LAN IP it remains reachable when ATHENA changes Wi-Fi or travels.
No incoming port forward is needed at KRATOS or ATHENA. Run the relay
under appropriate OS service isolation and a bounded host firewall.
The relay does not support HTTP, Cloudflare Workers HTTP routes or WebSocket;
do not misrepresent a private or HTTP endpoint as a public TCP relay.

Generate the route locally using a secure random 32-byte identifier,
for example Python secrets.token_hex(32), and do not commit it.

ATHENA scheduled E07 worker config: retain its TLS CA, key, cert,
server_name, existing local A05 program, seed and SQLite journal.
Add a relay socket address and the same route:

    "relay": "PUBLIC_RELAY_IP:4433",
    "relay_route": "64-lowercase-hexadecimal-characters"

The old direct control LAN address may be omitted. The worker reconnects
to the relay automatically after losing network, with the same durable
Node identity/generation handling already in E07. Do not replace a
running ATHENA worker until the rebuilt Windows binary and public
relay are verified and a backup config exists.

KRATOS Control uses the existing certificate, enrollment, digest and
SQLite journal arguments but replaces --listen with:

    --relay PUBLIC_RELAY_IP:4433 --relay-route SAME_64_HEX_VALUE

No second login, Grants or Ptah-side user policy. Only the real
transport technical condition changes. The existing E01 mTLS,
E02 session/fence rules, native A05 process and durable effect journals
remain as before. Control's acknowledgment is not independent proof.

## Tested versus untested

KRATOS relay unit tests cover opaque bidirectional binary streams,
malformed handshake and an E01 TLS 1.3 mutual-authentication exchange
over the relay. Existing native E07 tests also run in the same source.
A global internet endpoint has NOT been deployed or verified in this
change. The remaining physical different-network check requires one
public relay host and a Windows Node binary built from this update,
followed by a durable E02/A05 dispatch check while ATHENA is away.
No unrelated Ptah workspace capability may be blocked pending that check.

Prime OS integration LAST. Knights completely untouched.
