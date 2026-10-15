# Supervisor gateway: E05 native integration proof

Status: test-only candidate on branch `feat/e05-supervisor-gateway-proof-20261013`; not a deployed Ptah Node or Control service.

## Actual bounded KRATOS evidence — 2026-10-13

- Ptah native integration tests: **3/3 PASS** (one separate opt-in consumer test ignored in normal runs).
- Opt-in real TTG-Simulation through Ptah E02/A05 API: **1/1 PASS**.
- Simulation stdout digest: `sha256:96e23bb5817fe74df633e5f18423b0f0ce636fb64a7b14de77408b9e39cbc0bb`.
- Simulation output: `ttg.simulation-result.v2`, `qualification_status=candidate`, `authority_granted=false`, selected candidate `authority_violations=0`.
- A05 provider process exit successfully observed and stdout independently read back.
- E05/placement control uses exact E01 session and A02 snapshots, E05 class admission, E02 Reservation/Lease/Fence issuance, Node-side dispatch guard and A05 native process provider.
- Negative cases prove no dispatch without Node-side reservation/lease, and no dispatch after lease expiration.
- `cargo fmt --all -- --check`, focused `cargo test --offline`, and focused `cargo clippy --offline -- -D warnings` pass.

## Authority limitations

The E01 enrollment fingerprint and A02 Node snapshots in this *test* are synthetic, hermetic fixtures. The process is real, but **this is not live production mTLS enrollment or a persistent Ptah gateway**. This is distinct from the historical E05 single-shot proof dated 2026-10-01 and may not be used to claim E06 completion or E07 readiness.

The opt-in consumer uses the existing TTG-Simulation checkout and local installed `ttg-sim`, invoked through Ptah's actual Node Provider rather than a Cookpit subprocess. Consumer root is provided explicitly by `TTG_PTAH_SIM_REPO`; normal CI skips that host-specific test.

Next for actual Supervisor dispatch: current production E01 peer enrollment, persistent control and Node runtime, exact request schema/digest binding, durable Node/attempt/session/lease/fence/read-back receipts, recovery and independent qualification. Supervisor remains outside Ptah control: no timers or project routes changed.

## Reproduction

- Run focused hermetic suite: `cargo test -p ptah-node --test supervisor_gateway_boundary --offline`.
- Run explicit host consumer: `TTG_PTAH_SIM_REPO=/home/kratos/projects/TTG-Simulation cargo test -p ptah-node --test supervisor_gateway_boundary ptah_gateway_executes_real_ttg_simulation_as_candidate_only --offline -- --ignored --nocapture`.

## Cookpit → Ptah request-bound execution (same-day continuation)

Cookpit PR #69's `ttg.cookpit.ptah-shadow-preflight.v1` generated a deterministic
request at `~/.local/state/ttg-cookpit/ptah-shadow/request-20261013.json`.

- Canonical request digest: `sha256:3e5ade34bceff0d641c3980b9118b8d86b4ed0f7ff9c899aedeb15992b7f1a97`
- Exact E06 candidate observed by Cookpit and Ptah: `826f6726856083d39560166de8a9857f667314f4`
- Exact Simulation consumer commit: `77c18429c79a557f331db778db8cb5bce76b44a8`
- Ptah-native consumer: **PASS** after digest, shadow mode,
  authority=false, local Ptah and Simulation head checks and E02/Node/A05.
- Candidate-only Simulation stdout: `sha256:96e23bb5817fe74df633e5f18423b0f0ce636fb64a7b14de77408b9e39cbc0bb`.
- Separate negative hermetic test rejects altered request payload with unchanged digest.

This is a real cross-project consumer proof with TEST-FIXTURE E01/A02 context.
The SHA-256 request digest provides content integrity, **not authentication**.
There is still no persistent authenticated production Ptah dispatch service or
durable production lease/attempt ledger. E06 and E07 are not released.

To run the explicitly opt-in test on KRATOS, set both
`TTG_PTAH_SIM_REPO` and `TTG_PTAH_SHADOW_REQUEST` to the registered
Simulation checkout and exact Cookpit preflight request path respectively.

## Gateway operationalization candidate — 2026-10-13

Subsequent to the E05 single-shot proof, the Ptah-owned gateway branch adds:

- **Actual TLS 1.3 mutual authentication:** `ptah_control::gateway_enrollment::admit_authenticated_node` takes the real client-certificate SHA-256 fingerprint from the accepted TLS stream. It passes only this transport-attested fingerprint to the existing canonical E01 `PlacementAuthorityOwner::accept_hello`. It rejects a valid-CA peer whose fingerprint is not approved. Tested with repository-only test certificates; **no production credentials were provisioned**.
- **Durable Node dispatch ownership:** `ptah_node::gateway_journal::GatewayJournal` stores the exact dispatch/attempt identity, request digest, Node Generation, Connection Epoch and control-issued Fence in a SQLite `WAL` with `synchronous=FULL`, within an immediate transaction. Staging requires an existing current `NodeDispatchGuard`; the journal never creates E02 authority. Exact duplicates do not spawn again and identity/fence conflicts fail closed.
- **Durable actual A05 completion:** after independent process exit, the journal commits A05 exit code and digest of complete stdout. Missing exit, wrong Node Generation, truncated stdout or mismatched persisted attempt cannot produce a receipt.
- **Recovery:** on opening after crash/restart, in-flight attempts become `needs_reconciliation`. They cannot be replayed or marked completed by the ordinary completion method; current owner/Node authority and outcome evidence must be re-established through a separate reconciliation implementation.
- **Real consumer:** the opt-in Cookpit request-bound TTG-Simulation run now uses the durable journal before and after real Ptah A05 execution, then reads the committed attempt after reopening. The original Simulation stdout digest remains `sha256:96e23bb5817fe74df633e5f18423b0f0ce636fb64a7b14de77408b9e39cbc0bb`.

Evidence: 6/6 Ptah Node boundary tests PASS, 2/2 authenticated E01 TLS tests PASS, 1/1 real opt-in Simulation PASS, formatting and focused strict Clippy PASS on KRATOS.

**Not installed or admitted:** there is still no deployed production enrollment config/certificate chain, no continuously running Ptah gateway daemon with authenticated E01 and E02 ownership, and no independent crash outcome reconciliation against actual external processes. These must be resolved before automatic Supervisor dispatch, multi-node E07 or E06 release. Existing Supervisor timers and project routes remain untouched.


## Optional E01 enrollment-only service candidate

The binary `ptah-enrollment-gateway` has been added to the Ptah Control
package. It is **not installed, enabled or deployed**. It exposes a real
TLS-1.3 client-certificate authentication boundary, but no dispatch routes,
no admission-to-execution privilege promotion, and no provisioned Node authority.

It requires deployment-owned PEM files, an explicit approved canonical
enrollment projection, and a loopback endpoint:

    ptah-enrollment-gateway \
      --listen 127.0.0.1:8785 \
      --server-cert /secure/ptah/server-cert.pem \
      --server-key /secure/ptah/server-key.pem \
      --client-ca /secure/ptah/client-ca.pem \
      --enrollments /secure/ptah/approved-enrollments.json

No certificate, private key or approved fingerprint was created during
this work. The enrollment file must be a deployment-controlled export of
already approved `core.node_enrollment` records; supplying a file does
not confer owner approval. The binary rejects absent/unapproved, duplicate
or malformed enrollments and requires restrictive permissions for sensitive
inputs. It does not bind externally by default.

**Important:** this E01-only listener acknowledges a mutually authenticated
Hello then closes that connection. An enduring Node-link service, live A02
observations, dispatch-side session lifetime, authenticated E02 control
ownership and a durable production reconciliation worker remain separate
unimplemented gates. Do not route Supervisor to this binary as an executor.

The option parsing and enrollment/missing-secret tests pass 2/2; focused
strict Clippy and offline compile pass. No running Ptah service or
Supervisor configuration was changed.


## Follow-on: E01 disconnect fencing and recovery inventory

A Node's E01 session may be ended only if it remains the exact current
canonical binding. A late close from a superseded connection cannot revoke a
newer generation/epoch. Ending a current session also discards its cached
Ptah Control placement state, preventing disconnected Nodes from appearing
eligible on stale A02/E05 observations.

The Node-side durable journal now provides a read-only
\`unresolved()\` inventory containing dispatch and attempt identity,
request digest, Node identity, generation, epoch and control-issued fence.
A restarted in-flight entry remains \`needs_reconciliation\`. Merely reading
this inventory cannot execute, complete or reauthorize an attempt.

Tests: E01 session control (5/5), gateway journal/Node guard (6/6);
focused strict Clippy and formatting PASS on KRATOS.

**Still incomplete:** enrollment currently acknowledges then closes an E01
connection. A continuously retained authenticated transport loop is not
deployed. The retained-session transport is intentionally not part of this verified change set; it requires a separately reviewed deployment and lifetime contract. Persistent authenticated dispatch and
independent reconciliation of unknown external process outcomes still
require separate qualification.


### Node journal single-writer safeguard

The durable gateway attempt journal now holds an OS file lock for the full
lifetime of its SQLite connection. An overlapping gateway instance is denied
before it can classify the live owner's in-flight attempts as abandoned.
The database connection is dropped before the lock is released. Verified by
a duplicate-open rejection and subsequent successful restart with ownership
transferred; ordinary tests 7/7 PASS and strict Clippy PASS.

This is a **single-KRATOS process-ownership guarantee**, not a distributed
lease. The journal must live in a deployment-owned, non-attacker-writable
state directory. It cannot substitute for E02 cross-machine lease authority
or independent external-effect reconciliation.

## Retained authenticated enrollment milestone — 2026-10-14

The optional loopback E01 enrollment executable now retains mutually
authenticated TLS 1.3 Node sessions after Hello and HelloAck. An explicit
16-connection semaphore rejects overload without unbounded queued tasks.
The session accepts only bounded, strictly increasing heartbeat sequences
and a graceful Close. All other wire messages (including execution-changing
dispatch frames) are denied. Missing heartbeats close the connection after
30 seconds. Session disconnect invalidation is exact-current only, so a
late prior connection cannot revoke a newer E01 generation or epoch.

The owner lock is **not held during unauthenticated network handshake**.
This prevents a slow connection from monopolizing the owner while other
enrollments complete. Accepted TLS peer certificate identity, approved
E01 projection, epoch and generation remain the authority sources.

Verified locally: 4/4 retained TLS transport tests PASS, 5/5 existing E01
control tests PASS, 2/2 real TLS enrollment tests PASS, 2/2 executable tests
PASS, focused strict Clippy PASS, formatting PASS.

**Still separate:** the optional executable remains uninstalled, loopback-only,
and enrollment/liveness-only. It does not consume live A02 resource evidence,
admit E05 platforms, mint or forward E02 Reservations/Leases/Fences,
dispatch A05 workloads, or reconcile unknown external process outcomes.
Production certificate enrollment and revocation remain deployment-controlled.


## E02 journal-gated launch and E06 head refresh — 2026-10-14

The Ptah Node now exposes \`GatewayJournal::spawn_once\`, a narrow A05
execution entrypoint that **first durably stages** an exact current E02
dispatch/attempt/Node/epoch/fence/request-digest binding. Only a newly staged
attempt can reach the existing \`spawn_native_process_if_authorized\`.
Already-registered attempts fail closed even if their durable phase is
completed or needs reconciliation. On any later Provider error, the staged
attempt remains conservatively unresolved, not silently retried.

After publishing the clean E06 documentation commit \`b062e208...\`, the
Cookpit shadow preflight was refreshed at that exact published E06 head
and Simulation commit \`77c18429...\`. The new shadow request digest is
\`sha256:713e6e4cd7ef2d55b78aba7e811418ad0506b98a51e08bfa9c59bc558c5c84b3\`.
The real KRATOS TTG-Simulation consumer passed through the new Ptah
journal-gated \`spawn_once\` API, with stdout digest
\`sha256:96e23bb5817fe74df633e5f18423b0f0ce636fb64a7b14de77408b9e39cbc0bb\`.
The opt-in consumer remains explicitly **TEST-FIXTURE E01/A02**; no
production control-to-Node authenticated dispatch service was installed.

Focused tests demonstrate a real provider launch, duplicate launch
rejection, persisted completion receipt and restart readback. This is a
building block for a persistent Node dispatcher, not authorization to
enable remote execution, mark E06 complete or initiate E07.

## Authenticated E02 wire ingress and unresolved-attempt fencing — 2026-10-14

The Ptah Node now has a narrow E02 TLS receiver. It preserves the
authenticated E01 Control-side TLS stream after an exact HelloAck, then
accepts precisely a **Reservation → Lease → DispatchRequest** sequence
within bounded per-frame timeouts. Each frame is checked by the existing
NodeDispatchGuard for Node, generation, connection epoch, expiry, attempt,
reservation, lease and monotonic fence. The receiver returns an
authorized request but **never executes an arbitrary wire-selected program**:
the A05 provider and ProcessSpec remain Node-local choices, and
GatewayJournal::spawn_once remains the durable pre-effect boundary.

The genuine TLS transport tests use repo-only credential and authority
fixtures. A positive E02 wire sequence reached the actual A05
`/bin/true` provider with persisted, restart-readable completion.
Out-of-order and expired lease sequences fail closed. The positive fixture
does not constitute production Control enrollment, live A02/E05 discovery,
a persistent remote dispatcher or qualified Supervisor activation.

The journal additionally blocks any *new* dispatch reusing an existing
A04 Attempt identity, regardless of an increased fence. A different
dispatch/fence after an unresolved crash cannot justify replay.
A replacement requires an independently reconciled external effect
and a **new attempt identity** before any execution.

KRATOS: 12/12 normal Node gateway tests PASS, focused strict Clippy
PASS, cargo formatting PASS. No production dispatch listener
was deployed and no Supervisor registry/timer routes changed.

## Control-owned E02 durable issuance and crash uncertainty — 2026-10-14

Control now issues E02 grants through its PlacementAuthorityOwner and sends
Reservation, Lease/Fence, and DispatchRequest frames only over the matched
authenticated E01 peer connection. A SQLite WAL/FULL ControlDispatchJournal
persists the exact request-digest-bound Attempt before any socket write.
A successful send is sent_unconfirmed, never an execution receipt.
Restart converts unconfirmed dispatch into needs_reconciliation without replay.

KRATOS: 13/13 normal Node gateway tests, 4/4 retained E01 tests, 2/2
mTLS enrollment tests, 2/2 executable tests, strict Clippy and formatting
PASS. Negative tests reject reused Attempt, altered dispatch, invalid digest,
competing Control owners, and duplicate sends across restart.

These tests use fixture certificates. No persistent production Control dispatch
service, independently witnessed cross-host outcome reconciliation, production
enrollment, Supervisor cutover, or E07 authorization is claimed.

## E07 independently signed external-effect verifier — 2026-10-14

The integrated Control/Node gateway now has a read-only Ed25519 external-effect verifier. It binds one signed independent witness observation to the exact Control Dispatch/Attempt/request digest/fence and the Node's recorded Attempt/Node/Generation/E01 epoch/A05 exit/stdout digest. The verification key must be pinned independently of Node and Control. Canonical domain-separated messages prevent repurposing a signature as dispatch authority. A forged signature, untrusted observer, conflicting process result, swapped Node or epoch, incomplete journal completion or mismatched request is rejected. This is a verifier, **not** an installed witness service or an automatic reconciliation decision. No release, retry or completion state is promoted. Tests and strict Clippy are bound into the exact-head workflow.

Remaining production proof requires independent observer deployment, secure key lifecycle/revocation, actual external effect observation across hard process and host crashes, two-host E01/E02 admission, and E07 acceptance. ATHENA is visible to Oracle but its terminal currently rejects with `NO_QUALIFIED_NODE`; do not bypass the machine qualification gate.

### E07 durable signed evidence after Control restart — 2026-10-14

The Control journal has an immutable `control_verified_effects` table. Only the `record_verified_effect` method can add a row, after checking an externally pinned Ed25519 witness signature against the exact persisted Control Node/Generation/E01 epoch/Dispatch/Attempt/request/fence and the Node's real A05 completion. A repeated identical receipt is idempotent; conflicting receipts, swapped Node identity, altered signed bytes and Node `needs_reconciliation` are rejected. After Control restart, the independent evidence remains readable, while the original dispatch remains `needs_reconciliation` and cannot automatically replay or promote further work. The KRATOS integration test uses an actual A05 `/bin/true` effect and explicitly test-only signing credentials; it does **not** prove an independent production witness daemon, real machine power-loss durability or deployment-ready recovery.


## Explicit private-LAN E01 bind candidate — 2026-10-15

Physical ATHENA and KRATOS have a direct working IPv4 route, but Ptah's
enrollment executable previously permitted loopback binding only. This
change adds an explicit `--allow-private-lan` switch allowing one
specific RFC1918 IPv4 endpoint, e.g. an approved KRATOS interface.

Loopback remains the default. Without the flag, every nonloopback bind
is rejected. Even with the flag, wildcard (`0.0.0.0` or `[::]`),
public IPv4, link-local, CGNAT, unapproved ranges and all nonloopback
IPv6 addresses are refused. The executable **still** validates
deployment-owned server TLS key, trusted client CA and approved
canonical E01 enrollment *before* opening any listener.

This code is not a deployment approval. The explicit endpoint, firewall
access policy, TLS server SAN, approved A02 Node identity, certificate
expiry/revocation and role admission must be qualified independently.
The listener remains **E01 Hello/Heartbeat/Close only** and cannot
accept E02/A05 commands. No production service was started on either
machine and Supervisor was not rerouted.

Focused opt-in/negative executable tests: 5/5 PASS; strict Clippy PASS.
The native ATHENA `ptah-e01-node-client.exe` remains fail-closed
pending Windows ACL/durable state custody. Host TCP reachability does
not establish mutually authenticated Ptah E01 session authority.
