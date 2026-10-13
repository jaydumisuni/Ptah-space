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
