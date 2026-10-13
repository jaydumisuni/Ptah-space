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
