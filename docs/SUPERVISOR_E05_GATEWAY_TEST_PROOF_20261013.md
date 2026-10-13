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
