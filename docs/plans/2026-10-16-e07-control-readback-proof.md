# E07 shared workspace Control readback — KRATOS qualification

**Date:** 2026-10-16
**Scope:** PR #126, exact Control A14 submission → persistence → lookup after server restart.

## Verified
- Built the actual `ptah-control` Rust executable and executed an independent loopback process with the repository A14 fixture snapshot.
- The reusable Python `PtahControlClient` observed identical D01/A14 authority stamps, submitted an authorized `checkpoint_request`, retrieved the exact request identity, and stopped Control.
- A new Control process reopened the same persistent `submissions.ndjson`; the client retrieved the same identity and verified exactly one durable submission.
- A14 server binary tests **11/11 PASS**; client tests **9/9 PASS**; strict Control Clippy and formatting PASS on KRATOS.
- Independent repeated live smoke PASS: retained `execution_status=not_executed_by_this_control_service`, never fabricated A05 completion. Both localhost processes exited.

## Fail-closed boundary
This Control HTTP endpoint records authorization to dispatch but does not independently select a qualified Ptah Node, mint E02 leases, launch an A05 process, or return external-effect receipts. These remain separate acceptance gates before calling the path a production tool-to-Ptah executor. The A14 fixture is not a production enrollment, and this operation did not alter live Supervisor timers or routes.

## Reproduction
```bash
cargo test --locked -p ptah-control --bin ptah-control
cargo build --locked -p ptah-control --bin ptah-control
python3 -m unittest discover -s clients/python -p test_ptah_control_client.py
python3 clients/python/qualify_live_ptah_control.py \
  --binary target/debug/ptah-control \
  --fixture services/ptah-control/tests/fixtures/a14_snapshot.json
```

The dedicated GitHub workflow runs this same real-process smoke after a build. No production deployment is claimed from a standalone proof process.
