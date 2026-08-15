# A01 — Repository, contracts and reproducible scaffold

Status: **candidate for exact-head proof**.

A01 promotes the repository/toolchain/contract scaffold prepared during Phase 0C into the first independently proved implementation work package. It does not rewrite the historical Phase 0C evidence that was correctly non-authorizing when produced.

## Existing foundation promoted by A01

A01 reuses and proves the existing repository-owned foundation:

- Rust workspace/package boundaries;
- Browser Provider Node/npm boundary;
- exact Rust and Node toolchain pins;
- exact Cargo and npm dependency locks;
- frozen Phase 0B contract catalog lock;
- deterministic generated Rust contract metadata;
- frozen WP13 conformance harness wiring;
- Apache-2.0 licence, NOTICE, contribution, security and REUSE boundary;
- immutable GitHub Action commit pins;
- source-policy/public-private checks.

A01 does not rebuild those assets merely because implementation authorization now exists.

## Required exact-head proof

The A01 acceptance workflow must prove at one exact candidate head:

1. the expected monorepo layout and package boundaries exist;
2. Rust `1.97.1`, Node `24.18.0`, Playwright `1.60.0` and dependency locks remain exact;
3. the fourteen frozen catalogs still bind to the accepted Phase 0B freeze;
4. generated bindings are reproduced twice and are byte-identical to each other and to the committed generated tree;
5. a deliberately altered catalog digest is rejected;
6. schema/binding generation succeeds from local frozen inputs without network schema resolution;
7. frozen WP13 unit, structural and semantic conformance still passes;
8. public/private source-policy and licence boundaries remain enforced;
9. workflow Action references used by the A01 proof are immutable commit SHAs;
10. the repository remains on the same clean exact head after proof.

## Claim boundary

A01 proves **scaffold readiness only**.

It does not claim that Ptah already has a functioning Node, ledger runtime, Activity runtime, persistent Workspace, PTY Provider, Browser Provider, container Provider, transfer engine, recovery runtime, Prime integration, production deployment or accepted release.

Those capabilities belong to later roadmap packages and require their own evidence.

## Historical Phase 0C evidence

`PHASE0C_SCAFFOLD.md`, Phase 0C evidence JSON and their `runtime_implementation_authorized: false` fields remain valid historical records. They are not mutated to manufacture a later authorization state.

The current repository status may advance while those historical records remain non-authorizing by design.
