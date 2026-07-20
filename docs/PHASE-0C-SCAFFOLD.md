# Phase 0C scaffold

Status: selection and CI scaffold only — Ptah runtime implementation is not authorized

## Purpose

This branch proves that the public implementation repository can pin its toolchain, compile a zero-dependency guard crate, consume the frozen roadmap contracts and produce exact-head CI evidence without starting the Ptah runtime.

## Frozen planning inputs

- Phase 0B freeze / Phase 0C entry: `dc2db457f1705d0cba80f17ab76e5e93f808aee0`
- WP14 corpus and proof-plan merge: `fef387c4f074af7fcf86f2d99f7f9b7637e91f88`
- Proposed implementation-selection ADR: `ADR-0033`

## What exists

- Rust `1.97.1` toolchain pin;
- one `publish = false`, zero-dependency preflight crate;
- committed zero-dependency `Cargo.lock`;
- fail-closed runtime-authorization constant and tests;
- immutable-SHA GitHub Actions workflow;
- local execution of the frozen WP13 structural and semantic conformance harness;
- retained exact-head reports.

## What does not exist

- Node agent;
- ledger;
- Workspace runtime;
- Activity scheduler;
- PTY/terminal runtime;
- Object store or CAS;
- transfer engine;
- container, Browser, Git or decomposition adapters;
- checkpoint/recovery runtime;
- public licence acceptance;
- production deployment.

## Dependency state

The direct Rust dependency graph is intentionally empty. This proves the workspace and lock discipline but does not select the later runtime crates. Runtime crate selection remains a Phase 0C blocker and requires exact versions, features, licence review, advisories and replacement boundaries.

## Local preflight

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --doc
cargo metadata --locked --format-version 1
```

The frozen roadmap harness is executed by CI against a local checkout of the exact governance checkpoint. Schema resolution during conformance is local.

## Authorization rule

No contributor or automation may change `RUNTIME_IMPLEMENTATION_AUTHORIZED` to `true` merely inside this repository. Authorization requires:

1. owner licence/contribution decision;
2. accepted final Phase 0C dependency and CI evidence;
3. accepted ADR-0033 or successor;
4. merged roadmap control-book entry stating `Runtime implementation: AUTHORIZED`;
5. a follow-up implementation-start decision referencing that exact roadmap commit.

Until then, additions must remain selection, scaffolding, conformance or proof-preparation work.