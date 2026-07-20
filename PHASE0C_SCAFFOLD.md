# Phase 0C non-claiming scaffold

Status: candidate scaffold only.

This tree exists to prove repository layout, toolchain locks, dependency boundaries, generated-contract locking and CI wiring before ADR-0033 is accepted.

It deliberately does not implement or claim:

- a Ptah Node;
- a persistent Workspace;
- an Activity runtime;
- a ledger backend;
- a Browser Provider;
- a container Provider;
- a transfer engine;
- a decomposition engine;
- a device or repair workflow;
- implementation authorization.

The authoritative runtime gate remains `ptah-roadmap-/CURRENT_STATE.md`.
