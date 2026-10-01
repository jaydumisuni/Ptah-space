# E05 Platform Nodes — Implementation Plan

Accepted predecessor: `77bbd876aaefd78fed2c0583b2b124eee428eb5f`

Roadmap authority: `ptah-roadmap-` `98dc8c4e8639cda80510bee0625db34b4fdf9384`.

## Task 1 — Freeze design and RED admission corpus

- add the E05 design and plan;
- add a new `ptah-platform-admission` workspace crate;
- write RED tests for exact session/state/snapshot binding and all five platform classes;
- prove tests fail because admission implementation does not yet exist.

## Task 2 — Implement pure E05 admission policy

- implement `PlatformNodeClass`, `PlatformAdmissionProfile`, typed rejection reasons and `PlatformAdmissionDecision`;
- require current Active/Online health evidence and complete capability snapshot;
- require exact OS/class match and explicit capabilities/Provider Revisions;
- add diagnostic-advisory projection using existing A02 `DiagnosticAdvisory`;
- run strict crate tests, Clippy and fmt.

## Task 3 — Integrate E05 with control-owned E02 placement

- retain E05 decision alongside current Node placement state;
- clear admission on capability refresh or session supersession;
- add `admit_platform_node`;
- add E05-specific `place_admitted_and_issue` while leaving existing E02 `place_and_issue` unchanged;
- prove admission cannot mint Reservation/Lease/Fence by itself.

## Task 4 — Prove D08 and Android boundaries

- prove admitted Windows/macOS candidates can reach existing D08 remote-ready only through exact E02 authority;
- prove non-admitted candidates remain blocked;
- prove Android/Device admission does not replace C10 Device/Application Session authority.

## Task 5 — First physical stage: Linux Platform Node

- collect current Linux host evidence using existing accepted collectors without widening their claim;
- map only supported observed facts to an E05 Linux admission proof;
- prove one real current Linux Node as the first E05 physical stage;
- retain any limitation explicitly.

## Task 6 — Workstation/GPU stage

- add explicit GPU capability evidence collection;
- admit workstation/GPU only when GPU capability is independently evidenced;
- do not infer GPU readiness from model/vendor names alone.

## Task 7 — Windows, macOS, Android/Device stages

- execute platform-specific physical proof only when each real platform is available;
- software policy may be complete earlier, but physical proof status remains separate and honest.

## Task 8 — Frozen E05 conformance corpus

- create exact design-order corpus for acceptance obligations;
- add deterministic fail-closed checker and mutation regressions;
- prove inherited E01/E02/E04/D08/C10 owners.

## Task 9 — Permanent exact-head workflow

- exact predecessor and path-set guard;
- immutable Action pins;
- dependency/source audit;
- E05 corpus and targeted owner proofs;
- strict workspace Clippy/fmt/full locked tests;
- secret scan;
- SHA-bound retained proof bundle with `merge_claimed=false`.

## Task 10 — Release

- full exact-delta and nonclaim review;
- frozen PR from exact proven head;
- PR-context E05 proof;
- expected-head guarded merge commit;
- verify parent 1 = E04 merge, parent 2 = proven E05 candidate and merge tree = candidate tree.
