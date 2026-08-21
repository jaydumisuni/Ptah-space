# Visual Device Verification Lab — Evolution Ledger

Current experimental revision: `lab-v0.1`  
Canonical Ptah capability: **not yet authorized**

## Proven donor use

### NoTVerse

The lab concept was extracted from the NoTVerse mobile/WebKit completion campaign after repeated iPhone-specific failures showed that one generic mobile viewport was insufficient.

Reusable lessons already earned:

1. exact viewport evidence only — never stretch a 390px capture into mini/Plus/Max proof;
2. WebKit and Chromium must be treated as independent evidence lanes;
3. keyboard-open and keyboard-return are separate visual states;
4. safe-area geometry must be visible during review;
5. screenshots must be inspected after automated assertions because green geometry tests can still miss visual overlap;
6. live iframe inspection is exploratory only, not acceptance evidence;
7. device proof machinery belongs outside the product repository until the reusable contract is stable.

## Current capabilities

- reusable iPhone device-profile registry;
- visual device wall;
- exact-capture/missing-evidence display contract;
- one-device live inspection mode;
- safe-area overlay;
- keyboard overlay;
- Chromium/WebKit viewport capture helper;
- project profile boundary;
- console/page-error capture report.

## Current limitations

- scenario automation is not generic yet;
- keyboard overlay is visual simulation, not an OS keyboard;
- WebKit Playwright is WebKit evidence, not a claim of every shipping iOS Safari build;
- no image-diff scoring yet;
- no automatic layout/occlusion detector yet;
- no Android device wall yet;
- no tablet/desktop wall yet;
- no Ptah runtime integration is authorized.

## Evolution frontier

### E01 — Scenario adapters

Project adapters should define bounded actions such as:

```text
open Notes
open Comments
focus composer
submit
close keyboard-equivalent viewport
Back
capture
```

The generic runner executes the adapter; project semantics stay outside the device engine.

### E02 — Exact evidence manifest

Every capture should emit:

- project;
- candidate identity;
- target URL/build;
- engine;
- device profile;
- CSS viewport;
- scene;
- timestamp;
- screenshot path;
- console/page errors;
- assertions/verdict.

### E03 — Visual comparison

Add baseline/candidate comparison with explicit tolerances and human-review output. Image diff is evidence, not automatic design authority.

### E04 — Layout diagnostics

Collect computed rectangles for declared critical controls and detect:

- viewport escape;
- nav/composer overlap;
- hidden controls;
- safe-area intrusion;
- unexpected document scroll;
- clipped fixed surfaces.

### E05 — Device families

Add separately validated profiles for:

- iPad;
- common Android phones;
- foldables where justified;
- desktop/tablet breakpoints.

### E06 — Ptah promotion decision

After repeated use across multiple projects, decide whether the stable machinery becomes:

```text
Ptah
└─ Visual / Device Verification
   ├─ device profiles
   ├─ browser engines
   ├─ scenarios
   ├─ captures
   ├─ evidence manifests
   ├─ visual comparison
   └─ proof export
```

Promotion requires roadmap authority and independent Ptah proof. This ledger is not that authority.

## Change discipline

For every lab change:

1. identify the reusable requirement;
2. keep project-specific behavior in a project adapter;
3. preserve exact-device evidence semantics;
4. do not weaken missing-evidence reporting;
5. update this ledger when capability or boundary changes;
6. do not merge this branch into Ptah `main` merely because the lab is useful.
