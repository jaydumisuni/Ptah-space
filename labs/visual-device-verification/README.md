# Ptah Visual Device Verification Lab

Status: **experimental workspace machinery**  
Branch authority: `lab/visual-device-verification`  
Ptah product authority: **none**

This lab is a persistent proving/workbench surface for visually inspecting web interfaces across exact mobile device viewports before product changes are promoted to their canonical repositories.

It originated while closing NoTVerse iPhone/WebKit regressions, but it is intentionally generic and may be used by NoTVerse, Huawei, Lumi, Ptah UI work, and other browser-facing projects.

## Boundary

This directory is **not a Ptah runtime claim** and must not be treated as an implemented Ptah capability while Ptah `main` remains in its scaffold/selection phases.

The lab may evolve aggressively on this branch. A capability becomes canonical Ptah product code only after the Ptah roadmap explicitly authorizes that capability and it independently passes the relevant Ptah implementation/review/proof gates.

Temporary project proof screenshots are not canonical product assets and should normally remain outside the public repository. The repository stores the reusable machinery, profiles, contracts, and project adapters.

## Core evidence rule

> A screenshot captured at one viewport never proves another viewport.

Every device/scene proof is keyed by exact CSS viewport and browser engine. Missing evidence must be shown as **Not captured**, never stretched or inferred.

## Current device wall

The initial iPhone set is defined in `device-profiles.json`:

- iPhone 13 mini — 375×812
- iPhone 13 / 14 — 390×844
- iPhone 13 Pro Max / 14 Plus — 428×926
- iPhone 14 Pro — 393×852
- iPhone 15 / 15 Pro — 393×852
- iPhone 15 Plus / Pro Max — 430×932
- iPhone 16 Pro — 402×874
- iPhone 16 Pro Max — 440×956

Android, tablet and desktop profiles can be added without changing the proof rule.

## Modes

### Proof mode

Offline-first. Displays only exact captures available for the selected project, scene, engine and device profile.

### Live selected

Loads one selected device against a target URL for exploratory inspection. Live iframe rendering is not proof because browser embedding, permissions and network state can differ from the actual target device/browser.

### Capture mode

`capture.mjs` launches Chromium and WebKit at the exact CSS viewport for each selected device and records screenshots plus console/page errors.

## Initial project profile

`projects/notverse.json` records NoTVerse as the donor/first proving campaign. It is a project adapter, not product authority.

The initial NoTVerse scenes are:

- Notes / white Note
- Comments + keyboard
- Comments → Back / nav restored
- Companion chat + keyboard

Scenario automation will evolve separately from the generic device wall.

## Working cycle

```text
project candidate
      ↓
freeze exact build / URL
      ↓
capture exact device + engine evidence
      ↓
visual wall
      ↓
compare / inspect / flag missing cases
      ↓
product fix in owning repository
      ↓
repeat proof
      ↓
ship only proven product change
```

## Evolution rule

Every time the lab discovers a reusable requirement, record it in `LAB_STATUS.md` before expanding the machinery. Project-specific hacks should stay in project adapters rather than leaking into the generic device engine.

## Promotion rule

The eventual Ptah capability should be promoted only when the lab has proven itself across multiple projects and the reusable contract is stable enough to become a Ptah-owned Visual / Device Verification capability.
