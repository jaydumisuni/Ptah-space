# A11: qualification evidence is not workspace execution permission

Date: 19 October 2026. Status: tested candidate, not deployed.

## Root cause

A11's Playwright Backend called assertLockedRuntime() for each normal browser
launch. That method was developed for the original A11 one-head, one-toolchain
qualification baseline and required Node exactly 24.18.0. It rejected newer
Node 24.19.0 and available 22.23.2 before attempting the owned browser.
This was an architectural placement error: a frozen tested version is a
historical fact, not a reason to deny workspace tasks on compatible hosts.

## Change

- A11's exact assertLockedRuntime remains unchanged for replaying the
  original frozen qualification.
- Normal Browser Provider launch now calls assertRuntimeCompatible:
  Node >=22, a version-aligned installed Playwright/playwright-core pair,
  and an installed Chromium manifest matching the approved Ptah-owned
  Chromium bundle. Actual browser process launch remains the final
  capability test.
- The provider reports observed Node version and whether the original
  24.18.0 baseline was an exact match. It never claims new owner authority.
- The A01 frozen manifest/package-lock still records Node 24.18.0. Its
  compatibility mismatch may produce a package-manager warning; the
  provider does not turn that historical pin into an execution veto.
- Ordinary profile isolation, Ptah-owned executable realpath protections,
  TLS validation, anti-secret controls, E01/E02 external admission,
  lease/fence and human challenge requirements remain unchanged.
- Oracle remains the authorized transport to KRATOS and ATHENA;
  Ptah remains a shared execution workspace, never the transport.

## Physical KRATOS verification

Node 22.23.2 and Node 24.19.0:
- installed Playwright 1.60.0 / Chromium 148.0.7778.96 launched and
  rendered a local test page;
- after this change, exact Ptah workspace default read route started
  Ptah-owned Chromium and confirmed page readiness with five passing tests;
- two-agent physical isolation test passed with independent Chromium
  processes and no cross-agent state leakage;
- new runtime compatibility check passed and reported a distinct
  nonmatching historical Node qualification baseline;
- nonphysical package tests and syntax checks passed under Node 22.
- A01 frozen scaffold and Phase 0C historical checks passed after keeping
  the old manifest pin unchanged.

This is not a new physical A11 frozen-version re-admission and does not
promote all future Node, Playwright or browser builds without testing.
A genuinely missing or incompatible OWNED browser fails with its real
provider error; the workspace and other tools are not globally disabled.
No production service, personal profile, untrusted external browser or
system-wide package path was changed.
