# Ptah Browser Provider — A11

Mechanical Playwright/Chromium Provider for Ptah A11.

Authority boundary:
- canonical Browser identity/lifecycle/generation lives in `ptah-browser-runtime`;
- backend handles/PIDs/targets are aliases only;
- navigation acknowledgement is not verified Page readiness;
- persistent writable profiles require upstream canonical Lease/fence authority;
- ordinary personal Chrome/Edge profiles are refused;
- challenge states are surfaced and automation may be fenced, but no CAPTCHA/MFA/passkey/consent bypass exists;
- Browser download bytes are streamed into A08 Transfer and are never declared A07 Content/Object truth by this service;
- evidence payloads are returned for privacy-controlled A07 registration; protocol metadata, URLs, headers, and error details are privacy-redacted before emission, while raw evidence bytes remain subject to the governing A07 privacy/redaction policy.

Locked physical qualification target: Node.js 24.18.0; Playwright/playwright-core 1.60.0; Chromium 148.0.7778.96 revision 1223.

`src/index.mjs` intentionally avoids importing Playwright. `src/server.mjs` loads the concrete locked backend.

## Dedicated Ptah-owned browser (not Oracle shared browser)

The A11 provider launches its **own pinned Playwright Chromium executable** from
`browser-provider/.workspace/browser-runtime/chromium-1223/` by default.
Set `PTAH_BROWSER_RUNTIME_DIR` to an absolute path inside the **installed
Ptah application-managed runtime directory** for a packaged deployment.
The directory contains a separate Chromium runtime; it must not be a link
to a personal Chrome profile, the OS browser executable, or Oracle's shared
browser instance. The provider fails closed when the owned binary is missing.

On a Linux development workspace using existing free Playwright assets:

```bash
cd browser-provider
# Pinned Node.js 24.18.0 must be on the execution path.
mkdir -p .workspace/browser-runtime
# The source is Playwright's pinned revision 1223, NOT the user's Chrome browser.
cp -a ~/.cache/ms-playwright/chromium-1223 .workspace/browser-runtime/
node --test test/owned-chromium.test.mjs
PTAH_PLAYWRIGHT_PHYSICAL=1 node --test test/playwright-qualification.test.mjs test/owned-physical-isolation.test.mjs
```

For a fresh, free installation without an existing Playwright revision cache,
use the exact project's locked Playwright version:

```bash
cd browser-provider
PLAYWRIGHT_BROWSERS_PATH="$PWD/.workspace/browser-runtime" \
  node ./node_modules/playwright/cli.js install chromium
```

The browser engine is bundled/managed by Ptah, while the host's Linux kernel
and operating-system libraries necessarily still provide process execution.
This does **not** mean Ptah controls or borrows the user's desktop Chrome.
The browser provider rejects `channel: "chrome"`, `channel: "msedge"`,
arbitrary `executablePath`, and symlink escapes.

Independent agents use separately launched **ephemeral Browser Processes
and Contexts**. These require **no Oracle `humanControl` takeover** and do
not share cookies, localStorage or tabs. Persistent writable profiles remain
separately fenced by Ptah's canonical lease to prevent simultaneous writes
to the same profile; that is not a human's hold over agent-owned browsers.
Sensitive website challenges still require their legitimate completion.

The A11 server (`node src/server.mjs`) is the mechanical provider entry
point. A human/operator using Oracle's shared browser to inspect a website is
**not equivalent to exercising Ptah's own A11 browser**, and should not be
used as evidence for the latter. Workspace agent selection/invocation of A11
must be verified separately before claiming automatic Ptah routing.

## Ptah-native workspace operator (agent-accessible, read-only)

Use the pinned Node 24.18.0 binary and this Ptah-owned entry point, not
`Oracle.browser_navigate`, when checking browser rendering for Ptah:

```bash
/path/to/node-24.18.0 tools/ptah_workspace_browser.mjs read https://example.com/ --screenshot
```

Returns verified browser-rendered page state, accessible page text, source
truth (`RENDERED_PAGE_NOT_FACT_VERIFIED`) and an optional screenshot saved
under `.workspace/browser-evidence/`. Runs an independent **ephemeral** A11
Browser Process; no shared browser session and no Oracle `humanControl`
state are consulted. `--headed` is optional when a display is available.

This entry point exercises the A11 mechanical provider and is suitable for
operator/agent diagnostics, **not** a replacement for canonical Ptah
workspace-agent routing, long-lived browser sessions or authenticated
interactive workflows. Canonical A11 admission still governs production
workspace selection and command authority.


## Default Ptah workspace browser command

For an agent or operator executing a **browser intent within this Ptah workspace**,
use the Ptah-owned A11 route, never Oracle's shared browser:

```bash
/path/to/node-24.18.0 tools/ptah_workspace.mjs https://example.com/
/path/to/node-24.18.0 tools/ptah_workspace.mjs browser read https://example.com/
```

Both forms launch a **new ephemeral Ptah-managed Chromium session** and return
rendered page evidence. The route rejects arbitrary commands, credential-embedded
URLs, and headed desktop windows unless the caller explicitly sets
`PTAH_WORKSPACE_ALLOW_HEADED=1`. It has **no Oracle or OS Chrome fallback**.
The dedicated Playwright runtime and isolated profile boundaries are unchanged.

This is the default *command-level* browser route, not an assertion of universal
production AI-agent task dispatch. Production Node enrollment and canonical
provider selection still require separate control-plane admission. Neither the
operator CLI nor this wrapper grants persistent-profile leases or bypasses site
authentication/captcha restrictions.


## Zambia Parliament certificate-chain recovery

The public `https://www.parliament.gov.zm/` server (41.77.146.98, observed 2026-10-17) sends
a valid `*.parliament.gov.zm` RapidSSL leaf certificate **without its RapidSSL TLS RSA CA G1
intermediate**. OpenSSL/curl consequently report `unable to get local issuer certificate`.
The official `https://parliament.gov.zm/` server (41.77.145.34) serves the same valid
wildcard leaf **plus its intermediate** and the standard trusted DigiCert root, but the
apex website redirects to an AppSuite login. That login is NOT an equivalent public
Parliament website and is never substituted into search/browser results.

If and **only if** Ptah Chromium receives `ERR_CERT_AUTHORITY_INVALID` from the **exact**
public HTTPS host `www.parliament.gov.zm`, A11 opens a temporary separate page to
`https://parliament.gov.zm/` **inside the same isolated browser context**. Chromium
must itself validate that HTTPS page and load the expected official origin successfully;
only then does it retry the original, unchanged public HTTPS URL. The browser has
**no `ignoreHTTPSErrors`, `--ignore-certificate-errors` or certificate-verification bypass**.
If either HTTPS verification fails, navigation is rejected. No new root authority or
system trust setting is installed. Normal navigation never incurs the recovery request.

Security regression: `test/parliament-tls-chain-recovery.test.mjs` checks exact hostname
gating, same-path recovery, authenticated warmup, closure on failed warmup, and explicit
TLS-bypass rejection. Dedicated current-head CI runs these tests **in addition** to
the original 31 physical A11 tests; the A11 historical proof and maintenance governance
checks are unchanged.

The server-side missing intermediate remains the website operator's responsibility.
Ptah repairs this narrow **client rendering** failure; this does **not** make the
original web server's incomplete TLS chain valid for other software or claim
universal Internet certificate remediation.


## Live runtime compatibility versus frozen qualification

The A11 qualification proof remains exactly Node 24.18.0,
Playwright/playwright-core 1.60.0 and Chromium revision 1223 / 148.0.7778.96.
That historical baseline is never rewritten to imply a new qualification.

The package manifest still records Node 24.18.0 because A01 uses it as
the frozen historical dependency proof; it is not enforced by the browser
provider at operational launch time. Development installs with Node 22/24.19
can show an engine warning; this is separate from live runtime support.

A normal Ptah workspace launch instead calls assertRuntimeCompatible(), not
assertLockedRuntime(). Node >=22 can use the installed Playwright provider;
the observed Node version and exact-baseline-match are diagnostic evidence,
not workspace execution permission. Playwright and playwright-core must still
match, and the installed browser manifest must match Ptah's currently
qualified **owned** Chromium bundle. New browser bundles need their own
compatibility qualification. A missing browser executable or a genuinely
incompatible runtime fails at its relevant step and never falls back to
the host's personal Chrome, Oracle's browser, an unowned executable or a
TLS-insecure path.

This compatibility check is not an authorization decision, a substitute for
a source-owned Agent/Owner action, or proof of browser page readiness.
Browser Process ownership, lease/fence, user-profile isolation, credential
redaction, TLS checks and explicit launch confirmation are unchanged.

KRATOS development checks: Node 22.23.2 and 24.19.0 both passed
Playwright 1.60.0 / Chromium 148 local-data page boot and the new
assertRuntimeCompatible() check. These checks do not certify every possible
Node version; newer combinations are admitted by observed compatibility,
not historical proof inheritance.
