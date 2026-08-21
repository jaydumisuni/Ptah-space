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
