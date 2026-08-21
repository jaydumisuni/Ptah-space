# ptah-browser-runtime

A11 canonical Browser projections and authority fencing for Ptah. The crate records Browser Profile, Process, Context, Page, Navigation, Challenge, Download and evidence state over the A03 ledger while keeping browser-engine handles as backend aliases. It does not implement browser automation itself; mechanical Playwright/Chromium execution remains in `browser-provider/`.
