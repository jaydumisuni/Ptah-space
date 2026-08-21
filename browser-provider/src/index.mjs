/**
 * Ptah A11 mechanical Browser Provider control surface.
 * Concrete Playwright is loaded only by server.mjs so contract tests remain deterministic.
 */
export { ProviderCore, BrowserProviderError, isDefaultPersonalProfilePath, redactEvidence, redactUrl } from "./core.mjs";
export { LOCKED_RUNTIME, MAX_DOWNLOAD_CHUNK_BYTES, PROVIDER_PROTOCOL } from "./locks.mjs";
