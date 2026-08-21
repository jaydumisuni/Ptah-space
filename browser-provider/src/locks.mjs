export const LOCKED_RUNTIME = Object.freeze({
  node: "24.18.0",
  playwright: "1.60.0",
  playwrightCore: "1.60.0",
  chromiumVersion: "148.0.7778.96",
  chromiumRevision: "1223",
});
export const PROVIDER_PROTOCOL = Object.freeze({ name: "ptah.browser.provider", version: "0.1.0" });
export const MAX_DOWNLOAD_CHUNK_BYTES = 1024 * 1024;
export const SENSITIVE_HEADERS = Object.freeze(new Set(["authorization", "cookie", "set-cookie", "proxy-authorization"]));
