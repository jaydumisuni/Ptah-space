import { createRequire } from "node:module";
import { open, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { chromium } from "playwright";
import { BrowserProviderError, invariant } from "./errors.mjs";
import { LOCKED_RUNTIME, SENSITIVE_HEADERS } from "./locks.mjs";
import { supportedNodeRuntime } from "./runtime_compat.mjs";
import { BROWSER_SOURCE, lockedOwnedLaunchOptions } from "./owned_chromium.mjs";

const require = createRequire(import.meta.url);

/**
 * The public National Assembly host omits its RapidSSL intermediate certificate,
 * while the official apex host serves a complete, normally trusted chain.
 * Never apply this recovery to any other site or any non-certificate failure.
 */
export function needsParliamentChainRecovery(url, error) {
  if (!String(error?.message ?? "").includes("net::ERR_CERT_AUTHORITY_INVALID")) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" && parsed.hostname === "www.parliament.gov.zm" &&
      parsed.username === "" && parsed.password === "" && parsed.port === "";
  } catch {
    return false;
  }
}

export class PlaywrightBackend {
  #events = [];
  #downloads = new Map();
  #sequence = 0;

  // Exact frozen A11 Node version remains a qualification test baseline,
  // NOT a machine-wide requirement for ordinary Browser Provider operation.
  // Playwright 1.60 depends on Node >=18; this provider supports >=22.
  async assertRuntimeCompatible() {
    const observed = process.versions.node;
    invariant(supportedNodeRuntime(observed),
      "node_runtime_unsupported",
      "Ptah Browser Provider needs Node >=22, not a frozen patch version");
    const playwrightPackage = require("playwright/package.json");
    const corePackage = require("playwright-core/package.json");
    invariant(playwrightPackage.version === corePackage.version,
      "playwright_dependency_mismatch", "Playwright and playwright-core must be version-aligned");
    // The library's version is runtime evidence, not a frozen proof gate.
    // The underlying owned browser image still has to match the Playwright
    // manifest; otherwise it is a real executable/dependency mismatch.
    const corePackagePath = require.resolve("playwright-core/package.json");
    const manifest = JSON.parse(await readFile(join(dirname(corePackagePath), "browsers.json"), "utf8"));
    const entry = manifest.browsers.find((item) => item.name === "chromium");
    invariant(entry && String(entry.revision) === LOCKED_RUNTIME.chromiumRevision
      && entry.browserVersion === LOCKED_RUNTIME.chromiumVersion,
      "owned_chromium_bundle_unqualified", "Playwright Chromium does not match the qualified Ptah-owned bundle");
    return Object.freeze({
      nodeObserved: observed,
      nodeQualificationBaseline: LOCKED_RUNTIME.node,
      exactNodeQualificationMatch: observed === LOCKED_RUNTIME.node,
      playwright: playwrightPackage.version,
      chromium: entry.browserVersion,
      chromiumRevision: String(entry.revision),
      authorityGranted: false,
    });
  }

  async assertLockedRuntime() {
    invariant(process.versions.node === LOCKED_RUNTIME.node, "node_lock_mismatch", `Node ${LOCKED_RUNTIME.node} required, observed ${process.versions.node}`);
    const playwrightPackage = require("playwright/package.json");
    const corePackage = require("playwright-core/package.json");
    invariant(playwrightPackage.version === LOCKED_RUNTIME.playwright, "playwright_lock_mismatch", "Playwright version mismatch");
    invariant(corePackage.version === LOCKED_RUNTIME.playwrightCore, "playwright_core_lock_mismatch", "playwright-core version mismatch");
    const corePackagePath = require.resolve("playwright-core/package.json");
    const browsers = JSON.parse(await readFile(join(dirname(corePackagePath), "browsers.json"), "utf8"));
    const chromiumEntry = browsers.browsers.find((entry) => entry.name === "chromium");
    invariant(chromiumEntry, "chromium_lock_missing", "Playwright Chromium lock is absent");
    invariant(String(chromiumEntry.revision) === LOCKED_RUNTIME.chromiumRevision, "chromium_revision_mismatch", "Chromium revision mismatch");
    invariant(chromiumEntry.browserVersion === LOCKED_RUNTIME.chromiumVersion, "chromium_version_mismatch", "Chromium version mismatch");
    return true;
  }

  describe() {
    return { implementation: "playwright", version: require("playwright/package.json").version, playwrightQualificationBaseline: LOCKED_RUNTIME.playwright, browser: "chromium", chromiumVersion: LOCKED_RUNTIME.chromiumVersion, chromiumRevision: LOCKED_RUNTIME.chromiumRevision, browserSource: BROWSER_SOURCE, sharesPersonalBrowser: false, dependsOnOracleBrowserControl: false, nodeObserved: process.versions.node, nodeQualificationBaseline: LOCKED_RUNTIME.node, exactNodeQualificationMatch: process.versions.node === LOCKED_RUNTIME.node };
  }

  async launchProcess({ profileMode, userDataDir, readonly, launchOptions }) {
    await this.assertRuntimeCompatible();
    const ownedOptions = await lockedOwnedLaunchOptions(launchOptions);
    // launchPersistentContext accepts context-level TLS flags directly.
    // Reject those before any profile is opened, not only in createContext.
    invariant(ownedOptions.ignoreHTTPSErrors !== true,
      "tls_verification_bypass_forbidden", "Ptah-owned Chromium must verify HTTPS certificates");
    invariant(!ownedOptions.args?.some(arg => typeof arg === "string" &&
      /^(--ignore-certificate-errors(?:[-=].*)?|--allow-insecure-localhost(?:=.*)?|--disable-web-security(?:=.*)?)$/i.test(arg)),
      "tls_verification_bypass_forbidden", "Ptah-owned Chromium must verify HTTPS certificates");
    invariant(profileMode !== "managed_remote" && profileMode !== "other_registered", "profile_mode_not_supported", `local Playwright backend cannot implement ${profileMode}`);
    if (profileMode === "persistent_shared_readonly") {
      invariant(readonly === true, "readonly_profile_required", "shared persistent profile must be read-only");
      throw new BrowserProviderError("readonly_profile_backend_unavailable", "Playwright persistent contexts write profile state; a read-only snapshot backend is required");
    }
    if (profileMode === "persistent_exclusive") {
      const context = await chromium.launchPersistentContext(userDataDir, ownedOptions);
      this.#wireContext(context);
      return { kind: "persistent", context, browser: context.browser(), claimedContext: false, aliases: [{ kind: "playwright_browser", value: context.browser()?.browserType().name() ?? "chromium" }] };
    }
    const browser = await chromium.launch(ownedOptions);
    return { kind: "ephemeral", browser, aliases: [{ kind: "playwright_browser", value: browser.browserType().name() }] };
  }

  async createContext(processHandle, { contextOptions }) {
    invariant(contextOptions?.ignoreHTTPSErrors !== true,
      "tls_verification_bypass_forbidden", "Ptah-owned Chromium must verify HTTPS certificates");
    let context;
    if (processHandle.kind === "persistent") {
      invariant(!processHandle.claimedContext, "persistent_context_already_claimed", "persistent Browser Process exposes one persistent context");
      processHandle.claimedContext = true;
      context = processHandle.context;
    } else {
      context = await processHandle.browser.newContext(contextOptions);
      this.#wireContext(context);
    }
    return { context, aliases: [] };
  }

  async verifyContext(contextHandle) {
    const pages = contextHandle.context.pages();
    const browser = contextHandle.context.browser();
    return { verified: browser ? browser.isConnected() : true, evidence: { pageCount: pages.length } };
  }
  async verifyProcess(processHandle) {
    const browser = processHandle.kind === "persistent" ? processHandle.context.browser() : processHandle.browser;
    return { verified: browser ? browser.isConnected() : processHandle.kind === "persistent", evidence: { kind: processHandle.kind } };
  }
  async createPage(contextHandle) {
    const page = await contextHandle.context.newPage();
    const holder = this.#wirePage(page);
    return { ...holder, aliases: [] };
  }
  async navigate(pageHandle, { url, timeoutMs }) {
    let response;
    let validChainRecovered = false;
    try {
      response = await pageHandle.page.goto(url, { waitUntil: "commit", timeout: timeoutMs });
    } catch (error) {
      if (!needsParliamentChainRecovery(url, error)) throw error;
      // Fetch ONLY the certificate-chain-complete official HTTPS sibling host
      // inside this isolated Chromium process. Chromium validates this TLS
      // connection itself and may cache the intermediate for the original host.
      // The AppSuite login page is NOT substituted for the public website.
      const warmup = await pageHandle.page.context().newPage();
      try {
        const trusted = await warmup.goto("https://parliament.gov.zm/", {
          waitUntil: "domcontentloaded", timeout: Math.min(timeoutMs ?? 20_000, 20_000),
        });
        invariant(trusted?.status() === 200 &&
          new URL(warmup.url()).origin === "https://parliament.gov.zm",
          "parliament_chain_source_invalid",
          "Official issuer-chain source could not be authenticated by Chromium");
      } finally {
        await warmup.close();
      }
      // Retry ORIGINAL public site, ORIGINAL path, same TLS verification.
      // Failure remains a failure; no ignoreHTTPSErrors/CA trust escalation.
      response = await pageHandle.page.goto(url, { waitUntil: "commit", timeout: timeoutMs });
      validChainRecovered = true;
    }
    pageHandle.lastResponse = response;
    return { state: "committed", committedUrl: pageHandle.page.url(), status: response?.status(), evidence: {
      url: pageHandle.page.url(), responseHeaders: response ? await response.allHeaders() : {},
      parliamentIssuerChainRecovered: validChainRecovered,
    } };
  }
  async verifyPageState(pageHandle, { waitUntil, timeoutMs }) {
    try {
      await pageHandle.page.waitForLoadState(waitUntil, { timeout: timeoutMs });
      return { verified: true, state: waitUntil === "domcontentloaded" ? "dom_content_loaded" : "load_complete", url: pageHandle.page.url(), title: await pageHandle.page.title(), evidence: { waitUntil } };
    } catch (error) {
      return { verified: false, state: "unknown", url: pageHandle.page.url(), evidence: { waitUntil, error: error.message } };
    }
  }
  async captureEvidence(pageHandle, evidenceClass) {
    const capturedAt = new Date().toISOString();
    switch (evidenceClass) {
      case "dom_snapshot": return { capturedAt, mediaType: "text/html; charset=utf-8", bytes: Buffer.from(await pageHandle.page.content()) };
      case "accessibility_snapshot": return { capturedAt, mediaType: "text/plain; charset=utf-8", bytes: Buffer.from(await pageHandle.page.locator("body").ariaSnapshot()) };
      case "screenshot": return { capturedAt, mediaType: "image/png", bytes: await pageHandle.page.screenshot({ type: "png" }) };
      case "visible_state": return { capturedAt, mediaType: "application/json", bytes: Buffer.from(JSON.stringify({ url: pageHandle.page.url(), title: await pageHandle.page.title() })) };
      case "source_response": {
        invariant(pageHandle.lastResponse, "source_response_unavailable", "no current source response is retained");
        return { capturedAt, mediaType: (await pageHandle.lastResponse.headerValue("content-type")) ?? "application/octet-stream", bytes: await pageHandle.lastResponse.body(), metadata: { status: pageHandle.lastResponse.status(), headers: safeHeaders(await pageHandle.lastResponse.allHeaders()) } };
      }
      case "console_log": return { capturedAt, mediaType: "application/json", bytes: Buffer.from(JSON.stringify(pageHandle.consoleEvents ?? [])) };
      case "network_log": return { capturedAt, mediaType: "application/json", bytes: Buffer.from(JSON.stringify(pageHandle.networkEvents ?? [])) };
      default: throw new BrowserProviderError("evidence_capture_not_implemented", `Playwright evidence class requires an explicit capture lane: ${evidenceClass}`);
    }
  }
  async uploadFiles(pageHandle, { selector, paths }) { await pageHandle.page.locator(selector).setInputFiles(paths); return { acknowledged: true }; }
  async readDownloadChunk(downloadHandle, { offset, maxBytes }) {
    const download = this.#downloads.get(downloadHandle);
    invariant(download, "stale_download", "unknown Playwright download handle");
    const path = await download.download.path();
    invariant(path, "download_path_unavailable", "Playwright download path is unavailable on this backend");
    const file = await open(path, "r");
    try {
      const stat = await file.stat();
      const buffer = Buffer.allocUnsafe(Math.min(maxBytes, Math.max(0, stat.size - offset)));
      if (buffer.length === 0) return { bytes: Buffer.alloc(0), eof: offset >= stat.size };
      const { bytesRead } = await file.read(buffer, 0, buffer.length, offset);
      return { bytes: buffer.subarray(0, bytesRead), eof: offset + bytesRead >= stat.size };
    } finally { await file.close(); }
  }
  async pollEvents({ limit }) { return this.#events.splice(0, Math.max(0, Math.min(Number(limit) || 0, 1000))); }
  async detachProcess() {}
  async closeProcess(processHandle) { if (processHandle.kind === "persistent") await processHandle.context.close(); else await processHandle.browser.close(); }

  #wireContext(context) { for (const page of context.pages()) this.#wirePage(page); context.on("page", (page) => this.#wirePage(page)); }
  #wirePage(page) {
    const holder = { page, consoleEvents: [], networkEvents: [], lastResponse: null };
    page.on("console", (message) => holder.consoleEvents.push({ type: message.type(), text: message.text() }));
    page.on("request", (request) => holder.networkEvents.push({ type: "request", method: request.method(), url: request.url(), headers: safeHeaders(request.headers()) }));
    page.on("response", async (response) => { holder.lastResponse = response; holder.networkEvents.push({ type: "response", status: response.status(), url: response.url(), headers: safeHeaders(await response.allHeaders()) }); });
    page.on("download", (download) => {
      this.#sequence += 1;
      const handle = `download-${this.#sequence.toString(36).padStart(6, "0")}`;
      this.#downloads.set(handle, { download });
      this.#events.push({ event: "download", downloadHandle: handle, suggestedFilename: download.suggestedFilename(), sourceUrl: download.url() });
    });
    return holder;
  }
}
function safeHeaders(headers = {}) { return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key, SENSITIVE_HEADERS.has(key.toLowerCase()) ? "[REDACTED]" : value])); }
