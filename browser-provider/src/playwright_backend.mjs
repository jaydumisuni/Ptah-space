import { createRequire } from "node:module";
import { open, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { chromium } from "playwright";
import { BrowserProviderError, invariant } from "./errors.mjs";
import { LOCKED_RUNTIME, SENSITIVE_HEADERS } from "./locks.mjs";

const require = createRequire(import.meta.url);

export class PlaywrightBackend {
  #events = [];
  #downloads = new Map();
  #sequence = 0;

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
    return { implementation: "playwright", version: LOCKED_RUNTIME.playwright, browser: "chromium", chromiumVersion: LOCKED_RUNTIME.chromiumVersion, chromiumRevision: LOCKED_RUNTIME.chromiumRevision };
  }

  async launchProcess({ profileMode, userDataDir, readonly, launchOptions }) {
    await this.assertLockedRuntime();
    invariant(profileMode !== "managed_remote" && profileMode !== "other_registered", "profile_mode_not_supported", `local Playwright backend cannot implement ${profileMode}`);
    if (profileMode === "persistent_shared_readonly") {
      invariant(readonly === true, "readonly_profile_required", "shared persistent profile must be read-only");
      throw new BrowserProviderError("readonly_profile_backend_unavailable", "Playwright persistent contexts write profile state; a read-only snapshot backend is required");
    }
    if (profileMode === "persistent_exclusive") {
      const context = await chromium.launchPersistentContext(userDataDir, launchOptions);
      this.#wireContext(context);
      return { kind: "persistent", context, browser: context.browser(), claimedContext: false, aliases: [{ kind: "playwright_browser", value: context.browser()?.browserType().name() ?? "chromium" }] };
    }
    const browser = await chromium.launch(launchOptions);
    return { kind: "ephemeral", browser, aliases: [{ kind: "playwright_browser", value: browser.browserType().name() }] };
  }

  async createContext(processHandle, { contextOptions }) {
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
    const response = await pageHandle.page.goto(url, { waitUntil: "commit", timeout: timeoutMs });
    pageHandle.lastResponse = response;
    return { state: "committed", committedUrl: pageHandle.page.url(), status: response?.status(), evidence: { url: pageHandle.page.url(), responseHeaders: response ? await response.allHeaders() : {} } };
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
