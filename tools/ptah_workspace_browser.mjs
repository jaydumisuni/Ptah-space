#!/usr/bin/env node
/**
 * Agent/operator read-only browser entry. Always launches Ptah-owned A11
 * Chromium via ProviderCore; never uses Oracle browser state or personal Chrome.
 * This is an ephemeral diagnostic tool, not persistent A11 control-plane admission.
 */
import { writeFile, mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ProviderCore } from "../browser-provider/src/core.mjs";
import { PlaywrightBackend } from "../browser-provider/src/playwright_backend.mjs";

const workspaceRoot = resolve(fileURLToPath(new URL("../", import.meta.url)));
const evidenceRoot = join(workspaceRoot, ".workspace", "browser-evidence");

async function main(argv) {
  const [action, rawUrl, ...extra] = argv;
  if (action !== "read" || !rawUrl || extra.some(x => x !== "--screenshot" && x !== "--headed")) {
    throw new Error("usage: ptah_workspace_browser.mjs read https://example.com/ [--screenshot] [--headed]");
  }
  const url = new URL(rawUrl);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) {
    throw new Error("only public website-style HTTP(S) URLs without embedded credentials are accepted");
  }
  const backend = new PlaywrightBackend();
  const core = new ProviderCore({ backend, providerGeneration: 1 });
  const launched = await core.launchProcess({
    expectedProviderGeneration: 1, processGeneration: 1, profileMode: "ephemeral",
    launchOptions: { headless: !extra.includes("--headed") },
  });
  try {
    const context = await core.createContext({
      expectedProviderGeneration: 1, processHandle: launched.processHandle,
      processGeneration: 1, contextGeneration: 1, storageMode: "ephemeral",
      contextOptions: { viewport: { width: 1280, height: 800 }, acceptDownloads: false }
    });
    const page = await core.createPage({
      expectedProviderGeneration: 1, contextHandle: context.contextHandle,
      processGeneration: 1, contextGeneration: 1, pageGeneration: 1
    });
    const navigation = await core.navigate({
      expectedProviderGeneration: 1, pageHandle: page.pageHandle,
      processGeneration: 1, contextGeneration: 1, pageGeneration: 1,
      navigationSequence: 1, url: url.toString(), timeoutMs: 20_000
    });
    const verified = await core.verifyPageState({
      expectedProviderGeneration: 1, pageHandle: page.pageHandle,
      processGeneration: 1, contextGeneration: 1, pageGeneration: 1,
      waitUntil: "domcontentloaded", timeoutMs: 20_000
    });
    const content = await core.captureEvidence({
      expectedProviderGeneration: 1, pageHandle: page.pageHandle,
      processGeneration: 1, contextGeneration: 1, pageGeneration: 1,
      evidenceClass: "accessibility_snapshot"
    });
    let screenshotFile = null;
    if (extra.includes("--screenshot")) {
      const screenshot = await core.captureEvidence({
        expectedProviderGeneration: 1, pageHandle: page.pageHandle,
        processGeneration: 1, contextGeneration: 1, pageGeneration: 1,
        evidenceClass: "screenshot"
      });
      await mkdir(evidenceRoot, { recursive: true, mode: 0o700 });
      screenshotFile = join(evidenceRoot, `ptah-${Date.now()}-${process.pid}.png`);
      await writeFile(screenshotFile, screenshot.bytes, { mode: 0o600, flag: "wx" });
    }
    return {
      tool: "ptah_owned_workspace_browser",
      browserSource: core.describe().backend.browserSource,
      sharesPersonalBrowser: false, oracleBrowserControlUsed: false,
      ephemeralAgentSession: true, navigationAcknowledged: navigation.acknowledged,
      pageStateVerified: verified.verified, state: verified.state,
      committedUrl: navigation.committedUrl, title: verified.title,
      httpStatus: navigation.status ?? null,
      contentTruth: "RENDERED_PAGE_NOT_FACT_VERIFIED",
      pageText: content.bytes.toString("utf8").slice(0, 12000),
      screenshotFile
    };
  } finally {
    await core.closeProcess({
      expectedProviderGeneration: 1, processHandle: launched.processHandle,
      processGeneration: 1
    });
  }
}
main(process.argv.slice(2)).then((result) => {
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
}).catch(error => {
  process.stderr.write(JSON.stringify({
    status: "BROWSER_UNAVAILABLE", errorCode: error.code || "invalid_or_failed_request",
    message: error.message
  }) + "\n");
  process.exitCode = 2;
});
