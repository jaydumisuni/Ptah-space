import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { PlaywrightBackend } from "../src/playwright_backend.mjs";
import { ProviderCore } from "../src/core.mjs";

test("two agents have independently controllable Ptah Chromium processes, not Oracle sessions", {
  skip: process.env.PTAH_PLAYWRIGHT_PHYSICAL !== "1",
}, async () => {
  const server = createServer((request, response) => {
    response.setHeader("content-type", "text/html");
    if (request.url === "/set") {
      response.setHeader("set-cookie", "ptah_agent_private=a-only; SameSite=Lax");
      response.end("<html><title>Agent A</title><body>set<script>localStorage.setItem('agent-private','A');</script></body></html>");
    } else {
      response.end("<html><title>Private Session Check</title><body><div id='proof'></div><script>document.getElementById('proof').textContent='cookie='+document.cookie+';storage='+localStorage.getItem('agent-private');</script></body></html>");
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const root = `http://127.0.0.1:${address.port}`;
  const backend = new PlaywrightBackend();
  const core = new ProviderCore({ backend, providerGeneration: 71 });
  const processes = [];
  const navig = async (page, gen, path) => {
    await core.navigate({ expectedProviderGeneration: 71, pageHandle: page.pageHandle,
      processGeneration: gen, contextGeneration: gen, pageGeneration: gen,
      navigationSequence: 1, url: root+path, timeoutMs: 10_000 });
    const state = await core.verifyPageState({ expectedProviderGeneration: 71, pageHandle: page.pageHandle,
      processGeneration: gen, contextGeneration: gen, pageGeneration: gen,
      waitUntil: "load", timeoutMs: 10_000 });
    assert.equal(state.verified, true);
  };
  const create = async (gen) => {
    // No human-control token or lease needed: this is an independent ephemeral agent browser.
    const proc = await core.launchProcess({
      expectedProviderGeneration: 71, processGeneration: gen, profileMode: "ephemeral",
      launchOptions: { headless: true }
    });
    processes.push({ handle: proc.processHandle, gen });
    const context = await core.createContext({ expectedProviderGeneration: 71, processHandle: proc.processHandle,
      processGeneration: gen, contextGeneration: gen, storageMode: "ephemeral" });
    const page = await core.createPage({ expectedProviderGeneration: 71,
      contextHandle: context.contextHandle, processGeneration: gen,
      contextGeneration: gen, pageGeneration: gen });
    return { proc, context, page };
  };
  try {
    const a = await create(1);
    const b = await create(2);
    assert.notEqual(a.proc.processHandle, b.proc.processHandle);
    await navig(a.page, 1, "/set");
    await navig(b.page, 2, "/inspect");
    const visibleB = await core.captureEvidence({ expectedProviderGeneration: 71,
      pageHandle: b.page.pageHandle, processGeneration: 2, contextGeneration: 2,
      pageGeneration: 2, evidenceClass: "dom_snapshot" });
    const textB = visibleB.bytes.toString("utf-8");
    assert.match(textB, /storage=null/);
    assert.doesNotMatch(textB, /a-only/);
    await core.verifyContext({ expectedProviderGeneration: 71,
      contextHandle: b.context.contextHandle, processGeneration: 2, contextGeneration: 2 });
    const descriptor = core.describe();
    assert.equal(descriptor.backend.browserSource, "ptah_owned_chromium");
    assert.equal(descriptor.backend.sharesPersonalBrowser, false);
    assert.equal(descriptor.backend.dependsOnOracleBrowserControl, false);
  } finally {
    for (const item of processes.reverse()) await core.closeProcess({
      expectedProviderGeneration: 71, processHandle: item.handle,
      processGeneration: item.gen
    });
    await new Promise((resolve) => server.close(resolve));
  }
});
