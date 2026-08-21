import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProviderCore } from "../src/core.mjs";
import { LOCKED_RUNTIME } from "../src/locks.mjs";

const physical = process.env.PTAH_PLAYWRIGHT_PHYSICAL === "1";
const secret = "a11-private-token-should-redact";
const downloadBytes = Buffer.from("ptah-a11-download-bounded-read");

function html(body, script = "") {
  return `<!doctype html><html><head><title>Ptah A11</title></head><body>${body}<script>${script}</script></body></html>`;
}

async function localServer() {
  const server = createServer((request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    if (url.pathname === "/set") {
      response.setHeader("content-type", "text/html");
      response.setHeader("set-cookie", "ptah-secret-cookie=private; HttpOnly");
      response.end(html("<div id=state>set</div>", `localStorage.setItem('ptah-a11-persist','yes'); console.log('ptah-a11-console');`));
      return;
    }
    if (url.pathname === "/check") {
      response.setHeader("content-type", "text/html");
      response.end(html("<div id=state></div>", `document.querySelector('#state').textContent='persist='+localStorage.getItem('ptah-a11-persist');`));
      return;
    }
    if (url.pathname === "/upload") {
      response.setHeader("content-type", "text/html");
      response.end(html("<input id=u type=file><span id=fn>none</span>", `u.addEventListener('change',()=>fn.textContent=u.files[0]?.name ?? 'none');`));
      return;
    }
    if (url.pathname === "/download-page") {
      response.setHeader("content-type", "text/html");
      response.end(html(`<a id=d download=proof.bin href="/download?token=${secret}">download</a>`, `setTimeout(()=>d.click(),50);`));
      return;
    }
    if (url.pathname === "/download") {
      response.setHeader("content-type", "application/octet-stream");
      response.setHeader("content-disposition", "attachment; filename=proof.bin");
      response.end(downloadBytes);
      return;
    }
    response.statusCode = 404;
    response.end("not found");
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return { server, base: `http://127.0.0.1:${address.port}` };
}

function launchArgs(processGeneration, profileDir) {
  return {
    expectedProviderGeneration: 11,
    processGeneration,
    profileMode: "persistent_exclusive",
    userDataDir: profileDir,
    writableAuthorization: { leaseRef: "lease-a11", fenceRef: "fence-a11" },
    launchOptions: { headless: true },
  };
}

async function pageFor(core, process, generation) {
  const context = await core.createContext({
    expectedProviderGeneration: 11,
    processHandle: process.processHandle,
    processGeneration: generation,
    contextGeneration: generation,
    storageMode: "persistent_exclusive",
    networkPolicy: { mode: "local_test_only" },
    permissionPolicy: { default: "deny" },
  });
  const page = await core.createPage({
    expectedProviderGeneration: 11,
    contextHandle: context.contextHandle,
    processGeneration: generation,
    contextGeneration: generation,
    pageGeneration: generation,
  });
  return { context, page };
}

async function navigate(core, page, generation, sequence, url) {
  const ack = await core.navigate({
    expectedProviderGeneration: 11,
    pageHandle: page.pageHandle,
    processGeneration: generation,
    contextGeneration: generation,
    pageGeneration: generation,
    navigationSequence: sequence,
    url,
    timeoutMs: 15_000,
  });
  assert.equal(ack.acknowledged, true);
  assert.equal(ack.completionVerified, false);
  const verified = await core.verifyPageState({
    expectedProviderGeneration: 11,
    pageHandle: page.pageHandle,
    processGeneration: generation,
    contextGeneration: generation,
    pageGeneration: generation,
    waitUntil: "load",
    timeoutMs: 15_000,
  });
  assert.equal(verified.verified, true);
  return { ack, verified };
}

test("A11 locked Playwright/Chromium physical qualification", { skip: !physical }, async () => {
  assert.equal(process.versions.node, LOCKED_RUNTIME.node);
  const profileDir = await mkdtemp(join(tmpdir(), "ptah-a11-profile-"));
  const uploadDir = await mkdtemp(join(tmpdir(), "ptah-a11-upload-"));
  const uploadPath = join(uploadDir, "a11-upload.txt");
  await writeFile(uploadPath, "a11-upload-proof");
  const { server, base } = await localServer();
  const { PlaywrightBackend } = await import("../src/playwright_backend.mjs");
  const backend = new PlaywrightBackend();
  const core = new ProviderCore({ backend, providerGeneration: 11, maxDownloadChunkBytes: 8 });
  try {
    assert.equal(await backend.assertLockedRuntime(), true);
    assert.equal(core.describe().lockedRuntime.chromiumRevision, "1223");

    const first = await core.launchProcess(launchArgs(1, profileDir));
    const firstPage = await pageFor(core, first, 1);
    const firstNav = await navigate(core, firstPage.page, 1, 1, `${base}/set?token=${secret}`);
    assert.equal(firstNav.ack.evidence.url.includes(secret), false);
    assert.equal(JSON.stringify(firstNav.ack.evidence).includes("ptah-secret-cookie"), false);
    const screenshot = await core.captureEvidence({
      expectedProviderGeneration: 11,
      pageHandle: firstPage.page.pageHandle,
      processGeneration: 1,
      contextGeneration: 1,
      pageGeneration: 1,
      evidenceClass: "screenshot",
    });
    assert.equal(screenshot.evidenceClass, "screenshot");
    assert.ok(Buffer.isBuffer(screenshot.bytes) && screenshot.bytes.length > 100);
    assert.equal(screenshot.canonicalObjectRef, null);

    const detached = await core.detachProcess({ expectedProviderGeneration: 11, processHandle: first.processHandle, processGeneration: 1 });
    assert.equal(detached.backendProcessClosed, false);
    const reconnected = await core.reconnectProcess({ expectedProviderGeneration: 11, processHandle: first.processHandle, processGeneration: 1 });
    assert.equal(reconnected.processHandle, first.processHandle);
    assert.equal(reconnected.completionVerified, true);
    await core.closeProcess({ expectedProviderGeneration: 11, processHandle: first.processHandle, processGeneration: 1 });

    const second = await core.launchProcess(launchArgs(2, profileDir));
    const secondPage = await pageFor(core, second, 2);
    await navigate(core, secondPage.page, 2, 1, `${base}/check`);
    const persistedDom = await core.captureEvidence({
      expectedProviderGeneration: 11,
      pageHandle: secondPage.page.pageHandle,
      processGeneration: 2,
      contextGeneration: 2,
      pageGeneration: 2,
      evidenceClass: "dom_snapshot",
    });
    assert.match(persistedDom.bytes.toString("utf8"), /persist=yes/);

    await navigate(core, secondPage.page, 2, 2, `${base}/upload`);
    const upload = await core.uploadFiles({
      expectedProviderGeneration: 11,
      pageHandle: secondPage.page.pageHandle,
      processGeneration: 2,
      contextGeneration: 2,
      pageGeneration: 2,
      selector: "#u",
      materializedPathAliases: [uploadPath],
    });
    assert.equal(upload.acknowledged, true);
    assert.equal(upload.completionVerified, false);
    assert.deepEqual(upload.canonicalObjectRefs, []);
    const uploadDom = await core.captureEvidence({
      expectedProviderGeneration: 11,
      pageHandle: secondPage.page.pageHandle,
      processGeneration: 2,
      contextGeneration: 2,
      pageGeneration: 2,
      evidenceClass: "dom_snapshot",
    });
    assert.match(uploadDom.bytes.toString("utf8"), /a11-upload\.txt/);

    await navigate(core, secondPage.page, 2, 3, `${base}/download-page`);
    await new Promise((resolve) => setTimeout(resolve, 300));
    const events = await core.pollEvents({ expectedProviderGeneration: 11, limit: 100 });
    const download = events.find((event) => event.event === "download");
    assert.ok(download, "download event must be observed");
    assert.equal(JSON.stringify(download).includes(secret), false);
    const chunks = [];
    let offset = 0;
    for (;;) {
      const chunk = await core.readDownloadChunk({
        expectedProviderGeneration: 11,
        downloadHandle: download.downloadHandle,
        offset,
        maxBytes: 8,
      });
      assert.ok(chunk.bytes.length <= 8);
      assert.equal(chunk.canonicalContentRef, null);
      assert.equal(chunk.canonicalObjectRef, null);
      chunks.push(chunk.bytes);
      offset += chunk.bytes.length;
      if (chunk.eof) break;
    }
    assert.deepEqual(Buffer.concat(chunks), downloadBytes);

    await core.closeProcess({ expectedProviderGeneration: 11, processHandle: second.processHandle, processGeneration: 2 });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(profileDir, { recursive: true, force: true });
    await rm(uploadDir, { recursive: true, force: true });
  }
});
