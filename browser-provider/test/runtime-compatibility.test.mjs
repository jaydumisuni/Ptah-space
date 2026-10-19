import test from "node:test";
import assert from "node:assert/strict";
import { PlaywrightBackend } from "../src/playwright_backend.mjs";
import { LOCKED_RUNTIME } from "../src/locks.mjs";
import { supportedNodeRuntime } from "../src/runtime_compat.mjs";

test("Node runtime checks compatibility rather than one qualification patch", () => {
  for (const version of ["22.0.0", "22.23.2", "24.18.0", "24.19.0", "26.0.0"]) {
    assert.equal(supportedNodeRuntime(version), true, version);
  }
  for (const version of ["", "v24.19.0", "21.99.99", "18.20.0", "24", "24.19", "24.19.0-beta", "-24.19.0", "x.y.z", null]) {
    assert.equal(supportedNodeRuntime(version), false, String(version));
  }
});

test("ordinary Browser Provider compatibility is independent of exact A11 node proof", async () => {
  const backend = new PlaywrightBackend();
  const evidence = await backend.assertRuntimeCompatible();
  assert.equal(evidence.nodeObserved, process.versions.node);
  assert.equal(evidence.nodeQualificationBaseline, LOCKED_RUNTIME.node);
  assert.equal(evidence.exactNodeQualificationMatch, process.versions.node === LOCKED_RUNTIME.node);
  assert.equal(evidence.playwright, LOCKED_RUNTIME.playwright);
  assert.equal(evidence.chromium, LOCKED_RUNTIME.chromiumVersion);
  assert.equal(evidence.chromiumRevision, LOCKED_RUNTIME.chromiumRevision);
  assert.equal(evidence.authorityGranted, false);
});

test("A11 original frozen qualification remains available and exact", async () => {
  assert.equal(LOCKED_RUNTIME.node, "24.18.0");
  assert.equal(LOCKED_RUNTIME.playwright, "1.60.0");
  assert.equal(LOCKED_RUNTIME.chromiumVersion, "148.0.7778.96");
  const backend = new PlaywrightBackend();
  if (process.versions.node !== LOCKED_RUNTIME.node) {
    await assert.rejects(backend.assertLockedRuntime(),
      (error) => error?.code === "node_lock_mismatch");
  } else {
    assert.equal(await backend.assertLockedRuntime(), true);
  }
});

test("workspace descriptor reports observed runtime without inventing authority", () => {
  const d = new PlaywrightBackend().describe();
  assert.equal(d.nodeObserved, process.versions.node);
  assert.equal(d.nodeQualificationBaseline, LOCKED_RUNTIME.node);
  assert.equal(d.exactNodeQualificationMatch, process.versions.node === LOCKED_RUNTIME.node);
  assert.equal(d.browserSource, "ptah_owned_chromium");
  assert.equal(d.sharesPersonalBrowser, false);
  assert.equal(d.dependsOnOracleBrowserControl, false);
});

test("normal launch no longer rejects Node patch before checking owned runtime", async () => {
  const backend = new PlaywrightBackend();
  const prior = process.env.PTAH_BROWSER_RUNTIME_DIR;
  process.env.PTAH_BROWSER_RUNTIME_DIR = "/nonexistent/ptah-compatibility-proof-owned-browser";
  try {
    await assert.rejects(
      backend.launchProcess({ profileMode: "ephemeral", launchOptions: { headless: true } }),
      (error) => error?.code === "ptah_browser_bundle_missing");
  } finally {
    if (prior === undefined) delete process.env.PTAH_BROWSER_RUNTIME_DIR;
    else process.env.PTAH_BROWSER_RUNTIME_DIR = prior;
  }
});

test("unowned executable override is still prohibited", async () => {
  const backend = new PlaywrightBackend();
  await assert.rejects(
    backend.launchProcess({ profileMode: "ephemeral", launchOptions: { executablePath: "/usr/bin/chromium" } }),
    (error) => error?.code === "external_browser_forbidden");
});
