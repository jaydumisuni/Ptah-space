import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
const execFileAsync = promisify(execFile);
const cli = resolve(fileURLToPath(new URL("../../tools/ptah_workspace_browser.mjs", import.meta.url)));
const physical = process.env.PTAH_PLAYWRIGHT_PHYSICAL === "1";

test("Ptah native operator opens rendered page without Oracle shared browser", { skip: !physical }, async () => {
  const server = createServer((_req, res) => {
    res.setHeader("Content-Type", "text/html");
    res.end("<html><head><title>Ptah Owned Fixture</title></head><body><h1>A11 Independent Agent Browser</h1></body></html>");
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  try {
    const { port } = server.address();
    const { stdout, stderr } = await execFileAsync(process.execPath,
      [cli, "read", `http://127.0.0.1:${port}/`], {
      timeout: 30000, maxBuffer: 200_000,
    });
    assert.equal(stderr, "");
    const result = JSON.parse(stdout);
    assert.equal(result.browserSource, "ptah_owned_chromium");
    assert.equal(result.oracleBrowserControlUsed, false);
    assert.equal(result.sharesPersonalBrowser, false);
    assert.equal(result.ephemeralAgentSession, true);
    assert.equal(result.title, "Ptah Owned Fixture");
    assert.equal(result.pageStateVerified, true);
    assert.equal(result.httpStatus, 200);
    assert.match(result.pageText, /A11 Independent Agent Browser/);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test("Ptah operator rejects file URLs without invoking browser", async () => {
  const rejected = await execFileAsync(process.execPath,
    [cli, "read", "file:///etc/passwd"], { timeout: 12000 }).then(
      () => false, (error) => error.code === 2 && error.stderr.includes("only public website-style HTTP")
    );
  assert.equal(rejected, true);
});
