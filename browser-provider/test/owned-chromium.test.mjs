import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { ownedChromiumExecutable, bundleLayout, lockedOwnedLaunchOptions } from "../src/owned_chromium.mjs";

test("workspace-owned Chromium bundle layout is pinned to the A11 revision", () => {
  assert.equal(bundleLayout("linux"), join("chromium-1223", "chrome-linux64", "chrome"));
  assert.equal(bundleLayout("win32"), join("chromium-1223", "chrome-win64", "chrome.exe"));
});

test("external Chrome/Edge channels and arbitrary executable paths are rejected", async () => {
  await assert.rejects(lockedOwnedLaunchOptions({ channel: "chrome" }), { code: "external_browser_forbidden" });
  await assert.rejects(lockedOwnedLaunchOptions({ executablePath: "/usr/bin/google-chrome" }), { code: "external_browser_forbidden" });
});

test("profile and debugging switches cannot redirect isolated browser into a human session", async () => {
  await assert.rejects(lockedOwnedLaunchOptions({ args: ["--user-data-dir=/home/user/.config/google-chrome"] }), { code: "browser_profile_override_forbidden" });
  await assert.rejects(lockedOwnedLaunchOptions({ args: ["--remote-debugging-port=9222"] }), { code: "browser_profile_override_forbidden" });
  await assert.rejects(lockedOwnedLaunchOptions({ ignoreDefaultArgs: true }), { code: "browser_profile_override_forbidden" });
});

test("absent Ptah-owned browser fails closed rather than launching a system browser", async () => {
  const folder = await mkdtemp(join(tmpdir(), "ptah-a11-no-owned-runtime-"));
  try {
    await assert.rejects(ownedChromiumExecutable({ root: folder, platform: "linux" }), { code: "ptah_browser_bundle_missing" });
  } finally { await rm(folder, { recursive: true, force: true }); }
});

test("managed browser path cannot escape via symlink into shared host executable", async () => {
  const folder = await mkdtemp(join(tmpdir(), "ptah-a11-owned-runtime-symlink-"));
  const external = await mkdtemp(join(tmpdir(), "ptah-a11-external-chrome-"));
  try {
    const dest = join(folder, "chromium-1223", "chrome-linux64");
    await mkdir(dest, { recursive: true });
    const outside = join(external, "chrome");
    await writeFile(outside, "outside source");
    await symlink(outside, join(dest, "chrome"));
    await assert.rejects(ownedChromiumExecutable({ root: folder, platform: "linux" }), { code: "browser_bundle_escape" });
  } finally {
    await rm(folder, { recursive: true, force: true });
    await rm(external, { recursive: true, force: true });
  }
});

test("browser runtime root cannot alias shared Playwright cache", async () => {
  const folder = await mkdtemp(join(tmpdir(), "ptah-a11-symlink-root-"));
  const target = await mkdtemp(join(tmpdir(), "ptah-a11-target-"));
  try {
    const root = join(folder, "runtime");
    await symlink(target, root);
    await assert.rejects(ownedChromiumExecutable({ root }), { code: "browser_bundle_root_link_forbidden" });
  } finally {
    await rm(folder, { recursive: true, force: true });
    await rm(target, { recursive: true, force: true });
  }
});

test("valid workspace-owned path is selected without Oracle or personal browser control", async () => {
  const folder = await mkdtemp(join(tmpdir(), "ptah-a11-owned-browser-"));
  const prev = process.env.PTAH_BROWSER_RUNTIME_DIR;
  try {
    const dest = join(folder, "chromium-1223", "chrome-linux64");
    await mkdir(dest, { recursive: true });
    const binary = join(dest, "chrome");
    await writeFile(binary, "standalone test executable");
    process.env.PTAH_BROWSER_RUNTIME_DIR = folder;
    const opts = await lockedOwnedLaunchOptions({ headless: true });
    assert.equal(opts.executablePath, resolve(binary));
    assert.equal(opts.headless, true);
    assert.equal("channel" in opts, false);
  } finally {
    if (prev === undefined) delete process.env.PTAH_BROWSER_RUNTIME_DIR;
    else process.env.PTAH_BROWSER_RUNTIME_DIR = prev;
    await rm(folder, { recursive: true, force: true });
  }
});
