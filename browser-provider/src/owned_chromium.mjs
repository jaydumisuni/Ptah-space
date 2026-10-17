import { lstat, realpath, stat } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { BrowserProviderError, invariant } from "./errors.mjs";
import { LOCKED_RUNTIME } from "./locks.mjs";

const providerDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const DEFAULT_PTAH_BROWSER_RUNTIME_DIR = join(providerDir, ".workspace", "browser-runtime");
export const BROWSER_SOURCE = "ptah_owned_chromium";

export function bundleLayout(platform = process.platform) {
  const revision = LOCKED_RUNTIME.chromiumRevision;
  if (platform === "linux") return join("chromium-" + revision, "chrome-linux64", "chrome");
  if (platform === "win32") return join("chromium-" + revision, "chrome-win64", "chrome.exe");
  if (platform === "darwin") return join("chromium-" + revision, "chrome-mac", "Chromium.app", "Contents", "MacOS", "Chromium");
  throw new BrowserProviderError("browser_platform_unsupported", "Ptah Chromium bundle platform is unsupported");
}

export async function ownedChromiumExecutable({
  root = process.env.PTAH_BROWSER_RUNTIME_DIR || DEFAULT_PTAH_BROWSER_RUNTIME_DIR,
  platform = process.platform,
} = {}) {
  invariant(typeof root === "string" && root.length > 0 && isAbsolute(root),
    "browser_bundle_root_invalid", "Ptah browser bundle must be an absolute dedicated runtime path");
  const expected = resolve(root, bundleLayout(platform));
  let realRoot, executable, attributes;
  try {
    const rootStat = await lstat(root);
    invariant(!rootStat.isSymbolicLink(), "browser_bundle_root_link_forbidden",
      "Ptah runtime root must be a real directory, not a link to a shared or personal browser");
    realRoot = await realpath(root);
    executable = await realpath(expected);
    attributes = await stat(executable);
  } catch (error) {
    if (error instanceof BrowserProviderError) throw error;
    throw new BrowserProviderError("ptah_browser_bundle_missing",
      "Ptah-owned pinned Chromium runtime is missing; do not fall back to system Chrome or Oracle's browser");
  }
  const inside = relative(realRoot, executable);
  invariant(Boolean(inside) && inside !== ".." && !inside.startsWith(".." + sep) && !isAbsolute(inside),
    "browser_bundle_escape", "Chromium executable resolves outside Ptah's browser runtime");
  invariant(attributes.isFile(), "browser_bundle_invalid", "Ptah-managed Chromium target is not a file");
  return executable;
}

export async function lockedOwnedLaunchOptions(launchOptions = {}) {
  invariant(launchOptions && typeof launchOptions === "object" && !Array.isArray(launchOptions),
    "browser_launch_options_invalid", "Browser launch options must be an object");
  invariant(launchOptions.executablePath === undefined && launchOptions.channel === undefined,
    "external_browser_forbidden", "Ptah cannot attach to system Chrome, Edge or an arbitrary browser executable");
  invariant(launchOptions.ignoreDefaultArgs === undefined,
    "browser_profile_override_forbidden", "Ptah cannot disable Playwright's isolated default browser arguments");
  invariant(!Array.isArray(launchOptions.args) || !launchOptions.args.some(
    (argument) => typeof argument === "string" &&
      /^(--user-data-dir|--profile-directory|--remote-debugging-port)(=|$)/i.test(argument)
  ), "browser_profile_override_forbidden",
  "Ptah agents cannot attach their workspace browser to a personal profile or debugging session");
  return { ...launchOptions, executablePath: await ownedChromiumExecutable() };
}
