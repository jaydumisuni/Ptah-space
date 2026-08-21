#!/usr/bin/env node
/*
 * Ptah Visual Device Verification Lab — exact-device capture runner.
 *
 * Experimental workspace machinery only. It does not make Ptah runtime claims.
 *
 * Examples:
 *   node capture.mjs --target http://127.0.0.1:4173 --project notverse --scene baseline
 *   node capture.mjs --target http://127.0.0.1:4173 --project notverse --scene notes --adapter ./projects/notverse.adapter.mjs --engines webkit
 */
import { chromium, webkit } from "playwright";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import path from "node:path";

const root = new URL("./", import.meta.url);
const args = parseArgs(process.argv.slice(2));
const target = args.target || "http://127.0.0.1:4173";
const projectId = args.project || "notverse";
const sceneId = args.scene || "baseline";
const requestedEngines = String(args.engines || "chromium,webkit").split(",").map((v) => v.trim()).filter(Boolean);
const adapterPath = args.adapter ? path.resolve(String(args.adapter)) : null;

const devicesDoc = JSON.parse(await readFile(new URL("./device-profiles.json", root), "utf8"));
const projectDoc = await readProject(projectId);
const devices = devicesDoc.profiles || [];
const scene = projectDoc?.scenes?.find((item) => item.id === sceneId) || {
  id: sceneId,
  name: sceneId === "baseline" ? "Baseline" : sceneId,
  proofFile: `${sceneId}.png`,
};
const adapter = adapterPath ? await import(pathToFileURL(adapterPath).href) : null;

if (sceneId !== "baseline" && !adapter?.prepare) {
  throw new Error(`Scene '${sceneId}' requires an adapter with export async function prepare(page, context). The lab will not pretend an unprepared page is scene proof.`);
}

const engineRegistry = { chromium, webkit };
for (const name of requestedEngines) {
  if (!engineRegistry[name]) throw new Error(`Unsupported engine '${name}'. Supported: ${Object.keys(engineRegistry).join(", ")}`);
}

const candidate = args.candidate || process.env.CANDIDATE_ID || "unidentified-candidate";
const runId = new Date().toISOString().replace(/[:.]/g, "-");
const report = {
  schema: "ptah.visual-evidence-manifest.v0",
  status: "experimental",
  project: projectId,
  candidate,
  target,
  scene: scene.id,
  createdAt: new Date().toISOString(),
  runId,
  captures: [],
};

for (const engineName of requestedEngines) {
  const browser = await engineRegistry[engineName].launch({ headless: true });
  try {
    for (const device of devices) {
      const { width, height } = device.cssViewport;
      const context = await browser.newContext({
        viewport: { width, height },
        isMobile: true,
        hasTouch: true,
        deviceScaleFactor: 1,
      });
      const page = await context.newPage();
      const consoleErrors = [];
      page.on("console", (message) => {
        if (message.type() === "error") consoleErrors.push(message.text());
      });
      page.on("pageerror", (error) => consoleErrors.push(String(error)));

      const record = {
        engine: engineName,
        deviceId: device.id,
        deviceName: device.name,
        cssViewport: { width, height },
        safeArea: device.safeArea || null,
        scene: scene.id,
        candidate,
        consoleErrors,
      };

      try {
        await page.goto(target, { waitUntil: "networkidle", timeout: 45_000 });
        if (adapter?.prepare) {
          await adapter.prepare(page, {
            project: projectDoc,
            scene,
            device,
            engine: engineName,
            target,
            candidate,
          });
        }

        const fileName = `${engineName}-${scene.proofFile || `${scene.id}.png`}`;
        const relative = path.join("proof", projectId, scene.id, device.id, fileName).replaceAll("\\", "/");
        const absolute = new URL(`./${relative}`, root);
        await mkdir(new URL("./", absolute), { recursive: true });
        await page.screenshot({ path: absolute, fullPage: false });

        record.screenshot = relative;
        record.pageUrl = page.url();
        record.documentMetrics = await page.evaluate(() => ({
          innerWidth: window.innerWidth,
          innerHeight: window.innerHeight,
          documentWidth: document.documentElement.scrollWidth,
          documentHeight: document.documentElement.scrollHeight,
          visualViewport: window.visualViewport ? {
            width: window.visualViewport.width,
            height: window.visualViewport.height,
            offsetTop: window.visualViewport.offsetTop,
            offsetLeft: window.visualViewport.offsetLeft,
          } : null,
        }));
      } catch (error) {
        record.error = error instanceof Error ? error.stack || error.message : String(error);
      }

      report.captures.push(record);
      await context.close();
    }
  } finally {
    await browser.close();
  }
}

const reportDir = new URL(`./proof/${projectId}/${scene.id}/`, root);
await mkdir(reportDir, { recursive: true });
await writeFile(new URL(`manifest-${runId}.json`, reportDir), `${JSON.stringify(report, null, 2)}\n`);

const passed = report.captures.filter((item) => item.screenshot).length;
console.log(`Visual-device capture complete: ${passed}/${report.captures.length} exact cases captured.`);
if (passed !== report.captures.length) process.exitCode = 1;

async function readProject(id) {
  try {
    return JSON.parse(await readFile(new URL(`./projects/${id}.json`, root), "utf8"));
  } catch {
    return { id, name: id, scenes: [] };
  }
}

function parseArgs(tokens) {
  const parsed = {};
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token.startsWith("--")) continue;
    const key = token.slice(2);
    const next = tokens[index + 1];
    if (!next || next.startsWith("--")) parsed[key] = true;
    else {
      parsed[key] = next;
      index += 1;
    }
  }
  return parsed;
}
