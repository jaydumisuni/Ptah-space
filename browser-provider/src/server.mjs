import { createInterface } from "node:readline";
import { ProviderCore, redactEvidence } from "./core.mjs";
import { BrowserProviderError } from "./errors.mjs";
import { PlaywrightBackend } from "./playwright_backend.mjs";

const providerGeneration = Number(process.env.PTAH_BROWSER_PROVIDER_GENERATION ?? "1");
const core = new ProviderCore({ backend: new PlaywrightBackend(), providerGeneration });
const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of input) {
  if (!line.trim()) continue;
  let request;
  try {
    request = JSON.parse(line);
    const result = await core.handleCommand(request);
    process.stdout.write(`${JSON.stringify(encodeBuffers({ id: request.id ?? null, ok: true, result }))}\n`);
  } catch (error) {
    const known = error instanceof BrowserProviderError;
    process.stdout.write(`${JSON.stringify({ id: request?.id ?? null, ok: false, error: { code: known ? error.code : "provider_internal_error", message: known ? error.message : "Browser Provider internal failure", details: known ? redactEvidence(error.details) : undefined } })}\n`);
  }
}
function encodeBuffers(value) {
  if (Buffer.isBuffer(value)) return { encoding: "base64", data: value.toString("base64") };
  if (Array.isArray(value)) return value.map(encodeBuffers);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, encodeBuffers(item)]));
  return value;
}
