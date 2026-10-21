import { createInterface } from "node:readline";
import { PublicWebProvider, PublicWebError, PROTOCOL } from "./core.mjs";

const python = process.env.PTAH_PUBLIC_WEB_PYTHON;
const cwd = process.env.PTAH_PUBLIC_WEB_HOME;
const stateDir = process.env.PTAH_PUBLIC_WEB_STATE_DIR;
const indexDb = process.env.PTAH_PUBLIC_WEB_INDEX_DB || undefined;
let provider;
try {
  provider = new PublicWebProvider({ python, cwd, stateDir, indexDb });
} catch {
  process.stderr.write("public-web-search: configuration invalid\n");
  process.exit(2);
}
const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of input) {
  if (!line.trim()) continue;
  let id = null;
  try {
    if (Buffer.byteLength(line, "utf8") > 16_384)
      throw new PublicWebError("request_too_large");
    const req = JSON.parse(line);
    id = req && (typeof req.id === "string" || Number.isSafeInteger(req.id)) ? req.id : null;
    const result = await provider.command(req);
    process.stdout.write(JSON.stringify({ id, ok: true, result }) + "\n");
  } catch (error) {
    const code = error instanceof PublicWebError ? error.code : "search_internal_error";
    process.stdout.write(JSON.stringify({ id, ok: false, error: { code } }) + "\n");
  }
}
