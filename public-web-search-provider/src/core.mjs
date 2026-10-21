import { spawn } from "node:child_process";
import { isAbsolute, resolve } from "node:path";
import { isIP } from "node:net";

export const SEARCH_VERSION = "0.7.0a2";
export const PROTOCOL = "ptah.public_web_search.v1";
export const MAX_OUTPUT_BYTES = 1_500_000;
const MAX_QUERY = 250;
const MAX_INPUT_BYTES = 16_384;

export class PublicWebError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "PublicWebError";
    this.code = code;
  }
}
const text = (s) => typeof s === "string" && s.length > 0 && !/[\x00-\x1f\x7f]/.test(s);

function validateHttpUrl(value) {
  if (!text(value) || value.length > 2048) throw new PublicWebError("invalid_url");
  let parsed;
  try { parsed = new URL(value); } catch { throw new PublicWebError("invalid_url"); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password ||
      parsed.port || !parsed.hostname || parsed.hash ||
      isIP(parsed.hostname.replace(/^\[|\]$/g,"")) ||
      /(?:^|\.)(?:localhost|local|internal|test)$/.test(parsed.hostname.toLowerCase()))
    throw new PublicWebError("invalid_url");
  return parsed.toString();
}

export function validateRequest(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new PublicWebError("invalid_request");
  }
  const { id = null, operation } = value;
  if (!(id === null || (typeof id === "string" && text(id) && id.length <= 80) ||
        (Number.isSafeInteger(id) && id >= 0))) throw new PublicWebError("invalid_request_id");
  if (!["search", "read", "health"].includes(operation)) throw new PublicWebError("unsupported_operation");
  const keys = new Set(operation === "search" ?
    ["id", "operation", "query", "limit", "offline", "require_fresh", "scope"] :
    operation === "read" ? ["id", "operation", "url"] : ["id", "operation"]);
  if (Object.keys(value).some((key) => !keys.has(key))) throw new PublicWebError("unsupported_field");
  if (operation === "search") {
    if (!text(value.query) || value.query.length > MAX_QUERY)
      throw new PublicWebError("invalid_query");
    const limit = value.limit === undefined ? 5 : value.limit;
    if (!Number.isInteger(limit) || limit < 1 || limit > 10)
      throw new PublicWebError("invalid_limit");
    if (value.offline !== undefined && typeof value.offline !== "boolean")
      throw new PublicWebError("invalid_offline");
    if (value.require_fresh !== undefined && typeof value.require_fresh !== "boolean")
      throw new PublicWebError("invalid_require_fresh");
    const scope = value.scope ?? "general";
    if (!["general", "github", "wikipedia"].includes(scope)) throw new PublicWebError("invalid_scope");
    if (value.offline && scope !== "general") throw new PublicWebError("offline_scope_conflict");
    return { id, operation, query: value.query, limit,
             offline: value.offline ?? false, require_fresh: value.require_fresh ?? false, scope };
  }
  if (operation === "read") return { id, operation, url: validateHttpUrl(value.url) };
  return { id, operation };
}

function searchArgs(req, indexDb) {
  const args = ["-I", "-B", "-m", "ttg_search", "search", req.query,
                "--limit", String(req.limit), "--no-preview-fallback"];
  if (req.offline) args.push("--offline");
  if (req.require_fresh) args.push("--require-fresh");
  if (req.scope === "github") args.push("--github-repos");
  if (req.scope === "wikipedia") args.push("--wikipedia");
  if (indexDb) args.push("--index-db", indexDb);
  return args;
}

export function buildInvocation(req, indexDb) {
  if (req.operation === "search") return searchArgs(req, indexDb);
  if (req.operation === "read") return ["-I", "-B", "-m", "ttg_search", "read", req.url];
  return ["-I", "-B", "-m", "ttg_search", "version"];
}

function boundedEnvironment(config) {
  // No provider secrets, account tokens, proxy rotation, payment keys, or arbitrary PYTHONPATH.
  return {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: process.env.HOME ?? "/tmp",
    LANG: "C.UTF-8",
    PYTHONNOUSERSITE: "1",
    PYTHONSAFEPATH: "1",
    TTG_SEARCH_STATE_DIR: config.stateDir,
  };
}

export function runPython(args, config) {
  return new Promise((done, fail) => {
    const child = spawn(config.python, args, {
      cwd: config.cwd,
      env: boundedEnvironment(config),
      stdio: ["ignore", "pipe", "pipe"],
      shell: false,
      windowsHide: true,
    });
    let stdout = "";
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let finalized = false;
    const finish = (error, value) => {
      if (finalized) return;
      finalized = true;
      clearTimeout(timer);
      if (error) fail(error); else done(value);
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(new PublicWebError("search_timeout"));
    }, config.timeoutMs);
    child.on("error", () => finish(new PublicWebError("search_runtime_unavailable")));
    child.stdout.on("data", chunk => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_OUTPUT_BYTES) {
        child.kill("SIGKILL");
        return finish(new PublicWebError("search_output_over_limit"));
      }
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", chunk => {
      stderrBytes += chunk.length;
      if (stderrBytes > MAX_INPUT_BYTES) {
        child.kill("SIGKILL");
        finish(new PublicWebError("search_stderr_over_limit"));
      }
      // stderr intentionally not forwarded (could contain source URLs or query).
    });
    child.on("close", (status) => finish(null, { status, stdout }));
  });
}

export class PublicWebProvider {
  constructor({ python, cwd, indexDb, stateDir, timeoutMs = 20000, runner = runPython }) {
    for (const [key, value] of Object.entries({ python, cwd, stateDir })) {
      if (!text(value) || !isAbsolute(value)) throw new PublicWebError("invalid_" + key);
    }
    if (indexDb !== undefined && indexDb !== null &&
        (!text(indexDb) || !isAbsolute(indexDb))) throw new PublicWebError("invalid_index_path");
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 60000)
      throw new PublicWebError("invalid_timeout");
    this.config = { python: resolve(python), cwd: resolve(cwd),
                    stateDir: resolve(stateDir), indexDb: indexDb ? resolve(indexDb) : null,
                    timeoutMs };
    this.runner = runner;
  }
  async command(input) {
    const req = validateRequest(input);
    const invocation = buildInvocation(req, this.config.indexDb);
    const { status, stdout } = await this.runner(invocation, this.config);
    if (req.operation === "health") {
      const firstLine = stdout.trim().split("\n")[0];
      if (status !== 0 ||
          firstLine !== `ttg-internet-search ${SEARCH_VERSION} (standalone candidate)`)
        throw new PublicWebError("search_version_mismatch");
      return { protocol: PROTOCOL, engine: SEARCH_VERSION, budget_zmw: 0,
               browser_replacement: false, online_guaranteed: false,
               canonical_evidence: false, status: "READY" };
    }
    if (![0, 2].includes(status)) throw new PublicWebError("search_engine_error");
    let result;
    try { result = JSON.parse(stdout); } catch {
      throw new PublicWebError("search_invalid_response");
    }
    if (!result || typeof result !== "object" || Array.isArray(result))
      throw new PublicWebError("search_invalid_response");
    if (req.operation === "search") {
      if (!Array.isArray(result.results) || result.results.length > req.limit ||
          result.paid_requests > 0) throw new PublicWebError("search_contract_violation");
      return { ...result, protocol: PROTOCOL, budget_zmw: 0,
               source_class: result.status === "LOCAL_MATCH"
                 ? "owned_public_index_noncanonical" : "external_discovery_noncanonical",
               canonical_evidence: false, browser_replacement: false };
    }
    if (!["READABLE", "BLOCKED", "BROWSER_REQUIRED", "UNREADABLE", "ERROR"].includes(result.status))
      throw new PublicWebError("read_contract_violation");
    return { ...result, protocol: PROTOCOL, source_class: "untrusted_public_html",
             canonical_evidence: false };
  }
}
