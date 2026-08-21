import { BrowserProviderError, invariant } from "./errors.mjs";
import { LOCKED_RUNTIME, MAX_DOWNLOAD_CHUNK_BYTES, PROVIDER_PROTOCOL, SENSITIVE_HEADERS } from "./locks.mjs";

const PROFILE_MODES = new Set(["persistent_exclusive","persistent_shared_readonly","ephemeral","incognito","managed_remote","other_registered"]);
const EVIDENCE_CLASSES = new Set(["source_response","dom_snapshot","accessibility_snapshot","screenshot","video","trace","network_log","console_log","download_bytes","visible_state","manual_receipt","other_registered"]);
const CHALLENGE_STATES = new Set(["none","login_required","mfa_required","captcha_or_anti_bot","consent_or_terms","certificate_or_device_approval","human_completion_required","blocked_by_policy","expired","resolved"]);
const PERSONAL_PROFILE_PATTERNS = [
  /[/\\]google[/\\]chrome[/\\]user data(?:[/\\]|$)/i,
  /[/\\]chromium[/\\](?:user data|default)(?:[/\\]|$)/i,
  /[/\\]microsoft[/\\]edge[/\\]user data(?:[/\\]|$)/i,
  /[/\\]\.config[/\\]google-chrome[/\\]default(?:[/\\]|$)/i,
];
const RAW_SECRET_KEYS = new Set(["password","passwd","secret","token","access_token","refresh_token","authorization","cookie","set-cookie","proxy-authorization","apikey","api_key","clientsecret","client_secret","httpcredentials"]);
const SENSITIVE_QUERY_KEYS = new Set(["token","access_token","refresh_token","code","key","api_key","signature","sig","auth"]);

function positiveInteger(value, field) {
  invariant(Number.isSafeInteger(value) && value > 0, "invalid_generation", `${field} must be a positive integer`);
  return value;
}
function requiredText(value, field) {
  invariant(typeof value === "string" && value.trim().length > 0, "invalid_request", `${field} is required`);
  return value;
}
function redactHeaders(headers = {}) {
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key, SENSITIVE_HEADERS.has(key.toLowerCase()) ? "[REDACTED]" : value]));
}
function redactEvidence(value) {
  if (Array.isArray(value)) return value.map(redactEvidence);
  if (value && typeof value === "object" && !Buffer.isBuffer(value)) {
    const output = {};
    for (const [key, item] of Object.entries(value)) {
      const normalized = key.toLowerCase();
      if (normalized === "headers" && item && typeof item === "object") output[key] = redactHeaders(item);
      else if (["authorization","cookie","set-cookie","proxy-authorization"].includes(normalized)) output[key] = "[REDACTED]";
      else if (typeof item === "string" && (normalized === "url" || normalized.endsWith("url"))) output[key] = redactUrl(item);
      else output[key] = redactEvidence(item);
    }
    return output;
  }
  return value;
}
function redactUrl(value) {
  try {
    const url = new URL(value);
    if (url.username) url.username = "[REDACTED]";
    if (url.password) url.password = "[REDACTED]";
    for (const key of [...url.searchParams.keys()]) if (SENSITIVE_QUERY_KEYS.has(key.toLowerCase())) url.searchParams.set(key, "[REDACTED]");
    return url.toString();
  } catch { return value; }
}
function assertNoRawSecrets(value, path = []) {
  if (Array.isArray(value)) { value.forEach((item, index) => assertNoRawSecrets(item, [...path, String(index)])); return; }
  if (!value || typeof value !== "object" || Buffer.isBuffer(value)) return;
  for (const [key, item] of Object.entries(value)) {
    const normalized = key.toLowerCase().replaceAll("-", "_");
    invariant(!RAW_SECRET_KEYS.has(normalized) && !RAW_SECRET_KEYS.has(normalized.replaceAll("_", "")), "raw_secret_forbidden", `raw credential/secret field is forbidden in Browser Provider protocol: ${[...path, key].join(".")}`);
    assertNoRawSecrets(item, [...path, key]);
  }
}
function isDefaultPersonalProfilePath(path) { return PERSONAL_PROFILE_PATTERNS.some((pattern) => pattern.test(path)); }
function opaqueHandle(prefix, sequence) { return `${prefix}-${sequence.toString(36).padStart(6, "0")}`; }
function sanitizeAliases(aliases) {
  if (!Array.isArray(aliases)) return [];
  return aliases.filter((alias) => alias && typeof alias.kind === "string" && typeof alias.value === "string").map((alias) => ({ kind: alias.kind, value: alias.value }));
}

export class ProviderCore {
  #backend; #providerGeneration; #processes = new Map(); #contexts = new Map(); #pages = new Map(); #sequence = 0; #maxDownloadChunkBytes;
  constructor({ backend, providerGeneration, maxDownloadChunkBytes = MAX_DOWNLOAD_CHUNK_BYTES }) {
    invariant(backend && typeof backend === "object", "invalid_backend", "backend is required");
    this.#backend = backend;
    this.#providerGeneration = positiveInteger(providerGeneration, "providerGeneration");
    this.#maxDownloadChunkBytes = positiveInteger(maxDownloadChunkBytes, "maxDownloadChunkBytes");
  }
  describe() {
    const backend = typeof this.#backend.describe === "function" ? this.#backend.describe() : {};
    return Object.freeze({ protocol: PROVIDER_PROTOCOL, lockedRuntime: LOCKED_RUNTIME, providerGeneration: this.#providerGeneration,
      authority: Object.freeze({ canonicalIdentityOwner: "ptah_control_plane", backendHandlesAreAliases: true, providerAckIsCompletion: false, challengeBypassAuthorized: false, browserOwnsContentIdentity: false }), backend });
  }
  async launchProcess(request) {
    this.#checkProviderGeneration(request.expectedProviderGeneration);
    const processGeneration = positiveInteger(request.processGeneration, "processGeneration");
    invariant(PROFILE_MODES.has(request.profileMode), "invalid_profile_mode", "unknown browser profile mode");
    if (request.profileMode === "persistent_exclusive") {
      const userDataDir = requiredText(request.userDataDir, "userDataDir");
      invariant(!isDefaultPersonalProfilePath(userDataDir), "personal_profile_forbidden", "ordinary personal browser profiles may not be attached directly");
      invariant(request.writableAuthorization?.leaseRef && request.writableAuthorization?.fenceRef, "writable_profile_authority_required", "persistent writable profile launch requires canonical Lease and fence authority");
    }
    if (request.profileMode === "persistent_shared_readonly") invariant(request.readonly === true, "readonly_profile_required", "shared persistent profile must be read-only");
    const backendProcess = await this.#backend.launchProcess({ profileMode: request.profileMode, userDataDir: request.userDataDir, readonly: request.readonly === true, launchOptions: request.launchOptions ?? {} });
    const handle = this.#newHandle("process");
    this.#processes.set(handle, { backend: backendProcess, processGeneration, detached: false, closed: false, profileMode: request.profileMode });
    return { processHandle: handle, providerGeneration: this.#providerGeneration, processGeneration, acknowledged: true, completionVerified: false, backendAliases: sanitizeAliases(backendProcess?.aliases) };
  }
  async createContext(request) {
    this.#checkProviderGeneration(request.expectedProviderGeneration);
    const process = this.#process(request.processHandle, request.processGeneration);
    const contextGeneration = positiveInteger(request.contextGeneration, "contextGeneration");
    invariant(!process.closed, "stale_process", "browser process is closed");
    invariant(PROFILE_MODES.has(request.storageMode), "invalid_profile_mode", "unknown Browser Context storage mode");
    if (process.profileMode === "persistent_shared_readonly") invariant(request.storageMode === "persistent_shared_readonly", "readonly_profile_required", "shared persistent Browser Process only permits read-only Contexts");
    const backendContext = await this.#backend.createContext(process.backend, { storageMode: request.storageMode, networkPolicy: request.networkPolicy ?? {}, permissionPolicy: request.permissionPolicy ?? {}, contextOptions: request.contextOptions ?? {} });
    const handle = this.#newHandle("context");
    this.#contexts.set(handle, { backend: backendContext, processHandle: request.processHandle, processGeneration: process.processGeneration, contextGeneration, closed: false });
    return { contextHandle: handle, processGeneration: process.processGeneration, contextGeneration, acknowledged: true, completionVerified: false, backendAliases: sanitizeAliases(backendContext?.aliases) };
  }
  async verifyContext(request) {
    this.#checkProviderGeneration(request.expectedProviderGeneration);
    const context = this.#context(request.contextHandle, request.processGeneration, request.contextGeneration);
    const observation = await this.#backend.verifyContext(context.backend);
    return { contextHandle: request.contextHandle, verified: observation?.verified === true, completionVerified: observation?.verified === true, evidence: redactEvidence(observation?.evidence ?? {}) };
  }
  async createPage(request) {
    this.#checkProviderGeneration(request.expectedProviderGeneration);
    const context = this.#context(request.contextHandle, request.processGeneration, request.contextGeneration);
    const pageGeneration = positiveInteger(request.pageGeneration, "pageGeneration");
    invariant(!context.closed, "stale_context", "browser context is closed");
    const backendPage = await this.#backend.createPage(context.backend, request.pageOptions ?? {});
    const handle = this.#newHandle("page");
    this.#pages.set(handle, { backend: backendPage, contextHandle: request.contextHandle, processGeneration: context.processGeneration, contextGeneration: context.contextGeneration, pageGeneration, navigationSequence: 0, closed: false });
    return { pageHandle: handle, processGeneration: context.processGeneration, contextGeneration: context.contextGeneration, pageGeneration, acknowledged: true, completionVerified: false, backendAliases: sanitizeAliases(backendPage?.aliases) };
  }
  async navigate(request) {
    this.#checkProviderGeneration(request.expectedProviderGeneration);
    const page = this.#page(request.pageHandle, request.processGeneration, request.contextGeneration, request.pageGeneration);
    requiredText(request.url, "url");
    const navigationSequence = positiveInteger(request.navigationSequence, "navigationSequence");
    invariant(navigationSequence > page.navigationSequence, "stale_navigation", "navigationSequence must increase monotonically");
    page.navigationSequence = navigationSequence;
    const observation = await this.#backend.navigate(page.backend, { url: request.url, timeoutMs: request.timeoutMs });
    return { pageHandle: request.pageHandle, navigationSequence, acknowledged: true, completionVerified: false, state: observation?.state ?? "committed", committedUrl: observation?.committedUrl, status: observation?.status, evidence: redactEvidence(observation?.evidence ?? {}) };
  }
  async verifyPageState(request) {
    this.#checkProviderGeneration(request.expectedProviderGeneration);
    const page = this.#page(request.pageHandle, request.processGeneration, request.contextGeneration, request.pageGeneration);
    const observation = await this.#backend.verifyPageState(page.backend, { waitUntil: request.waitUntil ?? "load", timeoutMs: request.timeoutMs });
    return { pageHandle: request.pageHandle, navigationSequence: page.navigationSequence, verified: observation?.verified === true, state: observation?.state ?? "unknown", url: observation?.url, title: observation?.title, evidence: redactEvidence(observation?.evidence ?? {}) };
  }
  async captureEvidence(request) {
    this.#checkProviderGeneration(request.expectedProviderGeneration);
    const page = this.#page(request.pageHandle, request.processGeneration, request.contextGeneration, request.pageGeneration);
    invariant(EVIDENCE_CLASSES.has(request.evidenceClass), "unsupported_evidence_class", "unsupported browser evidence class");
    invariant(request.evidenceClass !== "manual_receipt", "authority_violation", "manual receipts are not manufactured by the Browser Provider");
    const captured = await this.#backend.captureEvidence(page.backend, request.evidenceClass, request.options ?? {});
    return { evidenceClass: request.evidenceClass, capturedAt: captured?.capturedAt, mediaType: captured?.mediaType, bytes: captured?.bytes, metadata: redactEvidence(captured?.metadata ?? {}), canonicalObjectRef: null, canonicalArtifactRef: null };
  }
  async readDownloadChunk(request) {
    this.#checkProviderGeneration(request.expectedProviderGeneration);
    requiredText(request.downloadHandle, "downloadHandle");
    const maxBytes = positiveInteger(request.maxBytes, "maxBytes");
    invariant(maxBytes <= this.#maxDownloadChunkBytes, "download_chunk_too_large", "download chunk exceeds provider bound");
    const offset = Number(request.offset ?? 0);
    invariant(Number.isSafeInteger(offset) && offset >= 0, "invalid_offset", "offset must be a non-negative integer");
    const result = await this.#backend.readDownloadChunk(request.downloadHandle, { offset, maxBytes });
    invariant(Buffer.isBuffer(result?.bytes), "invalid_backend_result", "download backend must return Buffer bytes");
    invariant(result.bytes.length <= maxBytes, "backend_bound_violation", "download backend exceeded requested bound");
    return { downloadHandle: request.downloadHandle, offset, bytes: result.bytes, eof: result.eof === true, canonicalContentRef: null, canonicalObjectRef: null };
  }
  async pollEvents(request) {
    this.#checkProviderGeneration(request.expectedProviderGeneration);
    const events = await this.#backend.pollEvents({ limit: request.limit ?? 100 });
    return (events ?? []).map((event) => redactEvidence(event));
  }
  async uploadFiles(request) {
    this.#checkProviderGeneration(request.expectedProviderGeneration);
    const page = this.#page(request.pageHandle, request.processGeneration, request.contextGeneration, request.pageGeneration);
    requiredText(request.selector, "selector");
    invariant(Array.isArray(request.materializedPathAliases) && request.materializedPathAliases.length > 0, "upload_materialization_required", "upload requires A08-materialized local path aliases");
    const paths = request.materializedPathAliases.map((path) => requiredText(path, "materializedPathAlias"));
    const result = await this.#backend.uploadFiles(page.backend, { selector: request.selector, paths });
    return { pageHandle: request.pageHandle, acknowledged: result?.acknowledged !== false, completionVerified: false, canonicalObjectRefs: [], canonicalArtifactRefs: [] };
  }
  async reconnectProcess(request) {
    this.#checkProviderGeneration(request.expectedProviderGeneration);
    const process = this.#process(request.processHandle, request.processGeneration);
    const observation = typeof this.#backend.verifyProcess === "function" ? await this.#backend.verifyProcess(process.backend) : { verified: true };
    invariant(observation?.verified === true, "process_reconnect_unverified", "Browser Process liveness could not be verified for reconnect");
    process.detached = false;
    return { processHandle: request.processHandle, reconnected: true, completionVerified: true, evidence: redactEvidence(observation?.evidence ?? {}) };
  }
  observeChallenge(request) {
    this.#checkProviderGeneration(request.expectedProviderGeneration);
    invariant(CHALLENGE_STATES.has(request.state), "invalid_challenge_state", "unknown challenge state");
    invariant(!["none", "resolved"].includes(request.state), "challenge_not_active", "only active challenge observations belong here");
    return { state: request.state, automationPauseRequired: request.automationPauseRequired !== false, humanCompletionAllowed: request.humanCompletionAllowed === true, bypassAuthorized: false };
  }
  async detachProcess(request) {
    this.#checkProviderGeneration(request.expectedProviderGeneration);
    const process = this.#process(request.processHandle, request.processGeneration);
    process.detached = true;
    if (typeof this.#backend.detachProcess === "function") await this.#backend.detachProcess(process.backend);
    return { processHandle: request.processHandle, detached: true, backendProcessClosed: false };
  }
  async closeProcess(request) {
    this.#checkProviderGeneration(request.expectedProviderGeneration);
    const process = this.#process(request.processHandle, request.processGeneration, { allowClosed: true });
    if (!process.closed) { await this.#backend.closeProcess(process.backend); process.closed = true; }
    return { processHandle: request.processHandle, closed: true };
  }
  async handleCommand(command) {
    invariant(command && typeof command === "object", "invalid_request", "command object is required");
    const handlers = { describe: () => this.describe(), launchProcess: (a) => this.launchProcess(a), createContext: (a) => this.createContext(a), verifyContext: (a) => this.verifyContext(a), createPage: (a) => this.createPage(a), navigate: (a) => this.navigate(a), verifyPageState: (a) => this.verifyPageState(a), captureEvidence: (a) => this.captureEvidence(a), uploadFiles: (a) => this.uploadFiles(a), readDownloadChunk: (a) => this.readDownloadChunk(a), pollEvents: (a) => this.pollEvents(a), observeChallenge: (a) => this.observeChallenge(a), detachProcess: (a) => this.detachProcess(a), reconnectProcess: (a) => this.reconnectProcess(a), closeProcess: (a) => this.closeProcess(a) };
    const handler = handlers[command.operation];
    invariant(handler, "command_not_supported", `unsupported Browser Provider operation: ${String(command.operation)}`);
    assertNoRawSecrets(command.args ?? {});
    return handler(command.args ?? {});
  }
  #checkProviderGeneration(expected) { invariant(positiveInteger(expected, "expectedProviderGeneration") === this.#providerGeneration, "stale_provider_generation", "stale Browser Provider generation"); }
  #process(handle, expectedProcessGeneration, { allowClosed = false } = {}) {
    requiredText(handle, "processHandle"); const process = this.#processes.get(handle); invariant(process, "stale_process", "unknown Browser Process handle");
    invariant(process.processGeneration === positiveInteger(expectedProcessGeneration, "processGeneration"), "stale_process_generation", "stale Browser Process generation");
    invariant(allowClosed || !process.closed, "stale_process", "Browser Process is closed"); return process;
  }
  #context(handle, expectedProcessGeneration, expectedContextGeneration) {
    requiredText(handle, "contextHandle"); const context = this.#contexts.get(handle); invariant(context, "stale_context", "unknown Browser Context handle");
    invariant(context.processGeneration === positiveInteger(expectedProcessGeneration, "processGeneration") && context.contextGeneration === positiveInteger(expectedContextGeneration, "contextGeneration"), "stale_context_generation", "stale Browser Context generation");
    this.#process(context.processHandle, context.processGeneration); return context;
  }
  #page(handle, expectedProcessGeneration, expectedContextGeneration, expectedPageGeneration) {
    requiredText(handle, "pageHandle"); const page = this.#pages.get(handle); invariant(page, "stale_page", "unknown Browser Page handle");
    invariant(page.processGeneration === positiveInteger(expectedProcessGeneration, "processGeneration") && page.contextGeneration === positiveInteger(expectedContextGeneration, "contextGeneration") && page.pageGeneration === positiveInteger(expectedPageGeneration, "pageGeneration"), "stale_page_generation", "stale Browser Page generation");
    this.#context(page.contextHandle, page.processGeneration, page.contextGeneration); invariant(!page.closed, "stale_page", "Browser Page is closed"); return page;
  }
  #newHandle(prefix) { this.#sequence += 1; return opaqueHandle(prefix, this.#sequence); }
}
export { BrowserProviderError, isDefaultPersonalProfilePath, redactEvidence, redactUrl };
