export class BrowserProviderError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = "BrowserProviderError";
    this.code = code;
    this.details = details;
  }
}

export function invariant(condition, code, message, details = undefined) {
  if (!condition) throw new BrowserProviderError(code, message, details);
}
