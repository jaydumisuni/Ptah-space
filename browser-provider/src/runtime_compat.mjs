/**
 * A11's frozen proof baseline is not the live browser-engine entitlement.
 * Node >=22 is a conservative provider runtime floor; actual Playwright and
 * owned Chromium compatibility are checked separately before a real launch.
 */
export function supportedNodeRuntime(value) {
  const parts = typeof value === "string" ? value.split(".") : [];
  return parts.length === 3 && parts.every(
    (part) => part.length > 0 && [...part].every((c) => c >= "0" && c <= "9")
  ) && Number(parts[0]) >= 22;
}
