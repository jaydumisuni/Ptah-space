import { createServer } from "node:http";
import { connect, isIP } from "node:net";
import { lookup } from "node:dns/promises";
import { once } from "node:events";

// Public read egress policy. This is not an agent login or a browser
// entitlement. It pins every permitted TLS tunnel to the verified address
// instead of trusting the browser DNS cache or following redirects blindly.
export function isPublicIPv4(address) {
  if (typeof address !== "string" || isIP(address) !== 4) return false;
  const o = address.split(".").map(Number);
  const [a, b, c] = o;
  if (a === 0 || a === 10 || a === 127 || a >= 224 ||
      a === 100 && b >= 64 && b <= 127 ||
      a === 169 && b === 254 ||
      a === 172 && b >= 16 && b <= 31 ||
      a === 192 && b === 168 ||
      a === 192 && b === 0 && c === 0 ||
      a === 192 && b === 0 && c === 2 ||
      a === 192 && b === 88 && c === 99 ||
      a === 198 && (b === 18 || b === 19) ||
      a === 198 && b === 51 && c === 100 ||
      a === 203 && b === 0 && c === 113) return false;
  return true;
}
export function publicHttpsHost(authority) {
  if (typeof authority !== "string" || authority.length > 257) return null;
  const match = /^([a-z0-9][a-z0-9.-]{0,252}):443$/i.exec(authority);
  if (!match) return null;
  const host = match[1].toLowerCase();
  if (host.startsWith(".") || host.endsWith(".") || host.includes("..") ||
      !host.includes(".") || isIP(host) ||
      host.endsWith(".local") || host.endsWith(".localhost") ||
      host.endsWith(".internal") || host.endsWith(".test") ||
      host.endsWith(".home.arpa") || host === "metadata.google.internal" ||
      host.split(".").some(part => !part || part.length > 63 ||
        part.startsWith("-") || part.endsWith("-"))) return null;
  return host;
}
export async function authorizedPublicIp(authority, resolveDns = lookup) {
  const host = publicHttpsHost(authority);
  if (!host) return null;
  try {
    const entries = await resolveDns(host, { family: 4, all: true });
    if (!Array.isArray(entries) || entries.length === 0 ||
        entries.length > 32 || !entries.every(e => isPublicIPv4(e?.address))) return null;
    return { host, address: entries[0].address };
  } catch { return null; }
}
export async function startPublicHttpsProxy({ resolveDns = lookup } = {}) {
  const sockets = new Set();
  const server = createServer((_req, res) => {
    res.writeHead(403, { "content-type": "text/plain", connection: "close" });
    res.end("HTTPS CONNECT required");
  });
  server.on("connection", socket => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.setTimeout(35000, () => socket.destroy());
  });
  server.on("connect", async (req, client, head) => {
    // A remote client may reset its socket while DNS resolution is awaited.
    // Install error and close listeners before that async boundary.
    let remote = null;
    client.on("error", () => remote?.destroy());
    client.on("close", () => remote?.destroy());
    const deny = () => {
      if (!client.destroyed) client.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
    };
    // Reject non-CONNECT, alternate ports, IP literals, private DNS
    // addresses, and redirects toward private services before opening
    // any destination socket.
    const allowed = await authorizedPublicIp(req.url, resolveDns);
    if (!allowed || client.destroyed) return deny();
    remote = connect({ host: allowed.address, port: 443, timeout: 24000 });
    sockets.add(remote);
    remote.on("close", () => sockets.delete(remote));
    remote.once("connect", () => {
      if (client.destroyed) return remote.destroy();
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) remote.write(head);
      client.pipe(remote);
      remote.pipe(client);
    });
    remote.on("error", () => { if (!client.destroyed) client.destroy(); });
    remote.on("timeout", () => remote.destroy());
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return {
    url: "http://127.0.0.1:" + server.address().port,
    async close() {
      for (const sock of sockets) sock.destroy();
      await new Promise(resolve => server.close(() => resolve()));
    }
  };
}
