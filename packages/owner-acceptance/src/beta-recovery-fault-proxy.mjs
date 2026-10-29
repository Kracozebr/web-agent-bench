import { createServer, request as httpRequest } from "node:http";
import { createHash } from "node:crypto";

const ACTION_KEY = /^task-action-([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

// AICODE-NOTE: Acceptance-only transport fault. The upstream executes normally;
// only a fully received successful response is withheld from the real worker.
// No request/response bodies, credentials or authorization headers are retained.
export async function startBetaRecoveryFaultProxy({ upstreamOrigin }) {
  const upstream = new URL(upstreamOrigin);
  if (upstream.protocol !== "http:" || upstream.pathname !== "/" || upstream.search || upstream.hash ||
      upstream.username || upstream.password ||
      !["127.0.0.1", "localhost", "host.docker.internal"].includes(upstream.hostname)) {
    throw new Error("recovery_proxy_upstream_invalid");
  }
  let armed = false;
  let pathFilter;
  let onDropped;
  let dropped;
  const incidents = [];
  const submissions = new Map();
  const sockets = new Set();
  const server = createServer((incoming, outgoing) => {
    const path = incoming.url ?? "/";
    if (!path.startsWith("/") || path.startsWith("//")) { outgoing.writeHead(400).end(); return; }
    const key = incoming.headers["idempotency-key"];
    const actionId = typeof key === "string" ? ACTION_KEY.exec(key)?.[1]?.toLowerCase() : undefined;
    if (actionId && incoming.method === "POST") submissions.set(actionId, (submissions.get(actionId) ?? 0) + 1);
    const eligible = armed && !dropped && actionId && incoming.method === "POST" &&
      (pathFilter === undefined || new URL(path, upstream).pathname === pathFilter);
    const forwarded = httpRequest({ hostname: upstream.hostname, port: upstream.port || 80,
      path, method: incoming.method, headers: { ...incoming.headers, host: upstream.host, connection: "close" } }, (response) => {
      if (!eligible || !armed || dropped || response.statusCode < 200 || response.statusCode >= 300) {
        outgoing.writeHead(response.statusCode ?? 502, response.headers);
        response.pipe(outgoing);
        return;
      }
      // Claim once as soon as this response is accepted, so concurrent requests
      // cannot accidentally create multiple lost-response incidents.
      armed = false;
      const digest = createHash("sha256");
      let bytes = 0;
      response.on("data", (chunk) => { digest.update(chunk); bytes += chunk.length; });
      response.on("end", () => {
        dropped = { actionId, method: incoming.method, path: new URL(path, upstream).pathname,
          upstreamStatus: response.statusCode, upstreamResponseSha256: digest.digest("hex"),
          responseBytes: bytes, upstreamResponseComplete: true, downstreamResponseDelivered: false,
          observedAt: new Date().toISOString() };
        try { onDropped?.({ ...dropped }); }
        catch { dropped.faultHookFailed = true; }
        finally { outgoing.destroy(); }
        incidents.push({ ...dropped });
      });
      response.on("error", () => outgoing.destroy());
    });
    forwarded.setTimeout(45_000, () => forwarded.destroy());
    forwarded.on("error", () => { if (!outgoing.headersSent) outgoing.writeHead(502); outgoing.end(); });
    incoming.on("error", () => forwarded.destroy());
    incoming.pipe(forwarded);
  });
  server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  await new Promise((done, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", done); });
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    arm({ path, onDrop } = {}) {
      if (armed || dropped || (path !== undefined && !/^\/[a-z_]+$/.test(path)) ||
          (onDrop !== undefined && typeof onDrop !== "function")) throw new Error("recovery_proxy_arm_invalid");
      pathFilter = path;
      onDropped = onDrop;
      armed = true;
    },
    snapshot() {
      return { schemaVersion: "beta-recovery-transport-fault/v1", fault: dropped ? { ...dropped } : null,
        incidents: incidents.map((row) => ({ ...row })),
        submissions: [...submissions].map(([actionId, count]) => ({ actionId, count })),
        upstreamOriginSha256: hash(upstream.origin),
        boundary: "real_upstream_http_response_withheld_after_complete_read" };
    },
    resetAfterIncident() {
      if (!dropped || armed) throw new Error("recovery_proxy_incident_not_complete");
      dropped = undefined;
      pathFilter = undefined;
      onDropped = undefined;
    },
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
    },
  };
}
