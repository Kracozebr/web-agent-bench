import { createConnection, createServer } from "node:net";

// AICODE-NOTE: Local acceptance fault affects only the read-only BEF observer
// transport. It neither intercepts SQL nor changes the authoritative database.
export async function startBetaRecoveryObserverProxy({ upstreamHost, upstreamPort }) {
  if (!["127.0.0.1", "localhost", "host.docker.internal"].includes(upstreamHost) ||
      !Number.isSafeInteger(upstreamPort) || upstreamPort < 1 || upstreamPort > 65535) {
    throw new Error("recovery_observer_proxy_upstream_invalid");
  }
  const sockets = new Set();
  const intervals = [];
  let blocked = false;
  let rejectedConnections = 0;
  const track = (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); return socket; };
  const server = createServer((downstream) => {
    track(downstream);
    downstream.on("error", () => undefined);
    if (blocked) { rejectedConnections += 1; downstream.destroy(); return; }
    const upstream = track(createConnection({ host: upstreamHost, port: upstreamPort }));
    upstream.on("error", () => downstream.destroy());
    downstream.once("close", () => upstream.destroy());
    upstream.once("close", () => downstream.destroy());
    downstream.pipe(upstream).pipe(downstream);
  });
  await new Promise((done, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", done); });
  return {
    port: server.address().port,
    block() {
      if (blocked) throw new Error("recovery_observer_proxy_already_blocked");
      blocked = true;
      intervals.push({ startedAt: new Date().toISOString(), endedAt: null });
      for (const socket of sockets) socket.destroy();
    },
    unblock() {
      if (!blocked) throw new Error("recovery_observer_proxy_not_blocked");
      intervals.at(-1).endedAt = new Date().toISOString();
      blocked = false;
    },
    snapshot() {
      return { schemaVersion: "beta-recovery-observer-fault/v1", blocked, rejectedConnections,
        intervals: intervals.map((row) => ({ ...row })), boundary: "readonly_observer_tcp_unavailable" };
    },
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise((done, reject) => server.close((error) => error ? reject(error) : done()));
    },
  };
}
