import assert from "node:assert/strict";
import { createConnection, createServer } from "node:net";
import test from "node:test";
import { startBetaRecoveryObserverProxy } from "./beta-recovery-observer-proxy.mjs";

test("observer outage drops active connections, refuses new reads and permits recovery without changing upstream", async () => {
  const upstream = createServer((socket) => socket.pipe(socket));
  await new Promise((done) => upstream.listen(0, "127.0.0.1", done));
  const proxy = await startBetaRecoveryObserverProxy({ upstreamHost: "127.0.0.1", upstreamPort: upstream.address().port });
  const connect = () => new Promise((done, reject) => {
    const socket = createConnection({ host: "127.0.0.1", port: proxy.port }, () => done(socket));
    socket.on("error", reject);
  });
  const echo = (socket, value) => new Promise((done) => {
    socket.once("data", (bytes) => done(bytes.toString())); socket.write(value);
  });
  try {
    const first = await connect();
    assert.equal(await echo(first, "original-read"), "original-read");
    const closed = new Promise((done) => first.once("close", done));
    proxy.block();
    await closed;
    const refused = await connect();
    await new Promise((done) => refused.once("close", done));
    assert.equal(proxy.snapshot().rejectedConnections, 1);
    proxy.unblock();
    const recovered = await connect();
    assert.equal(await echo(recovered, "original-read"), "original-read");
    recovered.destroy();
    assert.ok(proxy.snapshot().intervals[0].endedAt);
    assert.equal(proxy.snapshot().blocked, false);
  } finally { await proxy.close(); await new Promise((done) => upstream.close(done)); }
});
