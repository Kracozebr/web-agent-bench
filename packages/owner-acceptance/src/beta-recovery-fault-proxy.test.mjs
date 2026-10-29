import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { startBetaRecoveryFaultProxy } from "./beta-recovery-fault-proxy.mjs";

test("lost response follows exactly one committed upstream action and retains no secret material", async () => {
  let committed = 0;
  const upstream = createServer((request, response) => {
    if (request.method === "POST") committed += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ committed, privateFixtureValue: "not-in-metadata" }));
  });
  await new Promise((done) => upstream.listen(0, "127.0.0.1", done));
  const proxy = await startBetaRecoveryFaultProxy({ upstreamOrigin: `http://127.0.0.1:${upstream.address().port}` });
  try {
    proxy.arm({ path: "/wrap" });
    const key = "task-action-11111111-1111-4111-8111-111111111111";
    await assert.rejects(fetch(proxy.origin + "/wrap", { method: "POST", headers: {
      "idempotency-key": key, authorization: "Bearer private-fixture-credential",
    }, body: "{}" }));
    assert.equal(committed, 1);
    const snapshot = proxy.snapshot();
    assert.equal(snapshot.fault.upstreamResponseComplete, true);
    assert.equal(snapshot.fault.downstreamResponseDelivered, false);
    assert.equal(snapshot.submissions[0].count, 1);
    assert.match(snapshot.fault.upstreamResponseSha256, /^[0-9a-f]{64}$/);
    assert.equal(JSON.stringify(snapshot).includes("private-fixture"), false);
    assert.equal(JSON.stringify(snapshot).includes("not-in-metadata"), false);
    assert.equal((await fetch(proxy.origin + "/healthz")).status, 200);
    assert.throws(() => proxy.arm(), /arm_invalid/);
  } finally {
    await proxy.close();
    await new Promise((done) => upstream.close(done));
  }
});

test("fault proxy refuses remote or credential-bearing upstreams", async () => {
  for (const origin of ["https://127.0.0.1", "http://example.com", "http://user:secret@localhost", "http://localhost/path"]) {
    await assert.rejects(startBetaRecoveryFaultProxy({ upstreamOrigin: origin }), /upstream_invalid/);
  }
});
