import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { startBetaRecoveryFaultProxy } from "./beta-recovery-fault-proxy.mjs";
import { assertSecretFree } from "./evidence.mjs";

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

test("proxy-generated 502 retains bounded transport causality without retransmission or secrets", async () => {
  let requests = 0;
  const upstream = createServer(request => { requests++; request.socket.destroy(); });
  await new Promise(done => upstream.listen(0, "127.0.0.1", done));
  const proxy = await startBetaRecoveryFaultProxy({ upstreamOrigin: `http://127.0.0.1:${upstream.address().port}` });
  try {
    const response = await fetch(proxy.origin + "/approve?private-query=hidden", {
      method: "POST", headers: { "idempotency-key": "task-action-22222222-2222-4222-8222-222222222222",
        authorization: "Bearer private-auth-hidden" }, body: "private-body-hidden",
    });
    assert.equal(response.status, 502);
    assert.equal(await response.text(), "");
    assert.equal(requests, 1);
    const snapshot = proxy.snapshot(), failure = snapshot.transportFailures[0];
    assert.equal(snapshot.transportFailures.length, 1);
    assert.equal(snapshot.omittedTransportFailures, 0);
    assert.equal(snapshot.submissions[0].count, 1);
    assert.equal(failure.actionId, "22222222-2222-4222-8222-222222222222");
    assert.equal(failure.path, "/approve");
    assert.equal(failure.errorCode, "ECONNRESET");
    assert.equal(failure.generatedHttpStatus, 502);
    assert.equal(failure.upstreamResponseStartedAt, undefined);
    assert.ok(Date.parse(failure.upstreamConnectedAt) >= Date.parse(failure.requestStartedAt));
    assert.ok(Date.parse(failure.errorObservedAt) >= Date.parse(failure.upstreamConnectedAt));
    assert.equal(/private-|hidden/.test(JSON.stringify(snapshot)), false);
  } finally {
    await proxy.close();
    await new Promise(done => upstream.close(done));
  }
});

test("x402 challenge and one signed settlement remain distinct when the settlement reply is lost", async () => {
  let settlements = 0;
  const upstream = createServer((request, response) => {
    const paid = typeof request.headers["payment-signature"] === "string";
    if (paid) settlements++;
    response.writeHead(paid ? 200 : 402, { "content-type": "application/json" });
    response.end(JSON.stringify(paid ? { settled: true } : { paymentRequired: true }));
  });
  await new Promise(done => upstream.listen(0, "127.0.0.1", done));
  const proxy = await startBetaRecoveryFaultProxy({ upstreamOrigin: `http://127.0.0.1:${upstream.address().port}` });
  try {
    const payPath = "/tools/bef-env-a/pay";
    for (const path of ["//pay", "/tools/../pay", "/tools/bef-env-a/pay?token=hidden"]) {
      assert.throws(() => proxy.arm({ path }), /arm_invalid/);
    }
    proxy.arm({ path: payPath });
    const headers = { "idempotency-key": "task-action-33333333-3333-4333-8333-333333333333" };
    const challenge = await fetch(proxy.origin + payPath, { method: "POST", headers, body: "{}" });
    assert.equal(challenge.status, 402);
    await challenge.arrayBuffer();
    await assert.rejects(fetch(proxy.origin + payPath, { method: "POST",
      headers: { ...headers, "payment-signature": "private-proof-never-retained" }, body: "{}" }));
    const snapshot = proxy.snapshot(), rows = snapshot.actionRequests;
    assert.equal(settlements, 1);
    assert.equal(snapshot.submissions[0].count, 2);
    assert.equal(snapshot.omittedActionRequests, 0);
    assert.ok(rows.every(row => row.path === payPath));
    assert.deepEqual(rows.map(r => [r.ordinal, r.paymentProofPresent, r.upstreamStatus, r.upstreamResponseComplete]),
      [[1, false, 402, true], [2, true, 200, true]]);
    assert.deepEqual(rows.map(r => r.downstreamResponseFinished), [true, false]);
    assert.equal(rows[1].upstreamResponseSha256, snapshot.fault.upstreamResponseSha256);
    assert.equal(rows[1].responseBytes, snapshot.fault.responseBytes);
    assert.equal(JSON.stringify(snapshot).includes("private-proof"), false);
    assertSecretFree(snapshot, "protocol-phase-test");
  } finally {
    await proxy.close();
    await new Promise(done => upstream.close(done));
  }
});
