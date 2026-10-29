import assert from "node:assert/strict";
import test from "node:test";
import { attachSafeBrowserCapture } from "./browser-support.mjs";
import { browserEvidence } from "./report-cases.mjs";

test("report browser evidence normalizes the actual capture wrapper and keeps the initiating click", () => {
  const registrations = [];
  const fakePage = { on: (event, handler) => registrations.push({ event, handler }) };
  const capture = attachSafeBrowserCapture(fakePage, "BPC-SC-018");
  capture.action("click", "owner-report-submit-linked");

  const evidence = browserEvidence(capture, "http://127.0.0.1:3000", { requests: [], responses: [] });

  assert.deepEqual(registrations.map(({ event }) => event), ["request", "response"]);
  assert.deepEqual(evidence.actions, [{ action: "click", controlId: "owner-report-submit-linked" }]);
  assert.deepEqual(evidence.requests, []);
  assert.deepEqual(evidence.responses, []);
});

test("report browser evidence fails closed when capture or trace arrays are missing", () => {
  assert.throws(() => browserEvidence({ capture: {} }, "http://127.0.0.1:3000", { requests: [], responses: [] }),
    /actions array/);
  assert.throws(() => browserEvidence({ actions: [] }, "http://127.0.0.1:3000", { requests: [] }),
    /request and response trace arrays/);
  assert.throws(() => browserEvidence({ actions: [null] }, "http://127.0.0.1:3000", { requests: [], responses: [] }),
    /invalid action row/);
});
