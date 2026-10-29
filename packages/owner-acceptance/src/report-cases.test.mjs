import assert from "node:assert/strict";
import test from "node:test";
import { attachSafeBrowserCapture } from "./browser-support.mjs";
import { browserEvidence, captureOwnerReport } from "./report-cases.mjs";

function reportUi({ payloadOverrides = {} } = {}) {
  const fills = {};
  const openedContext = [];
  const actions = [];
  const operationId = "0123456789abcdef0123456789abcdef";
  const reportId = "11111111-1111-4111-8111-111111111111";
  const capture = { capture: { requests: [] }, action: (...args) => actions.push(args) };
  let resolveResponse;
  const responsePromise = new Promise((resolve) => { resolveResponse = resolve; });
  let acceptedNotice = null;
  const page = {
    async goto() {},
    getByLabel(label) {
      return { async fill(value) { fills[label] = value; } };
    },
    getByText(text) {
      return { async click() { openedContext.push(text); } };
    },
    getByRole(role, options = {}) {
      if (role === "button" && options.name === "Submit report") {
        return { async click() {
          const payload = {
            operationId, title: fills.Title, body: fills["What happened?"], imageUploadIds: [],
            ...(fills["Run ID"] ? { runId: fills["Run ID"] } : {}),
            ...(fills["Task ID"] ? { taskId: fills["Task ID"] } : {}),
            ...(fills["Action ID"] ? { actionId: fills["Action ID"] } : {}),
          };
          Object.assign(payload, payloadOverrides);
          capture.capture.requests.push({ method: "POST", path: "/api/owner/reports", operationId });
          const request = { method: () => "POST", postDataJSON: () => payload };
          resolveResponse({
            url: () => "http://127.0.0.1:3000/api/owner/reports",
            request: () => request,
            status: () => 201,
            async json() { return { report: { id: reportId }, replayed: false }; },
          });
        } };
      }
      if (role === "status") {
        return { filter({ hasText }) {
          acceptedNotice = hasText;
          return { async waitFor({ state }) { assert.equal(state, "visible"); } };
        } };
      }
      throw new Error(`Unexpected role locator: ${role}`);
    },
    async waitForResponse(predicate) {
      const response = await responsePromise;
      assert.equal(predicate(response), true, "the awaited response must be the owner report POST");
      return response;
    },
  };
  return { page, capture, fills, openedContext, actions, getAcceptedNotice: () => acceptedNotice,
    operationId, reportId };
}

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

test("linked owner report UI submits the real run, task, and action context", async () => {
  const ui = reportUi();
  const accepted = [];
  const context = {
    runId: "22222222-2222-4222-8222-222222222222",
    taskId: "S1",
    actionId: "33333333-3333-4333-8333-333333333333",
  };
  const result = await captureOwnerReport({
    page: ui.page, capture: ui.capture, title: "Bound action report", body: "Synthetic non-secret local report.",
    linkedRunId: context.runId, linkedTaskId: context.taskId, linkedActionId: context.actionId,
    imageBuffer: null, trace: {}, captureRoot: ".", browserErrors: [],
    onAcceptedReport: async (event) => accepted.push(event),
  });

  assert.deepEqual(ui.openedContext, ["Optional run context"]);
  assert.deepEqual(ui.fills, {
    Title: "Bound action report", "What happened?": "Synthetic non-secret local report.",
    "Run ID": context.runId, "Task ID": context.taskId, "Action ID": context.actionId,
  });
  assert.equal(accepted.length, 1);
  assert.deepEqual(accepted[0].payload, {
    operationId: ui.operationId, title: "Bound action report", body: "Synthetic non-secret local report.",
    imageUploadIds: [], ...context,
  });
  assert.equal(result.responseStatus, 201);
  assert.equal(accepted[0].payload.actionId, context.actionId);
  assert.equal(accepted[0].payload.taskId, context.taskId);
  assert.equal(accepted[0].payload.runId, context.runId);
  assert.equal(ui.getAcceptedNotice(), "Your report was submitted.");
  assert.deepEqual(ui.actions, [["click", "owner-report-submit-linked"]]);
});

test("linked owner report refuses an accepted response missing the requested action binding", async () => {
  const ui = reportUi({ payloadOverrides: { actionId: undefined } });
  let callbackCalled = false;
  await assert.rejects(captureOwnerReport({
    page: ui.page, capture: ui.capture, title: "Bound action report", body: "Synthetic non-secret local report.",
    linkedRunId: "22222222-2222-4222-8222-222222222222", linkedTaskId: "S1",
    linkedActionId: "33333333-3333-4333-8333-333333333333", imageBuffer: null,
    trace: {}, captureRoot: ".", browserErrors: [], onAcceptedReport: async () => { callbackCalled = true; },
  }), /accepted report request body could not be correlated/);
  assert.equal(callbackCalled, false);
});
