import assert from "node:assert/strict";
import test from "node:test";
import {
  browserCaptureApi,
  captureRows,
  capturedOperation,
  hasCodeError,
  sameRedemptionReceipt,
} from "./bonus-code-capture-contract.mjs";

function makeCapture() {
  return {
    scenarioId: "BPC-SC-004",
    actions: [],
    requests: [
      { method: "POST", path: "/api/owner/bonus-codes/redeem", operationId: "first-operation-id" },
      { method: "POST", path: "/api/owner/bonus-codes/redeem", operationId: "second-operation-id" },
    ],
    responses: [],
  };
}

test("capture helpers accept raw rows and the browser wrapper without confusing their shapes", () => {
  const rows = makeCapture();
  let actionThis;
  const wrapper = {
    capture: rows,
    action(name, selector) {
      actionThis = this;
      this.capture.actions.push({ action: name, selector });
    },
  };

  assert.equal(captureRows(rows), rows);
  assert.equal(captureRows(wrapper), rows);
  assert.throws(() => browserCaptureApi(rows), /attachSafeBrowserCapture wrapper/);

  const api = browserCaptureApi(wrapper);
  assert.equal(api.rows, rows);
  api.action("click", "bonus-code-redeem-submit");
  assert.equal(actionThis, wrapper);
  assert.deepEqual(rows.actions, [{ action: "click", selector: "bonus-code-redeem-submit" }]);
});

test("captured operation lookup works for raw and wrapped captures and respects the start offset", () => {
  const rows = makeCapture();
  const wrapper = { capture: rows, action() {} };

  assert.equal(capturedOperation(rows, "/api/owner/bonus-codes/redeem"), "second-operation-id");
  assert.equal(capturedOperation(wrapper, "/api/owner/bonus-codes/redeem", "POST", 1), "second-operation-id");
  assert.equal(capturedOperation(rows, "/api/owner/bonus-codes/redeem", "POST", 2), null);
  assert.equal(capturedOperation(rows, "/api/owner/bonus-codes/redeem", "GET"), null);
});

test("same-owner replay after disable or exhaustion requires the original receipt and grant", () => {
  const original = { status: 200, redemptionId: "receipt-1", grantId: "grant-1" };
  assert.equal(sameRedemptionReceipt(original, { status: 200, redemptionId: "receipt-1", grantId: "grant-1" }), true);
  assert.equal(sameRedemptionReceipt(original, { status: 200, redemptionId: "receipt-2", grantId: "grant-1" }), false);
  assert.equal(sameRedemptionReceipt(original, { status: 200, redemptionId: "receipt-1", grantId: "grant-2" }), false);
  assert.equal(sameRedemptionReceipt(original, { status: 409, redemptionId: "receipt-1", grantId: "grant-1" }), false);
});

test("a different owner receives the explicit disabled or exhausted code error", () => {
  assert.equal(hasCodeError({ status: 409, errorCode: "BONUS_CODE_DISABLED" }, 409, "BONUS_CODE_DISABLED"), true);
  assert.equal(hasCodeError({ status: 409, errorCode: "BONUS_CODE_EXHAUSTED" }, 409, "BONUS_CODE_DISABLED"), false);
  assert.equal(hasCodeError({ status: 200, errorCode: "BONUS_CODE_DISABLED" }, 409, "BONUS_CODE_DISABLED"), false);
});
