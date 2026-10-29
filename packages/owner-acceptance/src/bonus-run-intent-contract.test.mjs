import assert from "node:assert/strict";
import test from "node:test";
import { validateCreatedRunIntent } from "./run-intent-contract.mjs";

const UUID = "11111111-1111-4111-8111-111111111111";
const TASK_IDS = ["S1"];

function fixture({ id = UUID, price = "1.000000", taskIds = TASK_IDS } = {}) {
  return {
    responseStatus: 201,
    agentId: "22222222-2222-4222-8222-222222222222",
    expectedQuote: "1.000000",
    expectedTaskIds: TASK_IDS,
    request: { operationId: "01234567-89ab-4cde-8f01-23456789abcd", expectedQuotePrice: "1.000000", taskIds: TASK_IDS },
    body: { intent: { id, agentId: "22222222-2222-4222-8222-222222222222", mode: "training", taskIds,
      quote: { price, precision: 6, token: "USDC" } } },
  };
}

test("created run intent accepts the API's nested quote shape and exact selection", () => {
  const result = validateCreatedRunIntent(fixture());
  assert.equal(result.intentId, UUID);
  assert.deepEqual(result.taskIds, TASK_IDS);
  assert.equal(result.quotePrice, "1.000000");
});

test("HTTP 201 with a missing id, wrong quote, or altered task selection fails closed", () => {
  const missingId = fixture();
  delete missingId.body.intent.id;
  assert.throws(() => validateCreatedRunIntent(missingId));
  assert.throws(() => validateCreatedRunIntent(fixture({ price: "0.999999" })));
  assert.throws(() => validateCreatedRunIntent(fixture({ taskIds: ["S2"] })));
});
