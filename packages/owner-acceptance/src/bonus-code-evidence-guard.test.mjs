import assert from "node:assert/strict";
import test from "node:test";
import { assertSecretFree } from "./bonus-code-evidence.mjs";

test("BPC-SC-005's direct-service schema marker is not mistaken for a redemption code", () => {
  assert.doesNotThrow(() => assertSecretFree({
    schemaVersion: "bpc-sc005-bonus-only-cash-substitution/v1",
  }, "safe-schema"));
});

test("a real BPC-prefixed 43-character secret still fails the evidence guard", () => {
  assert.throws(() => assertSecretFree({ value: `BPC-${"A".repeat(43)}` }, "unsafe-fixture"),
    /credential-like text/);
});
