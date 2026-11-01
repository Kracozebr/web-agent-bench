import assert from "node:assert/strict";
import test from "node:test";
import { exactPolicyLimit } from "./consent-financial-policy";

test("consent policy retains exact micro limits without rounding or Number precision loss", () => {
  assert.equal(exactPolicyLimit("0.000001"), "0.000001 USDC / 1 micro-USDC");
  assert.equal(exactPolicyLimit("0.000000"), "0.000000 USDC / 0 micro-USDC");
  assert.equal(exactPolicyLimit("9007199254740993.123456"), "9007199254740993.123456 USDC / 9007199254740993123456 micro-USDC");
  assert.equal(exactPolicyLimit(null), "Unlimited by this policy limit");
});

test("malformed or negative financial limits remain unavailable rather than appearing unlimited", () => {
  for (const amount of ["NaN", "Infinity", "-0.000001", "1e6", "01.000000", "0.0000001", "1.00", "<script>"]) {
    assert.equal(exactPolicyLimit(amount), "Unavailable");
  }
});
