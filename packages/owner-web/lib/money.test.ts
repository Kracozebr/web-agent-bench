import assert from "node:assert/strict";
import test from "node:test";
import { moneyDisplay, ledgerDisplayAmount } from "./money";

test("money presentation preserves subcent, signed refund and rounding-edge accounting", () => {
  for (const [amount, summary, units] of [
    ["0", "0.00", "0"], ["0.000001", "<0.01", "1"], ["0.009999", "<0.01", "9999"],
    ["-0.000001", "-<0.01", "-1"], ["1.004999", "1.00", "1004999"],
    ["1.005000", "1.01", "1005000"], ["-1.005000", "-1.01", "-1005000"],
    ["9007199254740993.123456", "9007199254740993.12", "9007199254740993123456"],
  ]) assert.deepEqual(moneyDisplay(amount!), { summary, units });
  for (const amount of ["NaN", "Infinity", "1e3", "1.0000001", "01.00", "<script>"]) assert.equal(moneyDisplay(amount), null);
});

test("ledger direction derives from type while raw positive magnitudes stay intact", () => {
  assert.equal(ledgerDisplayAmount("debit", "0.000001"), "-0.000001");
  for (const type of ["refund", "reserve", "release", "grant"]) assert.equal(ledgerDisplayAmount(type, "0.000001"), "0.000001");
});
