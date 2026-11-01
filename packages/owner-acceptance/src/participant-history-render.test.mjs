import assert from "node:assert/strict";
import test from "node:test";
import vm from "node:vm";
import { waitForHistoryRefreshRender } from "./participant-history-render.mjs";

// Unit boundary: emulate delayed DOM commits, not a backend or browser acceptance result.
function delayedPage(states) {
  let polls = 0;
  return { get polls() { return polls; }, async waitForFunction(predicate, args) {
    for (const state of states) {
      polls++;
      const document = { querySelector(selector) {
        if (selector.includes(args.refresh)) return { disabled: state.busy };
        if (selector.includes(`${args.section}-empty`)) return state.empty ? {} : null;
        return state.empty ? null : { querySelectorAll() { return state.ids.map((id) => ({ getAttribute: () => args.prefix + id })); } };
      } };
      const result = vm.runInNewContext(`(${predicate.toString()})(args)`, { args, document });
      if (result !== false) return { jsonValue: async () => JSON.parse(JSON.stringify(result)), dispose: async () => {} };
    }
    throw new Error("DOM never committed the response identities");
  } };
}
const resource = { section: "owner-runs", item: "owner-run-" };
test("refresh waits past the HTTP response, stale full traversal, and busy shared requests", async () => {
  const page = delayedPage([{ ids: ["old1", "old2"], busy: false }, { ids: ["new1"], busy: true }, { ids: ["new1"], busy: false }]);
  assert.deepEqual(await waitForHistoryRefreshRender(page, resource, "runs", [{ id: "new1" }]), ["new1"]);
  assert.equal(page.polls, 3);
});
test("refresh cannot accept a stale or incorrectly ordered render", async () => {
  const page = delayedPage([{ ids: ["old"], busy: false }, { ids: ["b", "a"], busy: false }]);
  await assert.rejects(waitForHistoryRefreshRender(page, resource, "runs", [{ id: "a" }, { id: "b" }]), /never committed/);
});
test("empty response waits for the actual empty-state marker", async () => {
  const page = delayedPage([{ ids: ["old"], busy: false }, { empty: true, busy: false }]);
  assert.deepEqual(await waitForHistoryRefreshRender(page, resource, "runs", []), []);
  assert.equal(page.polls, 2);
});
