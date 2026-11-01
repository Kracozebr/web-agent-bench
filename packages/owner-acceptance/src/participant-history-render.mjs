import assert from "node:assert/strict";

/** Wait for the actual response's identities to replace the browser rows, after every shared refresh request settles. */
export async function waitForHistoryRefreshRender(page, resource, kind, records) {
  assert.ok(Array.isArray(records), "History refresh records missing");
  const expectedIds = records.map((record) => record.id);
  assert.ok(expectedIds.every((id) => typeof id === "string") && new Set(expectedIds).size === expectedIds.length, "Invalid history refresh identities");
  const handle = await page.waitForFunction(({ section, prefix, selector, refresh, expectedIds }) => {
    const button = document.querySelector(`[data-testid="${refresh}"]`);
    if (!button || button.disabled) return false;
    const container = document.querySelector(`[data-testid="${section}"]`);
    if (!container) return expectedIds.length === 0 && document.querySelector(`[data-testid="${section}-empty"]`) ? [] : false;
    const actualIds = Array.from(container.querySelectorAll(selector), (row) => row.getAttribute("data-testid")?.slice(prefix.length));
    return JSON.stringify(actualIds) === JSON.stringify(expectedIds) ? actualIds : false;
  }, { section: resource.section, prefix: resource.item,
    selector: kind === "runs" || kind === "intents" ? ":scope > article" : "tbody > tr",
    refresh: kind === "runs" || kind === "intents" ? "run-intents-refresh" : "billing-refresh", expectedIds });
  try { return await handle.jsonValue(); }
  finally { await handle.dispose(); }
}
