import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import pg from "pg";
import { attachSafeBrowserCapture } from "./browser-support.mjs";
import { assertSecretFree, sha256 } from "./evidence.mjs";

async function snapshot(pool, ownerId, agentId) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    const identity = (await client.query("SELECT current_user AS role, current_setting('transaction_read_only') AS transaction_read_only")).rows[0];
    assert.equal(identity.role, "oid_observer");
    assert.equal(identity.transaction_read_only, "on");
    const tables = ["oid_run_launch_intent", "oid_benchmark_run", "oid_ledger_entry"];
    const rows = {};
    for (const table of tables) {
      // Table names are fixed source constants; only synthetic fixture identity is a parameter.
      rows[table] = (await client.query(`SELECT * FROM ${table} WHERE owner_id=$1 ORDER BY id`, [ownerId])).rows;
    }
    rows.slots = (await client.query("SELECT * FROM oid_run_execution_slot WHERE agent_id=$1", [agentId])).rows;
    await client.query("COMMIT");
    return { identity, rows };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally { client.release(); }
}

// AICODE-NOTE: This captures only the real browser/API/database unavailable-release
// boundary. It cannot pass BRL-023/024/025 or substitute for a positive 12-case release.
export async function runLaunchBoundaryCases({ page, ownerId, agentId, observerDatabaseUrl }) {
  const pool = new pg.Pool({ connectionString: observerDatabaseUrl, max: 1 });
  const capture = attachSafeBrowserCapture(page, "BRL-SC-025");
  try {
    const before = await snapshot(pool, ownerId, agentId);
    capture.action("navigate", "/runs");
    await page.goto("/runs", { waitUntil: "domcontentloaded" });
    await page.getByTestId("run-launch-page").waitFor({ state: "visible" });
    await page.getByTestId("run-catalog-status").waitFor({ state: "visible" });
    const catalogResponse = await page.request.get("/api/owner/runs/catalog");
    assert.equal(catalogResponse.status(), 200);
    const catalog = await catalogResponse.json();
    // A genuine complete release needs a separate positive browser/client capture.
    assert.equal(catalog.activeRelease, null, "Update this blocked-boundary capture when an actual release becomes available");
    assert.equal(await page.getByTestId("run-intent-create").isDisabled(), true);
    capture.action("click", "run-intents-refresh");
    await page.getByTestId("run-intents-refresh").click();
    await page.getByTestId("run-intents-refresh").waitFor({ state: "visible" });
    const operationId = randomUUID();
    const denied = await page.request.post("/api/owner/runs/intents", {
      headers: { origin: new URL(page.url()).origin },
      data: { operationId, agentId, mode: "training", taskIds: ["S1"], cashCeiling: "0.000000",
        expectedReleaseIdentity: "unavailable-release-reference", expectedManifestHash: "0".repeat(64), expectedQuotePrice: "0.033334" },
    });
    const denialBody = await denied.json();
    assert.ok([403, 409, 503].includes(denied.status()), "Unavailable release must reject admission");
    assert.equal(typeof denialBody?.error?.code, "string");
    assert.equal(Object.hasOwn(denialBody, "intent"), false);
    const after = await snapshot(pool, ownerId, agentId);
    assert.deepEqual(after.rows, before.rows, "Blocked launch changed persisted financial/run/slot state");
    const result = {
      schemaVersion: "run-launch-boundary-capture/v1",
      status: "partial_blocked",
      scope: "Browser readiness display/disabled launch and separate direct API rejection; no positive launch/client execution claim",
      fullScenarioAcceptance: false,
      blockedReason: "complete_validated_task_release_and_execution_reference_evidence_unavailable",
      ownerId, agentId, catalog,
      browserCapture: capture.capture,
      apiDenial: { operationId, status: denied.status(), errorCode: denialBody.error.code },
      database: { before, after },
    };
    assertSecretFree(result);
    return result;
  } finally { await pool.end(); }
}

export async function saveLaunchBoundaryCapture({ result, provenance, repoRoot }) {
  const captureId = randomUUID();
  const directory = resolve(repoRoot, "artifacts/runs/launch-boundary", captureId);
  await mkdir(directory, { recursive: true });
  const payload = { ...result, provenance };
  assertSecretFree(payload);
  const bytes = Buffer.from(JSON.stringify(payload, null, 2) + "\n");
  await writeFile(resolve(directory, "capture.json"), bytes, { flag: "wx" });
  const manifest = { captureId, status: "partial_blocked", fullScenarioAcceptance: false,
    artifacts: [{ path: "capture.json", sha256: sha256(bytes) }] };
  await writeFile(resolve(directory, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n", { flag: "wx" });
  return { ...manifest, directory };
}
