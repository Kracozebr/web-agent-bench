import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, mkdir, copyFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { saveReportEvidence } from "./report-evidence.mjs";

const scenarioIds = ["BPC-SC-018", "BPC-SC-019", "BPC-SC-020", "BPC-SC-024", "BPC-SC-026"];
const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = [here, ...Array.from({ length: 5 }, (_, index) => resolve(here, "../".repeat(index + 1)))]
  .find((candidate) => existsSync(resolve(candidate, "tests/bdd/changes/beta-poc-delivery/harness-contracts.json")));
if (!repositoryRoot) throw new Error("Could not locate the repository BPC harness contract");

test("report evidence writer hashes sanitized raw artifacts and keeps local facts not_run", async () => {
  const tempRoot = resolve(repositoryRoot, ".tmp");
  await mkdir(tempRoot, { recursive: true });
  const root = await mkdtemp(join(tempRoot, "bpc-report-evidence-"));
  try {
    const contractDir = resolve(root, "tests/bdd/changes/beta-poc-delivery");
    await mkdir(contractDir, { recursive: true });
    await copyFile(resolve(repositoryRoot, "tests/bdd/changes/beta-poc-delivery/harness-contracts.json"), join(contractDir, "harness-contracts.json"));
    const contract = JSON.parse(await readFile(join(contractDir, "harness-contracts.json"), "utf8"));
    const scenarioData = Object.fromEntries(scenarioIds.map((scenarioId) => [scenarioId, {
      scenarioId,
      localStatus: "observed_partial",
      captureEvidence: {
        schemaVersion: "bpc-report-runtime-observation/v1",
        scenarioId,
        boundaryDetail: contract.protected_scenarios[scenarioId].boundary_detail,
        captureBoundary: "local_acceptance_runner",
        browser: {},
        observer: { databaseRole: "oid_observer", transactionReadOnly: "on", before: {}, after: {} },
        negativeAttempts: [],
      },
    }]));
    const summary = await saveReportEvidence({
      result: { scenarioData, databaseIsolation: "dedicated_unique_acceptance_database" },
      provenance: { runId: "run-fixture", sourceStableDuringRun: true,
        inputHashesBefore: { "packages/owner-identity/src/report-service.ts": "a".repeat(64) },
        inputHashesAfter: { "packages/owner-identity/src/report-service.ts": "a".repeat(64) } },
      repositoryRoot: root,
    });
    assert.equal(summary.scenarios.length, scenarioIds.length);
    for (const row of summary.scenarios) {
      assert.equal(row.status, "blocked");
      const manifestPath = resolve(root, row.manifestPath);
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      assert.equal(manifest.status, "blocked");
      assert.ok(Object.values(manifest.observations).every((fact) => fact.status === "not_run"));
      assert.ok(Object.values(manifest.negativeVariants).every((fact) => fact.status === "not_run"));
      const runtimeRow = manifest.artifacts.find((artifact) => artifact.path === "runtime-evidence.json");
      assert.ok(runtimeRow && /^[0-9a-f]{64}$/.test(runtimeRow.sha256));
      const runtime = JSON.parse(await readFile(join(resolve(manifestPath, ".."), "runtime-evidence.json"), "utf8"));
      assert.equal(runtime.captureBoundary, "local_acceptance_runner");
      const provenance = JSON.parse(await readFile(join(resolve(manifestPath, ".."), "provenance.json"), "utf8"));
      assert.equal(provenance.contractSha256, summary.contractSha256);
      assert.deepEqual(provenance.inputHashesBefore, provenance.inputHashesAfter);
    }
    const secondSummary = await saveReportEvidence({
      result: { scenarioData, databaseIsolation: "dedicated_unique_acceptance_database" },
      provenance: { runId: "run-fixture-2", sourceStableDuringRun: true,
        inputHashesBefore: { "packages/owner-identity/src/report-service.ts": "a".repeat(64) },
        inputHashesAfter: { "packages/owner-identity/src/report-service.ts": "a".repeat(64) } },
      repositoryRoot: root,
    });
    for (const row of secondSummary.scenarios) {
      const indexPath = resolve(root, "artifacts/runs/acceptance", row.scenarioId, "manifest.json");
      const index = JSON.parse(await readFile(indexPath, "utf8"));
      assert.equal(index.latestRunId, row.manifestPath.split("/").at(-2));
      assert.equal(index.runs.length, 2);
    }
  } finally {
    await rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  }
});
