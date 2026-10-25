import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { REPOSITORY_ROOT, EVIDENCE_ROOT, assertSecretFree, sha256 } from "./evidence.mjs";

const SCENARIO_IDS = Array.from({ length: 15 }, (_, index) => `TBB-SC-${String(index + 1).padStart(3, "0")}`);
const CONTRACT_PATH = resolve(REPOSITORY_ROOT, "tests/bdd/changes/tester-bonus-billing/harness-contracts.json");
const ACTIVE_SCHEMA = "tester-bonus-billing-acceptance/v1";
const INDEX_SCHEMA = "tester-bonus-billing-evidence-index/v1";

function assertScenarioId(value) {
  if (!SCENARIO_IDS.includes(value)) throw new Error(`Unsupported TBB scenario identity: ${String(value)}`);
  return value;
}

function scenarioRoot(scenarioId) {
  return resolve(EVIDENCE_ROOT, assertScenarioId(scenarioId));
}

async function readContract(contract) {
  if (contract && typeof contract === "object" && contract.protected_scenarios) return contract;
  const bytes = await readFile(CONTRACT_PATH);
  const parsed = JSON.parse(bytes.toString("utf8"));
  if (!parsed || typeof parsed.protected_scenarios !== "object") {
    throw new Error("Active TBB harness contract is missing protected scenarios");
  }
  return parsed;
}

async function writeArtifact(runDirectory, scenarioId, name, boundary, payload) {
  assertScenarioId(scenarioId);
  if (!["browser.json", "database.json", "provenance.json"].includes(name)) {
    throw new Error(`Unsupported TBB evidence artifact: ${name}`);
  }
  assertSecretFree(payload, `${scenarioId}/${name}`);
  const bytes = Buffer.from(`${JSON.stringify(payload, null, 2)}\n`, "utf8");
  await writeFile(resolve(runDirectory, name), bytes, { flag: "wx" });
  return { path: name, sha256: sha256(bytes), boundary, contentType: "application/json" };
}

async function publishIndex(scenarioId, runId, status, blockedReasonCode) {
  const root = scenarioRoot(scenarioId);
  await mkdir(root, { recursive: true });
  const indexPath = resolve(root, "manifest.json");
  let previousRuns = [];
  try {
    const previous = JSON.parse(await readFile(indexPath, "utf8"));
    if (previous.schemaVersion === INDEX_SCHEMA && Array.isArray(previous.runs)) {
      previousRuns = previous.runs.filter((item) => typeof item === "string" && /^[0-9a-f-]{36}$/.test(item));
    }
  } catch {
    // A missing or malformed earlier index is not used as evidence.
  }
  const index = {
    schemaVersion: INDEX_SCHEMA,
    scenarioId,
    latestRunId: runId,
    status,
    runs: [...new Set([...previousRuns, runId])],
    ...(blockedReasonCode ? { blockedReasonCode } : {}),
  };
  assertSecretFree(index, `${scenarioId}/manifest-index`);
  const temporary = resolve(root, `.manifest-${runId}.tmp`);
  await writeFile(temporary, `${JSON.stringify(index, null, 2)}\n`, { flag: "wx" });
  await rename(temporary, indexPath);
}

function blockedArtifact(scenarioId, reasonCode, boundary) {
  return {
    schemaVersion: `tbb-${boundary}-observation/v1`,
    scenarioId,
    observationStatus: "not_run",
    reasonCode,
  };
}

export async function saveBillingEvidence({
  browserData = {},
  databaseData = {},
  provenance = {},
  sc001Ready = false,
  sc002Ready = false,
  blockedScenarios = {},
  contract: contractInput,
}) {
  const contract = await readContract(contractInput);
  const results = [];
  for (const scenarioId of SCENARIO_IDS) {
    const row = contract.protected_scenarios[scenarioId];
    if (!row || !Array.isArray(row.required_observations) || !Array.isArray(row.negative_variants)) {
      throw new Error(`TBB contract inventory is incomplete for ${scenarioId}`);
    }
    const runId = randomUUID();
    const root = scenarioRoot(scenarioId);
    const runDirectory = resolve(root, "runs", runId);
    await mkdir(runDirectory, { recursive: true });

    const candidateBrowser = browserData[scenarioId];
    const candidateDatabase = databaseData[scenarioId];
    const hasRawBoundary = scenarioId === "TBB-SC-001" || scenarioId === "TBB-SC-002";
    const hasPartialTbb013 = scenarioId === "TBB-SC-013" && candidateBrowser && candidateDatabase;
    const hasCapturedBoundary = hasRawBoundary || hasPartialTbb013;
    const safeBrowser = hasCapturedBoundary && candidateBrowser
      ? candidateBrowser
      : blockedArtifact(scenarioId, blockedScenarios[scenarioId] ?? "required_product_boundary_unavailable", "browser");
    const safeDatabase = hasCapturedBoundary && candidateDatabase
      ? candidateDatabase
      : blockedArtifact(scenarioId, blockedScenarios[scenarioId] ?? "required_product_boundary_unavailable", "database");
    const safeProvenance = {
      schemaVersion: "tbb-provenance/v1",
      ...provenance,
      contractSha256: provenance.contractSha256 ?? sha256(await readFile(CONTRACT_PATH)),
      source: provenance.source ?? "local Docker Fastify/PostgreSQL/Next.js acceptance fixture",
      identity: provenance.identity ?? "synthetic local owner/admin/agent identities",
    };
    const artifacts = [];
    artifacts.push(await writeArtifact(runDirectory, scenarioId, "browser.json",
      hasRawBoundary ? "actual-admin-browser-and-scoped-http"
        : hasPartialTbb013 ? "partial-owner-financial-policy-browser-observation-not-full-TBB-SC-013"
          : "blocked-boundary-no-browser-action", safeBrowser));
    artifacts.push(await writeArtifact(runDirectory, scenarioId, "database.json",
      hasRawBoundary ? "independent-oid_observer-read-only-postgresql"
        : hasPartialTbb013 ? "partial-owner-financial-policy-read-only-database-observation-not-full-TBB-SC-013"
          : "blocked-boundary-no-database-claim", safeDatabase));
    artifacts.push(await writeArtifact(runDirectory, scenarioId, "provenance.json",
      "source-contract-and-local-runtime-provenance", safeProvenance));

    const passed = scenarioId === "TBB-SC-001" ? sc001Ready === true
      : scenarioId === "TBB-SC-002" ? sc002Ready === true : false;
    const blockedReasonCode = passed ? undefined
      : blockedScenarios[scenarioId]
        ?? (hasRawBoundary ? "required_observations_not_complete" : "required_product_boundary_unavailable");
    const notObserved = (reasonCode) => ({ status: "not_run", reasonCode });
    const manifest = {
      schemaVersion: ACTIVE_SCHEMA,
      specProfile: "active-delta",
      scenarioId,
      runId,
      status: passed ? "passed" : "blocked",
      ...(passed ? {} : { blockedReasonCode }),
      observationStatus: passed ? "complete" : "not_run",
      negativeVariantStatus: passed ? "complete" : "not_run",
      statusDetail: passed
        ? "Real admin UI grant, server authorization, restart replay and independent PostgreSQL evidence were captured."
        : hasRawBoundary
          ? "The first-slice evidence is retained, but one or more contract observations or negatives are incomplete."
          : hasPartialTbb013
            ? "Partial owner financial-policy UI and database observations are retained; the full TBB-SC-013 contract remains blocked."
            : "The required actual forum, coordinator, refund or pilot projection boundary is not implemented in this first slice.",
      observations: Object.fromEntries(row.required_observations.map((name) => [name,
        passed ? { status: "observed", evidence: ["browser.json", "database.json"] }
          : notObserved(blockedReasonCode)])),
      negativeVariants: Object.fromEntries(row.negative_variants.map((name) => [name,
        passed ? { status: "observed", evidence: ["browser.json", "database.json"] }
          : notObserved(blockedReasonCode)])),
      artifacts,
    };
    assertSecretFree(manifest, `${scenarioId}/manifest`);
    await writeFile(resolve(runDirectory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx" });
    await publishIndex(scenarioId, runId, manifest.status, blockedReasonCode);
    results.push({ scenarioId, runId, status: manifest.status, ...(blockedReasonCode ? { blockedReasonCode } : {}) });
  }
  return results;
}

export { ACTIVE_SCHEMA as BILLING_EVIDENCE_SCHEMA };
