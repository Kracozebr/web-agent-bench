import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";

const SCENARIO_IDS = ["BPC-SC-003", "BPC-SC-004", "BPC-SC-005", "BPC-SC-006"];
const EVIDENCE_ROOT = "artifacts/runs/acceptance";

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertSecretFree(value, label) {
  const secretKey = /^(?:secret|plaintextcode|codeverifiersecret|databaseurl|authorization|cookie|password)$/i;
  const secretText = /(?<![A-Za-z0-9_-])BPC-[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])|\bBearer\s+\S+|(?:[?&](?:code|state|access_token|refresh_token|id_token|client_secret)=)[^&#\s]+/i;
  const visit = (current, path) => {
    if (Array.isArray(current)) {
      current.forEach((item, index) => visit(item, `${path}[${index}]`));
    } else if (current && typeof current === "object") {
      for (const [key, item] of Object.entries(current)) {
        if (secretKey.test(key.replace(/[^a-z]/gi, ""))) throw new Error(`${label} contains a prohibited secret field at ${path}.${key}`);
        visit(item, `${path}.${key}`);
      }
    } else if (typeof current === "string" && secretText.test(current)) {
      throw new Error(`${label} contains credential-like text at ${path}`);
    }
  };
  visit(value, label);
}

async function writeJson(runDirectory, name, payload, label, boundary) {
  assertSecretFree(payload, `${label}/${name}`);
  const bytes = Buffer.from(`${JSON.stringify(payload, null, 2)}\n`, "utf8");
  await writeFile(resolve(runDirectory, name), bytes, { flag: "wx", mode: 0o600 });
  return { path: name, sha256: digest(bytes), bytes: bytes.length, contentType: "application/json", boundary };
}

async function publishIndex(repositoryRoot, scenarioId, runId, status, blockedReasonCode) {
  const scenarioRoot = resolve(repositoryRoot, EVIDENCE_ROOT, scenarioId);
  await mkdir(scenarioRoot, { recursive: true, mode: 0o700 });
  const indexPath = resolve(scenarioRoot, "manifest.json");
  let previousRuns = [];
  try {
    const previous = JSON.parse(await readFile(indexPath, "utf8"));
    if (previous.schemaVersion === "beta-poc-delivery-evidence-index/v1" && Array.isArray(previous.runs)) {
      previousRuns = previous.runs.filter((value) => typeof value === "string" && /^[0-9a-f-]{36}$/.test(value));
    }
  } catch {
    // A prior malformed index is not trusted or retained.
  }
  const index = {
    schemaVersion: "beta-poc-delivery-evidence-index/v1",
    scenarioId,
    status,
    latestRunId: runId,
    runs: [...new Set([...previousRuns, runId])],
    ...(blockedReasonCode ? { blockedReasonCode } : {}),
  };
  assertSecretFree(index, `${scenarioId}/index`);
  const temporary = resolve(scenarioRoot, `.manifest-${runId}.tmp`);
  await writeFile(temporary, `${JSON.stringify(index, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  await rename(temporary, indexPath);
}

function blockedRecords(names, reasonCode) {
  return Object.fromEntries(names.map((name) => [name, { status: "not_run", reasonCode }]));
}

export async function saveBonusCodeEvidence({ result, provenance, repositoryRoot }) {
  if (!result || !result.scenarioData || typeof result.scenarioData !== "object") {
    throw new Error("Bonus-code capture did not return scenario data");
  }
  const contractPath = resolve(repositoryRoot, "tests/bdd/changes/beta-poc-delivery/harness-contracts.json");
  const contractBytes = await readFile(contractPath);
  const contractHash = digest(contractBytes);
  const contract = JSON.parse(contractBytes.toString("utf8"));
  const sourceStable = provenance?.sourceStableDuringRun === true;
  const saved = [];

  for (const scenarioId of SCENARIO_IDS) {
    const scenario = result.scenarioData[scenarioId];
    const definition = contract.protected_scenarios?.[scenarioId];
    if (!scenario || !definition) throw new Error(`Bonus-code contract or capture is missing ${scenarioId}`);
    const blockedReasonCode = !sourceStable
      ? "source_inputs_changed_during_run"
      : scenarioId === "BPC-SC-005" ? "target_host_and_training_worker_not_available" : "beta_target_host_not_selected";
    const runId = randomUUID();
    const scenarioRoot = resolve(repositoryRoot, EVIDENCE_ROOT, scenarioId);
    const runDirectory = resolve(scenarioRoot, "runs", runId);
    await mkdir(runDirectory, { recursive: true, mode: 0o700 });

    const runtimeEvidence = {
      schemaVersion: "bpc-local-runtime-observation/v1",
      scenarioId,
      testedBoundary: result.localBoundary,
      localObservations: scenario.localObservations,
      localNegativeResults: scenario.negativeVariants,
      browser: scenario.browserData ?? {},
      database: scenario.databaseData ?? {},
      migrationPreservation: result.migrationPreservation ?? { status: "not_run" },
      localStatus: scenario.localStatus,
      ...(scenario.blocker ? { localBlocker: scenario.blocker } : {}),
      captureComplete: true,
      acceptanceStatus: "blocked",
      acceptanceBlocker: blockedReasonCode,
    };
    const provenanceEvidence = {
      schemaVersion: "bpc-source-provenance/v1",
      runId: provenance.runId,
      databaseIsolation: provenance.databaseIsolation,
      contractSha256: contractHash,
      contract: { path: "tests/bdd/changes/beta-poc-delivery/harness-contracts.json", sha256: contractHash },
      sourceStableDuringRun: sourceStable,
      inputHashesBefore: provenance.inputHashesBefore,
      inputHashesAfter: provenance.inputHashesAfter,
    };
    const artifacts = [
      await writeJson(runDirectory, "runtime-evidence.json", runtimeEvidence, scenarioId, definition.boundary_detail),
      await writeJson(runDirectory, "provenance.json", provenanceEvidence, scenarioId, definition.boundary_detail),
    ];
    const manifest = {
      schemaVersion: "beta-poc-delivery-acceptance/v1",
      specProfile: "active-delta",
      scenarioId,
      runId,
      status: "blocked",
      gate: definition.gate,
      mandatory: definition.mandatory,
      boundaryDetail: definition.boundary_detail,
      blockedReasonCode,
      localStatus: scenario.localStatus,
      contractSha256: contractHash,
      sourceStableDuringRun: sourceStable,
      observations: blockedRecords(definition.required_observations, blockedReasonCode),
      negativeVariants: blockedRecords(definition.negative_variants, blockedReasonCode),
      artifacts,
    };
    assertSecretFree(manifest, `${scenarioId}/manifest`);
    await writeFile(resolve(runDirectory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    const manifestPath = relative(repositoryRoot, resolve(runDirectory, "manifest.json")).split(sep).join("/");
    await publishIndex(repositoryRoot, scenarioId, runId, "blocked", blockedReasonCode);
    saved.push({ scenarioId, status: "blocked", blockedReasonCode, manifestPath });
  }
  return { schemaVersion: "beta-poc-delivery-capture-summary/v1", contractSha256: contractHash, scenarios: saved };
}
