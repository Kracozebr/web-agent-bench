import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";

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
        if (secretKey.test(key.replace(/[^a-z]/gi, ""))) throw new Error(`${label} includes a prohibited key at ${path}.${key}`);
        visit(item, `${path}.${key}`);
      }
    } else if (typeof current === "string" && secretText.test(current)) {
      throw new Error(`${label} includes credential-like text at ${path}`);
    }
  };
  visit(value, label);
}

function notRunRecords(names, reasonCode) {
  return Object.fromEntries(names.map((name) => [name, { status: "not_run", reasonCode }]));
}

function validSourceInventory(value) {
  return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length > 0
    && Object.entries(value).every(([path, hash]) => typeof path === "string" && path.length > 0
      && !path.includes("\\") && !path.includes(":") && !path.startsWith("/")
      && !path.split("/").some((part) => !part || part === "." || part === "..")
      && typeof hash === "string" && /^[0-9a-f]{64}$/.test(hash));
}

async function writeJson(runDirectory, name, payload, boundary) {
  assertSecretFree(payload, `${name}`);
  const bytes = Buffer.from(`${JSON.stringify(payload, null, 2)}\n`, "utf8");
  await writeFile(resolve(runDirectory, name), bytes, { flag: "wx", mode: 0o600 });
  return { path: name, sha256: digest(bytes), bytes: bytes.length, contentType: "application/json", boundary };
}

async function publishIndex(repositoryRoot, scenarioId, runId, blockedReasonCode) {
  const scenarioRoot = resolve(repositoryRoot, EVIDENCE_ROOT, scenarioId);
  const indexPath = resolve(scenarioRoot, "manifest.json");
  let previousRuns = [];
  try {
    const previous = JSON.parse(await readFile(indexPath, "utf8"));
    if (previous.schemaVersion === "beta-poc-delivery-evidence-index/v1" && Array.isArray(previous.runs)) {
      previousRuns = previous.runs.filter((value) => typeof value === "string" && /^[0-9a-f-]{36}$/.test(value));
    }
  } catch {
    // A missing or malformed prior index does not become acceptance evidence.
  }
  const index = {
    schemaVersion: "beta-poc-delivery-evidence-index/v1",
    scenarioId,
    status: "blocked",
    latestRunId: runId,
    runs: [...new Set([...previousRuns, runId])],
    blockedReasonCode,
  };
  assertSecretFree(index, `${scenarioId}/index`);
  const temporary = resolve(scenarioRoot, `.manifest-${runId}.tmp`);
  await writeFile(temporary, `${JSON.stringify(index, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  await rename(temporary, indexPath);
}

/**
 * Persist raw, sanitized local report observations without promoting any BPC fact.
 * A target-host capture must use the separate approved capture path and replay gates.
 */
export async function saveReportEvidence({ result, provenance, repositoryRoot }) {
  if (!result || !result.scenarioData || typeof result.scenarioData !== "object") {
    throw new Error("Report capture did not return scenario data");
  }
  const contractPath = resolve(repositoryRoot, "tests/bdd/changes/beta-poc-delivery/harness-contracts.json");
  const contractBytes = await readFile(contractPath);
  const contractHash = digest(contractBytes);
  const contract = JSON.parse(contractBytes.toString("utf8"));
  if (!validSourceInventory(provenance?.inputHashesBefore) || !validSourceInventory(provenance?.inputHashesAfter)) {
    throw new Error("Report evidence requires non-empty, safe before and after source inventories");
  }
  const sourceStable = provenance?.sourceStableDuringRun === true
    && JSON.stringify(provenance.inputHashesBefore) === JSON.stringify(provenance.inputHashesAfter);
  const sourceHashesBefore = provenance.inputHashesBefore;
  const sourceHashesAfter = provenance.inputHashesAfter;
  const saved = [];

  for (const scenarioId of ["BPC-SC-018", "BPC-SC-019", "BPC-SC-020", "BPC-SC-024", "BPC-SC-026"]) {
    const scenario = result.scenarioData[scenarioId];
    const definition = contract.protected_scenarios?.[scenarioId];
    if (!scenario || !definition) throw new Error(`Report contract or capture is missing ${scenarioId}`);
    const reason = !sourceStable ? "source_inputs_changed_during_run" : scenarioId === "BPC-SC-019"
      ? "four_native_client_capture_unavailable"
      : "actual_target_host_capture_unavailable";
    const runId = randomUUID();
    const scenarioRoot = resolve(repositoryRoot, EVIDENCE_ROOT, scenarioId);
    const runDirectory = resolve(scenarioRoot, "runs", runId);
    await mkdir(runDirectory, { recursive: true, mode: 0o700 });

    const runtimeEvidence = scenario.captureEvidence;
    if (!runtimeEvidence || runtimeEvidence.schemaVersion !== "bpc-report-runtime-observation/v1"
      || runtimeEvidence.scenarioId !== scenarioId || runtimeEvidence.captureBoundary !== "local_acceptance_runner"
      || runtimeEvidence.boundaryDetail !== definition.boundary_detail) {
      throw new Error(`${scenarioId} must preserve raw local report evidence and its non-target boundary`);
    }
    const provenanceEvidence = {
      schemaVersion: "bpc-source-provenance/v1",
      runId: provenance?.runId ?? randomUUID(),
      contractSha256: contractHash,
      contract: { path: "tests/bdd/changes/beta-poc-delivery/harness-contracts.json", sha256: contractHash },
      sourceStableDuringRun: sourceStable,
      inputHashesBefore: sourceHashesBefore,
      inputHashesAfter: sourceHashesAfter,
      databaseIsolation: result.databaseIsolation ?? "dedicated_acceptance_database",
    };
    const artifacts = [
      await writeJson(runDirectory, "runtime-evidence.json", runtimeEvidence, definition.boundary_detail),
      await writeJson(runDirectory, "provenance.json", provenanceEvidence, definition.boundary_detail),
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
      blockedReasonCode: reason,
      localStatus: scenario.localStatus ?? "partial",
      contractSha256: contractHash,
      sourceStableDuringRun: sourceStable,
      observations: notRunRecords(definition.required_observations, reason),
      negativeVariants: notRunRecords(definition.negative_variants, reason),
      artifacts,
    };
    assertSecretFree(manifest, `${scenarioId}/manifest`);
    await writeFile(resolve(runDirectory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    const manifestPath = relative(repositoryRoot, resolve(runDirectory, "manifest.json")).split(sep).join("/");
    await publishIndex(repositoryRoot, scenarioId, runId, reason);
    saved.push({ scenarioId, status: "blocked", blockedReasonCode: reason, manifestPath });
  }
  return { schemaVersion: "beta-poc-delivery-report-capture-summary/v1", contractSha256: contractHash, scenarios: saved };
}
