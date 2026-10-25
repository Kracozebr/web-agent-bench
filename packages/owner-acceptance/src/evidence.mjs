import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, realpath, rename, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const REPOSITORY_ROOT = resolve(PACKAGE_ROOT, "../..");
export const EVIDENCE_ROOT = resolve(REPOSITORY_ROOT, "artifacts/runs/acceptance");
export const EVIDENCE_SCHEMA = "owner-identity-acceptance/v1";

const SCENARIO_ID = /^OID-SC-(?:00[1-9]|01[0-2])$/;
const SAFE_ARTIFACT_NAME = /^[a-z][a-z0-9-]*\.json$/;
const SECRET_KEY = /^(?:accesstoken|authtoken|bearer|cookie|cookies|password|secret|clientsecret|invitationcode|invitationsecret|privatekey|mnemonic|seedphrase|authorization|databaseurl|rpcurl|oauthcode|oauthstate|rawsignature|signaturevalue)$/i;
const SECRET_TEXT = /\bBearer\s+(?!<redacted>|\[redacted\]|\*{3})\S+|(?:[?&](?:code|state|access_token|refresh_token|id_token|client_secret)=)(?!<redacted>|\[redacted\])[^&#\s]+/i;

export function assertScenarioId(value) {
  if (typeof value !== "string" || !SCENARIO_ID.test(value)) {
    throw new Error(`Unsupported owner identity scenario: ${String(value)}`);
  }
  return value;
}

export function assertSecretFree(value, label = "evidence") {
  const visit = (current, path) => {
    if (Array.isArray(current)) {
      current.forEach((item, index) => visit(item, `${path}[${index}]`));
      return;
    }
    if (current && typeof current === "object") {
      for (const [key, item] of Object.entries(current)) {
        if (SECRET_KEY.test(key.replace(/[^a-z]/gi, ""))) {
          throw new Error(`${label} contains a prohibited secret-bearing field at ${path}.${key}`);
        }
        visit(item, `${path}.${key}`);
      }
      return;
    }
    if (typeof current === "string" && (SECRET_TEXT.test(current) || /\baap1_[A-Za-z0-9_-]{43}\b/.test(current))) {
      throw new Error(`${label} contains an unredacted credential-like value at ${path}`);
    }
  };
  visit(value, label);
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

export function scenarioDirectory(scenarioId) {
  return resolve(EVIDENCE_ROOT, assertScenarioId(scenarioId));
}

export async function beginScenarioRun(scenarioId) {
  assertScenarioId(scenarioId);
  const runId = randomUUID();
  const root = scenarioDirectory(scenarioId);
  const directory = resolve(root, "runs", runId);
  await mkdir(directory, { recursive: true });
  await publishScenarioIndex(scenarioId, runId, "running");
  return { scenarioId, runId, root, directory };
}

export async function writeJsonArtifact(scenarioId, name, boundary, payload, runDirectory = scenarioDirectory(scenarioId)) {
  assertScenarioId(scenarioId);
  if (!SAFE_ARTIFACT_NAME.test(name)) throw new Error(`Unsafe evidence artifact name: ${name}`);
  if (typeof boundary !== "string" || !boundary.trim()) throw new Error("Evidence boundary is required");
  assertSecretFree(payload, `${scenarioId}/${name}`);
  await mkdir(runDirectory, { recursive: true });
  const path = resolve(runDirectory, name);
  const bytes = Buffer.from(`${JSON.stringify(payload, null, 2)}\n`, "utf8");
  await writeFile(path, bytes, { flag: "wx" });
  return {
    path: name,
    sha256: sha256(bytes),
    boundary,
    contentType: "application/json",
  };
}

export async function writeManifest(scenarioId, payload, runDirectory = scenarioDirectory(scenarioId)) {
  assertScenarioId(scenarioId);
  const manifest = {
    schemaVersion: EVIDENCE_SCHEMA,
    scenarioId,
    ...payload,
  };
  assertSecretFree(manifest, `${scenarioId}/manifest`);
  await mkdir(runDirectory, { recursive: true });
  const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  await writeFile(resolve(runDirectory, "manifest.json"), bytes, "utf8");
  return resolve(runDirectory, "manifest.json");
}

export async function publishScenarioIndex(scenarioId, runId, status, blockedReasonCode) {
  assertScenarioId(scenarioId);
  if (!/^[0-9a-f-]{36}$/.test(runId)) throw new Error("Invalid OID evidence run identity");
  if (!new Set(["running", "passed", "blocked", "failed"]).has(status)) throw new Error("Invalid OID index status");
  const root = scenarioDirectory(scenarioId);
  await mkdir(root, { recursive: true });
  const path = resolve(root, "manifest.json");
  let previousRuns = [];
  try {
    const previous = await readJson(path);
    if (previous.schemaVersion === "owner-identity-evidence-index/v1" && Array.isArray(previous.runs)) {
      previousRuns = previous.runs.filter((item) => typeof item === "string" && /^[0-9a-f-]{36}$/.test(item));
    }
  } catch {
    // A malformed prior index is not trusted or retained.
  }
  const runs = [...new Set([...previousRuns, runId])];
  const index = {
    schemaVersion: "owner-identity-evidence-index/v1",
    scenarioId,
    status,
    latestRunId: runId,
    runs,
    ...(blockedReasonCode ? { blockedReasonCode } : {}),
  };
  assertSecretFree(index, `${scenarioId}/manifest-index`);
  const temporary = resolve(root, `.manifest-${runId}.tmp`);
  await writeFile(temporary, `${JSON.stringify(index, null, 2)}\n`, { flag: "wx" });
  await rename(temporary, path);
}

export async function verifyManifest(directoryPath, { requirePassed = false } = {}) {
  const directory = await realpath(directoryPath);
  const root = await realpath(EVIDENCE_ROOT);
  const rel = relative(root, directory);
  if (!rel || rel.startsWith(`..${sep}`) || rel === ".." || isAbsolute(rel)) {
    throw new Error("Evidence directory must be a child of artifacts/runs/acceptance");
  }
  let runDirectory = directory;
  let manifest = await readJson(resolve(directory, "manifest.json"));
  if (manifest.schemaVersion === "owner-identity-evidence-index/v1") {
    if (manifest.scenarioId !== rel.split(sep)[0] || !/^[0-9a-f-]{36}$/.test(manifest.latestRunId ?? "")) {
      throw new Error("OID evidence index identity is invalid");
    }
    const runId = manifest.latestRunId;
    if (!Array.isArray(manifest.runs) || !manifest.runs.includes(runId)) throw new Error("OID evidence index run list is inconsistent");
    runDirectory = await realpath(resolve(directory, "runs", runId));
    if (!runDirectory.startsWith(`${directory}${sep}`)) throw new Error("OID evidence run escapes its scenario directory");
    manifest = await readJson(resolve(runDirectory, "manifest.json"));
  }
  assertSecretFree(manifest, "manifest.json");
  if (manifest.schemaVersion !== EVIDENCE_SCHEMA) throw new Error("Unsupported OID evidence schema");
  if (manifest.scenarioId !== rel.split(sep)[0]) throw new Error("Evidence directory and scenario ID differ");
  if (!(manifest.status === "passed" || manifest.status === "blocked" || manifest.status === "failed")) {
    throw new Error("OID evidence has an invalid status");
  }
  if (requirePassed && manifest.status !== "passed") throw new Error(`OID evidence status is ${manifest.status}`);
  if (!Array.isArray(manifest.artifacts)) throw new Error("OID evidence has no artifact inventory");

  const seen = new Set();
  const verifiedArtifacts = [];
  for (const entry of manifest.artifacts) {
    if (!entry || typeof entry.path !== "string" || !SAFE_ARTIFACT_NAME.test(entry.path)) {
      throw new Error("OID evidence contains an invalid artifact path");
    }
    if (seen.has(entry.path)) throw new Error(`Duplicate OID evidence artifact: ${entry.path}`);
    seen.add(entry.path);
    const candidate = resolve(directory, entry.path);
    const actual = await realpath(candidate);
    if (!actual.startsWith(`${directory}${sep}`)) throw new Error(`OID artifact escapes its scenario directory: ${entry.path}`);
    const bytes = await readFile(actual);
    if (sha256(bytes) !== entry.sha256) throw new Error(`OID artifact SHA-256 mismatch: ${entry.path}`);
    if (entry.contentType !== "application/json" || typeof entry.boundary !== "string") {
      throw new Error(`OID artifact metadata is invalid: ${entry.path}`);
    }
    const payload = JSON.parse(bytes.toString("utf8"));
    assertSecretFree(payload, entry.path);
    verifiedArtifacts.push({ ...entry, payload });
  }
  if (manifest.status === "blocked" && !manifest.blockedReasonCode) {
    throw new Error("Blocked OID evidence needs a machine-readable reason code");
  }
  return { directory, runDirectory, manifest, artifacts: verifiedArtifacts };
}
