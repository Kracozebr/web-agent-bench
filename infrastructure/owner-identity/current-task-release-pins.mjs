// Current local release pointers are explicit artifact references, not release activation.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';

export const CURRENT_TASK_RELEASE_INPUTS_PATH = 'infrastructure/owner-identity/current-task-release-inputs.json';
export const CURRENT_TASK_RELEASE_POINTER_PATH = '.local/owner-identity/current-task-release.json';

const HASH = /^[0-9a-f]{64}$/;
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const PATHS = Object.freeze({
  cases: new RegExp(`^artifacts/runs/bts-difficulty-v2-case-candidates/${UUID}/candidate-cases\\.json$`),
  release: new RegExp(`^artifacts/runs/bts-difficulty-v2-release-candidates/${UUID}/candidate-release\\.json$`),
  minimum: new RegExp(`^artifacts/runs/bts-v2-minimum-action-review/${UUID}/review\\.json$`),
  references: new RegExp(`^artifacts/runs/bts-v2-reference-verification/${UUID}/verification\\.json$`),
  validation: new RegExp(`^artifacts/runs/bts-difficulty-v2-release-validation/${UUID}/validation\\.json$`),
});

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const record = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const demand = (condition, code) => { if (!condition) throw new Error(code); };
const exactKeys = (value, keys) => record(value) && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

async function pinnedBytes(repositoryRoot, path, expectedSha256, maxBytes = 16 * 1024 * 1024) {
  demand(typeof path === 'string' && path.length <= 512 && !isAbsolute(path) && !path.includes('\\')
    && !path.includes(':') && path.split('/').every((part) => part && part !== '.' && part !== '..')
    && HASH.test(expectedSha256), 'release_pin_path_or_hash_invalid');
  const actualRoot = await realpath(repositoryRoot);
  const actualPath = await realpath(resolve(actualRoot, path));
  const rel = relative(actualRoot, actualPath);
  demand(rel && !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`), 'release_pin_path_escape');
  const handle = await open(actualPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    demand(before.isFile() && before.size > 0 && before.size <= maxBytes, 'release_pin_file_invalid');
    const bytes = await handle.readFile();
    const after = await handle.stat();
    demand(bytes.length === before.size && after.size === before.size && after.mtimeMs === before.mtimeMs
      && after.ctimeMs === before.ctimeMs && sha256(bytes) === expectedSha256, 'release_pin_hash_or_stability_invalid');
    return bytes;
  } finally { await handle.close(); }
}

async function configurationBytes(repositoryRoot, path, maxBytes) {
  const actualRoot = await realpath(repositoryRoot);
  const actualPath = await realpath(resolve(actualRoot, path));
  const rel = relative(actualRoot, actualPath);
  demand(rel && !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`), 'release_config_path_escape');
  const handle = await open(actualPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    demand(before.isFile() && before.size > 0 && before.size <= maxBytes, 'release_config_file_invalid');
    const bytes = await handle.readFile();
    const after = await handle.stat();
    demand(bytes.length === before.size && after.size === before.size && after.mtimeMs === before.mtimeMs
      && after.ctimeMs === before.ctimeMs, 'release_config_changed_during_read');
    return bytes;
  } finally { await handle.close(); }
}

function artifactRef(value, kind) {
  demand(exactKeys(value, ['path', 'sha256']) && typeof value.path === 'string' && PATHS[kind].test(value.path)
    && HASH.test(value.sha256), `current_${kind}_artifact_pin_invalid`);
  return { path: value.path, sha256: value.sha256 };
}

export async function loadCurrentTaskReleaseInputPins(repositoryRoot) {
  const bytes = await configurationBytes(repositoryRoot, CURRENT_TASK_RELEASE_INPUTS_PATH, 64 * 1024);
  const config = JSON.parse(bytes.toString('utf8'));
  demand(exactKeys(config, ['schemaVersion', 'classification', 'cases', 'release', 'minimum', 'references'])
    && config.schemaVersion === 'bts-current-task-release-inputs/v1'
    && config.classification === 'current_candidate_artifact_pinset_not_validation_or_activation',
  'current_release_inputs_contract_invalid');
  return Object.freeze({
    cases: artifactRef(config.cases, 'cases'),
    release: artifactRef(config.release, 'release'),
    minimum: artifactRef(config.minimum, 'minimum'),
    references: artifactRef(config.references, 'references'),
    inputsConfig: Object.freeze({ path: CURRENT_TASK_RELEASE_INPUTS_PATH, sha256: sha256(bytes) }),
  });
}

export async function loadCurrentTaskReleasePins(repositoryRoot) {
  const pointerBytes = await configurationBytes(repositoryRoot, CURRENT_TASK_RELEASE_POINTER_PATH, 16 * 1024);
  const pointer = JSON.parse(pointerBytes.toString('utf8'));
  demand(exactKeys(pointer, ['schemaVersion', 'classification', 'validation'])
    && pointer.schemaVersion === 'bts-current-task-release-pointer/v1'
    && pointer.classification === 'local_current_validated_release_reference',
  'current_release_pointer_contract_invalid');
  const validationPin = artifactRef(pointer.validation, 'validation');
  const validationBytes = await pinnedBytes(repositoryRoot, validationPin.path, validationPin.sha256);
  const validation = JSON.parse(validationBytes.toString('utf8'));
  demand(record(validation) && validation.schemaVersion === 'bts-difficulty-v2-offline-release-validation/v1'
    && validation.status === 'validated_candidate' && validation.sourceUnchanged === true
    && HASH.test(String(validation.manifestBinding?.boundManifestHash))
    && validation.manifestBinding?.participantToolProtocol === 'separate_payment_delivery_v2'
    && validation.claims?.releaseCandidateValidated === true
    && validation.claims?.productReleaseActivated === false && validation.claims?.ownerRunAcceptance === false
    && validation.claims?.taskGrade === false, 'current_release_validation_not_authoritative');

  const sources = validation.sources;
  const pins = Object.freeze({
    cases: artifactRef(sources?.caseCandidate, 'cases'),
    release: artifactRef(sources?.releaseCandidate, 'release'),
    minimum: artifactRef(sources?.minimumActionReview, 'minimum'),
    references: artifactRef(sources?.semanticReferenceReview, 'references'),
    validation: validationPin,
  });
  demand(validation.manifestBinding?.difficultyReviewEvidence?.path === pins.minimum.path
    && validation.manifestBinding?.difficultyReviewEvidence?.sha256 === pins.minimum.sha256,
  'current_release_minimum_review_binding_missing');
  demand(Array.isArray(validation.sourceInputs), 'current_release_validation_sources_missing');
  const sourcePins = new Map(validation.sourceInputs.filter(record).map((row) => [row.path, row.sha256]));
  for (const pin of [pins.cases, pins.release, pins.minimum, pins.references]) {
    demand(sourcePins.get(pin.path) === pin.sha256, 'current_release_validation_artifact_binding_missing');
  }
  demand(sourcePins.has(CURRENT_TASK_RELEASE_INPUTS_PATH), 'current_release_input_config_not_source_pinned');
  demand(sourcePins.has('infrastructure/owner-identity/current-task-release-pins.mjs'),
    'current_release_pin_loader_not_source_pinned');
  return pins;
}
