/** Serial fresh-source qualification. Produces proposed pins; never activates or overwrites current release pointers. */
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sourceDigests } from '../../packages/benchmark-environment/src/probe/environment.ts';
import { APPROVED_REFRESH_BASELINE, readPinned } from './task-release-source-refresh.mjs';
import { qualificationArtifactPath } from './qualification-output-paths.mjs';

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const TASKS = ['S1','S2','S3','S4','M1','M2','M3','M4','H1','H2','H3','U1'];
const JOBS = [...TASKS.map((taskId) => ({ taskId, mode: 'ranked' })), ...['S1','M1','H1'].map((taskId) => ({ taskId, mode: 'training' }))];
const CURRENT = ['.local/owner-identity/current-task-release.json','infrastructure/owner-identity/current-task-release-inputs.json'];
function need(value, code) { if (!value) throw new Error(code); }
export function parseQualificationArguments(args) {
  if (args.length === 0 || args.length === 1 && args[0] === '--plan') return { execute: false };
  need(args.length === 7 && args[0] === '--execute' && args[1] === '--application-sha256' && args[3] === '--probe-sha256' &&
    args[5] === '--manifest-sha256' && [args[2],args[4],args[6]].every((value) => /^[0-9a-f]{64}$/.test(value)), 'qualification_usage');
  return { execute: true, application: args[2], probe: args[4], manifest: args[6] };
}
async function main() {
  need(process.platform === 'linux' && process.cwd() === '/workspace', 'qualification_docker_required');
  const root = '/workspace', options = parseQualificationArguments(process.argv.slice(2));
  const digests = await sourceDigests(root), manifest = sha(await readFile('infrastructure/benchmark-environment/manifest.json'));
  const plan = { schemaVersion: 'bts-source-refresh-qualification-plan/v1', executionRequested: options.execute,
    expectedApplicationSourceSha256: digests.appSourceSha256, expectedProbeSourceSha256: digests.probeSourceSha256,
    expectedManifestSha256: manifest, approvedBaseline: APPROVED_REFRESH_BASELINE, cases: JOBS,
    stages: ['fresh_readonly_feasibility','independent_feasibility_verification','fifteen_serial_fenced_references',
      'raw_integrity_verification','source_only_semantic_preserving_case_assembly','minimum_action_review',
      'independent_reference_verification','release_candidate_assembly','pinned_candidate_validation'],
    currentPointersWritten: false, releaseActivation: false };
  if (!options.execute) { console.log(JSON.stringify(plan)); return; }
  need(options.application === digests.appSourceSha256 && options.probe === digests.probeSourceSha256 && options.manifest === manifest,
    'qualification_source_pin_mismatch');
  const originalPointers = await Promise.all(CURRENT.map(async (path) => ({ path, sha256: sha(await readFile(path)) })));
  const pipelinePaths = ['qualify-source-refresh','qualification-output-paths','current-task-release-pins','task-release-source-refresh','capture-release-feasibility',
    'verify-runtime-feasibility','verify-difficulty-v2-artifacts','assemble-source-refresh-candidates','assemble-difficulty-v2-candidates',
    'project-basic-v2-candidates','project-u1-v2-candidate','review-difficulty-v2-minima','verify-difficulty-v2-references',
    'assemble-difficulty-v2-release','validate-difficulty-v2-release'].map((name) => `infrastructure/owner-identity/${name}.mjs`);
  const pipelineInputs = await Promise.all(pipelinePaths.map(async (path) => ({ path, sha256: sha(await readFile(path)) })));
  const baseline = (await readPinned(root, APPROVED_REFRESH_BASELINE.path, APPROVED_REFRESH_BASELINE.sha256)).value;
  need(baseline.executionIdentity.environmentManifestSha256 === manifest, 'qualification_manifest_semantics_changed');
  const captureId = randomUUID(), prefix = `artifacts/runs/bts-source-refresh-qualification/${captureId}`;
  await mkdir(prefix, { recursive: false, mode: 0o700 }).catch(async (error) => {
    if (error.code !== 'ENOENT') throw error; await mkdir('artifacts/runs/bts-source-refresh-qualification', { recursive: true });
    await mkdir(prefix, { recursive: false, mode: 0o700 });
  });
  need(await realpath(prefix) === resolve(root, prefix), 'qualification_output_path_escape');
  const report = { ...plan, captureId, status: 'running', sourceBefore: digests, originalPointers, pipelineInputs, steps: [], references: [] };
  const persist = () => writeFile(`${prefix}/qualification.json`, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  const secrets = [];
  for (const name of ['admin-key','service-key','database-observer-password','database-owner-url','source-rpc-url']) {
    const value = await readFile(`infrastructure/benchmark-environment/.local/secrets/${name}`, 'utf8').catch(() => '');
    if (value.trim().length >= 8) secrets.push(value.trim());
  }
  const safeLog = (text) => secrets.reduce((value, secret) => value.split(secret).join('<redacted>'), text)
    .replace(/Bearer\s+[^\s"']+/gi, 'Bearer <redacted>');
  async function unchanged() {
    need(JSON.stringify(await sourceDigests(root)) === JSON.stringify(digests), 'qualification_source_changed');
    for (const pin of originalPointers) need(sha(await readFile(pin.path)) === pin.sha256, 'qualification_current_pointer_changed');
    for (const pin of pipelineInputs) need(sha(await readFile(pin.path)) === pin.sha256, 'qualification_pipeline_source_changed');
  }
  async function save(name, value) {
    const path = `${prefix}/${name}`, bytes = Buffer.from(JSON.stringify(value, null, 2) + '\n');
    await writeFile(path, bytes, { flag: 'wx', mode: 0o600 }); return { path, sha256: sha(bytes) };
  }
  async function step(name, script, args = [], acceptedExitCodes = [0]) {
    await unchanged();
    const entry = { name, script, args, startedAt: new Date().toISOString(), status: 'running' };
    report.steps.push(entry); await persist(); console.log(JSON.stringify({ event: 'source_qualification_stage_started', captureId, stage: name }));
    const child = spawn(process.execPath, ['--import','./packages/owner-identity/node_modules/tsx/dist/loader.mjs',script,...args],
      { cwd: root, env: process.env, stdio: ['ignore','pipe','pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; }); child.stderr.on('data', (chunk) => { stderr += chunk; });
    const code = await new Promise((done, reject) => { child.once('error', reject); child.once('exit', (value) => done(value)); });
    const logs = { stdout: safeLog(stdout), stderr: safeLog(stderr) };
    for (const [kind, text] of Object.entries(logs)) await writeFile(`${prefix}/${String(report.steps.length).padStart(2,'0')}-${name}.${kind}.log`, text, { flag: 'wx', mode: 0o600 });
    entry.exitCode = code; entry.finishedAt = new Date().toISOString(); entry.logsRedacted = true;
    const records = stdout.trim().split(/\r?\n/).flatMap((line) => { try { return [JSON.parse(line)]; } catch { return []; } });
    entry.result = records.at(-1) ?? null;
    need(acceptedExitCodes.includes(code), `qualification_${name}_failed`);
    entry.status = 'finished'; await unchanged(); await persist(); return entry.result;
  }
  function outputPin(value, filename) {
    need(value && /^[0-9a-f]{64}$/.test(value.sha256), 'qualification_output_pin_invalid');
    return { path: `${qualificationArtifactPath(value.outputPrefix)}/${filename}`, sha256: value.sha256 };
  }
  async function sourceBudget() {
    const port = process.env.BEF_SOURCE_PROXY_HOST_PORT ?? '18544';
    need(/^[1-9][0-9]{0,4}$/.test(port) && Number(port) <= 65535, 'qualification_source_port_invalid');
    const key = (await readFile('infrastructure/benchmark-environment/.local/secrets/service-key', 'utf8')).trim();
    const response = await fetch(`http://host.docker.internal:${port}/internal/admin/metrics`, {
      headers: { 'x-bef-service-key': key }, signal: AbortSignal.timeout(5000) });
    need(response.status === 200, 'qualification_source_metrics_unavailable');
    const metrics = await response.json(), reserved = metrics.sourceCallsReserved, limit = metrics.sourceCallLimit;
    need(Number.isSafeInteger(reserved) && Number.isSafeInteger(limit) && reserved >= 0 && reserved < limit,
      'qualification_source_budget_exhausted');
    return { observedAt: new Date().toISOString(), sourceCallsReserved: reserved, sourceCallLimit: limit };
  }
  try {
    const observed = await step('feasibility_capture', 'infrastructure/owner-identity/capture-release-feasibility.mjs',
      ['--manifest-sha256',manifest,'--application-sha256',digests.appSourceSha256]);
    need(observed?.status === 'captured', 'qualification_feasibility_blocked');
    const witness = { path: `${qualificationArtifactPath(observed.artifactDirectory, 'artifacts/runs/bts-release-feasibility-witness/')}/witness.json`, sha256: observed.witnessSha256 };
    report.witness = witness;
    const verified = await step('feasibility_verify', 'infrastructure/owner-identity/verify-runtime-feasibility.mjs', ['--witness',witness.path,'--sha256',witness.sha256]);
    need(verified?.result?.status === 'verified', 'qualification_feasibility_not_verified');
    report.feasibility = outputPin(verified, 'verification.json');
    report.sourceBudgetBefore = await sourceBudget();
    for (const job of JOBS) {
      report.sourceBudgetLast = await sourceBudget();
      const args = job.taskId === 'U1' ? ['--u1-v2'] : ['--task-id',job.taskId,'--mode',job.mode,'--env-id','bef-env-a'];
      if (job.taskId === 'S1') args.push('--recipient', baseline.cases.find((item) => item.taskId === 'S1' && item.mode === job.mode).objective.recipient);
      const script = `infrastructure/benchmark-environment/${job.taskId === 'U1' ? 'run-task-transfer.mjs' : 'run-difficulty-v2.mjs'}`;
      const captured = await step(`reference_${job.taskId.toLowerCase()}_${job.mode}`, script, args);
      need(captured && captured.exitCode === 0, 'qualification_reference_capture_missing');
      const path = `${qualificationArtifactPath(captured.captureDirectory, 'artifacts/runs/bts-difficulty-v2-reference/')}/probe.json`,
        raw = await readPinned(root, path), probe = raw.value;
      need(probe.taskId === job.taskId && probe.mode === job.mode && probe.status === 'captured' && probe.generationFence?.status === 'fenced' &&
        probe.generationFence.signerErased === true && probe.sourceDigests?.matches === true &&
        probe.sourceDigests.before.appSourceSha256 === digests.appSourceSha256 && probe.sourceDigests.before.probeSourceSha256 === digests.probeSourceSha256,
      'qualification_reference_identity_or_fence_failed');
      report.references.push({ path, sha256: raw.sha256 }); await persist();
    }
    const index = await save('source-index.json', { schemaVersion: 'bts-difficulty-v2-artifact-inputs/v1', captures: report.references });
    report.integrity = outputPin(await step('raw_integrity', 'infrastructure/owner-identity/verify-difficulty-v2-artifacts.mjs', ['--source-index',index.path,'--sha256',index.sha256]), 'verification.json');
    const profile = await save('refresh-profile.json', { schemaVersion: 'bts-source-refresh-profile/v1',
      classification: 'explicit_new_source_profile_not_release_acceptance', reason: 's2_public_identity_disclosure', approvedBaseline: APPROVED_REFRESH_BASELINE,
      feasibilityVerification: report.feasibility, rawIntegrity: report.integrity, expectedApplicationSourceSha256: digests.appSourceSha256,
      expectedProbeSourceSha256: digests.probeSourceSha256, expectedManifestSha256: manifest });
    report.cases = outputPin(await step('case_assembly', 'infrastructure/owner-identity/assemble-source-refresh-candidates.mjs', ['--refresh-profile',profile.path,'--sha256',profile.sha256]), 'candidate-cases.json');
    const caseArgs = ['--cases',report.cases.path,'--sha256',report.cases.sha256];
    report.minimum = outputPin(await step('minimum_review', 'infrastructure/owner-identity/review-difficulty-v2-minima.mjs', caseArgs), 'review.json');
    report.semantic = outputPin(await step('reference_semantics', 'infrastructure/owner-identity/verify-difficulty-v2-references.mjs', caseArgs), 'verification.json');
    // Composition intentionally exits 2: only the subsequent independent validator may validate it.
    report.release = outputPin(await step('release_assembly', 'infrastructure/owner-identity/assemble-difficulty-v2-release.mjs', caseArgs, [2]), 'candidate-release.json');
    const inputs = await save('candidate-inputs.json', { schemaVersion: 'bts-current-task-release-inputs/v1',
      classification: 'current_candidate_artifact_pinset_not_validation_or_activation', cases: report.cases,
      release: report.release, minimum: report.minimum, references: report.semantic });
    const validation = await step('release_validation', 'infrastructure/owner-identity/validate-difficulty-v2-release.mjs', ['--inputs',inputs.path,'--sha256',inputs.sha256]);
    need(validation?.status === 'validated_candidate' && validation.casesChecked === 15, 'qualification_candidate_validation_blocked');
    report.validation = outputPin(validation, 'validation.json'); report.proposedInputs = inputs;
    report.proposedPointer = await save('proposed-current-task-release.json', { schemaVersion: 'bts-current-task-release-pointer/v1',
      classification: 'local_current_validated_release_reference', validation: report.validation });
    report.sourceBudgetAfter = await sourceBudget(); report.status = 'validated_candidate_not_activated'; await unchanged();
  } catch (error) { report.status = 'blocked'; report.blocker = /^[a-z0-9_]{1,159}$/.test(error.message) ? error.message : 'qualification_failed'; process.exitCode = 2; }
  finally { report.finishedAt = new Date().toISOString(); await persist(); console.log(JSON.stringify({ event: 'source_qualification_finished', captureId,
    status: report.status, path: `${prefix}/qualification.json`, proposedInputs: report.proposedInputs ?? null,
    proposedPointer: report.proposedPointer ?? null, blocker: report.blocker ?? null, releaseActivated: false })); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) void main().catch(() => {
  console.error('source_refresh_qualification_preflight_failed'); process.exitCode = 2;
});
