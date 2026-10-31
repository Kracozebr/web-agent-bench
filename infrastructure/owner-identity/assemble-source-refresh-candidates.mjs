/** Fresh raw references -> immutable cases; no registry, participant, charge or grade writes. */
import { randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { buildProjection } from './assemble-difficulty-v2-candidates.mjs';
import { TaskCaseSchema, canonicalTaskJson, sha256CanonicalTaskJson, taskCaseHash } from '../../packages/owner-identity/src/task-release.ts';
import { sourceDigests } from '../../packages/benchmark-environment/src/probe/environment.ts';
import { assertSemanticCasePreserved, demand, loadSourceRefreshProfile, readPinned, REFRESH_BOUNDARY,
  REFRESH_POLICY_PATH, safeRelative, sha, verifySourceRefreshCandidate } from './task-release-source-refresh.mjs';

async function main() {
  demand(process.platform === 'linux' && process.cwd() === '/workspace', 'docker_required');
  const args = process.argv.slice(2);
  demand(args.length === 4 && args[0] === '--refresh-profile' && args[2] === '--sha256', 'usage');
  const profileRef = { path: args[1], sha256: args[3] };
  const context = await loadSourceRefreshProfile('/workspace', profileRef);
  const captureId = randomUUID(), outputPrefix = `artifacts/runs/bts-difficulty-v2-case-candidates/${captureId}`;
  const baselineByKey = new Map(context.baseline.cases.map((c) => [`${c.taskId}:${c.mode}`, c]));
  const refs = new Map(), evidenceFiles = [], cases = [];
  function remember(ref) {
    demand(safeRelative(ref.path) && /^[0-9a-f]{64}$/.test(ref.sha256), 'refresh_source_pin_invalid');
    const prior = refs.get(ref.path);
    demand(!prior || prior.sha256 === ref.sha256, 'refresh_source_pin_conflict');
    refs.set(ref.path, { path: ref.path, sha256: ref.sha256 });
  }
  context.sourceInputs.forEach(remember);
  for (const path of ['infrastructure/owner-identity/assemble-source-refresh-candidates.mjs',
    'infrastructure/owner-identity/task-release-source-refresh.mjs',
    'infrastructure/owner-identity/assemble-difficulty-v2-candidates.mjs',
    'infrastructure/owner-identity/project-basic-v2-candidates.mjs', 'infrastructure/owner-identity/project-u1-v2-candidate.mjs',
    'pnpm-lock.yaml', ...['task-release', 'task-catalog', 'task-case-assembler', 'task-reference-evidence-v2',
      'task-reference-evidence-v2-types', 'task-reference-evidence-v2-basic', 'task-reference-evidence-v2-advanced',
      'task-feasibility-evidence'].map((name) => `packages/owner-identity/src/${name}.ts`)]) {
    remember({ path, sha256: (await readPinned('/workspace', path, null, false)).sha256 });
  }
  await mkdir(outputPrefix, { recursive: true });
  for (const row of context.integrity.captures) {
    remember(row.probe);
    const probe = (await readPinned('/workspace', row.probe.path, row.probe.sha256)).value;
    demand(probe.taskId === row.taskId && probe.mode === row.mode && probe.status === 'captured'
      && probe.sourceDigests?.matches === true && probe.sourceDigests.before.appSourceSha256 === context.profile.expectedApplicationSourceSha256
      && probe.sourceDigests.before.probeSourceSha256 === context.profile.expectedProbeSourceSha256,
    'refresh_actual_probe_identity_mismatch');
    const captureRoot = dirname(row.probe.path), artifacts = new Map();
    demand(Array.isArray(probe.artifacts) && probe.artifacts.length > 0 && probe.artifacts.length <= 512, 'refresh_raw_inventory_invalid');
    for (const ref of probe.artifacts) {
      demand(safeRelative(ref.path) && !artifacts.has(ref.path), 'refresh_raw_reference_invalid');
      artifacts.set(ref.path, ref);
      remember({ path: `${captureRoot}/${ref.path}`, sha256: ref.sha256 });
    }
    async function rawArtifact(path) {
      const ref = artifacts.get(path);
      demand(ref, 'refresh_raw_artifact_not_indexed');
      return readPinned('/workspace', `${captureRoot}/${path}`, ref.sha256);
    }
    const manifest = (await rawArtifact(probe.manifest.path)).value;
    const projection = await buildProjection(probe, manifest, context.identity, context.policy, rawArtifact);
    (projection.resourceInputs ?? []).forEach(remember);
    const baseline = baselineByKey.get(`${row.taskId}:${row.mode}`);
    demand(baseline, 'refresh_unapproved_case');
    const initialHash = sha256CanonicalTaskJson(projection.initial), finalHash = sha256CanonicalTaskJson(projection.final);
    const rawReferences = [...artifacts.values()].map((r) => ({ path: `${captureRoot}/${r.path}`, sha256: r.sha256, boundary: r.boundary }));
    const envelope = { schemaVersion: 'bts-task-case-evidence-composition/v2',
      classification: 'schema_candidate_from_retained_reference_not_semantic_verification',
      caseId: baseline.caseId, taskId: row.taskId, mode: row.mode, executionIdentityHash: context.identityHash,
      initialState: projection.initial, finalState: projection.final, inputProfile: probe.difficultyProfile,
      measuredExpenseAndCandidateBudget: projection.expense, participantActions: probe.captureReferences.participantActions,
      policyInput: context.sourceInputs.find((r) => r.path === REFRESH_POLICY_PATH), probe: row.probe, rawReferences,
      projectionEvidence: projection.extraEvidence ?? null, noDifficultyApproval: true, noReleaseActivation: true };
    const caseDirectory = `${outputPrefix}/${row.mode}/${row.taskId}`;
    await mkdir(caseDirectory, { recursive: true });
    async function saveEnvelope(name, purpose, stateHash) {
      const path = `${caseDirectory}/${name}.json`;
      const bytes = Buffer.from(`${canonicalTaskJson({ ...envelope, purpose, taskStateSha256: stateHash })}\n`);
      await writeFile(path, bytes, { flag: 'wx' });
      const ref = { path, sha256: sha(bytes), boundary: REFRESH_BOUNDARY };
      evidenceFiles.push(ref); remember(ref); return ref;
    }
    const initialEvidence = await saveEnvelope('initial_state_projection', 'initial_state_projection', initialHash);
    const referenceEvidence = await saveEnvelope('reference_execution_trace', 'reference_execution_trace', finalHash);
    const { caseHash: _oldHash, ...approvedCore } = baseline;
    const nextCore = { ...approvedCore, executionIdentityHash: context.identityHash,
      initialState: { stateSha256: initialHash, ...projection.initial }, initialStateEvidence: initialEvidence,
      objective: projection.objective, referencePath: { ...baseline.referencePath, evidence: referenceEvidence,
        actionCount: probe.participantActionCount, initialStateSha256: initialHash, finalStateSha256: finalHash } };
    const next = TaskCaseSchema.parse({ ...nextCore, caseHash: taskCaseHash(nextCore) });
    assertSemanticCasePreserved(next, baseline);
    cases.push(next);
  }
  const candidate = { schemaVersion: 'bts-difficulty-v2-case-candidates/v1',
    classification: 'typed_case_candidates_not_validated_release', status: 'complete_inventory_candidates', captureId,
    executionIdentity: context.identity, executionIdentityHash: context.identityHash,
    participantToolProtocol: 'separate_payment_delivery_v2', sourceUnchanged: true,
    sourceRefreshProfile: profileRef, sourceRefreshClassification: 'fresh_source_immutable_baseline_preserved_semantics',
    sourceInputs: [...refs.values()], evidenceFiles, cases,
    claims: { releaseValidated: false, releaseActivated: false, taskGrade: false, difficultyApproved: false } };
  await verifySourceRefreshCandidate('/workspace', candidate);
  for (const ref of refs.values()) await readPinned('/workspace', ref.path, ref.sha256, false);
  const after = await sourceDigests('/workspace');
  demand(after.appSourceSha256 === context.profile.expectedApplicationSourceSha256
    && after.probeSourceSha256 === context.profile.expectedProbeSourceSha256, 'refresh_source_changed');
  const bytes = Buffer.from(`${JSON.stringify(candidate, null, 2)}\n`);
  await writeFile(`${outputPrefix}/candidate-cases.json`, bytes, { flag: 'wx' });
  console.log(JSON.stringify({ outputPrefix, sha256: sha(bytes), cases: cases.length,
    status: candidate.status, independentReferencesVerified: cases.length, releaseValidated: false }));
}
void main().catch((error) => {
  const code = typeof error?.message === 'string' && /^[a-z_][a-z0-9_]{1,159}$/.test(error.message)
    ? error.message : 'source_refresh_assembly_failed';
  console.error(JSON.stringify({ status: 'blocked', code })); process.exitCode = 2;
});
