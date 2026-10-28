// Offline retained reference verification; never writes registry, money or grades.
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { TaskCaseSchema, canonicalTaskJson } from '../../packages/owner-identity/src/task-release.ts';
import { loadV2ReferenceContext, verifyTaskReferenceEvidenceV2 } from '../../packages/owner-identity/src/task-reference-evidence-v2.ts';
import { V2ReferenceError } from '../../packages/owner-identity/src/task-reference-evidence-v2-types.ts';
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const sourcePaths = ['pnpm-lock.yaml', 'infrastructure/owner-identity/verify-difficulty-v2-references.mjs',
  ...['task-release', 'task-reference-evidence-v2', 'task-reference-evidence-v2-types']
    .map((name) => `packages/owner-identity/src/${name}.ts`)];
async function main() {
  const args = process.argv.slice(2), contextOnly = args.length === 5 && args[4] === '--context-only';
  if (process.platform !== 'linux' || process.cwd() !== '/workspace'
    || !(args.length === 4 || contextOnly) || args[0] !== '--cases' || args[2] !== '--sha256'
    || !/^artifacts\/runs\/[A-Za-z0-9_./-]+\/candidate-cases\.json$/.test(args[1])
    || args[1].split('/').some((part) => part === '..' || part === '.' || !part)
    || !/^[0-9a-f]{64}$/.test(args[3])) throw new Error('usage');
  const inputBytes = await readFile(args[1]);
  if (sha(inputBytes) !== args[3]) throw new Error('candidate_pin_mismatch');
  const candidate = JSON.parse(inputBytes);
  if (candidate.schemaVersion !== 'bts-difficulty-v2-case-candidates/v1' || !Array.isArray(candidate.cases)) throw new Error('candidate_invalid');
  const policyPath = 'infrastructure/owner-identity/task-release-local-policy.json';
  const policyHash = sha(await readFile(policyPath));
  if (!contextOnly) sourcePaths.push(...['basic', 'advanced'].map((name) => `packages/owner-identity/src/task-reference-evidence-v2-${name}.ts`));
  sourcePaths.push(policyPath, args[1]);
  const snapshot = () => Promise.all(sourcePaths.toSorted().map(async (path) => ({ path, sha256: sha(await readFile(path)) })));
  const before = await snapshot(), results = [];
  for (const raw of candidate.cases) {
    const taskCase = TaskCaseSchema.parse(raw);
    const input = { repositoryRoot: '/workspace', identity: candidate.executionIdentity,
      profilePolicy: { path: policyPath, sha256: policyHash }, evidence: taskCase.referencePath.evidence,
      taskCase, executionIdentityHash: candidate.executionIdentityHash };
    let result;
    try {
      if (contextOnly) {
        const context = await loadV2ReferenceContext(input);
        const checkpoints = [...new Map(context.rpc('eth_getBlockByNumber').flatMap((observation) => {
          const block = observation.result;
          return block && typeof block.hash === 'string' && typeof block.number === 'string'
            ? [[block.hash, { number: BigInt(block.number).toString(), hash: block.hash }]] : [];
        })).values()];
        const matchesAmounts = (shape) => checkpoints.find((checkpoint) => {
          try {
            const observed = context.stateAt(shape, checkpoint);
            return canonicalTaskJson(observed.balances) === canonicalTaskJson(shape.balances)
              && canonicalTaskJson(observed.allowances) === canonicalTaskJson(shape.allowances);
          } catch { return false; }
        });
        const initialCheckpoint = matchesAmounts(taskCase.initialState);
        const finalCheckpoint = matchesAmounts(context.envelope.finalState);
        result = { status: 'context_loaded', rawArtifacts: context.documents.length,
          actualPhaseObservations: context.actualDocuments.length, participantActions: context.actions.length,
          initialAmountCheckpoint: initialCheckpoint ?? null, finalAmountCheckpoint: finalCheckpoint ?? null };
        if (!initialCheckpoint || !finalCheckpoint) result = { ...result, status: 'unavailable', reason: 'raw_block_tagged_state_reads_incomplete' };
      } else result = await verifyTaskReferenceEvidenceV2(input);
    } catch (error) {
      result = { status: error instanceof V2ReferenceError ? error.disposition : 'unavailable',
        reason: error instanceof V2ReferenceError ? error.code : 'reference_context_unavailable' };
    }
    results.push({ taskId: taskCase.taskId, mode: taskCase.mode, caseHash: taskCase.caseHash, result });
  }
  const after = await snapshot();
  if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error('verification_source_changed');
  const success = results.every((row) => row.result.status === (contextOnly ? 'context_loaded' : 'verified'));
  const captureId = randomUUID(), outputPrefix = `artifacts/runs/bts-v2-reference-${contextOnly ? 'context-preflight' : 'verification'}/${captureId}`;
  await mkdir(outputPrefix, { recursive: true });
  const bytes = Buffer.from(`${JSON.stringify({ schemaVersion: 'bts-v2-reference-verification/v1', captureId,
    classification: contextOnly ? 'raw_context_preflight_not_reference_semantics'
      : 'retained_local_reference_goal_verification_not_owner_run_acceptance',
    status: success ? (contextOnly ? 'contexts_loaded' : 'verified_references') : 'blocked', contextOnly,
    candidate: { path: args[1], sha256: args[3] }, executionIdentityHash: candidate.executionIdentityHash,
    sourceInputs: before, sourceUnchanged: true, results,
    claims: { releaseValidated: false, releaseActivated: false, taskGrade: false, ownerRunAcceptance: false,
      mainnetExecution: false, semanticVerification: !contextOnly && success } }, null, 2)}\n`);
  await writeFile(`${outputPrefix}/verification.json`, bytes, { flag: 'wx' });
  process.stdout.write(`${JSON.stringify({ outputPrefix, sha256: sha(bytes), success, contextOnly,
    cases: results.length, blockers: results.filter((row) => !['verified', 'context_loaded'].includes(row.result.status)) })}\n`);
  if (!success) process.exitCode = 2;
}
void main().catch(() => { process.stderr.write('v2_reference_verification_failed\n'); process.exitCode = 2; });
