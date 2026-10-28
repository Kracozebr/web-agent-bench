import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { apiPath, findRepositoryRoot, loadProbeRuntime, runtimeEnvironment, sourceDigests } from './environment.js';
import { EvidenceWriter, sha256Bytes } from './evidence.js';
import { DatabaseObserver } from './observer.js';
import { ReadOnlyRpcEvidence } from './rpc.js';
import { HttpEvidenceTransport } from './transport.js';
import { captureCapabilities, missingCapabilityPrerequisites, type ProbeCapabilityDocument, type ProbeContext } from './runner.js';
import { captureU1SameGenerationReference } from './task-u1-capture.js';
import { captureU1DifficultyV2Task, type U1DifficultyV2Capture } from './task-v2-u1-capture.js';
import { loadDifficultyProfileV2, type DifficultyProfileSource } from './task-difficulty-v2-capture.js';
import type { GenerationSession } from './runner.js';
import type { LoadedProbeRuntime } from './environment.js';

type Options = { envId: 'bef-env-b'; evidenceDirectory: string; profile: 'legacy' | 'v2' };
type SourceBaseline = { appSourceSha256: string; probeSourceSha256: string; manifestSha256: string; profileSha256: string };
type SourceCheck = { before: SourceBaseline; after: SourceBaseline | null; matches: boolean };

function sourceBaseline(runtime: LoadedProbeRuntime, source: DifficultyProfileSource): SourceBaseline {
  return { appSourceSha256: runtime.appSourceSha256, probeSourceSha256: runtime.probeSourceSha256,
    manifestSha256: runtime.manifestSha256, profileSha256: source.sha256 };
}
async function sourceHashes(runtime: LoadedProbeRuntime, source: DifficultyProfileSource): Promise<SourceBaseline> {
  const [tree, manifestBytes, profileBytes] = await Promise.all([
    sourceDigests(runtime.root), readFile(runtime.manifestPath), readFile(resolve(runtime.root, source.path)),
  ]);
  return { ...tree, manifestSha256: sha256Bytes(manifestBytes), profileSha256: sha256Bytes(profileBytes) };
}
function sourceCheckMatches(before: SourceBaseline, after: SourceBaseline): boolean {
  return before.appSourceSha256 === after.appSourceSha256 && before.probeSourceSha256 === after.probeSourceSha256
    && before.manifestSha256 === after.manifestSha256 && before.profileSha256 === after.profileSha256;
}
function profileReference(source: DifficultyProfileSource, evidencePath: string): Record<string, unknown> {
  return { profileId: 'bts-task-difficulty-v2', sourcePath: source.path, sourceSha256: source.sha256,
    evidencePath, evidenceSha256: source.sha256 };
}

function parseArguments(args: string[]): Options {
  let envId = 'bef-env-b'; let evidenceDirectory: string | undefined; let profile: 'legacy' | 'v2' = 'legacy';
  const offset = args[0] === '--' ? 1 : 0;
  for (let index = offset; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--env-id') envId = args[++index] ?? '';
    else if (arg === '--evidence-dir') evidenceDirectory = args[++index];
    else if (arg === '--profile') {
      const value = args[++index];
      if (value !== 'legacy' && value !== 'v2') throw new Error('task_u1_usage');
      profile = value;
    }
    else throw new Error('task_u1_usage');
  }
  if (envId !== 'bef-env-b' || !evidenceDirectory) throw new Error('task_u1_usage');
  return { envId: 'bef-env-b', evidenceDirectory, profile };
}
function safeErrorCode(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (/^(?:probe|task_u1|task_reference|task_native|task_h3|task_split|task_difficulty_v2)_[a-z0-9_-]+(?:_\d{3})?$/i.test(message)) return message;
  return 'task_u1_capture_failed';
}
async function fenceU1Generation(ctx: ProbeContext, session: GenerationSession, profile: Options['profile']): Promise<Record<string, unknown>> {
  const variantId = profile === 'v2' ? 'bts_u1_ranked_difficulty_v2_reference' : 'bts_u1_same_generation_local_reference';
  if (profile === 'v2') {
    const cleanupDeadlineAt = Date.now() + 15_000;
    ctx.transport.setDeadlineAt(cleanupDeadlineAt);
    ctx.database.setDeadlineAt(cleanupDeadlineAt);
  }
  const response = await ctx.transport.request({
    boundary: 'private-admin-http', observationId: profile === 'v2' ? 'task-u1-v2-actual-generation-fence' : 'task-u1-generation-fence', method: 'POST',
    url: apiPath(ctx.env.apiBaseUrl, '/internal/admin/environments/' + session.envId + '/generations/' + session.generationId + '/fence'),
    headers: { 'X-BEF-Admin-Key': ctx.env.adminKey, 'content-type': 'application/json' }, body: {}, operationId: null,
    variantId,
  });
  const body = response.body && typeof response.body === 'object' ? response.body as Record<string, unknown> : null;
  if (response.status !== 200 || body?.status !== 'fenced' || body?.signerErased !== true) throw new Error('task_u1_generation_fence_failed_' + response.status);
  const snapshot = await ctx.database.snapshot({ envId: session.envId, generationId: session.generationId,
    variantId, label: profile === 'v2' ? 'task-u1-v2-actual-generation-after-fence' : 'task-u1-generation-after-fence' });
  const generation = snapshot.generation[0];
  if (snapshot.generation.length !== 1 || generation?.status !== 'fenced') throw new Error('task_u1_generation_fence_not_persisted');
  if (profile === 'v2') {
    if (String(generation.generation_id).toLowerCase() !== session.generationId.toLowerCase()
      || String(generation.participant_id) !== session.participantId
      || String(generation.payer_address).toLowerCase() !== session.payerAddress.toLowerCase()) {
      throw new Error('task_u1_v2_generation_fence_identity_invalid');
    }
    const unresolved = snapshot.operations.filter((row) => ['awaiting_payment', 'verifying', 'settling', 'settlement_unknown']
      .includes(String(row.status)) || String(row.receipt_status) === 'unknown');
    return { status: 'fenced', signerErased: true, envId: session.envId, generationId: session.generationId,
      independentObserver: { status: generation.status, participantId: generation.participant_id,
        payerAddress: String(generation.payer_address).toLowerCase(),
        economicOutcome: unresolved.length ? 'unresolved' : 'settled_or_absent', unresolvedOperationCount: unresolved.length,
        unresolvedOperations: unresolved.map((row) => ({ operationId: String(row.operation_id ?? ''), status: String(row.status ?? 'unknown'),
          receiptStatus: row.receipt_status === null || row.receipt_status === undefined ? null : String(row.receipt_status) })) } };
  }
  return { status: 'fenced', signerErased: true, databaseGeneration: generation };
}

async function main(): Promise<void> {
  let options: Options;
  try { options = parseArguments(process.argv.slice(2)); process.chdir(findRepositoryRoot()); }
  catch { process.stderr.write('task_u1_usage: --env-id bef-env-b --evidence-dir PATH [--profile legacy|v2]\n'); process.exitCode = 2; return; }
  const runtime = await loadProbeRuntime().catch(() => null);
  if (!runtime) { process.stderr.write('status=error phase=runtime code=task_u1_runtime_unavailable\n'); process.exitCode = 2; return; }
  let evidence: EvidenceWriter | null = null; let database: DatabaseObserver | null = null; let context: ProbeContext | null = null;
  let manifestCopy: { path: 'manifest.json'; sha256: string } | null = null;
  let v2ProfileEvidence: { path: string; sha256: string } | null = null;
  let v2Result: U1DifficultyV2Capture | null = null;
  let v2Source: DifficultyProfileSource | null = null;
  let sourceCheck: SourceCheck | null = null;
  let phase = 'runtime'; let missingPrerequisites: string[] = []; let capture: Record<string, unknown> | null = null;
  let fence: Record<string, unknown> | null = null; let fenceAttempted = false; let fenceErrorCode: string | null = null;
  try {
    const env = runtimeEnvironment(runtime.manifest, options.envId);
    phase = 'evidence_setup'; evidence = new EvidenceWriter(options.evidenceDirectory); await evidence.initialize();
    if ((await readdir(evidence.directory)).length > 0) throw new Error('task_u1_evidence_directory_not_empty');
    manifestCopy = await evidence.writeManifestCopy(runtime.manifestBytes);
    database = new DatabaseObserver(env.databaseObserverUrl, evidence);
    phase = 'database_observer'; await database.verifyReadOnlyRole(); await database.writePrivilegeObservation();
    const secrets = [env.adminKey, env.serviceKey];
    context = {
      scenarioId: 'BEF-SC-009', runtime, env, evidence,
      transport: new HttpEvidenceTransport(evidence, secrets, 10_000, runtime.manifest.guardrails.maxSwapScenarioSeconds * 1_000),
      rpc: new ReadOnlyRpcEvidence(evidence), database, secretValues: secrets, operations: new Map(),
      replayedOriginalCaptures: [],
      capability: { schemaVersion: 'bef-probe-capabilities/v1', envId: env.envId, manifestSha256: runtime.manifestSha256,
        ready: false, implemented: {} } satisfies ProbeCapabilityDocument,
      primaryGeneration: null, primarySession: null, sequence: 0,
    };
    phase = 'capabilities'; context.capability = await captureCapabilities(context);
    missingPrerequisites = missingCapabilityPrerequisites('BEF-SC-009', context.capability,
      runtime.manifestSha256, runtime.appSourceSha256, options.envId);
    if (missingPrerequisites.length) throw new Error('task_u1_required_capabilities_missing');
    const deadlineAt = Date.now() + runtime.manifest.guardrails.maxSwapScenarioSeconds * 1_000;
    context.transport.setDeadlineAt(deadlineAt); context.rpc.setDeadlineAt(deadlineAt); database.setDeadlineAt(deadlineAt);
    phase = 'local_rpc_identity'; await context.rpc.bindLocalEndpoint({ url: env.localRpcUrl, environmentId: env.envId,
      manifestSha256: runtime.manifestSha256, label: 'task-u1-local-rpc-identity' });
    if (options.profile === 'v2') {
      phase = 'difficulty_v2_profile';
      v2Source = await loadDifficultyProfileV2({ runtime });
      sourceCheck = { before: sourceBaseline(runtime, v2Source), after: null, matches: false };
      const path = 'task-u1-v2/source-profile.json';
      await evidence.writeRawJson(path, v2Source.bytes, 'task-case-input-profile');
      const sourceArtifact = evidence.artifacts.find((item) => item.path === path);
      if (!sourceArtifact || sourceArtifact.sha256 !== v2Source.sha256) throw new Error('task_u1_v2_profile_evidence_hash_mismatch');
      v2ProfileEvidence = { path, sha256: sourceArtifact.sha256 };
      phase = 'difficulty_v2_reference_capture';
      v2Result = await captureU1DifficultyV2Task(context, v2Source, deadlineAt);
      capture = v2Result.capture;
    } else {
      phase = 'same_generation_reference_capture'; capture = await captureU1SameGenerationReference(context);
    }
    const session = v2Result?.session ?? context.primarySession;
    if (!session) throw new Error('task_u1_primary_generation_missing');
    phase = 'generation_fence'; fenceAttempted = true; fence = await fenceU1Generation(context, session, options.profile);
    phase = 'source_integrity';
    if (options.profile === 'v2' && v2Source) {
      const after = await sourceHashes(runtime, v2Source);
      sourceCheck = { before: sourceBaseline(runtime, v2Source), after, matches: sourceCheckMatches(sourceBaseline(runtime, v2Source), after) };
      if (!sourceCheck.matches) throw new Error('task_u1_v2_source_changed_during_capture');
      const actions = v2Result!.participantActions;
      await evidence.writeProbe({
        schemaVersion: 'bts-difficulty-v2-reference-probe/v1',
        classification: 'local_fork_reference_evidence_not_bts_task_acceptance',
        status: 'captured', phase: 'complete', taskId: 'U1', mode: 'ranked',
        participantToolProtocol: runtime.manifest.tools.participantProtocol,
        manifest: manifestCopy,
        difficultyProfile: profileReference(v2Source, v2ProfileEvidence!.path),
        environment: { envId: env.envId, chainId: runtime.manifest.local.chainId,
          forkBlock: runtime.manifest.local.forkBlock, generationId: v2Result!.session.generationId,
          participantId: v2Result!.session.participantId, payerAddress: v2Result!.session.payerAddress.toLowerCase() },
        sourceDigests: sourceCheck, capture: v2Result!.capture,
        captureReferences: { caseArtifact: v2Result!.caseArtifact, participantActions: actions, participantActionCount: actions.length },
        participantActionCount: actions.length, generationFence: fence,
        releaseReadiness: 'blocked', noTaskGrade: true, noReleaseActivation: true, noAcceptanceClaim: true,
        observations: evidence.observations, artifacts: evidence.artifacts,
      });
      process.stdout.write(`status=captured task=U1 mode=ranked participant_actions=${actions.length} generation_fenced=true release_readiness=blocked artifacts=${evidence.artifacts.length}\n`);
    } else {
      const finalDigests = await sourceDigests(runtime.root);
      if (finalDigests.appSourceSha256 !== runtime.appSourceSha256 || finalDigests.probeSourceSha256 !== runtime.probeSourceSha256) {
        throw new Error('task_u1_source_changed_during_capture');
      }
      await evidence.writeProbe({
        schemaVersion: 'bts-task-u1-capture/v1', classification: 'local_fork_public_tool_evidence_not_bts_task_acceptance',
        status: 'captured', releaseReadiness: 'blocked', taskId: 'U1', manifest: manifestCopy,
        environment: { envId: env.envId, chainId: runtime.manifest.local.chainId, forkBlock: runtime.manifest.local.forkBlock,
          generation: context.primaryGeneration }, applicationSourceSha256: runtime.appSourceSha256,
        probeSourceSha256: runtime.probeSourceSha256, sourceBlock: { number: runtime.manifest.source.blockNumber, hash: runtime.manifest.source.blockHash },
        capture, generationFence: fence, observations: evidence.observations, artifacts: evidence.artifacts,
        noReleaseActivation: true, noGradePosted: true,
      });
      process.stdout.write('status=captured task=U1 generation_fenced=true release_readiness=blocked artifacts=' + evidence.artifacts.length + '\n');
    }
  } catch (error) {
    const errorCode = safeErrorCode(error);
    if (context?.primarySession && !fenceAttempted) {
      fenceAttempted = true;
      try { fence = await fenceU1Generation(context, context.primarySession, options.profile); }
      catch (fenceError) { fenceErrorCode = safeErrorCode(fenceError); }
    }
    if (evidence && !evidence.artifacts.some((artifact) => artifact.path === 'probe.json')) {
      if (options.profile === 'v2') {
        if (v2Source && !sourceCheck?.after) {
          try {
            const after = await sourceHashes(runtime, v2Source);
            const before = sourceBaseline(runtime, v2Source);
            sourceCheck = { before, after, matches: sourceCheckMatches(before, after) };
          } catch { /* source digests remain explicitly unavailable */ }
        }
        await evidence.writeProbe({
          schemaVersion: 'bts-difficulty-v2-reference-probe/v1',
          classification: 'local_fork_reference_evidence_not_bts_task_acceptance',
          status: 'error', phase, taskId: 'U1', mode: 'ranked', errorCode,
          ...(missingPrerequisites.length ? { missingPrerequisites } : {}), manifest: manifestCopy,
          difficultyProfile: v2Source && v2ProfileEvidence ? profileReference(v2Source, v2ProfileEvidence.path) : null,
          participantToolProtocol: runtime.manifest.tools.participantProtocol,
          environment: context?.primaryGeneration ? { ...context.primaryGeneration } : { envId: options.envId },
          sourceDigests: sourceCheck, capture: v2Result?.capture ?? capture,
          captureReferences: v2Result ? { caseArtifact: v2Result.caseArtifact, participantActions: v2Result.participantActions,
            participantActionCount: v2Result.participantActions.length } : null,
          generationFence: fence, generationFenceAttempted: fenceAttempted, generationFenceErrorCode: fenceErrorCode,
          releaseReadiness: 'blocked', noTaskGrade: true, noReleaseActivation: true, noAcceptanceClaim: true,
          observations: evidence.observations, artifacts: evidence.artifacts,
        }).catch(() => undefined);
      } else {
        await evidence.writeProbe({ schemaVersion: 'bts-task-u1-capture/v1',
          classification: 'local_fork_public_tool_evidence_not_bts_task_acceptance', status: 'error',
          releaseReadiness: 'blocked', taskId: 'U1', phase, errorCode,
          ...(missingPrerequisites.length ? { missingPrerequisites } : {}), manifest: manifestCopy,
          environment: context?.primaryGeneration ?? { envId: options.envId }, applicationSourceSha256: runtime.appSourceSha256,
          probeSourceSha256: runtime.probeSourceSha256, capture, generationFence: fence,
          observations: evidence.observations, artifacts: evidence.artifacts, noReleaseActivation: true, noGradePosted: true,
        }).catch(() => undefined);
      }
    }
    process.stderr.write('status=error phase=' + phase + ' code=' + errorCode + '\n'); process.exitCode = 2;
  } finally { await database?.close().catch(() => undefined); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) void main();
